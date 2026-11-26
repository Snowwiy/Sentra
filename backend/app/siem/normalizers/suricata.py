"""Conector `suricata_eve`: registros EVE JSON de Suricata (Fase 7F.3).

Una línea JSON por registro (eve.json). Reglas:

* Sin payloads: `payload`, `payload_printable`, `packet`, `packet_info`, cuerpos HTTP y
  similares se eliminan en el sensor y otra vez aquí (defensa en profundidad). La URL HTTP se
  guarda sin la query string (puede llevar tokens o credenciales).
* Una alerta de Suricata es EVIDENCIA EXTERNA de una firma que coincidió, no una intrusión
  confirmada: entra con confianza `low` y su severidad sale de la política explícita
  (alert.severity 1..4 → high, medium, low, informational).
* Identidad estable para deduplicar: el registro canónico (sin payloads, claves ordenadas).
  Una relectura del mismo fichero o un reintento produce la misma identidad.
* `flow_id` se guarda como `flow_ref` y `community_id` (si Suricata lo calcula) en `data`:
  son los que permiten unir registros de la misma conexión y con Zeek (7F.4).
"""

import json
import re
from typing import Any

from app.siem import fields
from app.siem.catalog import (
    INPUT_FILE,
    TRANSPORT_SENSOR,
    TRANSPORT_UPLOAD,
    Connector,
    NormalizeContext,
    register,
)
from app.siem.contract import NormalizedEvent, RawRecord, RecordRejectedError

VERSION = "1.0.0"

# Claves que pueden contener contenido de la comunicación. Se eliminan a cualquier nivel.
PAYLOAD_KEYS = frozenset(
    {
        "payload",
        "payload_printable",
        "packet",
        "packet_info",
        "http_request_body",
        "http_request_body_printable",
        "http_response_body",
        "http_response_body_printable",
        "stream",
        "rule",
    }
)

# event_type de EVE → (tipo Sentra, categoría). Lo que no está aquí se rechaza
# (`unsupported_event_type`): `stats` no es un evento de seguridad y un tipo nuevo debe
# añadirse con su prueba, no entrar con una forma desconocida.
EVENT_TYPES: dict[str, tuple[str, str]] = {
    "alert": ("ids.alert", "detection"),
    "anomaly": ("ids.anomaly", "network"),
    "drop": ("ids.drop", "network"),
    "flow": ("network.flow", "network"),
    "netflow": ("network.flow", "network"),
    "dns": ("dns.query", "dns"),
    "http": ("http.request", "http"),
    "tls": ("tls.handshake", "tls"),
    "ssh": ("ssh.session", "ssh"),
    "dhcp": ("dhcp.message", "dhcp"),
    "fileinfo": ("file.observed", "file"),
    "smb": ("network.smb", "network"),
    "krb5": ("auth.kerberos", "authentication"),
}

DEFAULT_POLICY = {"1": "high", "2": "medium", "3": "low", "4": "informational"}
_PROTO = re.compile(r"^[A-Za-z0-9_-]{1,16}$")


def strip_payloads(value: Any, depth: int = 0) -> Any:
    """Copia del registro sin claves de contenido (a cualquier profundidad, acotada)."""
    if depth > 8:
        return None
    if isinstance(value, dict):
        return {k: strip_payloads(v, depth + 1) for k, v in value.items() if k not in PAYLOAD_KEYS}
    if isinstance(value, list):
        return [strip_payloads(v, depth + 1) for v in value[:64]]
    return value


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _mitre(alert: dict[str, Any]) -> tuple[list[str], str | None]:
    """Técnicas ATT&CK del metadata de la firma (convención de ET Open: mitre_technique_id)."""
    metadata = _dict(alert.get("metadata"))
    techniques = fields.mitre(metadata.get("mitre_technique_id") or [])
    tactics = metadata.get("mitre_tactic_id")
    tactic = tactics[0] if isinstance(tactics, list) and tactics else None
    return techniques, tactic if isinstance(tactic, str) and re.fullmatch(
        r"TA\d{4}", tactic
    ) else None


def normalize(record: RawRecord, ctx: NormalizeContext) -> NormalizedEvent:
    try:
        value: Any = json.loads(record.raw)
    except ValueError as exc:
        raise RecordRejectedError("invalid_json") from exc
    if not isinstance(value, dict):
        raise RecordRejectedError("invalid_json")
    eve_type = value.get("event_type")
    if not isinstance(eve_type, str) or eve_type not in EVENT_TYPES:
        raise RecordRejectedError("unsupported_event_type")
    event_type, category = EVENT_TYPES[eve_type]
    if not ctx.allows(event_type):
        raise RecordRejectedError("event_type_not_allowed")
    clean = strip_payloads(value)
    http_clean = clean.get("http")
    if isinstance(http_clean, dict):
        # La query string y el fragmento pueden llevar tokens: tampoco van al extracto.
        for key in ("url", "http_refer", "redirect"):
            if key in http_clean:
                http_clean[key] = fields.url_path(http_clean[key])
    observed = fields.timestamp(value.get("timestamp"))
    if observed is None:
        raise RecordRejectedError("invalid_timestamp")
    proto_raw = value.get("proto")
    protocol = (
        str(proto_raw).lower()
        if isinstance(proto_raw, str | int) and _PROTO.fullmatch(str(proto_raw))
        else None
    )
    flow_id = value.get("flow_id")
    data: dict[str, Any] = {
        "eve_event_type": eve_type,
        "app_proto": fields.text(value.get("app_proto"), 32),
        "in_iface": fields.text(value.get("in_iface"), 32),
        "community_id": fields.text(value.get("community_id"), 64),
        "tx_id": value.get("tx_id") if isinstance(value.get("tx_id"), int) else None,
        "direction": fields.text(value.get("direction"), 16),
    }
    severity = "informational"
    source_severity: str | None = None
    signature_id = rule_id = message = None
    action = outcome = None
    mitre: list[str] = []
    confidence = "unknown"
    hostname: str | None = None
    if eve_type == "alert":
        alert = _dict(clean.get("alert"))
        raw_severity = alert.get("severity")
        source_severity = str(raw_severity) if isinstance(raw_severity, int) else None
        severity = ctx.severity_policy(DEFAULT_POLICY).get(source_severity or "", "unknown")
        signature_id = fields.ident(alert.get("signature_id"), 64)
        rule_id = fields.ident(
            f"{alert.get('gid', 1)}:{alert.get('signature_id')}:{alert.get('rev', 0)}", 64
        )
        message = fields.text(alert.get("signature"), 1000)
        action = "block" if alert.get("action") == "blocked" else "alert"
        mitre, tactic = _mitre(alert)
        # Firma que coincide = evidencia externa; no se presenta como intrusión confirmada.
        confidence = "low"
        data.update(
            {
                "alert_category": fields.text(alert.get("category"), 128),
                "alert_action": fields.text(alert.get("action"), 16),
                "gid": alert.get("gid") if isinstance(alert.get("gid"), int) else None,
                "rev": alert.get("rev") if isinstance(alert.get("rev"), int) else None,
                "mitre_tactic": tactic,
            }
        )
    elif eve_type == "drop":
        action, outcome = "drop", "failure"
    elif eve_type == "anomaly":
        anomaly = _dict(clean.get("anomaly"))
        message = fields.text(anomaly.get("event") or anomaly.get("type"), 1000)
        data["anomaly_layer"] = fields.text(anomaly.get("layer"), 16)
    elif eve_type == "dns":
        dns = _dict(clean.get("dns"))
        hostname = None
        data.update(
            {
                "dns_type": fields.text(dns.get("type"), 16),
                "rrname": fields.text(dns.get("rrname"), 253),
                "rrtype": fields.text(dns.get("rrtype"), 16),
                "rcode": fields.text(dns.get("rcode"), 16),
            }
        )
        message = data["rrname"]
    elif eve_type == "http":
        http = _dict(clean.get("http"))
        hostname = fields.hostname(http.get("hostname"))
        status = http.get("status")
        data.update(
            {
                "http_method": fields.text(http.get("http_method"), 16),
                "url_path": fields.url_path(http.get("url")),
                "status": status if isinstance(status, int) else None,
                "http_user_agent": fields.text(http.get("http_user_agent"), 256),
                "length": http.get("length") if isinstance(http.get("length"), int) else None,
            }
        )
    elif eve_type == "tls":
        tls = _dict(clean.get("tls"))
        hostname = fields.hostname(tls.get("sni"))
        data.update(
            {
                "sni": fields.text(tls.get("sni"), 253),
                "tls_version": fields.text(tls.get("version"), 16),
                "subject": fields.text(tls.get("subject"), 256),
                "issuer": fields.text(tls.get("issuerdn"), 256),
                "ja3": fields.ident(_dict(tls.get("ja3")).get("hash"), 32),
                "ja3s": fields.ident(_dict(tls.get("ja3s")).get("hash"), 32),
            }
        )
    elif eve_type in ("flow", "netflow"):
        flow = _dict(clean.get(eve_type))
        data.update(
            {
                "bytes_toserver": flow.get("bytes_toserver"),
                "bytes_toclient": flow.get("bytes_toclient"),
                "pkts_toserver": flow.get("pkts_toserver"),
                "pkts_toclient": flow.get("pkts_toclient"),
                "state": fields.text(flow.get("state"), 16),
                "reason": fields.text(flow.get("reason"), 16),
                "start": fields.text(flow.get("start"), 40),
                "end": fields.text(flow.get("end"), 40),
            }
        )
    elif eve_type == "ssh":
        ssh = _dict(clean.get("ssh"))
        data.update(
            {
                "client_software": fields.text(
                    _dict(ssh.get("client")).get("software_version"), 64
                ),
                "server_software": fields.text(
                    _dict(ssh.get("server")).get("software_version"), 64
                ),
            }
        )
    elif eve_type == "dhcp":
        dhcp = _dict(clean.get("dhcp"))
        hostname = fields.hostname(dhcp.get("hostname"))
        data.update(
            {
                "dhcp_type": fields.text(dhcp.get("dhcp_type"), 16),
                "client_mac": fields.text(dhcp.get("client_mac"), 17),
                "assigned_ip": fields.ip(dhcp.get("assigned_ip")),
            }
        )
    elif eve_type == "fileinfo":
        info = _dict(clean.get("fileinfo"))
        data.update(
            {
                "filename": fields.text(info.get("filename"), 255),
                "sha256": fields.ident(info.get("sha256"), 64),
                "size": info.get("size") if isinstance(info.get("size"), int) else None,
                "magic": fields.text(info.get("magic"), 128),
            }
        )
    canonical = json.dumps(clean, sort_keys=True, separators=(",", ":"), default=str)
    return NormalizedEvent(
        event_type=event_type,
        category=category,
        identity=fields.identity_hash("eve", canonical),
        observed_at=observed,
        severity=severity,
        source_severity=source_severity,
        confidence=confidence,
        hostname=hostname,
        src_ip=fields.ip(value.get("src_ip")),
        dst_ip=fields.ip(value.get("dest_ip")),
        src_port=fields.port(value.get("src_port")),
        dst_port=fields.port(value.get("dest_port")),
        protocol=protocol,
        action=action,
        outcome=outcome,
        signature_id=signature_id,
        rule_id=rule_id,
        message=message,
        mitre_techniques=mitre,
        external_id=fields.ident(flow_id),
        flow_ref=fields.ident(flow_id, 64),
        # El extracto se toma del registro YA sin payloads.
        excerpt=fields.excerpt(canonical, ctx.raw_store_bytes),
        data=fields.data(data),
    )


CONNECTOR = register(
    Connector(
        source_type="suricata_eve",
        title="Suricata EVE JSON",
        version=VERSION,
        transports=(TRANSPORT_SENSOR, TRANSPORT_UPLOAD),
        sensor_input=INPUT_FILE,
        description=(
            "Registros eve.json de Suricata leídos por el sensor (lectura incremental con"
            " offsets) o importados. Alertas, flujos, DNS, HTTP, TLS, SSH, DHCP y anomalías;"
            " nunca payloads."
        ),
        normalize=normalize,
        severity_policy=DEFAULT_POLICY,
        severity_policy_doc=(
            "alert.severity de Suricata (1 = más grave) → Sentra: 1 high, 2 medium, 3 low,"
            " 4 informational. Los registros que no son alertas entran como informational."
        ),
        event_types=tuple(sorted({v[0] for v in EVENT_TYPES.values()})),
        sensitive_fields=(
            "hostname",
            "data.rrname",
            "data.sni",
            "data.url_path",
            "data.http_user_agent",
            "data.filename",
        ),
        validation=(
            "Fixtures sintéticos con la estructura documentada de EVE JSON (Suricata 7);"
            " sin validación con un Suricata real."
        ),
        formats=("eve_json",),
    )
)
