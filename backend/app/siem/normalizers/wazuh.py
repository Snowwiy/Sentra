"""Conector `wazuh_alerts`: alertas exportadas de Wazuh (alerts.json, una por línea) (Fase 7F.5).

Integración OPCIONAL y de solo lectura: Sentra lee el fichero de alertas que el manager de
Wazuh ya escribe (con el lector de ficheros del sensor o con una importación manual). No usa la
API de Wazuh, no guarda credenciales de Wazuh y nunca modifica nada en Wazuh.

Reglas:
* Procedencia visible: el evento conserva el id de la alerta, la regla (id, nivel,
  descripción, grupos), el agente (id y nombre), el decoder, la ubicación y el MITRE que dice
  Wazuh. La UI los muestra como "según Wazuh".
* El nombre del agente NO es identidad definitiva: solo es una pista (app/siem/identity.py).
* Sin política explícita no hay severidad: por defecto todos los niveles dan `unknown` y una
  alerta de Wazuh no genera detecciones hasta que un admin define la política de la fuente
  (claves "0-3", "4-7", "8-11", "12-15"). La recomendada está en docs/fase-7f-wazuh.md.
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

LEVEL_BUCKETS = (("0-3", 0, 3), ("4-7", 4, 7), ("8-11", 8, 11), ("12-15", 12, 15))
# Sin política explícita, nada se traduce: severidad desconocida para todos los niveles.
DEFAULT_POLICY = {key: "unknown" for key, _low, _high in LEVEL_BUCKETS}

# Wazuh guarda la táctica por NOMBRE; Sentra usa el id de ATT&CK Enterprise.
TACTICS = {
    "reconnaissance": "TA0043",
    "resource development": "TA0042",
    "initial access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege escalation": "TA0004",
    "defense evasion": "TA0005",
    "credential access": "TA0006",
    "discovery": "TA0007",
    "lateral movement": "TA0008",
    "collection": "TA0009",
    "command and control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}
_ALERT_ID = re.compile(r"^[0-9]{1,20}(\.[0-9]{1,20})?$")


def bucket(level: int) -> str | None:
    for key, low, high in LEVEL_BUCKETS:
        if low <= level <= high:
            return key
    return None


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def normalize(record: RawRecord, ctx: NormalizeContext) -> NormalizedEvent:
    try:
        value: Any = json.loads(record.raw)
    except ValueError as exc:
        raise RecordRejectedError("invalid_json") from exc
    if not isinstance(value, dict):
        raise RecordRejectedError("invalid_json")
    rule = _dict(value.get("rule"))
    level = rule.get("level")
    rule_id = fields.ident(rule.get("id"), 32)
    if not isinstance(level, int) or isinstance(level, bool) or rule_id is None:
        raise RecordRejectedError("invalid_schema")
    key = bucket(level)
    if key is None:
        raise RecordRejectedError("invalid_schema")
    if not ctx.allows("wazuh.alert"):
        raise RecordRejectedError("event_type_not_allowed")
    observed = fields.timestamp(value.get("timestamp"))
    if observed is None:
        raise RecordRejectedError("invalid_timestamp")
    alert_id = value.get("id")
    alert_id = alert_id if isinstance(alert_id, str) and _ALERT_ID.fullmatch(alert_id) else None
    agent = _dict(value.get("agent"))
    manager = _dict(value.get("manager"))
    decoder = _dict(value.get("decoder"))
    extra = _dict(value.get("data"))
    mitre = _dict(rule.get("mitre"))
    tactics = [
        TACTICS[t.lower()]
        for t in (mitre.get("tactic") or [])
        if isinstance(t, str) and t.lower() in TACTICS
    ]
    groups = [g for g in (rule.get("groups") or []) if isinstance(g, str)]
    data: dict[str, Any] = {
        "origin_product": "wazuh",
        "alert_id": alert_id,
        "rule_level": level,
        "level_bucket": key,
        "rule_groups": groups[:16],
        "firedtimes": rule.get("firedtimes") if isinstance(rule.get("firedtimes"), int) else None,
        "agent_id": fields.ident(agent.get("id"), 16),
        "agent_name": fields.text(agent.get("name"), 128),
        "agent_ip": fields.ip(agent.get("ip")),
        "manager": fields.text(manager.get("name"), 128),
        "decoder": fields.text(decoder.get("name"), 64),
        "location": fields.text(value.get("location"), 255),
        "mitre_tactic": tactics[0] if tactics else None,
        "mitre_tactic_names": [t for t in (mitre.get("tactic") or []) if isinstance(t, str)][:4],
    }
    win_system = _dict(_dict(extra.get("win")).get("system"))
    raw_proto = extra.get("protocol")
    protocol = raw_proto.lower() if isinstance(raw_proto, str) and raw_proto.isalpha() else None
    username = fields.text(extra.get("dstuser") or extra.get("srcuser") or extra.get("user"), 128)
    severity = ctx.severity_policy(DEFAULT_POLICY).get(key, "unknown")
    return NormalizedEvent(
        event_type="wazuh.alert",
        category="detection",
        identity=fields.identity_hash(
            "wazuh", alert_id or fields.sha256_text(record.raw), rule_id, value.get("timestamp")
        ),
        observed_at=observed,
        severity=severity,
        source_severity=f"level {level}",
        # Una regla de Wazuh que salta es evidencia externa, no una intrusión confirmada.
        confidence="low",
        # El nombre del agente es una pista, no identidad (identity.py lo trata como tal).
        hostname=fields.hostname(agent.get("name")),
        src_ip=fields.ip(extra.get("srcip")),
        dst_ip=fields.ip(extra.get("dstip")),
        src_port=fields.port(extra.get("srcport")),
        dst_port=fields.port(extra.get("dstport")),
        protocol=protocol,
        username=username,
        process_name=fields.text(win_system.get("providerName"), 255),
        signature_id=rule_id,
        rule_id=rule_id,
        message=fields.text(rule.get("description"), 1000),
        tags=fields.tags(groups),
        mitre_techniques=fields.mitre(mitre.get("id") or []),
        external_id=fields.ident(alert_id),
        excerpt=fields.excerpt(record.raw, ctx.raw_store_bytes),
        data=fields.data(data),
    )


CONNECTOR = register(
    Connector(
        source_type="wazuh_alerts",
        title="Wazuh (alertas exportadas)",
        version=VERSION,
        transports=(TRANSPORT_SENSOR, TRANSPORT_UPLOAD),
        sensor_input=INPUT_FILE,
        description=(
            "alerts.json del manager de Wazuh (una alerta por línea), leído por el sensor o"
            " importado. Solo lectura: Sentra no usa la API de Wazuh ni lo modifica."
        ),
        normalize=normalize,
        severity_policy=DEFAULT_POLICY,
        severity_policy_doc=(
            "Nivel de la regla de Wazuh por tramos (0-3, 4-7, 8-11, 12-15) → Sentra. Sin"
            " política explícita todos los tramos dan unknown y las alertas no generan"
            " detecciones; un admin debe definirla en la fuente."
        ),
        event_types=("wazuh.alert",),
        sensitive_fields=("username", "hostname", "message", "data.location", "raw_excerpt"),
        validation=(
            "Fixtures sintéticos con la estructura documentada de alerts.json (Wazuh 4.x);"
            " sin validación con un manager de Wazuh real."
        ),
        formats=("wazuh_alerts_json",),
    )
)
