"""Conector `zeek_json`: logs JSON de Zeek (conn, dns, ssl, http, dhcp, ssh) (Fase 7F.4).

Zeek escribe un fichero por tipo de log; con `LogAscii::use_json=T` cada línea es un objeto
JSON. El tipo sale de `_path` (lo añade el sensor a partir del nombre del fichero si Zeek no lo
escribe, o lo traen los logs "json-streaming") o, si falta, de los campos característicos.

Reglas:
* El `uid` de Zeek se conserva como `flow_ref` y `external_id`: une los registros de la misma
  conexión entre logs (conn, dns, http...) y, con `community_id`, con Suricata.
* Zeek no tiene severidades: todo entra como `informational`. Zeek describe tráfico, no
  juzga; un registro de Zeek no genera por sí solo ninguna detección.
* Sin cuerpos HTTP ni ficheros extraídos (files.log y extract no se aceptan). La URI se
  guarda sin query string. DNS, SNI, URI y user-agent solo se ven con `siem:evidence`.
"""

import json
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

LOGS: dict[str, tuple[str, str]] = {
    "conn": ("network.connection", "network"),
    "dns": ("dns.query", "dns"),
    "ssl": ("tls.handshake", "tls"),
    "http": ("http.request", "http"),
    "dhcp": ("dhcp.message", "dhcp"),
    "ssh": ("ssh.session", "ssh"),
}
# Campos que identifican cada log cuando falta `_path` (en orden de comprobación).
_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("dns", ("query", "qtype_name")),
    ("http", ("method", "uri")),
    ("ssl", ("server_name", "cipher")),
    ("ssh", ("auth_attempts",)),
    ("dhcp", ("msg_types",)),
    ("conn", ("conn_state",)),
)
# Claves que nunca se guardan aunque una versión o un script de Zeek las añada.
_CONTENT_KEYS = frozenset({"post_body", "request_body", "response_body", "extracted", "data"})


def _infer(value: dict[str, Any]) -> str | None:
    path = value.get("_path")
    if isinstance(path, str):
        return path if path in LOGS else None
    for log, keys in _SIGNATURES:
        if any(key in value for key in keys):
            return log
    return None


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _strings(value: object, limit: int = 8, size: int = 255) -> list[str]:
    if not isinstance(value, list):
        return []
    out = [fields.text(v, size) for v in value[:limit]]
    return [v for v in out if v]


def normalize(record: RawRecord, ctx: NormalizeContext) -> NormalizedEvent:
    try:
        value: Any = json.loads(record.raw)
    except ValueError as exc:
        raise RecordRejectedError("invalid_json") from exc
    if not isinstance(value, dict):
        raise RecordRejectedError("invalid_json")
    value = {k: v for k, v in value.items() if k not in _CONTENT_KEYS}
    log = _infer(value)
    if log is None:
        raise RecordRejectedError("unsupported_log")
    event_type, category = LOGS[log]
    if not ctx.allows(event_type):
        raise RecordRejectedError("event_type_not_allowed")
    observed = fields.timestamp(value.get("ts"))
    if observed is None:
        raise RecordRejectedError("invalid_timestamp")
    uid = fields.ident(value.get("uid"), 64)
    proto = value.get("proto")
    protocol = proto.lower() if isinstance(proto, str) and proto.isalpha() else None
    data: dict[str, Any] = {
        "zeek_log": log,
        "community_id": fields.text(value.get("community_id"), 64),
    }
    hostname = username = message = action = outcome = None
    if log == "conn":
        data.update(
            {
                "service": fields.text(value.get("service"), 32),
                "conn_state": fields.text(value.get("conn_state"), 8),
                "history": fields.text(value.get("history"), 32),
                "duration": value.get("duration")
                if isinstance(value.get("duration"), int | float)
                else None,
                "orig_bytes": _int(value.get("orig_bytes")),
                "resp_bytes": _int(value.get("resp_bytes")),
                "orig_pkts": _int(value.get("orig_pkts")),
                "resp_pkts": _int(value.get("resp_pkts")),
                "missed_bytes": _int(value.get("missed_bytes")),
                "local_orig": value.get("local_orig")
                if isinstance(value.get("local_orig"), bool)
                else None,
            }
        )
    elif log == "dns":
        protocol = protocol or "udp"
        query = fields.text(value.get("query"), 253)
        data.update(
            {
                "query": query,
                "qtype_name": fields.text(value.get("qtype_name"), 16),
                "rcode_name": fields.text(value.get("rcode_name"), 16),
                "answers": _strings(value.get("answers")),
                "trans_id": _int(value.get("trans_id")),
            }
        )
        message = query
    elif log == "ssl":
        hostname = fields.hostname(value.get("server_name"))
        established = value.get("established")
        outcome = (
            "success" if established is True else ("failure" if established is False else None)
        )
        data.update(
            {
                "server_name": fields.text(value.get("server_name"), 253),
                "tls_version": fields.text(value.get("version"), 16),
                "cipher": fields.text(value.get("cipher"), 64),
                "validation_status": fields.text(value.get("validation_status"), 64),
                "ja3": fields.ident(value.get("ja3"), 32),
                "ja3s": fields.ident(value.get("ja3s"), 32),
            }
        )
    elif log == "http":
        hostname = fields.hostname(value.get("host"))
        data.update(
            {
                "method": fields.text(value.get("method"), 16),
                "host": fields.text(value.get("host"), 253),
                "uri_path": fields.url_path(value.get("uri")),
                "status_code": _int(value.get("status_code")),
                "user_agent": fields.text(value.get("user_agent"), 256),
                "request_body_len": _int(value.get("request_body_len")),
                "response_body_len": _int(value.get("response_body_len")),
                "trans_depth": _int(value.get("trans_depth")),
            }
        )
    elif log == "dhcp":
        hostname = fields.hostname(value.get("host_name"))
        uids = value.get("uids")
        if uid is None and isinstance(uids, list) and uids:
            uid = fields.ident(uids[0], 64)
        data.update(
            {
                "mac": fields.text(value.get("mac"), 17),
                "assigned_addr": fields.ip(value.get("assigned_addr")),
                "client_addr": fields.ip(value.get("client_addr")),
                "server_addr": fields.ip(value.get("server_addr")),
                "msg_types": _strings(value.get("msg_types"), 8, 16),
                "domain": fields.text(value.get("domain"), 253),
            }
        )
    elif log == "ssh":
        success = value.get("auth_success")
        outcome = "success" if success is True else ("failure" if success is False else "unknown")
        action = "login"
        protocol = protocol or "tcp"
        data.update(
            {
                "auth_attempts": _int(value.get("auth_attempts")),
                "direction": fields.text(value.get("direction"), 16),
                "client": fields.text(value.get("client"), 128),
                "server": fields.text(value.get("server"), 128),
                "version": _int(value.get("version")),
            }
        )
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    excerpt_source = dict(value)
    if log == "http" and isinstance(excerpt_source.get("uri"), str):
        excerpt_source["uri"] = fields.url_path(excerpt_source["uri"])
    if log == "http" and isinstance(excerpt_source.get("referrer"), str):
        excerpt_source["referrer"] = fields.url_path(excerpt_source["referrer"])
    return NormalizedEvent(
        event_type=event_type,
        category=category,
        identity=fields.identity_hash("zeek", log, canonical),
        observed_at=observed,
        severity="informational",
        source_severity=None,
        confidence="unknown",
        hostname=hostname,
        src_ip=fields.ip(value.get("id.orig_h")),
        dst_ip=fields.ip(value.get("id.resp_h")),
        src_port=fields.port(value.get("id.orig_p")),
        dst_port=fields.port(value.get("id.resp_p")),
        protocol=protocol,
        username=username,
        action=action,
        outcome=outcome,
        message=message,
        external_id=uid,
        flow_ref=uid,
        excerpt=fields.excerpt(
            json.dumps(excerpt_source, sort_keys=True, separators=(",", ":"), default=str),
            ctx.raw_store_bytes,
        ),
        data=fields.data(data),
    )


CONNECTOR = register(
    Connector(
        source_type="zeek_json",
        title="Zeek (logs JSON)",
        version=VERSION,
        transports=(TRANSPORT_SENSOR, TRANSPORT_UPLOAD),
        sensor_input=INPUT_FILE,
        description=(
            "Logs conn, dns, ssl, http, dhcp y ssh de Zeek en JSON (LogAscii::use_json=T),"
            " leídos por el sensor o importados. El uid de Zeek se conserva para unir"
            " registros de la misma conexión."
        ),
        normalize=normalize,
        severity_policy={},
        severity_policy_doc=(
            "Zeek no asigna severidades: todos los registros entran como informational y no"
            " generan detecciones por sí solos."
        ),
        event_types=tuple(sorted({v[0] for v in LOGS.values()})),
        sensitive_fields=(
            "hostname",
            "message",
            "data.query",
            "data.answers",
            "data.server_name",
            "data.host",
            "data.uri_path",
            "data.user_agent",
        ),
        validation=(
            "Fixtures sintéticos con los campos documentados de los logs de Zeek 6/7"
            " (docs.zeek.org); sin validación con un Zeek real."
        ),
        formats=("zeek_json",),
    )
)
