"""Conector `syslog`: mensajes RFC 5424 y RFC 3164 (BSD) recibidos por el sensor (Fase 7F.2).

El sensor solo enmarca (RFC 6587 / RFC 5425), acota y reenvía el texto; el análisis se hace
aquí, en el servidor, con una versión de normalización explícita. Reglas:

* La cabecera se interpreta por posiciones del RFC; un mensaje sin PRI válido se acepta con
  la PRI por defecto del RFC 3164 (user.notice, 13) y se marca `pri_missing`.
* RFC 3164 no lleva año ni zona horaria: su hora NO se usa como hora del evento (sería
  adivinar). El evento usa la hora de recepción del sensor (`time_quality=receiver`) y la
  cabecera original se conserva en `data.header_timestamp`.
* La clasificación es conservadora: solo unos pocos patrones muy conocidos (sshd, sudo,
  registros tipo netfilter) cambian el tipo de evento. Todo lo demás es `syslog.message`,
  categoría `system`, y la severidad sale de la política explícita, que por defecto nunca
  llega a `critical`: un mensaje desconocido no puede convertirse en una alerta crítica.
* El HOSTNAME de la cabecera lo escribe el emisor: es contexto, no identidad. La dirección
  del emisor (peer) tampoco autentica nada en UDP (docs/fase-7f-syslog.md).
"""

import re
from typing import Any

from app.siem import fields
from app.siem.catalog import (
    INPUT_SYSLOG,
    TRANSPORT_SENSOR,
    TRANSPORT_UPLOAD,
    Connector,
    NormalizeContext,
    register,
)
from app.siem.contract import NormalizedEvent, RawRecord, RecordRejectedError

VERSION = "1.0.0"
DEFAULT_PRI = 13

FACILITIES = (
    "kern",
    "user",
    "mail",
    "daemon",
    "auth",
    "syslog",
    "lpr",
    "news",
    "uucp",
    "cron",
    "authpriv",
    "ftp",
    "ntp",
    "security",
    "console",
    "solaris-cron",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
)
SEVERITY_NAMES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
# Política por defecto: deliberadamente por debajo de lo que diría el emisor. Un dispositivo
# que marca "emerg" no demuestra nada sobre seguridad; la escala se sube por fuente si un
# admin lo decide.
DEFAULT_POLICY = {
    "emerg": "high",
    "alert": "high",
    "crit": "medium",
    "err": "low",
    "warning": "low",
    "notice": "informational",
    "info": "informational",
    "debug": "informational",
}
EVENT_TYPES = (
    "syslog.message",
    "auth.failure",
    "auth.success",
    "privilege.sudo",
    "firewall.allow",
    "firewall.deny",
    "firewall.log",
)

_PRI = re.compile(r"^<(\d{1,3})>")
_5424 = re.compile(
    r"^(?P<version>[1-9]\d{0,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+)"
    r" (?P<msgid>\S+) (?P<rest>.*)$",
    re.DOTALL,
)
_3164_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (?P<rest>.*)$", re.DOTALL)
_TAG = re.compile(r"^(?P<tag>[A-Za-z0-9_./-]{1,48})(?:\[(?P<pid>\d{1,10})\])?: ?(?P<msg>.*)$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")
_SD_ELEMENT = re.compile(r'\[([^\s\]=" ]{1,32})((?:\s+[^\s\]=" ]{1,32}="(?:[^"\\]|\\.)*")*)\]')
_SD_PARAM = re.compile(r'([^\s\]=" ]{1,32})="((?:[^"\\]|\\.)*)"')

# Patrones reconocidos: anclados, sin cuantificadores anidados (sin backtracking explosivo).
_SSH_FAIL = re.compile(
    r"^Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
    r"(?P<user>\S{1,64}) from (?P<ip>[0-9A-Fa-f:.]{2,45}) port (?P<port>\d{1,5})"
)
_SSH_INVALID = re.compile(
    r"^Invalid user (?P<user>\S{1,64}) from (?P<ip>[0-9A-Fa-f:.]{2,45})(?: port (?P<port>\d{1,5}))?"
)
_SSH_OK = re.compile(
    r"^Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S{1,64})"
    r" from (?P<ip>[0-9A-Fa-f:.]{2,45}) port (?P<port>\d{1,5})"
)
_SUDO = re.compile(r"^\s*(?P<user>[A-Za-z0-9_.-]{1,64}) : .*\bCOMMAND=")
_KV = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT)=(\S{1,64})")
_DENY_WORDS = re.compile(r"\b(DROP|DENY|DENIED|REJECT|BLOCK|BLOCKED)\b", re.IGNORECASE)
_ALLOW_WORDS = re.compile(r"\b(ACCEPT|ALLOW|ALLOWED|PASS)\b", re.IGNORECASE)


def parse_structured_data(text: str) -> tuple[dict[str, dict[str, str]], str]:
    """STRUCTURED-DATA de RFC 5424 → ({sd-id: {param: valor}}, resto del mensaje).

    Acotado: como mucho 8 elementos y 16 parámetros por elemento; los valores se guardan
    como texto (escapes \\" \\\\ \\] resueltos) y se limpian después con fields.data.
    """
    if text.startswith("-"):
        return {}, text[2:] if text.startswith("- ") else text[1:]
    elements: dict[str, dict[str, str]] = {}
    position = 0
    while position < len(text) and text[position] == "[" and len(elements) < 8:
        match = _SD_ELEMENT.match(text, position)
        if match is None:
            break
        params: dict[str, str] = {}
        for param in _SD_PARAM.finditer(match.group(2)):
            if len(params) >= 16:
                break
            value = re.sub(r'\\(["\\\]])', r"\1", param.group(2))
            params[param.group(1)] = value[:256]
        elements[match.group(1)] = params
        position = match.end()
    rest = text[position:]
    return elements, rest[1:] if rest.startswith(" ") else rest


def parse(raw: str) -> dict[str, Any]:
    """Cabecera Syslog → campos. No lanza: lo que no encaja queda en `message`."""
    out: dict[str, Any] = {"format": "unknown"}
    text = raw.rstrip("\r\n")
    # BOM de RFC 5424 delante del MSG (UTF-8): no forma parte del texto.
    match = _PRI.match(text)
    pri = DEFAULT_PRI
    if match and int(match.group(1)) <= 191:
        pri = int(match.group(1))
        text = text[match.end() :]
    else:
        out["pri_missing"] = True
    out["facility"] = FACILITIES[pri >> 3]
    out["severity_name"] = SEVERITY_NAMES[pri & 7]
    out["pri"] = pri
    rfc5424 = _5424.match(text) if not out.get("pri_missing") else None
    if rfc5424 and rfc5424.group("version") == "1":
        out["format"] = "rfc5424"
        out["timestamp"] = rfc5424.group("ts")
        out["hostname"] = rfc5424.group("host")
        out["app_name"] = rfc5424.group("app")
        out["procid"] = rfc5424.group("procid")
        out["msgid"] = rfc5424.group("msgid")
        sd, message = parse_structured_data(rfc5424.group("rest"))
        out["structured_data"] = sd
        out["message"] = message.removeprefix("﻿")
        return out
    rfc3164 = _3164_TS.match(text)
    if rfc3164:
        out["format"] = "rfc3164"
        out["header_timestamp"] = rfc3164.group("ts")
        rest = rfc3164.group("rest")
        host, _, after = rest.partition(" ")
        # Algunos emisores omiten el HOSTNAME: si el primer token parece un TAG, no se usa.
        if _HOST.fullmatch(host) and not host.endswith(":") and after:
            out["hostname"] = host
            rest = after
    else:
        rest = text
    tag = _TAG.match(rest)
    if tag:
        out["app_name"] = tag.group("tag")
        out["procid"] = tag.group("pid")
        out["message"] = tag.group("msg")
    else:
        out["message"] = rest
    return out


def _classify(app: str | None, message: str) -> dict[str, Any]:
    """Tipo de evento solo para patrones conocidos. Lo demás queda como `syslog.message`."""
    program = (app or "").lower().rsplit("/", 1)[-1]
    if program in ("sshd", "sshd-session"):
        for pattern, event_type, outcome in (
            (_SSH_FAIL, "auth.failure", "failure"),
            (_SSH_INVALID, "auth.failure", "failure"),
            (_SSH_OK, "auth.success", "success"),
        ):
            found = pattern.match(message)
            if found:
                return {
                    "event_type": event_type,
                    "category": "authentication",
                    "username": found.group("user"),
                    "src_ip": found.group("ip"),
                    "src_port": found.group("port"),
                    "protocol": "ssh",
                    "outcome": outcome,
                    "action": "login",
                }
    if program == "sudo":
        found = _SUDO.match(message)
        if found:
            return {
                "event_type": "privilege.sudo",
                "category": "administrative",
                "username": found.group("user"),
                "outcome": "failure" if "NOT in sudoers" in message else "success",
                "action": "sudo",
            }
    pairs = dict(_KV.findall(message))
    if "SRC" in pairs and "DST" in pairs:
        prefix = message.split("SRC=", 1)[0]
        if _DENY_WORDS.search(prefix):
            event_type, action = "firewall.deny", "deny"
        elif _ALLOW_WORDS.search(prefix):
            event_type, action = "firewall.allow", "allow"
        else:
            event_type, action = "firewall.log", None
        return {
            "event_type": event_type,
            "category": "network",
            "src_ip": pairs.get("SRC"),
            "dst_ip": pairs.get("DST"),
            "src_port": pairs.get("SPT"),
            "dst_port": pairs.get("DPT"),
            "protocol": (pairs.get("PROTO") or "").lower() or None,
            "action": action,
        }
    return {"event_type": "syslog.message", "category": "system"}


def normalize(record: RawRecord, ctx: NormalizeContext) -> NormalizedEvent:
    if not record.raw.strip():
        raise RecordRejectedError("empty_record")
    parsed = parse(record.raw)
    message = parsed.get("message") or ""
    info = _classify(parsed.get("app_name"), message)
    if not ctx.allows(info["event_type"]):
        raise RecordRejectedError("event_type_not_allowed")
    observed = None
    if parsed["format"] == "rfc5424":
        stamp = parsed.get("timestamp")
        if stamp and stamp != "-":
            observed = fields.timestamp(stamp)
            if observed is None:
                raise RecordRejectedError("invalid_timestamp")
    policy = ctx.severity_policy(DEFAULT_POLICY)
    severity_name = parsed["severity_name"]
    protocol = info.get("protocol")
    data: dict[str, Any] = {
        "format": parsed["format"],
        "facility": parsed["facility"],
        "syslog_severity": severity_name,
        "app_name": fields.text(parsed.get("app_name"), 48),
        "procid": fields.text(parsed.get("procid"), 32),
        "msgid": fields.text(parsed.get("msgid"), 32),
        "header_hostname": fields.text(parsed.get("hostname"), 253),
        "header_timestamp": parsed.get("header_timestamp"),
        "structured_data": parsed.get("structured_data") or None,
        "pri_missing": parsed.get("pri_missing"),
        "peer_ip": record.peer_ip,
        "transport": record.transport,
    }
    # Un mismo texto puede llegar dos veces de forma legítima (dos fallos de login idénticos):
    # la identidad es la del registro en el receptor (o la línea del fichero importado), no
    # su contenido. Los reintentos del sensor reutilizan record_id y se deduplican.
    identity = fields.identity_hash("rec", record.record_id or record.reference)
    return NormalizedEvent(
        event_type=info["event_type"],
        category=info["category"],
        identity=identity,
        observed_at=observed,
        severity=policy.get(severity_name, "unknown"),
        source_severity=severity_name,
        confidence="low" if info["event_type"] == "syslog.message" else "medium",
        hostname=fields.hostname(parsed.get("hostname")),
        src_ip=fields.ip(info.get("src_ip")),
        dst_ip=fields.ip(info.get("dst_ip")),
        src_port=fields.port(info.get("src_port")),
        dst_port=fields.port(info.get("dst_port")),
        protocol=protocol if isinstance(protocol, str) and protocol.isalnum() else None,
        username=fields.text(info.get("username"), 128),
        process_name=fields.text(parsed.get("app_name"), 255),
        action=info.get("action"),
        outcome=info.get("outcome"),
        message=fields.text(message, 1000),
        excerpt=fields.excerpt(record.raw, ctx.raw_store_bytes),
        data=fields.data(data),
    )


CONNECTOR = register(
    Connector(
        source_type="syslog",
        title="Syslog (RFC 5424 / RFC 3164)",
        version=VERSION,
        transports=(TRANSPORT_SENSOR, TRANSPORT_UPLOAD),
        sensor_input=INPUT_SYSLOG,
        description=(
            "Mensajes Syslog recibidos por un receptor del sensor (TCP, TLS o UDP si se"
            " habilita) o importados desde un fichero exportado (una línea por mensaje)."
        ),
        normalize=normalize,
        severity_policy=DEFAULT_POLICY,
        severity_policy_doc=(
            "Severidad Syslog (emerg..debug) → Sentra. Por defecto ninguna llega a critical:"
            " emerg/alert = high, crit = medium, err/warning = low, el resto informational."
        ),
        event_types=EVENT_TYPES,
        sensitive_fields=("username", "hostname", "message", "data.structured_data"),
        validation=(
            "Fixtures sintéticos escritos a partir de los ejemplos de RFC 5424 y RFC 3164 y de"
            " formatos habituales de sshd, sudo y netfilter; sin validación con equipos reales."
        ),
        formats=("rfc5424", "rfc3164"),
    )
)
