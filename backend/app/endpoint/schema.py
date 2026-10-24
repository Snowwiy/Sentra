"""Esquema de `data` de cada evento de actividad y redacción de líneas de comando (6E.3).

Cada categoría tiene una lista cerrada de acciones y de campos con tipo y longitud máxima: lo
que el agente envíe fuera de ella se descarta en silencio (compatibilidad hacia delante) y un
tipo incorrecto en un campo conocido invalida ese evento (no el lote). Así la tabla nunca
guarda texto arbitrario sin tope aunque un agente esté comprometido.

La línea de comando se vuelve a redactar en el servidor (TELEMETRY_CMDLINE_POLICY): si el
agente la envió completa y el servidor pide `redacted`, gana la más restrictiva.
"""

import ipaddress
import re
from collections.abc import Callable
from typing import Any

FieldCheck = Callable[[Any], Any]


class InvalidFieldError(ValueError):
    pass


def _text(limit: int) -> FieldCheck:
    def check(value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            raise InvalidFieldError("expected text")
        clean = "".join(ch for ch in value if ch.isprintable() or ch in "\t")
        return clean[:limit]

    return check


def _int(low: int, high: int) -> FieldCheck:
    def check(value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise InvalidFieldError("expected integer in range")
        return value

    return check


def _bool(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    raise InvalidFieldError("expected boolean")


def _number(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidFieldError("expected number")
    return round(float(value), 3)


def _ip(value: Any) -> Any:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise InvalidFieldError("expected address")
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError as exc:
        raise InvalidFieldError("invalid address") from exc


def _choice(*values: str) -> FieldCheck:
    def check(value: Any) -> Any:
        if value is None:
            return None
        if value not in values:
            raise InvalidFieldError("unexpected value")
        return value

    return check


def _hex(length: int) -> FieldCheck:
    pattern = re.compile(rf"^[0-9a-f]{{{length}}}$")

    def check(value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str) or not pattern.match(value.lower()):
            raise InvalidFieldError("expected hex digest")
        return value.lower()

    return check


def _texts(count: int, limit: int) -> FieldCheck:
    item = _text(limit)

    def check(value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, list):
            raise InvalidFieldError("expected list")
        return [item(v) for v in value[:count] if v is not None]

    return check


PORT = _int(0, 65535)
PID = _int(0, 2**31 - 1)
NAME = _text(255)
PATH = _text(1024)
TIME = _text(40)

FIELDS: dict[str, dict[str, FieldCheck]] = {
    "process": {
        "pid": PID,
        "ppid": PID,
        "parent_instance_key": _hex(32),
        "parent_relation": _choice("observed", "inferred", "missing", "pid_reused"),
        "name": NAME,
        "exe": PATH,
        "cmdline": _text(8192),
        "username": NAME,
        "started_at": TIME,
        "ended_at": TIME,
        "sha256": _hex(64),
        "signer": NAME,
        "integrity": _text(16),
    },
    "network": {
        "pid": PID,
        "protocol": _choice("tcp", "udp"),
        "local_address": _ip,
        "local_port": PORT,
        "remote_address": _ip,
        "remote_port": PORT,
        "state": _text(24),
        "direction": _choice("outbound", "inbound", "listen"),
    },
    "service": {
        "name": NAME,
        "display_name": NAME,
        "start_type": _text(24),
        "status": _text(24),
        "exe": PATH,
        "username": NAME,
    },
    "scheduled_task": {
        "name": NAME,
        "path": PATH,
        "exe": PATH,
        "enabled": _bool,
        "trigger": _text(255),
    },
    "persistence": {
        "mechanism": _choice(
            "run_key", "startup_folder", "systemd_unit", "cron", "launch_agent", "launch_daemon"
        ),
        "location": PATH,
        "name": NAME,
        "target": PATH,
    },
    "auth": {"user": NAME, "logon_type": _text(32), "source_ip": _ip},
    "protection": {
        "product": NAME,
        "realtime_enabled": _bool,
        "antivirus_enabled": _bool,
        "tamper_protection": _bool,
        "signature_age_days": _int(0, 100_000),
    },
    "firewall": {
        "profile": _text(32),
        "enabled": _bool,
        "default_inbound": _text(16),
        "default_outbound": _text(16),
    },
    "dns": {"query": NAME, "record_type": _text(8), "answers": _texts(8, 255)},
    "agent_health": {
        "cpu_percent": _number,
        "rss_bytes": _int(0, 2**50),
        "queued": _int(0, 10_000_000),
        "dropped_total": _int(0, 2**50),
    },
}

ACTIONS: dict[str, frozenset[str]] = {
    "process": frozenset({"start", "stop"}),
    "network": frozenset({"connect", "listen"}),
    "service": frozenset({"created", "modified", "deleted", "started", "stopped"}),
    "scheduled_task": frozenset({"created", "modified", "deleted"}),
    "persistence": frozenset({"created", "modified", "deleted"}),
    "auth": frozenset({"success", "failure"}),
    "protection": frozenset({"state"}),
    "firewall": frozenset({"state"}),
    "dns": frozenset({"query"}),
    "agent_health": frozenset({"state"}),
}

SOURCES = frozenset(
    {
        "psutil_poll",
        "sysmon",
        "security_4688",
        "journald",
        "proc",
        "unified_log",
        "service_poll",
        "task_poll",
        "persistence_poll",
        "firewall_poll",
        "protection_poll",
        "agent",
    }
)


def clean_data(category: str, data: dict[str, Any]) -> dict[str, Any]:
    """`data` filtrado y acotado. InvalidFieldError si un campo conocido tiene un tipo inválido."""
    spec = FIELDS[category]
    out: dict[str, Any] = {}
    for key, check in spec.items():
        if key in data:
            value = check(data[key])
            if value is not None:
                out[key] = value
    return out


# --- redacción -------------------------------------------------------------------------------

CMDLINE_MAX = {"full": 8192, "redacted": 2048}
_SECRET_FLAGS = re.compile(
    r"(?i)(?P<flag>(?:--?|/)(?:p|pw|pwd|pass|passwd|password|secret|token|apikey|api-key|"
    r"api_key|key|auth|credential|credentials)(?:[:=]|\s+))(?P<value>\"[^\"]*\"|'[^']*'|\S+)"
)
_SECRET_ASSIGN = re.compile(
    r"(?i)(?P<flag>\b[\w.-]*(?:password|passwd|secret|token|apikey|api_key|access_key|"
    r"client_secret)[\w.-]*=)(?P<value>\"[^\"]*\"|'[^']*'|\S+)"
)
# curl/wget/psql: `-u usuario:clave` lleva la clave pegada al usuario.
_USER_PASSWORD = re.compile(
    r"(?i)(?P<flag>(?:-u|--user|--proxy-user|--http-user)(?:=|\s+))"
    r"(?P<user>[^\s:]+):(?P<value>\S+)"
)
_URL_CREDENTIALS = re.compile(r"(?i)(?P<scheme>[a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
# Bloques base64 largos (p. ej. -EncodedCommand): se sustituyen por su longitud. La regla
# conductual solo necesita saber que existe una orden codificada, no su contenido.
_LONG_BASE64 = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")


def redact_cmdline(cmdline: str | None, policy: str) -> str | None:
    if cmdline is None or policy == "off":
        return None
    if policy == "full":
        return cmdline[: CMDLINE_MAX["full"]]
    text = _URL_CREDENTIALS.sub(r"\g<scheme>[REDACTED]@", cmdline)
    text = _USER_PASSWORD.sub(r"\g<flag>\g<user>:[REDACTED]", text)
    text = _BEARER.sub(r"\1 [REDACTED]", text)
    text = _SECRET_FLAGS.sub(r"\g<flag>[REDACTED]", text)
    text = _SECRET_ASSIGN.sub(r"\g<flag>[REDACTED]", text)
    text = _LONG_BASE64.sub(lambda m: f"[BASE64:{len(m.group(0))}]", text)
    return text[: CMDLINE_MAX["redacted"]]
