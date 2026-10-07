"""Eventos Linux (Fase 5C.1): subconjunto acotado del journal de systemd.

Qué se recoge (docs/linux-events.md) y por qué así:
- solo fuentes concretas, nunca "todo journalctl": sshd, sudo, cuentas/PAM (su, login,
  useradd/usermod/userdel, groupadd, gpasswd, passwd), el gestor de servicios (PID 1), el
  kernel con prioridad warning o superior y, si auditd existe y journald recibe sus
  registros, un subconjunto de tipos de auditoría;
- de cada fuente solo los mensajes que se reconocen (lista cerrada de expresiones fijas) y,
  en el kernel, los errores; el resto del ruido (conexiones cerradas, volcados de OOM línea
  a línea...) no sale del equipo;
- `journalctl` con argumentos fijos y ruta absoluta, sin shell: un mensaje del journal es
  texto no confiable que solo se analiza con expresiones regulares, nunca se ejecuta;
- los comandos de sudo y los mensajes se sanean antes de enviarse (contraseñas, tokens,
  credenciales en URLs) porque un administrador puede escribir un secreto en la línea de
  comandos;
- un cursor del journal por fuente, persistido tras confirmar el envío: un reinicio del
  agente o del equipo no reenvía nada ni pierde nada. El primer arranque solo lee una
  ventana reciente acotada (la instalación no envía miles de eventos históricos);
- el record_id que deduplica en el servidor es un hash estable del cursor (identifica la
  entrada exacta del journal), no del mensaje: dos fallos SSH idénticos son dos eventos;
- cualquier fallo (sin permiso, journal ausente, salida inesperada) se registra una vez y se
  informa como cobertura; nunca afecta a heartbeat, telemetría ni inventario.

🐧 VALIDACIÓN EN LINUX REAL: el formato exacto de los mensajes varía entre versiones de
OpenSSH, sudo, shadow-utils y systemd; los tests cubren las formas de Debian/Ubuntu/Mint
actuales (y genéricas de RHEL/Fedora), pero no sustituyen a una prueba en el equipo.
"""

import contextlib
import hashlib
import json
import logging
import os
import re
import subprocess
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from sentra_agent.identity import write_atomic

logger = logging.getLogger("sentra_agent")

SOURCE = "linux_journal"
STATE_FILE = "linux_events_state.json"
STATE_VERSION = 1
# Primer arranque de una fuente: solo la última hora y como mucho estos eventos.
FIRST_RUN_SINCE = "-1h"
FIRST_RUN_MAX = 50
# Entradas leídas por fuente y ciclo. El runner parte el envío en lotes que el servidor
# acepta (500); si una fuente llena el cupo, el resto se lee en el ciclo siguiente.
BATCH_MAX = 200
MESSAGE_MAX = 2000
VALUE_MAX = 256
# Mensajes iguales del kernel dentro de un lote: más copias no aportan nada.
KERNEL_DUPLICATES_MAX = 5
# Tiempo máximo de una lectura de journalctl.
READ_TIMEOUT = 30.0
# Un cursor puede devolver entradas algo anteriores (varios ficheros del journal
# intercalados); más de esto por detrás del último evento enviado es una relectura (cursor
# perdido tras rotación o vaciado del journal) y se descarta.
REPLAY_TOLERANCE_USEC = 300 * 1_000_000
# La cobertura se reenvía al servidor al cambiar o, como mucho, cada hora.
COVERAGE_REFRESH_SECONDS = 3600

_CURSOR = re.compile(r"^[A-Za-z0-9=;_\-]{1,512}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

# --- Saneado de secretos ---------------------------------------------------------------------

# Nombres de campo que suelen llevar un secreto (patrón, no un secreto).
_SENSITIVE_NAMES = (
    r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|auth|credentials?"
    r"|private[_-]?key|access[_-]?key)"
)
# --password=x, password: x, TOKEN=x, "apikey x" no (demasiado ambiguo).
_KEY_VALUE = re.compile(
    rf"(?i)(\b[\w.-]*{_SENSITIVE_NAMES}[\w.-]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
)
# --password x / -p x en la forma con espacio.
_FLAG_VALUE = re.compile(rf"(?i)(\s--?{_SENSITIVE_NAMES}[\w-]*\s+)(\"[^\"]*\"|'[^']*'|\S+)")
# mysql -pSECRETO (sin espacio): solo con herramientas que lo usan así.
_MYSQL_P = re.compile(r"(?i)(\b(?:mysql|mariadb|mysqldump|mysqladmin)\b.*?\s-p)(\S+)")
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s]+)(@)")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
# Cadenas largas tipo token (base64/hex). Puede ocultar algún hash legítimo: se acepta, es
# preferible a enviar un secreto.
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}")
REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    """Quita de un texto lo que parece una credencial (Fase 5C.1, sudo y mensajes)."""
    text = _URL_CREDENTIALS.sub(rf"\1{REDACTED}\3", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _MYSQL_P.sub(rf"\1{REDACTED}", text)
    text = _FLAG_VALUE.sub(rf"\1{REDACTED}", text)
    text = _KEY_VALUE.sub(rf"\1{REDACTED}", text)
    return _LONG_TOKEN.sub(REDACTED, text)


def clean(value: object, limit: int = VALUE_MAX) -> str:
    """Texto de una línea, sin caracteres de control y acotado."""
    return " ".join(_CONTROL.sub(" ", str(value)).split())[:limit]


# --- Clasificación de mensajes ---------------------------------------------------------------


@dataclass(frozen=True)
class Classified:
    event_type: str
    level: str
    data: dict[str, str] = field(default_factory=dict)


def _kv(text: str) -> dict[str, str]:
    """Pares clave=valor de PAM y auditd (valores entre comillas o hasta el espacio)."""
    found: dict[str, str] = {}
    for key, quoted, plain in re.findall(r"(\w+)=(?:\"([^\"]*)\"|(\S*))", text):
        # auditd envuelve los campos en msg='...': la comilla final no es parte del valor.
        found.setdefault(key, quoted or plain.rstrip("'"))
    return found


def _ip(value: str | None) -> str | None:
    # sshd escribe "UNKNOWN" o "?" cuando no sabe el origen: no se inventa un valor.
    if not value or value in ("?", "UNKNOWN", "-"):
        return None
    value = value.strip("[]")
    return value if re.fullmatch(r"[0-9A-Fa-f:.%]{2,64}", value) else None


def _put(data: dict[str, str], key: str, value: str | None) -> None:
    if value and value not in ("?", "-", "(unknown)"):
        data[key] = clean(value, VALUE_MAX)


_SSH_FAILED = re.compile(
    r"^Failed (?P<method>[\w/-]+) for (?P<invalid>invalid user )?(?P<user>\S*) from"
    r" (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>[\w/-]+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_SSH_MAX = re.compile(
    r"^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S*)"
    r" from (?P<ip>\S+)"
)
_PAM_AUTH = re.compile(r"^pam_unix\((?P<svc>[\w-]+):auth\): authentication failure;(?P<rest>.*)$")
_PAM_SESSION = re.compile(
    r"^pam_unix\((?P<svc>[\w-]+):session\): session (?P<state>opened|closed) for user"
    r" (?P<user>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<by>[^\s(]*))?"
)
_PAM_PASSWORD = re.compile(
    r"^pam_unix\((?P<svc>[\w-]+):chauthtok\): password changed for (?P<user>\S+)"
)


def _ssh(message: str) -> Classified | None:
    data: dict[str, str]
    if m := _SSH_FAILED.match(message):
        data = {"auth_method": m["method"]}
        _put(data, "user", m["user"])
        _put(data, "source_ip", _ip(m["ip"]))
        _put(data, "source_port", m["port"])
        if m["invalid"]:
            data["invalid_user"] = "true"
        return Classified("auth_failure", "warning", data)
    if m := _SSH_ACCEPTED.match(message):
        data = {"auth_method": m["method"]}
        _put(data, "user", m["user"])
        _put(data, "source_ip", _ip(m["ip"]))
        _put(data, "source_port", m["port"])
        return Classified("auth_success", "info", data)
    if m := _SSH_INVALID.match(message):
        # sshd escribe además "Failed ... for invalid user": esa línea es la que cuenta como
        # fallo; esta se guarda como evento sin señal para no contar dos veces el intento.
        data = {}
        _put(data, "user", m["user"])
        _put(data, "source_ip", _ip(m["ip"]))
        return Classified("ssh_invalid_user", "warning", data)
    if m := _SSH_MAX.match(message):
        data = {}
        _put(data, "user", m["user"])
        _put(data, "source_ip", _ip(m["ip"]))
        return Classified("ssh_max_auth_exceeded", "warning", data)
    if m := _PAM_AUTH.match(message):
        # El fallo PAM de sshd duplica su propio "Failed password": evento sin señal.
        fields = _kv(m["rest"])
        data = {"pam_service": m["svc"]}
        _put(data, "user", fields.get("user"))
        _put(data, "source_ip", _ip(fields.get("rhost")))
        return Classified("pam_auth_failure", "warning", data)
    return _session(message)


def _session(message: str) -> Classified | None:
    if m := _PAM_SESSION.match(message):
        data = {"pam_service": m["svc"]}
        _put(data, "user", m["user"])
        _put(data, "by_user", m["by"])
        return Classified(f"session_{m['state']}", "info", data)
    return None


def _sudo(message: str) -> Classified | None:
    fields: dict[str, str]
    data: dict[str, str]
    if m := _PAM_AUTH.match(message):
        fields = _kv(m["rest"])
        data = {"pam_service": m["svc"]}
        # En sudo, `user` es la cuenta que se autentica (la que invoca sudo).
        _put(data, "user", fields.get("user") or fields.get("ruser") or fields.get("logname"))
        return Classified("auth_failure", "warning", data)
    session = _session(message)
    if session is not None:
        return session
    user, sep, rest = message.partition(" : ")
    user = user.strip()
    if not sep or not user or " " in user:
        return None
    parts = [part.strip() for part in rest.split(" ; ")]
    fields = {}
    problem = None
    for index, part in enumerate(parts):
        key, eq, value = part.partition("=")
        if key == "COMMAND" and eq:
            # El comando es lo último y puede contener " ; ": se une todo lo que queda.
            fields["COMMAND"] = " ; ".join([value, *parts[index + 1 :]])
            break
        if eq and key.isupper():
            fields[key] = value
        elif index == 0:
            problem = part
    data = {}
    _put(data, "user", user)
    _put(data, "target_user", fields.get("USER"))
    _put(data, "tty", fields.get("TTY"))
    if "COMMAND" in fields:
        _put(data, "command", redact(fields["COMMAND"]))
    if problem is None:
        if "COMMAND" not in fields:
            return None
        return Classified("sudo_command", "info", data)
    lowered = problem.lower()
    if "incorrect password" in lowered:
        return Classified("sudo_auth_failure", "warning", data)
    if "not in sudoers" in lowered or "not allowed" in lowered:
        return Classified("sudo_not_allowed", "warning", data)
    return Classified("sudo_error", "warning", data)


_USERADD = re.compile(r"^new user: name=(?P<user>[^,\s]+), UID=(?P<uid>\d+)")
_GROUPADD = re.compile(r"^new group: name=(?P<group>[^,\s]+)")
_USERMOD_ADD = re.compile(r"^add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
_USERMOD_DEL = re.compile(r"^delete '(?P<user>[^']+)' from group '(?P<group>[^']+)'")
_USERMOD_LOCK = re.compile(r"^(?P<op>lock|unlock) user '(?P<user>[^']+)' password")
_USERMOD_CHANGE = re.compile(r"^change user '(?P<user>[^']+)' (?P<what>\w+)")
_GPASSWD_ADD = re.compile(r"^user (?P<user>\S+) added by (?P<actor>\S+) to group (?P<group>\S+)")
_GPASSWD_DEL = re.compile(
    r"^user (?P<user>\S+) removed by (?P<actor>\S+) from group (?P<group>\S+)"
)
_USERDEL = re.compile(r"^delete user '(?P<user>[^']+)'")
_GROUPDEL = re.compile(r"^(?:group '(?P<group>[^']+)' removed|removed group '(?P<group2>[^']+)')")
_FAILED_LOGIN = re.compile(r"^FAILED LOGIN \(\d+\) on '(?P<tty>[^']*)' FOR '(?P<user>[^']*)'")


def _accounts(message: str) -> Classified | None:
    if m := _PAM_AUTH.match(message):
        fields = _kv(m["rest"])
        data = {"pam_service": m["svc"]}
        _put(data, "user", fields.get("user"))
        _put(data, "source_ip", _ip(fields.get("rhost")))
        return Classified("auth_failure", "warning", data)
    if m := _PAM_PASSWORD.match(message):
        return Classified("password_changed", "info", {"user": clean(m["user"])})
    if m := _USERADD.match(message):
        return Classified("account_created", "warning", {"user": clean(m["user"]), "uid": m["uid"]})
    if m := _GROUPADD.match(message):
        return Classified("group_created", "info", {"group": clean(m["group"])})
    # usermod también escribe "add 'x' to shadow group 'sudo'": la copia de gshadow del mismo
    # cambio. No se reconoce (las expresiones exigen "to group"): un cambio, un evento.
    if m := _USERMOD_ADD.match(message):
        data = {"user": clean(m["user"]), "group": clean(m["group"], 64)}
        return Classified("group_member_added", "warning", data)
    if m := _USERMOD_DEL.match(message):
        data = {"user": clean(m["user"]), "group": clean(m["group"], 64)}
        return Classified("group_member_removed", "warning", data)
    if m := _GPASSWD_ADD.match(message):
        data = {"user": clean(m["user"]), "group": clean(m["group"], 64)}
        _put(data, "actor", m["actor"])
        return Classified("group_member_added", "warning", data)
    if m := _GPASSWD_DEL.match(message):
        data = {"user": clean(m["user"]), "group": clean(m["group"], 64)}
        _put(data, "actor", m["actor"])
        return Classified("group_member_removed", "warning", data)
    if m := _USERMOD_LOCK.match(message):
        kind = "account_locked" if m["op"] == "lock" else "account_unlocked"
        return Classified(kind, "warning", {"user": clean(m["user"])})
    if m := _USERMOD_CHANGE.match(message):
        data = {"user": clean(m["user"]), "change": clean(m["what"], 32)}
        return Classified("account_changed", "info", data)
    if m := _USERDEL.match(message):
        return Classified("account_deleted", "warning", {"user": clean(m["user"])})
    if m := _GROUPDEL.match(message):
        return Classified("group_deleted", "info", {"group": clean(m["group"] or m["group2"], 64)})
    if m := _FAILED_LOGIN.match(message):
        # login escribe además el fallo PAM, que es el que cuenta: aquí solo evento.
        data = {"user": clean(m["user"]), "tty": clean(m["tty"], 32)}
        return Classified("login_failure", "warning", data)
    return _session(message)


_UNIT_PREFIX = re.compile(r"^(?P<unit>[\w@.:\\-]+\.service): ")
_FAILED_RESULT = re.compile(r": Failed with result '(?P<result>[^']+)'")
_MAIN_EXIT = re.compile(r": Main process exited, code=(?P<code>\w+), status=(?P<status>\S+)")


def _systemd(message: str, entry: dict[str, Any]) -> Classified | None:
    unit = str(entry.get("UNIT") or "")
    if not unit and (m := _UNIT_PREFIX.match(message)):
        unit = m["unit"]
    if message.startswith("Reloading requested from client") or message == "Reloading.":
        # Recarga de la configuración de systemd: una unidad se creó o cambió (sin saber
        # cuál). Contexto; la unidad nueva la detecta el inventario (PER-001).
        return Classified("systemd_reload", "info", {})
    if not unit.endswith(".service"):
        return None
    data = {"unit": clean(unit, VALUE_MAX)}
    if m := _FAILED_RESULT.search(message):
        data["result"] = clean(m["result"], 64)
        return Classified("service_failed", "error", data)
    if message.startswith("Failed to start "):
        # Acompaña a "Failed with result" del mismo fallo: evento sin señal.
        return Classified("service_start_failed", "error", data)
    if m := _MAIN_EXIT.search(message):
        if m["code"] == "exited" and m["status"].startswith("0/"):
            return None
        data["exit"] = clean(f"{m['code']} {m['status']}", 64)
        return Classified("service_exited", "warning", data)
    if message.startswith("Started "):
        return Classified("service_started", "info", data)
    if message.startswith("Stopped "):
        return Classified("service_stopped", "info", data)
    return None


_OOM = re.compile(r"Out of memory: Killed process (?P<pid>\d+) \((?P<proc>[^)]*)\)")
_FS = re.compile(
    r"(EXT[234]-fs (?:error|warning \(device [^)]*\): ext4_.*error)|XFS \([^)]*\):"
    r" (?:Corruption|metadata I/O error|Filesystem has been shut down)|BTRFS (?:error|critical)"
    r"|Buffer I/O error on dev|I/O error, dev \S+|blk_update_request: I/O error)"
)
_FS_DEVICE = re.compile(r"\(device (?P<dev>[^)]+)\)|(?:on dev|, dev) (?P<dev2>[\w-]+)")
_HW = re.compile(r"(\[Hardware Error\]|Machine check events logged|mce: |EDAC \S+: \d+ [CU]E )")
_KBUG = re.compile(
    r"(\bBUG: |\bOops: |kernel BUG at|general protection fault|Kernel panic|soft lockup)"
)


def _kernel(message: str, priority: int) -> Classified | None:
    level = _level(priority)
    if m := _OOM.search(message):
        data = {"process": clean(m["proc"], 64), "pid": m["pid"]}
        return Classified("oom_kill", "error", data)
    if _FS.search(message):
        data = {}
        if d := _FS_DEVICE.search(message):
            _put(data, "device", d["dev"] or d["dev2"])
        return Classified("filesystem_error", "error", data)
    if _HW.search(message):
        return Classified("hardware_error", "error", {})
    if _KBUG.search(message):
        return Classified("kernel_bug", "critical", {})
    # Avisos sin clasificar (volcados de OOM, trazas línea a línea, avisos de drivers): no
    # salen del equipo. Los errores sin clasificar sí, por si son un fallo de hardware nuevo.
    if priority <= 3:
        return Classified("kernel_error", level, {})
    return None


# Tipos de auditd que se envían (subconjunto defensivo). Las autenticaciones correctas no:
# duplicarían cada sudo y cada SSH ya recogidos por sus propias fuentes.
AUDIT_TYPES = (
    "ADD_USER",
    "DEL_USER",
    "ADD_GROUP",
    "DEL_GROUP",
    "USER_MGMT",
    "GRP_MGMT",
    "USER_CHAUTHTOK",
    "USER_AUTH",
    "USER_LOGIN",
    "CONFIG_CHANGE",
    "ANOM_ABEND",
    "ANOM_PROMISCUOUS",
    "ANOM_LOGIN_FAILURES",
)
_AUDIT_ONLY_FAILED = frozenset({"USER_AUTH", "USER_LOGIN"})


def _audit(message: str, entry: dict[str, Any]) -> Classified | None:
    kind = str(entry.get("_AUDIT_TYPE_NAME") or "").upper()
    if kind not in AUDIT_TYPES:
        return None
    fields = _kv(message)
    failed = fields.get("res") in ("failed", "0")
    if kind in _AUDIT_ONLY_FAILED and not failed:
        return None
    data: dict[str, str] = {"audit_type": kind}
    _put(data, "user", fields.get("acct") or fields.get("id"))
    _put(data, "exe", fields.get("exe"))
    _put(data, "source_ip", _ip(fields.get("addr")))
    _put(data, "result", fields.get("res"))
    level = "warning" if failed or kind.startswith("ANOM_") or kind == "CONFIG_CHANGE" else "info"
    return Classified(f"audit_{kind.lower()}", level, data)


def _level(priority: int) -> str:
    if priority <= 2:
        return "critical"
    if priority == 3:
        return "error"
    if priority == 4:
        return "warning"
    return "info"


# --- Fuentes -------------------------------------------------------------------------------


@dataclass(frozen=True)
class JournalSource:
    key: str
    channel: str
    # Coincidencias de journalctl: el mismo campo repetido es OR, campos distintos son AND.
    matches: tuple[str, ...]
    classify: Callable[[str, dict[str, Any], int], Classified | None]
    priority: str | None = None
    # Binarios que indican que la fuente existe en este equipo (alguno basta). Sin ellos la
    # cobertura es "unavailable", que no es lo mismo que "0 eventos".
    requires: tuple[str, ...] = ()


def _ident(*names: str) -> tuple[str, ...]:
    return tuple(f"SYSLOG_IDENTIFIER={name}" for name in names)


SOURCES = (
    JournalSource(
        "sshd",
        "journal",
        # OpenSSH >= 9.8 registra las sesiones con el proceso sshd-session.
        _ident("sshd", "sshd-session"),
        lambda message, entry, priority: _ssh(message),
        requires=("/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"),
    ),
    JournalSource(
        "sudo",
        "journal",
        _ident("sudo"),
        lambda message, entry, priority: _sudo(message),
        requires=("/usr/bin/sudo", "/bin/sudo"),
    ),
    JournalSource(
        "accounts",
        "journal",
        _ident(
            "su",
            "login",
            "useradd",
            "userdel",
            "usermod",
            "groupadd",
            "groupdel",
            "groupmod",
            "gpasswd",
            "passwd",
            "chpasswd",
        ),
        lambda message, entry, priority: _accounts(message),
    ),
    JournalSource(
        "systemd",
        "journal",
        ("_PID=1", "_COMM=systemd"),
        lambda message, entry, priority: _systemd(message, entry),
    ),
    JournalSource(
        "kernel",
        "journal",
        ("_TRANSPORT=kernel",),
        lambda message, entry, priority: _kernel(message, priority),
        priority="warning",
    ),
    JournalSource(
        "auditd",
        "audit",
        ("_TRANSPORT=audit", *(f"_AUDIT_TYPE_NAME={name}" for name in AUDIT_TYPES)),
        lambda message, entry, priority: _audit(message, entry),
        requires=("/usr/sbin/auditd", "/sbin/auditd"),
    ),
)

_OUTPUT_FIELDS = ",".join(
    (
        "MESSAGE",
        "PRIORITY",
        "SYSLOG_IDENTIFIER",
        "_COMM",
        "_PID",
        "UNIT",
        "_TRANSPORT",
        "_HOSTNAME",
        "_BOOT_ID",
        "_AUDIT_TYPE_NAME",
    )
)


# --- Lectura de journalctl ------------------------------------------------------------------


# Cómo terminó una lectura de journalctl (contrato de run_journalctl):
# - "completed": journalctl salió por sí mismo; `returncode` es SU código (0 = bien, otro =
#   error real que el colector conserva).
# - "limit": Sentra dejó de leer y detuvo el proceso al llenar el cupo. No es un error: el
#   código de salida lo provoca la propia parada (-9 en POSIX, 1 con TerminateProcess en
#   Windows) y no dice nada de journalctl, así que se informa 0. El resto se lee desde el
#   cursor en el ciclo siguiente.
# El timeout no es un resultado: lanza subprocess.TimeoutExpired.
ReadOutcome = Literal["completed", "limit"]


@dataclass
class JournalRead:
    entries: list[dict[str, Any]]
    stderr: str = ""
    returncode: int = 0
    outcome: ReadOutcome = "completed"


class JournalError(Exception):
    def __init__(self, state: str, message: str) -> None:
        super().__init__(message)
        self.state = state


def journalctl_path() -> str | None:
    # Ruta absoluta conocida: nunca se busca en PATH ni en el directorio de trabajo.
    for candidate in ("/usr/bin/journalctl", "/bin/journalctl"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def run_journalctl(argv: list[str], limit: int, timeout: float) -> JournalRead:
    """Ejecuta journalctl (sin shell) y lee como mucho `limit` entradas JSON.

    `argv` va tal cual a Popen como lista (shell=False): ningún argumento se interpreta.
    Si hay más de `limit` entradas, Sentra detiene el proceso (outcome "limit", returncode
    0). Si journalctl termina solo, se conserva su código (outcome "completed"). Pasado
    `timeout` el proceso se mata y se lanza TimeoutExpired, también si no escribe nada.
    stderr va a un fichero temporal para no bloquear al proceso si escribe mucho; que haya
    stderr no implica fallo.
    """
    entries: list[dict[str, Any]] = []
    with open(os.devnull, "rb") as stdin, _TempErr() as err:
        process = subprocess.Popen(  # noqa: S603  (ruta absoluta, sin shell, argumentos fijos)
            argv,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=err.handle,
            close_fds=True,
            shell=False,
        )
        assert process.stdout is not None  # noqa: S101
        # El vigilante mata el proceso al vencer el plazo aunque no escriba ninguna línea (un
        # bucle sobre stdout quedaría bloqueado esperando la siguiente).
        expired = threading.Event()

        def _expire() -> None:
            expired.set()
            _stop(process)

        watchdog = threading.Timer(timeout, _expire)
        watchdog.daemon = True
        watchdog.start()
        stopped_by_us = False
        limit_reached = False
        try:
            for raw in process.stdout:
                line = raw.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    # Línea corrupta: se salta, no invalida el resto.
                    continue
                if isinstance(entry, dict):
                    entries.append(entry)
                if len(entries) >= limit:
                    limit_reached = True
                    break
            if not limit_reached:
                # Fin de stdout: journalctl está terminando. Se espera su código real en vez
                # de matarlo (el vigilante sigue activo si no llega a salir).
                process.wait()
        finally:
            watchdog.cancel()
            if process.poll() is None:
                # Sigue vivo: lo para Sentra (cupo lleno, plazo vencido o excepción). Solo en
                # este caso el código de salida es nuestro y no de journalctl.
                stopped_by_us = True
                _stop(process)
            try:
                returncode = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                returncode = -9
            process.stdout.close()
        stderr = err.read()
    if expired.is_set():
        raise subprocess.TimeoutExpired(argv, timeout)
    if stopped_by_us and limit_reached:
        return JournalRead(entries, stderr, 0, "limit")
    return JournalRead(entries, stderr, returncode, "completed")


def _stop(process: "subprocess.Popen[bytes]") -> None:
    # OSError: ya había terminado (carrera entre poll y kill); wait() da su código real.
    with contextlib.suppress(OSError):
        process.kill()


class _TempErr:
    def __enter__(self) -> "_TempErr":
        import tempfile

        self.handle = tempfile.TemporaryFile()
        return self

    def read(self) -> str:
        self.handle.seek(0)
        return self.handle.read(8192).decode("utf-8", "replace")

    def __exit__(self, *exc: object) -> None:
        self.handle.close()


JournalRunner = Callable[[list[str], int, float], JournalRead]


def build_args(
    journalctl: str, source: JournalSource, cursor: str | None, with_fields: bool = True
) -> list[str]:
    args = [journalctl, "--output=json", "--no-pager", "--quiet"]
    if with_fields:
        args.append(f"--output-fields={_OUTPUT_FIELDS}")
    if source.priority:
        args.append(f"--priority={source.priority}")
    if cursor:
        args.append(f"--after-cursor={cursor}")
    else:
        # Primera lectura: solo lo reciente (no se envía el histórico del equipo).
        args += [f"--since={FIRST_RUN_SINCE}", f"--lines={FIRST_RUN_MAX}"]
    return [*args, *source.matches]


def _message(entry: dict[str, Any]) -> str:
    value = entry.get("MESSAGE")
    if isinstance(value, list):
        # journald guarda como lista de bytes los mensajes que no son UTF-8 válido.
        try:
            value = bytes(int(b) & 0xFF for b in value[:8192]).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return ""
    return value if isinstance(value, str) else ""


def _priority(entry: dict[str, Any]) -> int:
    try:
        return max(0, min(7, int(str(entry.get("PRIORITY", "6")))))
    except ValueError:
        return 6


def record_id(channel: str, entry: dict[str, Any], message: str) -> int:
    """Identificador estable de una entrada (BIGINT positivo) para la deduplicación.

    El cursor del journal identifica la entrada exacta (fichero, número de secuencia, arranque
    y hora), así que reenviar la misma entrada da el mismo id y el servidor la ignora. Sin
    cursor (salida anómala) se usa hora + arranque + origen + hash del mensaje.
    """
    cursor = entry.get("__CURSOR")
    if isinstance(cursor, str) and cursor:
        basis = f"linux|{channel}|{cursor}"
    else:
        digest = hashlib.sha256(message.encode("utf-8", "replace")).hexdigest()
        basis = "|".join(
            (
                "linux",
                channel,
                str(entry.get("__REALTIME_TIMESTAMP")),
                str(entry.get("_BOOT_ID")),
                str(entry.get("SYSLOG_IDENTIFIER")),
                digest,
            )
        )
    return int.from_bytes(hashlib.sha256(basis.encode()).digest()[:8], "big") & (2**63 - 1)


def _realtime(entry: dict[str, Any]) -> int | None:
    try:
        return int(str(entry.get("__REALTIME_TIMESTAMP")))
    except (TypeError, ValueError):
        return None


def to_event(source: JournalSource, entry: dict[str, Any]) -> dict[str, Any] | None:
    """Entrada del journal -> evento de la API, o None si no es de interés o está mal formada."""
    realtime = _realtime(entry)
    if realtime is None or realtime <= 0:
        return None
    message = _message(entry)
    if not message:
        return None
    priority = _priority(entry)
    classified = source.classify(message, entry, priority)
    if classified is None:
        return None
    provider = clean(entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or source.key, 64)
    if source.key == "kernel":
        provider = "kernel"
    elif source.key == "auditd":
        provider = "auditd"
    data = {k: v for k, v in classified.data.items() if v}
    occurred = datetime.fromtimestamp(realtime / 1_000_000, tz=UTC)
    return {
        "source": SOURCE,
        "channel": source.channel,
        "record_id": record_id(source.channel, entry, message),
        "event_type": classified.event_type,
        "provider": provider or source.key,
        "level": classified.level,
        "message": redact(clean(message, MESSAGE_MAX)),
        "computer": clean(entry.get("_HOSTNAME") or "", 255) or None,
        "occurred_at": occurred.isoformat(),
        **({"data": data} if data else {}),
    }


# --- Colector ------------------------------------------------------------------------------


def _boot_id() -> str | None:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError:
        return None


JOURNAL_DIRS = ("/run/log/journal", "/var/log/journal")


def _journal_files(dirs: Iterable[str] = JOURNAL_DIRS) -> bool | None:
    """¿Hay ficheros del journal? None si no se puede saber (directorio sin permiso).

    journalctl con --quiet sale con código 0 y sin salida cuando no hay journal (contenedores,
    syslog clásico sin journald): sin esta comprobación se informaría "activo, 0 eventos".
    """
    unknown = False
    for base in dirs:
        try:
            with os.scandir(base) as top:
                for item in top:
                    if item.name.endswith(".journal"):
                        return True
                    if item.is_dir(follow_symlinks=False):
                        try:
                            with os.scandir(item.path) as inner:
                                if any(f.name.endswith(".journal") for f in inner):
                                    return True
                        except PermissionError:
                            unknown = True
        except FileNotFoundError:
            continue
        except OSError:
            unknown = True
    return None if unknown else False


def _present(paths: Iterable[str]) -> bool:
    return any(os.path.exists(path) for path in paths)


class LinuxJournalCollector:
    """EventSource del runner para Linux: lee, clasifica, envía y avanza los cursores.

    `pending()` nunca lanza: cualquier fallo de una fuente se convierte en su estado de
    cobertura y las demás siguen. El estado (cursores) solo se guarda en `commit()`, que el
    runner llama después de que el servidor aceptó los eventos.
    """

    def __init__(
        self,
        state_dir: Path,
        runner: JournalRunner = run_journalctl,
        journalctl: Callable[[], str | None] = journalctl_path,
        exists: Callable[[Iterable[str]], bool] = _present,
        boot_id: Callable[[], str | None] = _boot_id,
        journal_files: Callable[[], bool | None] = _journal_files,
    ) -> None:
        self._path = state_dir / STATE_FILE
        self._runner = runner
        self._journalctl = journalctl
        self._exists = exists
        self._boot_id = boot_id
        self._journal_files = journal_files
        self._coverage: dict[str, str] = {}
        # Estados ya registrados en el log: un fallo se avisa una vez, no en cada ciclo.
        self._reported: dict[str, str] = {}
        self._with_fields = True

    # Estado persistido: {"version": 1, "boot_id": "...", "sources": {key: {"cursor": "...",
    # "realtime": usec}}}. Un fichero corrupto vuelve a empezar desde la ventana reciente;
    # el servidor ignora lo que ya tenga (record_id estable), así que no se duplica nada.
    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"version": STATE_VERSION, "sources": {}}
        except (OSError, ValueError) as exc:
            logger.warning("linux event state unreadable, starting over", extra={"error": str(exc)})
            return {"version": STATE_VERSION, "sources": {}}
        sources = data.get("sources") if isinstance(data, dict) else None
        clean_sources: dict[str, dict[str, Any]] = {}
        for key, value in (sources or {}).items() if isinstance(sources, dict) else ():
            if not isinstance(value, dict):
                continue
            cursor = value.get("cursor")
            realtime = value.get("realtime")
            clean_sources[str(key)] = {
                "cursor": cursor if isinstance(cursor, str) and _CURSOR.match(cursor) else None,
                "realtime": realtime if isinstance(realtime, int) else None,
            }
        return {
            "version": STATE_VERSION,
            "boot_id": data.get("boot_id") if isinstance(data, dict) else None,
            "sources": clean_sources,
        }

    def coverage(self) -> dict[str, str] | None:
        return dict(self._coverage) if self._coverage else None

    def _set(self, key: str, state: str, detail: str = "") -> None:
        self._coverage[key] = state
        previous = self._reported.get(key)
        if previous == state:
            return
        self._reported[key] = state
        if state in ("no_permission", "error"):
            logger.warning(
                "linux event source not readable; heartbeat, telemetry and inventory continue",
                extra={"source": key, "state": state, "error": detail[:300]},
            )
        elif previous in ("no_permission", "error"):
            logger.info("linux event source readable again", extra={"source": key})

    def pending(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        state = self._load()
        boot = self._boot_id()
        if boot and state.get("boot_id") and state["boot_id"] != boot:
            # Reinicio del equipo: los cursores siguen siendo válidos con journal persistente;
            # con journal volátil journalctl busca la posición por la hora del cursor. En
            # ambos casos el servidor ignora lo ya recibido.
            logger.info("reboot detected since last event read")
        state["boot_id"] = boot
        journalctl = self._journalctl()
        if journalctl is None or self._journal_files() is False:
            for source in SOURCES:
                self._coverage[source.key] = "unavailable"
            reason = "journalctl not found" if journalctl is None else "no journal files"
            self._set("journal", "unavailable", reason)
            return [], state
        events: list[dict[str, Any]] = []
        journal_state = "active"
        for source in SOURCES:
            if source.requires and not self._exists(source.requires):
                self._coverage[source.key] = "unavailable"
                continue
            try:
                found = self._read(journalctl, source, state["sources"])
            except JournalError as exc:
                self._set(source.key, exc.state, str(exc))
                if exc.state == "no_permission":
                    journal_state = "no_permission"
                elif journal_state == "active":
                    journal_state = exc.state
                continue
            except Exception as exc:  # una fuente nunca tumba el colector
                self._set(source.key, "error", repr(exc))
                continue
            events.extend(found)
        self._set("journal", journal_state)
        return events, state

    def _read(
        self, journalctl: str, source: JournalSource, sources: dict[str, Any]
    ) -> list[dict[str, Any]]:
        saved = sources.get(source.key) or {}
        cursor = saved.get("cursor")
        last_realtime = saved.get("realtime")
        argv = build_args(journalctl, source, cursor, self._with_fields)
        result = self._runner(argv, BATCH_MAX, READ_TIMEOUT)
        stderr = result.stderr.lower()
        if self._with_fields and "output-fields" in stderr and result.returncode != 0:
            # journalctl anterior a systemd 236: sin --output-fields (salida más grande).
            self._with_fields = False
            result = self._runner(
                build_args(journalctl, source, cursor, False), BATCH_MAX, READ_TIMEOUT
            )
            stderr = result.stderr.lower()
        if "cursor" in stderr and result.returncode != 0:
            # Cursor que el journal ya no reconoce (rotado, vaciado, otro equipo): se vuelve a
            # la ventana reciente en el siguiente ciclo, nunca se relee todo el journal.
            logger.warning(
                "journal cursor not found, restarting from recent window",
                extra={"source": source.key},
            )
            sources[source.key] = {"cursor": None, "realtime": last_realtime}
            self._set(source.key, "active")
            return []
        if (
            "not seeing messages from other users and the system" in stderr
            or "insufficient permissions" in stderr
            or "permission denied" in stderr
        ):
            # Sin el grupo systemd-journal/adm journalctl solo muestra los mensajes del propio
            # usuario (código 0): sería "0 eventos" falso. Se informa como sin permiso.
            raise JournalError("no_permission", result.stderr.strip())
        if result.returncode != 0 and not result.entries:
            if "no journal files" in stderr:
                raise JournalError("unavailable", result.stderr.strip())
            raise JournalError("error", result.stderr.strip() or f"exit {result.returncode}")
        if source.key == "auditd" and not result.entries and cursor is None:
            # Ninguna entrada de auditoría en el journal: auditd puede estar instalado pero
            # journald no recibe sus registros (socket de auditoría desactivado).
            self._set(source.key, "unavailable")
            return []
        self._set(source.key, "active")
        events: list[dict[str, Any]] = []
        seen: set[int] = set()
        kernel_copies: dict[str, int] = {}
        newest_cursor, newest_realtime = cursor, last_realtime
        for entry in result.entries:
            entry_cursor = entry.get("__CURSOR")
            realtime = _realtime(entry)
            if isinstance(entry_cursor, str) and _CURSOR.match(entry_cursor):
                newest_cursor = entry_cursor
                if realtime is not None:
                    newest_realtime = max(realtime, newest_realtime or 0)
            if (
                last_realtime is not None
                and realtime is not None
                and realtime < last_realtime - REPLAY_TOLERANCE_USEC
            ):
                continue
            event = to_event(source, entry)
            if event is None or event["record_id"] in seen:
                continue
            if source.key == "kernel":
                fingerprint = hashlib.sha256(event["message"].encode()).hexdigest()
                kernel_copies[fingerprint] = kernel_copies.get(fingerprint, 0) + 1
                if kernel_copies[fingerprint] > KERNEL_DUPLICATES_MAX:
                    continue
            seen.add(event["record_id"])
            events.append(event)
        sources[source.key] = {"cursor": newest_cursor, "realtime": newest_realtime}
        return events

    def commit(self, cursor: dict[str, Any]) -> None:
        write_atomic(self._path, json.dumps(cursor))
