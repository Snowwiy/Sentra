"""Eventos de macOS (Fase 6C.5): subconjunto acotado del Unified Logging.

Qué se recoge y por qué así (docs/agent-macos-installation.md, sección Eventos):
- `/usr/bin/log show --style ndjson` con un predicado FIJO escrito aquí (sshd, sudo, su,
  Compartir pantalla y fallos de autenticación de authd), nunca "todo el log" ni un
  predicado que llegue del servidor;
- de cada proceso solo los mensajes que se reconocen (expresiones fijas: las de sshd y sudo
  son las mismas que en Linux); el resto no sale del equipo;
- los mensajes son texto no confiable: solo se analizan con expresiones regulares y se
  sanean (contraseñas, tokens, credenciales en URLs) antes de enviarse;
- macOS sustituye por "<private>" los datos que el emisor marcó como privados: se respeta,
  no se intenta leerlos (no se activa el modo de datos privados ni se pide ningún perfil);
- cursor = marca de tiempo de la última entrada leída (más los ids de esa misma marca),
  persistido solo tras confirmar el envío; el primer arranque lee solo la última hora y como
  mucho 50 eventos; tras una parada larga se leen como mucho las últimas 24 h;
- record_id estable (arranque, machTimestamp, proceso, hilo, mensaje): un reenvío no duplica.

Permisos: el daemon corre como root, que puede leer el log del sistema sin permisos de TCC
(no hace falta Acceso total al disco). Como usuario no administrador `log show` puede
negarse: se informa la cobertura "no_permission" y heartbeat, telemetría e inventario
siguen. Ningún evento de Windows se simula: el servidor recibe source "macos_unified_log".

VALIDACIÓN EN macOS REAL PENDIENTE: el formato exacto de los mensajes y el formato de
--start con zona horaria se han tomado de macOS 14/15 y se prueban con fixtures.
"""

import hashlib
import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentra_agent.identity import write_atomic
from sentra_agent.linux_events import (
    MESSAGE_MAX,
    Classified,
    _put,
    _ssh,
    _sudo,
    clean,
    redact,
)
from sentra_agent.syscmd import (
    CommandOutput,
    CommandTimeoutError,
    CommandUnavailableError,
    run_bounded,
)

logger = logging.getLogger("sentra_agent")

SOURCE = "macos_unified_log"
CHANNEL = "unified_log"
COVERAGE_KEY = "unified_log"
LOG = "/usr/bin/log"
STATE_FILE = "macos_events_state.json"
STATE_VERSION = 1
FIRST_RUN_WINDOW = "1h"
FIRST_RUN_MAX = 50
# Entradas leídas por ciclo (todas, también las que no se envían) y bytes de salida.
BATCH_MAX = 200
OUTPUT_MAX_BYTES = 2 * 1024 * 1024
READ_TIMEOUT = 60.0
# Tras una parada larga del agente no se recorre más que esto hacia atrás.
MAX_BACKLOG = timedelta(hours=24)

# Predicado fijo (sintaxis NSPredicate de `log`). Solo procesos de autenticación y
# privilegios; authd solo con sus fallos, porque registra mucho más.
PREDICATE = (
    'process == "sshd" OR process == "sshd-session" OR process == "sudo" OR process == "su"'
    ' OR process == "screensharingd"'
    ' OR (process == "authd" AND eventMessage CONTAINS[c] "failed to authenticate")'
)

_PRIVATE = "<private>"


# --- Clasificación ---------------------------------------------------------------------------

_SU_BAD = re.compile(r"^BAD SU (?P<user>\S+) to (?P<target>\S+) on (?P<tty>\S+)")
_SU_OK = re.compile(r"^(?P<user>\S+) to (?P<target>\S+) on (?P<tty>\S+)$")
_SCREEN = re.compile(
    r"^Authentication: (?P<result>FAILED|SUCCEEDED) :: User Name: (?P<user>.*?)"
    r" :: Viewer Address: (?P<ip>\S+)"
)
_AUTHD = re.compile(r"^Failed to authenticate user (?P<user><[^>\s]*>|\S+)")
_PAM_MAC = re.compile(
    r"^error: PAM: authentication error for (?:illegal user )?(?P<user>\S+) from (?P<ip>\S+)"
)


def _su(message: str) -> Classified | None:
    data: dict[str, str] = {}
    if m := _SU_BAD.match(message):
        _put(data, "user", m["user"])
        _put(data, "target_user", m["target"])
        _put(data, "tty", m["tty"])
        return Classified("su_auth_failure", "warning", data)
    if m := _SU_OK.match(message):
        _put(data, "user", m["user"])
        _put(data, "target_user", m["target"])
        _put(data, "tty", m["tty"])
        return Classified("su_session", "info", data)
    return None


def _screen_sharing(message: str) -> Classified | None:
    if m := _SCREEN.match(message):
        data: dict[str, str] = {}
        _put(data, "user", m["user"])
        _put(data, "source_ip", m["ip"])
        if m["result"] == "FAILED":
            return Classified("screen_sharing_auth_failure", "warning", data)
        return Classified("screen_sharing_auth_success", "info", data)
    return None


def _authd(message: str) -> Classified | None:
    if m := _AUTHD.match(message):
        data: dict[str, str] = {}
        user = m["user"]
        if user != _PRIVATE:
            # authd escribe el nombre entre <>; "<private>" es el dato oculto por macOS.
            _put(data, "user", user.strip("<>"))
        return Classified("local_auth_failure", "warning", data)
    return None


def _sshd(message: str) -> Classified | None:
    if m := _PAM_MAC.match(message):
        # Mismo criterio que en Linux: el fallo PAM duplica el "Failed ..." de sshd, así que
        # se guarda como evento propio sin contar como otro intento.
        data: dict[str, str] = {}
        _put(data, "user", m["user"])
        _put(data, "source_ip", m["ip"])
        return Classified("pam_auth_failure", "warning", data)
    return _ssh(message)


CLASSIFIERS: dict[str, Callable[[str], Classified | None]] = {
    "sshd": _sshd,
    "sshd-session": _sshd,
    "sudo": _sudo,
    "su": _su,
    "screensharingd": _screen_sharing,
    "authd": _authd,
}


def classify(process: str, message: str) -> Classified | None:
    handler = CLASSIFIERS.get(process)
    if handler is None:
        return None
    # sudo escribe en el log unificado con un espacio inicial delante del usuario.
    return handler(message.strip())


# --- Entradas de `log show --style ndjson` --------------------------------------------------


def parse_timestamp(value: object) -> datetime | None:
    """ "2026-10-16 10:21:33.123456+0200" -> datetime con zona (UTC)."""
    if not isinstance(value, str):
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z"):
        try:
            return datetime.strptime(value.strip(), fmt).astimezone(UTC)
        except ValueError:
            continue
    return None


def parse_ndjson(output: bytes, truncated: bool) -> list[dict[str, Any]]:
    """Entradas JSON de la salida; ignora líneas que no lo son (cabeceras, resumen).

    Si Sentra cortó la salida, la última línea puede estar a medias y se descarta.
    """
    lines = output.split(b"\n")
    if truncated and lines:
        lines = lines[:-1]
    entries = []
    for raw in lines:
        line = raw.strip()
        if not line.startswith(b"{"):
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and "eventMessage" in entry and "timestamp" in entry:
            entries.append(entry)
    return entries


def _process(entry: dict[str, Any]) -> str:
    path = entry.get("processImagePath")
    if isinstance(path, str) and path:
        return path.rsplit("/", 1)[-1][:64]
    return str(entry.get("process") or "")[:64]


def record_id(entry: dict[str, Any]) -> int:
    message = str(entry.get("eventMessage") or "")
    digest = hashlib.sha256(message.encode("utf-8", "replace")).hexdigest()
    basis = "|".join(
        (
            "macos",
            str(entry.get("bootUUID")),
            str(entry.get("machTimestamp")),
            str(entry.get("processID")),
            str(entry.get("threadID")),
            str(entry.get("timestamp")),
            digest,
        )
    )
    return int.from_bytes(hashlib.sha256(basis.encode()).digest()[:8], "big") & (2**63 - 1)


def to_event(entry: dict[str, Any]) -> dict[str, Any] | None:
    occurred = parse_timestamp(entry.get("timestamp"))
    message = entry.get("eventMessage")
    if occurred is None or not isinstance(message, str) or not message.strip():
        return None
    process = _process(entry)
    classified = classify(process, message)
    if classified is None:
        return None
    # "<private>": dato que macOS oculta por privacidad; se omite en lugar de enviarlo.
    data = {k: v for k, v in classified.data.items() if v and v != _PRIVATE}
    return {
        "source": SOURCE,
        "channel": CHANNEL,
        "record_id": record_id(entry),
        "event_type": classified.event_type,
        "provider": clean(process, 64) or "unified_log",
        "level": classified.level,
        "message": redact(clean(message, MESSAGE_MAX)),
        "computer": None,
        "occurred_at": occurred.isoformat(),
        **({"data": data} if data else {}),
    }


def build_args(since: datetime | None) -> list[str]:
    args = [LOG, "show", "--style", "ndjson", "--info", "--predicate", PREDICATE]
    if since is None:
        return [*args, "--last", FIRST_RUN_WINDOW]
    # Segundos completos en UTC con su desplazamiento explícito: no depende de la zona del
    # equipo. Lo ya enviado dentro de ese segundo se filtra con los ids guardados.
    return [*args, "--start", since.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S%z")]


# --- Colector -------------------------------------------------------------------------------

LogRunner = Callable[[list[str]], CommandOutput]


def _run(argv: list[str]) -> CommandOutput:
    return run_bounded(argv, timeout=READ_TIMEOUT, max_bytes=OUTPUT_MAX_BYTES)


@dataclass
class _Cursor:
    last: datetime | None
    seen: set[int]

    def as_json(self) -> dict[str, Any]:
        return {
            "version": STATE_VERSION,
            "last": self.last.isoformat() if self.last else None,
            "seen": sorted(self.seen)[:BATCH_MAX],
        }


class MacUnifiedLogCollector:
    """EventSource del runner para macOS. `pending()` nunca lanza: los fallos son cobertura."""

    def __init__(
        self,
        state_dir: Path,
        runner: LogRunner = _run,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._path = state_dir / STATE_FILE
        self._runner = runner
        self._clock = clock
        self._coverage: dict[str, str] = {}
        self._reported: str | None = None

    def coverage(self) -> dict[str, str] | None:
        return dict(self._coverage) if self._coverage else None

    def _set(self, state: str, detail: str = "") -> None:
        self._coverage = {COVERAGE_KEY: state}
        if state == self._reported:
            return
        previous, self._reported = self._reported, state
        if state in ("no_permission", "error", "unavailable"):
            logger.warning(
                "macOS unified log not readable; heartbeat, telemetry and inventory continue",
                extra={"state": state, "error": detail[:300]},
            )
        elif previous in ("no_permission", "error", "unavailable"):
            logger.info("macOS unified log readable again")

    def _load(self) -> _Cursor:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return _Cursor(None, set())
        except (OSError, ValueError) as exc:
            logger.warning("macOS event state unreadable, starting over", extra={"error": str(exc)})
            return _Cursor(None, set())
        if not isinstance(data, dict):
            return _Cursor(None, set())
        last = None
        if isinstance(data.get("last"), str):
            try:
                last = datetime.fromisoformat(data["last"]).astimezone(UTC)
            except ValueError:
                last = None
        seen = {v for v in data.get("seen") or [] if isinstance(v, int)} if last else set()
        return _Cursor(last, seen)

    def pending(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        cursor = self._load()
        now = self._clock()
        since = cursor.last
        if since is not None and since < now - MAX_BACKLOG:
            logger.info("macOS event backlog older than 24 h skipped")
            since, cursor = now - MAX_BACKLOG, _Cursor(now - MAX_BACKLOG, set())
        try:
            output = self._runner(build_args(since))
        except CommandUnavailableError as exc:
            self._set("unavailable", str(exc))
            return [], cursor.as_json()
        except CommandTimeoutError as exc:
            self._set("error", str(exc))
            return [], cursor.as_json()
        except OSError as exc:
            self._set("error", str(exc))
            return [], cursor.as_json()
        if output.returncode != 0 and not output.truncated:
            stderr = output.stderr.lower()
            if "must be admin" in stderr or "not permitted" in stderr or "denied" in stderr:
                self._set("no_permission", output.stderr)
            else:
                self._set("error", output.stderr or f"exit {output.returncode}")
            return [], cursor.as_json()
        self._set("active")
        entries = parse_ndjson(output.stdout, output.truncated)
        events, new_cursor = self._select(entries, cursor, first_run=since is None)
        return events, new_cursor.as_json()

    def _select(
        self, entries: list[dict[str, Any]], cursor: _Cursor, first_run: bool
    ) -> tuple[list[dict[str, Any]], _Cursor]:
        events: list[dict[str, Any]] = []
        last, seen = cursor.last, set(cursor.seen)
        read = 0
        for entry in entries:
            moment = parse_timestamp(entry.get("timestamp"))
            if moment is None:
                continue
            rid = record_id(entry)
            if cursor.last is not None and (
                moment < cursor.last or (moment == cursor.last and rid in cursor.seen)
            ):
                continue  # ya leído en un ciclo anterior
            read += 1
            if last is None or moment > last:
                last, seen = moment, {rid}
            elif moment == last:
                seen.add(rid)
            event = to_event(entry)
            if event is not None:
                events.append(event)
            if read >= BATCH_MAX:
                break  # el resto se lee en el ciclo siguiente desde el nuevo cursor
        if first_run:
            events = events[-FIRST_RUN_MAX:]
            if last is None:
                # Primera lectura sin entradas: el siguiente ciclo empieza desde ahora, no
                # otra vez desde la última hora.
                last = self._clock().replace(microsecond=0)
        return events, _Cursor(last, seen)

    def commit(self, cursor: dict[str, Any]) -> None:
        write_atomic(self._path, json.dumps(cursor))
