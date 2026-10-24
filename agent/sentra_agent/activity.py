"""Actividad del endpoint (Fase 6E.3): eventos, identidad de procesos, privacidad y cola.

Piezas comunes al tracker de procesos, a los sondeos de servicios/persistencia, a Sysmon y al
envío a POST /agents/activity:

- `instance_key`: identifica un proceso concreto aunque el sistema reutilice su PID. Es el
  SHA-256 de `boot_id|pid|create_time_ms` (32 hex), igual en el agente y en el servidor.
- `redact_cmdline`: la línea de comandos sale del equipo ya recortada según la política local
  (`off`, `redacted`, `full`); el servidor vuelve a aplicar la suya y gana la más restrictiva.
- `ActivityQueue`: cola persistente y acotada. Si el servidor no responde durante horas, los
  eventos esperan en disco; al llenarse se descartan los más antiguos y se cuentan, para que el
  servidor sepa que hay un hueco en lugar de creer que no pasó nada.
"""

import hashlib
import json
import logging
import os
import re
import threading
import uuid
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

from sentra_agent.identity import write_atomic

logger = logging.getLogger("sentra_agent")

QUEUE_FILE = "activity_queue.jsonl"
QUEUE_META_FILE = "activity_queue.meta.json"
CMDLINE_MAX = 1024
REDACTED = "[REDACTED]"

CATEGORIES = frozenset(
    {
        "process",
        "network",
        "service",
        "scheduled_task",
        "persistence",
        "auth",
        "dns",
        "protection",
        "firewall",
        "agent_health",
    }
)
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
# Estados de colector del contrato (stats.collectors y heartbeat.telemetry.collectors).
ACTIVE = "active"
UNAVAILABLE = "unavailable"
PERMISSION_DENIED = "permission_denied"
DISABLED = "disabled"
ERROR = "error"


def instance_key(boot_id: str, pid: int, create_time_ms: int) -> str:
    """Clave estable de un proceso: un PID reutilizado tiene otro create_time y otra clave."""
    raw = f"{boot_id}|{pid}|{create_time_ms}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def create_time_ms(create_time: float) -> int:
    """Milisegundos truncados (no redondeados): Sysmon también trunca su UtcTime, así la
    misma ejecución vista por psutil y por Sysmon obtiene la misma instance_key."""
    return int(create_time * 1000)


_LINUX_BOOT_ID = Path("/proc/sys/kernel/random/boot_id")


def read_boot_id(path: Path = _LINUX_BOOT_ID) -> str:
    """Identificador del arranque actual del sistema.

    Linux expone un UUID por arranque. En el resto se usa la hora de arranque (entera): no
    cambia mientras el equipo sigue encendido y cambia en cada reinicio, que es lo que importa
    para que dos procesos de arranques distintos con el mismo PID no compartan clave.
    """
    try:
        text = path.read_text(encoding="ascii").strip()
        if text:
            return text[:64]
    except OSError:
        pass
    try:
        return f"boot-{int(psutil.boot_time())}"
    except (psutil.Error, OSError):
        return "boot-unknown"


def iso(timestamp: float | datetime) -> str:
    """ISO 8601 en UTC con milisegundos, el formato de `occurred_at` del contrato."""
    moment = (
        timestamp if isinstance(timestamp, datetime) else datetime.fromtimestamp(timestamp, UTC)
    )
    return moment.astimezone(UTC).isoformat(timespec="milliseconds")


# --- Línea de comandos ---------------------------------------------------------------------

# Opciones cuyo SIGUIENTE argumento es un secreto (comparación sin mayúsculas).
_SECRET_FLAGS = frozenset(
    {
        "-p",
        "/p",
        "-pw",
        "-pwd",
        "--pwd",
        "-password",
        "--password",
        "/password",
        "--pass",
        "--passwd",
        "--token",
        "-token",
        "--secret",
        "--api-key",
        "--apikey",
        "--access-key",
        "--client-secret",
        "-k",
    }
)
# --password=x, /p:x, token=x, apikey=x, client_secret=x... (también dentro de URLs ?a=b&c=d).
_KEY_VALUE = re.compile(
    r"(?i)((?:--?|/)?[A-Za-z0-9_.-]*(?:password|passwd|pwd|token|secret|key|/p)[=:])([^\s&;'\"]+)"
)
_AUTH_HEADER = re.compile(r"(?i)(authorization\s*:\s*)(?:(?:basic|bearer|digest|token)\s+)?\S+")
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]*):([^/\s@]+)@")


def redact_cmdline(argv: list[str] | None, policy: str) -> str | None:
    """Línea de comandos según la política local; None si no se envía o no se conoce.

    `redacted` quita valores que suelen ser secretos (-p, --password, /p, token=, key=,
    secret=, cabeceras Authorization y credenciales en URLs) y corta a 1024 caracteres. Es un
    filtro de buena fe, no una garantía: por eso existe `off`.
    """
    if policy == "off" or not argv:
        return None
    if policy == "full":
        return " ".join(argv)[:CMDLINE_MAX]
    parts: list[str] = []
    hide_next = False
    for raw in argv:
        token = str(raw)
        if hide_next:
            parts.append(REDACTED)
            hide_next = False
            continue
        if token.lower() in _SECRET_FLAGS:
            parts.append(token)
            hide_next = True
            continue
        parts.append(_KEY_VALUE.sub(lambda m: m.group(1) + REDACTED, token))
    text = " ".join(parts)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + REDACTED, text)
    text = _URL_CREDENTIALS.sub(lambda m: f"{m.group(1)}{m.group(2)}:{REDACTED}@", text)
    return text[:CMDLINE_MAX]


# --- Eventos -------------------------------------------------------------------------------


def clip(value: object, length: int) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    return text[:length] or None


def make_event(
    category: str,
    action: str,
    source: str,
    data: dict[str, Any],
    occurred_at: str,
    instance: str | None = None,
) -> dict[str, Any]:
    """Evento del contrato sin `seq` (la cola lo numera al encolar)."""
    if category not in CATEGORIES or source not in SOURCES:
        # Error de programación: nunca debe llegar al servidor algo fuera del catálogo.
        raise ValueError(f"unknown category/source {category}/{source}")
    return {
        "event_uid": str(uuid.uuid4()),
        "category": category,
        "action": action,
        "occurred_at": occurred_at,
        "source": source,
        "instance_key": instance,
        "data": data,
    }


class ActivityQueue:
    """Cola FIFO persistente y acotada de eventos de actividad (thread-safe).

    En memoria se guardan las líneas JSON ya serializadas (unos cientos de bytes cada una, no
    diccionarios de Python), así 20 000 eventos caben en pocos MB. En disco es un fichero
    JSONL al que solo se AÑADEN líneas; los eventos confirmados o descartados se saltan con un
    contador en el fichero de metadatos y el fichero se compacta cuando el hueco crece. Así un
    corte largo no reescribe megas en cada ciclo.

    Un fallo entre añadir líneas y guardar metadatos solo puede reenviar eventos (el servidor
    los deduplica por event_uid) o perder unos pocos: nunca corrompe la cola.
    """

    def __init__(self, maxlen: int, state_dir: Path | None = None) -> None:
        self.maxlen = maxlen
        self._lines: deque[str] = deque()
        self._lock = threading.Lock()
        self._path = state_dir / QUEUE_FILE if state_dir is not None else None
        self._meta_path = state_dir / QUEUE_META_FILE if state_dir is not None else None
        self._pending: list[str] = []  # líneas aún no añadidas al fichero
        self._skip = 0  # líneas del principio del fichero ya consumidas
        self._meta_dirty = False
        self._rewrite = False
        self.next_seq = 0
        self.dropped_total = 0
        self.dropped_since_last = 0
        if self._path is not None:
            self._load()

    # Persistencia ------------------------------------------------------------------------

    def _load(self) -> None:
        assert self._path is not None and self._meta_path is not None  # noqa: S101
        try:
            meta = json.loads(self._meta_path.read_text(encoding="utf-8"))
            skip = int(meta.get("skip", 0))
            self.next_seq = int(meta.get("next_seq", 0))
            self.dropped_total = int(meta.get("dropped_total", 0))
        except (OSError, ValueError, TypeError, AttributeError):
            skip = 0
        lines: list[str] = []
        try:
            with self._path.open(encoding="utf-8") as handle:
                for index, line in enumerate(handle):
                    if index < skip:
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        json.loads(line)
                    except ValueError:
                        continue  # línea a medio escribir tras un corte de luz
                    lines.append(line)
        except FileNotFoundError:
            return
        except OSError as exc:
            logger.warning("activity queue unreadable, discarded", extra={"error": str(exc)})
            return
        overflow = max(0, len(lines) - self.maxlen)
        if overflow:
            # max_events bajó entre ejecuciones: se conservan los más recientes.
            self.dropped_total += overflow
            self.dropped_since_last += overflow
        self._lines.extend(lines[overflow:])
        # Se reescribe compacto en el siguiente persist (sin líneas saltadas ni rotas).
        self._rewrite = True
        self._meta_dirty = True
        if self._lines:
            logger.info("restored queued activity events", extra={"count": len(self._lines)})

    def persist(self) -> None:
        """Lleva a disco lo que cambió desde la última vez (añadir, saltar o compactar)."""
        if self._path is None or self._meta_path is None:
            return
        with self._lock:
            try:
                if self._rewrite or self._skip > max(1000, len(self._lines)):
                    self._compact()
                elif self._pending:
                    self._path.parent.mkdir(parents=True, exist_ok=True)
                    with self._path.open("a", encoding="utf-8") as handle:
                        handle.write("\n".join(self._pending) + "\n")
                    self._pending = []
                if self._meta_dirty:
                    meta = {
                        "skip": self._skip,
                        "next_seq": self.next_seq,
                        "dropped_total": self.dropped_total,
                    }
                    write_atomic(self._meta_path, json.dumps(meta), private=False)
                    self._meta_dirty = False
            except OSError as exc:
                # Disco lleno o bloqueado: la copia en memoria sigue; se reintenta después.
                logger.warning("could not persist activity queue", extra={"error": str(exc)})

    def _compact(self) -> None:
        assert self._path is not None  # noqa: S101
        content = "".join(line + "\n" for line in self._lines)
        if content:
            write_atomic(self._path, content, private=False)
        else:
            self._path.unlink(missing_ok=True)
        self._pending = []
        self._skip = 0
        self._rewrite = False
        self._meta_dirty = True

    # Operaciones -------------------------------------------------------------------------

    def extend(self, events: list[dict[str, Any]]) -> int:
        """Encola eventos (les asigna `seq`); devuelve cuántos antiguos se descartaron."""
        dropped = 0
        with self._lock:
            for event in events:
                event["seq"] = self.next_seq
                self.next_seq += 1
                line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
                self._lines.append(line)
                self._pending.append(line)
                if len(self._lines) > self.maxlen:
                    self._lines.popleft()
                    dropped += 1
            if dropped:
                self.dropped_total += dropped
                self.dropped_since_last += dropped
                # Las líneas descartadas pueden estar ya en el fichero o solo en _pending:
                # reescribir es lo único seguro y solo ocurre con la cola llena.
                self._rewrite = True
            if events:
                self._meta_dirty = True
        return dropped

    def peek(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            return [json.loads(line) for line in list(self._lines)[:limit]]

    def ack(self, count: int) -> None:
        """Quita del principio los `count` eventos que el servidor ya aceptó (o rechazó)."""
        with self._lock:
            count = min(count, len(self._lines))
            for _ in range(count):
                self._lines.popleft()
            unwritten = len(self._pending)
            written_consumed = count
            if unwritten and len(self._lines) < unwritten:
                # Parte de lo confirmado ni siquiera llegó al fichero: se quita de _pending.
                drop_pending = unwritten - len(self._lines)
                self._pending = self._pending[drop_pending:]
                written_consumed = count - drop_pending
            self._skip += max(0, written_consumed)
            self._meta_dirty = True

    def reset_dropped_since_last(self) -> None:
        with self._lock:
            self.dropped_since_last = 0

    def oldest_occurred_at(self) -> str | None:
        with self._lock:
            if not self._lines:
                return None
            value = json.loads(self._lines[0]).get("occurred_at")
            return value if isinstance(value, str) else None

    def __len__(self) -> int:
        return len(self._lines)


def file_sha256(path: str, max_bytes: int) -> str | None:
    """SHA-256 de un fichero si no supera `max_bytes`; None si es mayor o no se puede leer."""
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
