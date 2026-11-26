"""Gestor SIEM del sensor: arranca receptores aprobados, agrupa registros y los encola.

Flujo: receptor → `submit` (buffer acotado por entrada) → lote con `batch_id` → spool SIEM
(SQLite, aparte) → runner → POST /sensor/siem/batches. El `batch_id` se fija al encolar y
viaja guardado: un reintento reenvía el mismo lote y el servidor lo deduplica.

Memoria acotada: cada entrada guarda como mucho un lote en memoria (`max_records_per_batch`
y `max_batch_bytes` del servidor); al llenarse se encola en el spool, que tiene su propio
tope de disco y antigüedad. Si el spool está lleno, descarta lo más antiguo y lo cuenta.
"""

import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from sentra_sensor.siem.config import (
    FileInput,
    SiemInput,
    SiemLocalConfig,
    SiemServerConfig,
    SiemServerSource,
    SyslogInput,
)
from sentra_sensor.siem.files import FileTailer
from sentra_sensor.siem.syslog import InputCounters, SyslogReceiver

logger = logging.getLogger("sentra_sensor.siem")

Enqueue = Callable[[str, dict[str, Any]], None]
# Sobrecoste JSON aproximado por registro (claves y metadatos) para no pasar del tope.
_RECORD_OVERHEAD = 256


class Receiver(Protocol):
    spec: Any
    counters: InputCounters
    state: str
    error_code: str | None

    def start(self) -> None: ...

    def stop(self, timeout: float = 5.0) -> None: ...


ReceiverFactory = Callable[[SiemInput, Callable[[str, dict[str, Any]], None]], Receiver]


def default_receiver_factory(
    spec: SiemInput, sink: Callable[[str, dict[str, Any]], None]
) -> Receiver:
    if isinstance(spec, SyslogInput):
        return SyslogReceiver(spec, sink)
    raise ValueError(f"unsupported siem input type {spec.type}")


def _file_factory(manager: "SiemManager", offsets_path: Path) -> ReceiverFactory:
    def factory(spec: SiemInput, sink: Callable[[str, dict[str, Any]], None]) -> Receiver:
        if isinstance(spec, FileInput):
            return FileTailer(spec, sink, manager.flush_input, offsets_path)
        return default_receiver_factory(spec, sink)

    return factory


@dataclass
class _Buffer:
    source: SiemServerSource
    records: list[dict[str, Any]] = field(default_factory=list)
    size: int = 0
    opened_at: float = 0.0
    # Contadores del receptor ya informados en lotes anteriores (para enviar deltas).
    reported: dict[str, int] = field(default_factory=dict)


class SiemManager:
    def __init__(
        self,
        local: SiemLocalConfig,
        enqueue: Enqueue,
        receiver_factory: ReceiverFactory | None = None,
        clock: Callable[[], float] = time.time,
        offsets_path: Path | None = None,
    ) -> None:
        self.local = local
        self._enqueue = enqueue
        if receiver_factory is not None:
            self._factory = receiver_factory
        elif offsets_path is not None:
            # Los lectores de ficheros necesitan dónde guardar sus offsets (data_dir).
            self._factory = _file_factory(self, offsets_path)
        else:
            self._factory = default_receiver_factory
        self._clock = clock
        self.server: SiemServerConfig | None = None
        self.receivers: dict[str, Receiver] = {}
        self.unknown_inputs: list[str] = []
        self._buffers: dict[str, _Buffer] = {}
        self.dropped_unapproved = 0
        self.dropped_oversize = 0
        self._lock = threading.RLock()

    # --- configuración ---------------------------------------------------------------

    def apply(self, server: SiemServerConfig | None) -> None:
        """Aplica el bloque `config.siem` (idempotente). Solo escucha en las entradas
        declaradas en sensor.toml Y aprobadas por el servidor."""
        with self._lock:
            if not self.local.enabled or server is None or not server.enabled:
                self._flush_all()
                self._stop_all()
                self.server = server
                self.unknown_inputs = []
                return
            wanted = {source.input: source for source in server.sources}
            # Entradas que dejan de estar aprobadas: se encola lo pendiente y se paran.
            for name in list(self.receivers):
                if name not in wanted:
                    self._flush(name)
                    self.receivers.pop(name).stop()
                    self._buffers.pop(name, None)
            self.unknown_inputs = []
            for name, source in wanted.items():
                spec = self.local.input(name)
                if spec is None:
                    # El servidor aprobó un alias que el host no declaró: no se abre nada.
                    self.unknown_inputs.append(name)
                    continue
                buffer = self._buffers.get(name)
                if buffer is not None and buffer.source.source_id != source.source_id:
                    # La entrada pasa a otra fuente: lo pendiente sale con la fuente anterior.
                    self._flush(name)
                    buffer = None
                if buffer is None:
                    self._buffers[name] = _Buffer(source=source)
                else:
                    buffer.source = source
                if name not in self.receivers:
                    receiver = self._factory(spec, self.submit)
                    self.receivers[name] = receiver
                    receiver.start()
            if self.server is None or self.server.revision != server.revision:
                logger.info(
                    "siem configuration applied",
                    extra={
                        "revision": server.revision,
                        "inputs": sorted(self.receivers),
                        "unknown": self.unknown_inputs,
                    },
                )
            self.server = server

    def _stop_all(self) -> None:
        for receiver in self.receivers.values():
            receiver.stop()
        self.receivers = {}
        self._buffers = {}

    def stop(self) -> None:
        """Para receptores y encola lo pendiente (queda en el spool para el próximo envío)."""
        with self._lock:
            for receiver in self.receivers.values():
                receiver.stop()
            self._flush_all()
            self.receivers = {}
            self._buffers = {}

    # --- registros -------------------------------------------------------------------

    def submit(self, name: str, record: dict[str, Any]) -> None:
        """Llamado desde los hilos de los receptores."""
        with self._lock:
            server = self.server
            buffer = self._buffers.get(name)
            if server is None or buffer is None:
                self.dropped_unapproved += 1
                return
            size = len(record["raw"].encode("utf-8", "surrogatepass")) + _RECORD_OVERHEAD
            if size - _RECORD_OVERHEAD > server.max_record_bytes:
                self.dropped_oversize += 1
                receiver = self.receivers.get(name)
                if receiver is not None:
                    receiver.counters.add(dropped_oversize=1)
                return
            if buffer.records and buffer.size + size > server.max_batch_bytes:
                self._flush(name)
            if not buffer.records:
                buffer.opened_at = self._clock()
            buffer.records.append(record)
            buffer.size += size
            if len(buffer.records) >= server.max_records_per_batch:
                self._flush(name)

    def flush_input(self, name: str) -> None:
        """Encola YA lo pendiente de una entrada (los lectores de ficheros lo llaman antes de
        guardar su offset)."""
        with self._lock:
            self._flush(name)

    def flush_due(self) -> int:
        """Encola los buffers con más antigüedad que `flush_interval_seconds`."""
        with self._lock:
            if self.server is None:
                return 0
            now = self._clock()
            interval = self.server.flush_interval_seconds
            due = [
                name
                for name, buffer in self._buffers.items()
                if buffer.records and now - buffer.opened_at >= interval
            ]
            for name in due:
                self._flush(name)
            return len(due)

    def next_flush_time(self) -> float | None:
        with self._lock:
            if self.server is None:
                return None
            opened = [b.opened_at for b in self._buffers.values() if b.records]
            if not opened:
                return None
            return min(opened) + self.server.flush_interval_seconds

    def _flush_all(self) -> None:
        for name in list(self._buffers):
            self._flush(name)

    def _flush(self, name: str) -> None:
        buffer = self._buffers.get(name)
        if buffer is None or not buffer.records:
            return
        receiver = self.receivers.get(name)
        stats: dict[str, int] = {}
        if receiver is not None:
            current = receiver.counters.snapshot()
            stats = {k: v - buffer.reported.get(k, 0) for k, v in current.items()}
            buffer.reported = current
        batch = {
            "batch_id": str(uuid.uuid4()),
            "source_id": buffer.source.source_id,
            "input": name,
            "config_revision": self.server.revision if self.server else None,
            "records": buffer.records,
            "stats": {k: max(0, v) for k, v in stats.items()},
        }
        buffer.records = []
        buffer.size = 0
        try:
            self._enqueue(name, batch)
        except Exception:
            # Un fallo del spool (disco lleno) no tumba los receptores; se registra.
            logger.exception("siem batch could not be spooled", extra={"input": name})

    # --- estado ----------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Estado para el heartbeat: alias, estados y contadores. Nunca puertos ni pares."""
        with self._lock:
            if not self.local.enabled:
                state = "disabled"
            elif self.server is None or not self.server.enabled:
                state = "not_configured"
            elif not self.receivers:
                state = "error"
            else:
                states = {r.state for r in self.receivers.values()}
                if "error" in states:
                    state = "error" if states == {"error"} else "degraded"
                elif self.unknown_inputs:
                    state = "degraded"
                elif states == {"running"}:
                    state = "running"
                else:
                    state = "starting"
            inputs: list[dict[str, Any]] = []
            for name, receiver in sorted(self.receivers.items()):
                counters = receiver.counters.snapshot()
                buffer = self._buffers.get(name)
                reasons = []
                if counters["dropped_rate"]:
                    reasons.append("rate_limited")
                if counters["dropped_oversize"]:
                    reasons.append("oversize_records")
                file_errors = getattr(receiver, "file_errors", None)
                if file_errors:
                    # Códigos (file_missing, symlink_refused...), nunca rutas.
                    reasons.extend(sorted(set(file_errors.values())))
                input_state = receiver.state
                if input_state == "running" and reasons:
                    input_state = "degraded"
                with receiver.counters.lock:
                    last = receiver.counters.last_record_at
                    connections = receiver.counters.connections
                inputs.append(
                    {
                        "name": name,
                        "source_id": buffer.source.source_id if buffer else None,
                        "state": input_state,
                        "error_code": receiver.error_code,
                        "degraded_reasons": reasons,
                        "received": counters["received"],
                        "dropped": counters["dropped_oversize"]
                        + counters["dropped_peer"]
                        + counters["dropped_rate"],
                        "malformed": counters["malformed"],
                        "connections": max(0, connections),
                        "last_record_at": _iso(last),
                    }
                )
            for name in self.unknown_inputs:
                inputs.append(
                    {"name": name, "state": "not_declared", "error_code": "input_not_declared"}
                )
            return {
                "state": state,
                "config_revision": self.server.revision if self.server else None,
                "inputs": inputs,
            }


def _iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, UTC).isoformat()
