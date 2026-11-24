"""Pipeline de captura pasiva por interfaz y gestor de NDR del sensor (Fase 7E.1).

Un hilo por interfaz aprobada: lee del backend, decodifica, alimenta la tabla de flujos y los
agregadores y, cada `export_interval_seconds`, encola un lote en el spool PROPIO de NDR. El
bucle principal del sensor (heartbeats, jobs, envíos) no se bloquea nunca por la captura: si
un backend falla, el hilo informa el código de error y reintenta con espera creciente, y el
resto del sensor sigue igual.

Presupuestos (estabilidad antes que cobertura):
* paquetes por segundo: token bucket; lo que excede se cuenta como `budget_dropped` y NO se
  decodifica (la cobertura baja y se informa, el host no se satura);
* CPU del hilo: medida con `time.thread_time`; si supera `max_cpu_percent` en una ventana, el
  presupuesto de paquetes se reduce a la mitad (mínimo 100 pps) y vuelve a subir poco a poco;
* flujos en memoria: `max_flows` (LRU, ver flows.py);
* spool: tamaño y antigüedad propios; lleno = se descarta lo más antiguo, contado.

Ninguna métrica se inventa: si el backend no informa pérdidas del kernel, el campo es null.
"""

import contextlib
import json
import logging
import random
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentra_sensor.ndr.capture import (
    CaptureBackend,
    CaptureError,
    DropCounters,
    make_backend,
)
from sentra_sensor.ndr.config import NdrInterface, NdrLocalConfig, NdrServerConfig
from sentra_sensor.ndr.decode import SUPPORTED_LINKTYPES, decode_packet
from sentra_sensor.ndr.flows import FlowTable, ObservationAggregator

logger = logging.getLogger("sentra_sensor.ndr")

# Bytes aproximados en memoria por flujo y por entrada de observación (medido con
# sys.getsizeof sobre los objetos reales en CPython 3.13; orientativo, no un límite duro).
FLOW_MEMORY_BYTES = 900
OBSERVATION_MEMORY_BYTES = 420
RETRY_MIN_SECONDS = 15.0
RETRY_MAX_SECONDS = 300.0
MIN_PPS_BUDGET = 100
# Margen para la cabecera del sobre (ids, ventana, estadísticas) al partir por bytes.
ENVELOPE_OVERHEAD_BYTES = 8192

BackendFactory = Callable[[NdrInterface, NdrServerConfig], CaptureBackend]
Emit = Callable[[str, dict[str, Any]], None]


def utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat()


@dataclass
class CaptureCounters:
    packets_seen: int = 0
    packets_processed: int = 0
    bytes_seen: int = 0
    malformed: int = 0
    truncated: int = 0
    unsupported: int = 0
    budget_dropped: int = 0
    export_failures: int = 0

    def delta(self, previous: "CaptureCounters") -> dict[str, int]:
        return {
            name: getattr(self, name) - getattr(previous, name)
            for name in self.__dataclass_fields__
        }

    def copy(self) -> "CaptureCounters":
        return CaptureCounters(**self.__dict__)


@dataclass
class InterfaceStatus:
    name: str
    state: str = "starting"
    error_code: str | None = None
    error_detail: str | None = None
    backend: str | None = None
    linktype: int | None = None
    last_packet_at: float | None = None
    last_export_at: float | None = None
    cpu_percent: float | None = None
    pps_budget: int = 0
    degraded_reasons: list[str] = field(default_factory=list)


class TokenBucket:
    def __init__(self, rate: float, clock: Callable[[], float]) -> None:
        self.rate = rate
        self._clock = clock
        self._tokens = rate
        self._last = clock()

    def take(self) -> bool:
        now = self._clock()
        self._tokens = min(self.rate, self._tokens + (now - self._last) * self.rate)
        self._last = now
        if self._tokens >= 1:
            self._tokens -= 1
            return True
        return False


class InterfaceCapture:
    """Captura de una interfaz aprobada. `run_once` se usa en tests sin hilos."""

    def __init__(
        self,
        interface: NdrInterface,
        config: NdrServerConfig,
        backend_factory: BackendFactory,
        emit: Emit,
        clock: Callable[[], float] = time.time,
        thread_clock: Callable[[], float] = time.thread_time,
    ) -> None:
        self.interface = interface
        self.config = config
        self._factory = backend_factory
        self._emit = emit
        self._clock = clock
        self._thread_clock = thread_clock
        self.status = InterfaceStatus(name=interface.name, pps_budget=config.max_packets_per_second)
        self.counters = CaptureCounters()
        self._exported = CaptureCounters()
        self._drops_exported = DropCounters()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._backend: CaptureBackend | None = None
        self._flows = FlowTable(
            config.max_flows,
            config.flow_idle_timeout_seconds,
            config.flow_active_timeout_seconds,
        )
        self._observations = ObservationAggregator(
            config.arp_metadata, config.dns_metadata, config.dhcp_metadata, config.tls_metadata
        )
        self._bucket = TokenBucket(config.max_packets_per_second, time.monotonic)
        self._window_start = clock()
        self._window_thread_time = thread_clock()
        self._retry_delay = RETRY_MIN_SECONDS
        self._rng = random.Random()  # noqa: S311  (jitter, no criptografía)
        self._capture_clock: float | None = None

    # --- ciclo de vida -------------------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"ndr-{self.interface.name}", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._finish()

    def _open(self) -> bool:
        try:
            backend = self._factory(self.interface, self.config)
            backend.open()
        except CaptureError as exc:
            self.status.state = "error"
            self.status.error_code = exc.code
            self.status.error_detail = exc.detail
            logger.warning(
                "ndr capture could not start",
                extra={"interface": self.interface.name, "code": exc.code, "detail": exc.detail},
            )
            return False
        if backend.linktype not in SUPPORTED_LINKTYPES:
            backend.close()
            self.status.state = "error"
            self.status.error_code = "unsupported_link_type"
            self.status.error_detail = f"link type {backend.linktype}"
            return False
        self._backend = backend
        self.status.backend = backend.name
        self.status.linktype = backend.linktype
        self.status.state = "running"
        self.status.error_code = None
        self.status.error_detail = None
        self._retry_delay = RETRY_MIN_SECONDS
        logger.info(
            "ndr capture started",
            extra={"interface": self.interface.name, "backend": backend.name},
        )
        return True

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._backend is None and not self._open():
                # Espera creciente con jitter: un Npcap ausente no debe reintentarse en bucle.
                delay = self._retry_delay * (0.8 + 0.4 * self._rng.random())
                self._retry_delay = min(RETRY_MAX_SECONDS, self._retry_delay * 2)
                self._stop.wait(delay)
                continue
            try:
                self.run_once(timeout=0.5)
            except CaptureError as exc:
                self.status.state = "error"
                self.status.error_code = exc.code
                self.status.error_detail = exc.detail
                logger.warning(
                    "ndr capture failed, reopening",
                    extra={"interface": self.interface.name, "code": exc.code},
                )
                self._close_backend()
            except Exception:
                # Un fallo inesperado del pipeline no tumba el sensor: se registra y se
                # reabre la captura con espera.
                logger.exception("ndr pipeline error", extra={"interface": self.interface.name})
                self.status.state = "error"
                self.status.error_code = "pipeline_error"
                self._close_backend()
                self._stop.wait(RETRY_MIN_SECONDS)

    def _close_backend(self) -> None:
        if self._backend is not None:
            # Cerrar es best-effort: un backend roto no debe impedir reabrir la captura.
            with contextlib.suppress(Exception):
                self._backend.close()
        self._backend = None

    def _finish(self) -> None:
        # Al parar se exporta lo pendiente: lo ya observado no se pierde con un reinicio.
        try:
            self._export(final=True)
        finally:
            self._close_backend()

    # --- procesamiento -------------------------------------------------------------------

    def process_frames(self, frames: list[Any], linktype: int) -> None:
        for frame in frames:
            self.counters.packets_seen += 1
            self.counters.bytes_seen += frame.wire_length
            if not self._bucket.take():
                self.counters.budget_dropped += 1
                continue
            packet = decode_packet(frame.data, frame.timestamp, frame.wire_length, linktype)
            self.counters.packets_processed += 1
            self._capture_clock = frame.timestamp
            self.status.last_packet_at = frame.timestamp
            if packet.malformed:
                self.counters.malformed += 1
                continue
            if packet.truncated:
                self.counters.truncated += 1
            if packet.unsupported and packet.arp is None and packet.src_ip is None:
                self.counters.unsupported += 1
                continue
            self._flows.add(packet)
            self._observations.add(packet)

    def run_once(self, timeout: float) -> None:
        backend = self._backend
        if backend is None:
            if not self._open():
                return
            backend = self._backend
            assert backend is not None  # noqa: S101
        frames = backend.read(timeout)
        self.process_frames(frames, backend.linktype)
        if self._clock() - self._window_start >= self.config.export_interval_seconds:
            self._export(final=False)

    def _now_for_flows(self) -> float:
        # Las caducidades se miden con la hora de la captura (la de los paquetes); sin
        # tráfico, con el reloj, para que los flujos inactivos salgan igualmente.
        wall = self._clock()
        if self._capture_clock is None:
            return wall
        return max(self._capture_clock, wall)

    def _export(self, final: bool) -> None:
        now = self._clock()
        flows = self._flows.drain() if final else self._flows.expire(self._now_for_flows())
        observations = self._observations.collect()
        thread_time = self._thread_clock()
        wall = max(0.001, now - self._window_start)
        cpu = max(0.0, (thread_time - self._window_thread_time) / wall * 100)
        self._adapt_budget(cpu)
        drops = self._backend.drops() if self._backend is not None else self._drops_exported
        stats = {
            **self.counters.delta(self._exported),
            "kernel_dropped": max(0, drops.kernel - self._drops_exported.kernel),
            "interface_dropped": max(0, drops.interface - self._drops_exported.interface),
            "flows_active": len(self._flows),
            "flows_evicted": self._flows.stats.flows_evicted,
            "flows_exported": len(flows),
            "unattributed_fragments": self._flows.stats.unattributed_fragments,
            "observations_overflow": self._observations.stats.overflow,
            "cpu_percent": round(cpu, 1),
            "pps_budget": self.status.pps_budget,
            "est_memory_kb": int(
                (
                    len(self._flows) * FLOW_MEMORY_BYTES
                    + sum(len(v) for v in observations.values()) * OBSERVATION_MEMORY_BYTES
                )
                / 1024
            ),
            "capture_state": self.status.state,
            "degraded_reasons": list(self.status.degraded_reasons),
        }
        self._flows.stats.flows_evicted = 0
        self._flows.stats.unattributed_fragments = 0
        self._observations.stats.overflow = 0
        batch = {
            "interface": self.interface.name,
            "config_revision": self.config.revision,
            "window_start": utc_iso(self._window_start),
            "window_end": utc_iso(now),
            "backend": self.status.backend,
            "flows": flows,
            **observations,
            "stats": stats,
        }
        self._exported = self.counters.copy()
        self._drops_exported = drops
        self._window_start = now
        self._window_thread_time = thread_time
        self.status.cpu_percent = round(cpu, 1)
        self.status.last_export_at = now
        try:
            self._emit(self.interface.name, batch)
        except Exception:
            self.counters.export_failures += 1
            logger.exception(
                "ndr batch could not be queued", extra={"interface": self.interface.name}
            )

    def _adapt_budget(self, cpu: float) -> None:
        maximum = self.config.max_packets_per_second
        reasons = [r for r in self.status.degraded_reasons if r != "cpu_budget"]
        if cpu > self.config.max_cpu_percent:
            self.status.pps_budget = max(MIN_PPS_BUDGET, self.status.pps_budget // 2)
            reasons.append("cpu_budget")
        elif cpu < self.config.max_cpu_percent / 2 and self.status.pps_budget < maximum:
            self.status.pps_budget = min(maximum, int(self.status.pps_budget * 1.5) + 1)
            if self.status.pps_budget < maximum:
                reasons.append("cpu_budget")
        self._bucket.rate = self.status.pps_budget
        if self.counters.budget_dropped > self._exported.budget_dropped:
            reasons.append("packet_budget")
        self.status.degraded_reasons = sorted(set(reasons))
        if self.status.state in ("running", "degraded"):
            self.status.state = "degraded" if self.status.degraded_reasons else "running"


def split_batch(
    batch: dict[str, Any], max_records: int, max_bytes: int | None = None
) -> list[dict[str, Any]]:
    """Parte un lote en sobres de como mucho `max_records` registros y ~`max_bytes` de JSON.

    Las estadísticas de la ventana viajan solo en el primer sobre (no se suman dos veces). El
    tope de bytes evita el 413 del límite de cuerpo del servidor, que haría descartar el lote:
    se mide cada registro serializado y se deja un margen para la cabecera del sobre.
    """
    kinds = ("flows", "arp", "dns", "dhcp", "tls")
    records = [(kind, item) for kind in kinds for item in batch.get(kind, [])]
    if not records:
        return [{**batch, "part": 0, "parts": 1}]
    budget = None if max_bytes is None else max(4096, max_bytes - ENVELOPE_OVERHEAD_BYTES)
    chunks: list[list[tuple[str, Any]]] = [[]]
    size = 0
    for record in records:
        length = len(json.dumps(record[1], separators=(",", ":"))) + 1
        current = chunks[-1]
        if current and (
            len(current) >= max_records or (budget is not None and size + length > budget)
        ):
            chunks.append([])
            current = chunks[-1]
            size = 0
        current.append(record)
        size += length
    result: list[dict[str, Any]] = []
    for index, chunk in enumerate(chunks):
        envelope = {k: v for k, v in batch.items() if k not in kinds}
        for kind in kinds:
            envelope[kind] = [item for k, item in chunk if k == kind]
        if index:
            envelope["stats"] = None
        envelope["part"] = index
        envelope["parts"] = len(chunks)
        result.append(envelope)
    return result


class NdrManager:
    """Arranca, reconfigura y para las capturas según la config local y la del servidor."""

    def __init__(
        self,
        local: NdrLocalConfig,
        enqueue: Callable[[str, dict[str, Any]], None],
        backend_factory: BackendFactory | None = None,
        threaded: bool = True,
    ) -> None:
        self.local = local
        self._enqueue = enqueue
        self._factory = backend_factory or self._default_factory
        self._threaded = threaded
        self.server: NdrServerConfig | None = None
        self.captures: dict[str, InterfaceCapture] = {}
        self.unknown_interfaces: list[str] = []
        self._lock = threading.Lock()

    def _default_factory(self, interface: NdrInterface, config: NdrServerConfig) -> CaptureBackend:
        return make_backend(
            self.local.backend, interface.device, config.snaplen, config.promiscuous
        )

    def _emit(self, name: str, batch: dict[str, Any]) -> None:
        config = self.server
        max_records = config.max_records_per_batch if config else 2000
        max_bytes = config.max_batch_bytes if config else None
        # batch_id se genera UNA vez aquí y viaja guardado en el spool: los reintentos lo
        # reenvían idéntico y el servidor deduplica.
        batch_group = str(uuid.uuid4())
        for envelope in split_batch(batch, max_records, max_bytes):
            envelope["batch_id"] = str(uuid.uuid5(uuid.UUID(batch_group), str(envelope["part"])))
            self._enqueue(name, envelope)

    def apply(self, server: NdrServerConfig | None) -> None:
        """Aplica la configuración recibida en el heartbeat (idempotente por revisión)."""
        with self._lock:
            if not self.local.enabled or server is None or not server.enabled:
                self._stop_all()
                self.server = server
                return
            if (
                self.server is not None
                and self.server.revision == server.revision
                and self.captures
            ):
                return
            self._stop_all()
            self.server = server
            self.unknown_interfaces = []
            for name in server.interfaces:
                interface = self.local.interface(name)
                if interface is None:
                    # El servidor aprobó un alias que este host no declaró: no se captura nada
                    # (el operador del host manda sobre qué dispositivos se abren).
                    self.unknown_interfaces.append(name)
                    continue
                capture = InterfaceCapture(interface, server, self._factory, self._emit)
                self.captures[name] = capture
                if self._threaded:
                    capture.start()
            logger.info(
                "ndr configuration applied",
                extra={
                    "revision": server.revision,
                    "interfaces": sorted(self.captures),
                    "unknown": self.unknown_interfaces,
                },
            )

    def _stop_all(self) -> None:
        for capture in self.captures.values():
            capture.stop()
        self.captures = {}

    def stop(self) -> None:
        with self._lock:
            self._stop_all()

    def health(self) -> dict[str, Any]:
        """Estado para el heartbeat: solo claves conocidas, nunca nombres de dispositivo."""
        if not self.local.enabled:
            state = "disabled"
        elif self.server is None or not self.server.enabled:
            state = "not_configured"
        elif not self.captures:
            state = "error"
        else:
            states = {c.status.state for c in self.captures.values()}
            if "error" in states:
                state = "error" if states == {"error"} else "degraded"
            elif "degraded" in states:
                state = "degraded"
            elif states == {"running"}:
                state = "running"
            else:
                state = "starting"
        interfaces = []
        for name, capture in sorted(self.captures.items()):
            status = capture.status
            counters = capture.counters
            interfaces.append(
                {
                    "name": name,
                    "state": status.state,
                    "error_code": status.error_code,
                    "backend": status.backend,
                    "packets_seen": counters.packets_seen,
                    "packets_processed": counters.packets_processed,
                    "budget_dropped": counters.budget_dropped,
                    "malformed": counters.malformed,
                    "cpu_percent": status.cpu_percent,
                    "pps_budget": status.pps_budget,
                    "last_packet_at": utc_iso(status.last_packet_at)
                    if status.last_packet_at
                    else None,
                    "last_export_at": utc_iso(status.last_export_at)
                    if status.last_export_at
                    else None,
                    "degraded_reasons": status.degraded_reasons,
                }
            )
        for name in self.unknown_interfaces:
            interfaces.append(
                {"name": name, "state": "error", "error_code": "interface_not_declared"}
            )
        return {
            "state": state,
            "config_revision": self.server.revision if self.server else None,
            "interfaces": interfaces,
        }
