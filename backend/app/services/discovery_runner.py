"""Ejecución en segundo plano de los descubrimientos pedidos desde el dashboard.

Por qué existe: un scan puede durar minutos y el navegador no debe mantener una petición
HTTP abierta todo ese tiempo (timeouts de proxy, pestañas cerradas, reintentos que
duplicarían el scan). La API crea el job en cola, responde al momento con su id y este
runner lo ejecuta; el navegador consulta el estado con GET /discovery/jobs/{id}.

Decisiones:
- Un solo hilo de trabajo por proceso: los jobs del dashboard se ejecutan de uno en uno, así
  la carga sobre la red nunca supera la de un scan (DISCOVERY_MAX_PROBES_PER_SECOND). Los
  demás esperan en cola (estado queued) y se ven como tales en la web.
- La red queda reservada desde la cola por el índice único parcial: un segundo "Iniciar"
  sobre la misma red, o el scheduler, recibe "ocupado" en lugar de escanear dos veces.
- Mismo motor y misma capa de servicio que la CLI y el scheduler (DiscoveryService): aquí
  solo se decide cuándo se ejecuta, nunca cómo se escanea ni qué se concluye.
- Sin huérfanos: al apagar la API se cancela el scan en curso (resultado parcial, sin
  inferencias negativas) y los jobs en cola se cierran como cancelados. Si el proceso muere
  sin apagarse, el latido deja de avanzar y expire_stale_jobs los marca como fallidos.
"""

import logging
import queue
import threading
import time
import uuid
from collections.abc import Callable

from app.core.config import get_settings
from app.core.exceptions import ConflictError
from app.db.session import get_sessionmaker
from app.services.alert_service import AlertThresholds
from app.services.discovery_service import DiscoveryConfig, DiscoveryService

logger = logging.getLogger(__name__)

# Jobs en cola por proceso. Las redes autorizadas son pocas; un límite evita que un bucle
# de peticiones acumule trabajo sin fin.
MAX_PENDING = 16
# Latido de los jobs en cola: muy por debajo de JOB_STALE_AFTER.
QUEUE_HEARTBEAT_SECONDS = 30.0


class DiscoveryQueueFullError(ConflictError):
    code = "discovery_queue_full"


class DiscoveryRunner:
    def __init__(self, service_factory: Callable[[threading.Event], DiscoveryService]) -> None:
        # Parada del proceso: compartida con el servicio para que el shutdown interrumpa el
        # scan en curso en lugar de esperar a que termine.
        self._stop = threading.Event()
        self._service = service_factory(self._stop)
        self._queue: queue.Queue[int] = queue.Queue()
        # Jobs de este proceso aún no terminados (en cola o en curso).
        self._pending: list[int] = []
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._keeper: threading.Thread | None = None

    @property
    def service(self) -> DiscoveryService:
        return self._service

    def submit(self, target: str, via: str) -> uuid.UUID:
        """Crea el job en cola y lo programa. Devuelve su public_id.

        Lanza TargetError (fuera de la allowlist), DiscoveryBusyError (red ocupada) o
        DiscoveryQueueFullError.
        """
        if self._stop.is_set():
            raise DiscoveryQueueFullError("Discovery is shutting down")
        with self._lock:
            if len(self._pending) >= MAX_PENDING:
                raise DiscoveryQueueFullError("Too many discovery jobs queued; retry later")
            job_id, public_id = self._service.enqueue(target, via)
            self._pending.append(job_id)
            self._ensure_threads()
        self._queue.put(job_id)
        return public_id

    def stop(self, timeout: float = 30.0) -> None:
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout=timeout)
        with self._lock:
            leftover = list(self._pending)
            self._pending.clear()
        try:
            # El job en curso ya quedó cancelado por la parada; aquí solo quedan los de
            # la cola, que nunca empezaron.
            self._service.abandon(leftover, "server stopped before the job started")
        except Exception:
            logger.warning("could not close queued discovery jobs", exc_info=True)

    def wait_idle(self, timeout: float) -> bool:
        """Espera a que no quede trabajo de este proceso (tests y apagado ordenado)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if not self._pending:
                    return True
            time.sleep(0.02)
        return False

    # --- hilos ------------------------------------------------------------------------------

    def _ensure_threads(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(target=self._work, name="discovery-runner", daemon=True)
            self._worker.start()
        if self._keeper is None or not self._keeper.is_alive():
            self._keeper = threading.Thread(
                target=self._keep_alive, name="discovery-runner-heartbeat", daemon=True
            )
            self._keeper.start()

    def _work(self) -> None:
        while not self._stop.is_set():
            try:
                job_id = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                if not self._stop.is_set():
                    self._service.run_job(job_id)
            except Exception:
                # run_job ya marcó el job como fallido; el hilo sigue con los demás.
                logger.exception("discovery job failed", extra={"job": job_id})
            finally:
                with self._lock:
                    if job_id in self._pending:
                        self._pending.remove(job_id)

    def _keep_alive(self) -> None:
        while not self._stop.wait(QUEUE_HEARTBEAT_SECONDS):
            with self._lock:
                pending = list(self._pending)
            try:
                self._service.touch(pending)
            except Exception:
                logger.warning("discovery queue heartbeat failed", exc_info=True)


def _default_service(stop: threading.Event) -> DiscoveryService:
    settings = get_settings()
    return DiscoveryService(
        get_sessionmaker(),
        DiscoveryConfig.from_settings(settings),
        AlertThresholds.from_settings(settings),
        cancel=stop,
    )


# Uno por proceso de la API: es quien posee el hilo de trabajo y la cola en memoria.
_runner: DiscoveryRunner | None = None
_runner_lock = threading.Lock()


def get_discovery_runner() -> DiscoveryRunner:
    """Dependencia FastAPI; los tests la sustituyen por un runner sobre su base de datos."""
    global _runner
    with _runner_lock:
        if _runner is None:
            _runner = DiscoveryRunner(_default_service)
        return _runner


def stop_discovery_runner() -> None:
    """Llamado al apagar la API (lifespan): cancela el scan en curso y cierra la cola."""
    global _runner
    with _runner_lock:
        runner, _runner = _runner, None
    if runner is not None:
        runner.stop()
