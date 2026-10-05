"""Periodic in-process jobs.

A daemon thread is enough for the MVP (one API process). With several workers each runs its own
sweeper; that is safe because alert creation is deduplicated by a unique index, only wasteful.
A dedicated scheduler/worker process is the step up when that matters.
"""

import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from app.core.config import get_settings
from app.db.session import get_sessionmaker
from app.detection.config import DetectionConfig
from app.detection.engine import DetectionEngine
from app.models.discovery import DiscoveryTrigger
from app.risk.config import RiskConfig
from app.risk.engine import RiskEngine
from app.services.alert_service import AlertService, AlertThresholds
from app.services.discovery_service import DiscoveryConfig, DiscoveryService
from app.services.retention_service import RetentionPolicy, RetentionService

logger = logging.getLogger(__name__)


class PeriodicJob:
    def __init__(
        self,
        name: str,
        interval_seconds: float,
        job: Callable[[], None],
        stop: threading.Event | None = None,
        first_run_after: float | None = None,
    ) -> None:
        self._name = name
        self._interval = interval_seconds
        # Delay before the first run (default: one interval).
        self._first = interval_seconds if first_run_after is None else first_run_after
        self._job = job
        # Shared with long jobs (discovery) so shutdown interrupts them instead of waiting.
        self._stop = stop or threading.Event()
        self._thread = threading.Thread(target=self._loop, name=name, daemon=True)
        # Solo informativo (estado del scheduler en la web): próxima ejecución prevista y si
        # hay una en curso. La espera se cuenta desde el final de la ejecución anterior.
        self.next_run_at: datetime | None = None
        self.running = False

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=min(self._interval, 30) + 5)

    def _loop(self) -> None:
        delay = self._first
        self.next_run_at = datetime.now(UTC) + timedelta(seconds=delay)
        while not self._stop.wait(delay):
            delay = self._interval
            self.next_run_at = None
            self.running = True
            try:
                self._job()
            except Exception:
                # A failing run (e.g. database briefly down) must not kill the thread;
                # the next run retries.
                logger.exception("background job failed", extra={"job": self._name})
            finally:
                self.running = False
                self.next_run_at = datetime.now(UTC) + timedelta(seconds=delay)


def sweep_offline_assets() -> None:
    """Periodic alert maintenance: offline detection and quiet event-based alerts."""
    thresholds = AlertThresholds.from_settings(get_settings())
    with get_sessionmaker()() as session:
        alerts = AlertService(session, thresholds)
        opened = alerts.sweep_offline()
        resolved = alerts.resolve_quiet_event_alerts()
    if opened:
        logger.info("offline alerts opened", extra={"count": opened})
    if resolved:
        logger.info("quiet event alerts resolved", extra={"count": resolved})


# Purga de señales: como mucho una vez cada SIGNAL_PURGE_EVERY (el job corre cada pocos s).
SIGNAL_PURGE_EVERY = timedelta(minutes=10)
_last_signal_purge: list[datetime] = []


def run_detection_engine() -> None:
    """Fase 4H: evalúa las señales que la ingesta dejó pendientes y purga las caducadas.

    Fuera de las peticiones de agentes: si una regla es lenta o falla, el heartbeat y la
    telemetría siguen igual (ver app/detection/engine.py).
    """
    settings = get_settings()
    config = DetectionConfig.from_settings(settings)
    with get_sessionmaker()() as session:
        engine = DetectionEngine(session, config, AlertThresholds.from_settings(settings))
        engine.process_pending()
        now = datetime.now(UTC)
        if not _last_signal_purge or now - _last_signal_purge[0] >= SIGNAL_PURGE_EVERY:
            _last_signal_purge[:] = [now]
            purged = engine.purge_signals(now)
            if purged:
                logger.info("detection signals purged", extra={"count": purged})


_last_risk_decay: list[datetime] = []


def run_risk_engine() -> None:
    """Fase 4I: crea filas de activos nuevos, procesa la cola de recálculo y aplica el decay.

    Cola (dirty_at) en cada vuelta; decay como mucho cada RISK_DECAY_INTERVAL_MINUTES. Cada
    pasada está acotada (lotes x MAX_BATCHES); lo que no cabe queda para la siguiente. Un
    fallo aquí lo registra PeriodicJob y la API sigue sirviendo el último riesgo guardado.
    """
    settings = get_settings()
    config = RiskConfig.from_settings(settings)
    with get_sessionmaker()() as session:
        engine = RiskEngine(session, config, AlertThresholds.from_settings(settings))
        engine.seed_missing()
        engine.process_dirty()
        now = datetime.now(UTC)
        if not _last_risk_decay or now - _last_risk_decay[0] >= config.decay_interval:
            _last_risk_decay[:] = [now]
            engine.process_decay(now)


def purge_old_data() -> None:
    policy = RetentionPolicy.from_settings(get_settings())
    with get_sessionmaker()() as session:
        result = RetentionService(session, policy).purge()
    if result.total:
        logger.info(
            "old data purged",
            extra={
                "telemetry_samples": result.telemetry_samples,
                "system_events": result.system_events,
                "asset_changes": result.asset_changes,
                "alerts": result.alerts,
                "detections": result.detections,
                "risk_snapshots": result.risk_snapshots,
            },
        )


def discovery_job(stop: threading.Event) -> Callable[[], None]:
    """Periodic discovery over every allowed network; `stop` cancels a run in progress."""

    def run() -> None:
        settings = get_settings()
        service = DiscoveryService(
            get_sessionmaker(),
            DiscoveryConfig.from_settings(settings),
            AlertThresholds.from_settings(settings),
            cancel=stop,
        )
        service.run(trigger=DiscoveryTrigger.SCHEDULED, via="scheduler")

    return run
