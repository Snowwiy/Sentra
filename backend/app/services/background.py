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
from app.models.discovery import DiscoveryTrigger
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
