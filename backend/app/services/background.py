"""Periodic in-process jobs.

A daemon thread is enough for the MVP (one API process). With several workers each runs its own
sweeper; that is safe because alert creation is deduplicated by a unique index, only wasteful.
A dedicated scheduler/worker process is the step up when that matters.
"""

import logging
import threading
from collections.abc import Callable

from app.core.config import get_settings
from app.db.session import get_sessionmaker
from app.services.alert_service import AlertService, AlertThresholds

logger = logging.getLogger(__name__)


class PeriodicJob:
    def __init__(self, name: str, interval_seconds: float, job: Callable[[], None]) -> None:
        self._name = name
        self._interval = interval_seconds
        self._job = job
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name=name, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=self._interval + 5)

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._job()
            except Exception:
                # A failing run (e.g. database briefly down) must not kill the thread;
                # the next run retries.
                logger.exception("background job failed", extra={"job": self._name})


def sweep_offline_assets() -> None:
    thresholds = AlertThresholds.from_settings(get_settings())
    with get_sessionmaker()() as session:
        opened = AlertService(session, thresholds).sweep_offline()
    if opened:
        logger.info("offline alerts opened", extra={"count": opened})
