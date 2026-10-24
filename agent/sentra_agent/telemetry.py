"""Servicio de telemetría avanzada del agente (Fase 6E.3).

Orquesta los colectores de actividad con su propio ritmo, independiente del ciclo principal
(heartbeat cada 30 s): procesos cada `process_poll_seconds`, Sysmon cada pocos segundos,
servicios y tareas cada pocos minutos, protección y firewall cada cinco. Todo lo que generan
va a la `ActivityQueue` persistente; el ciclo principal la vacía hacia POST /agents/activity.

En ejecución normal corre en un hilo propio (`start`); en `--once` y en los tests se llama a
`tick()` directamente, con relojes inyectados (sin esperas reales).
"""

import logging
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

import psutil

from sentra_agent.activity import (
    ACTIVE,
    DISABLED,
    UNAVAILABLE,
    ActivityQueue,
    iso,
    make_event,
    read_boot_id,
)
from sentra_agent.config import TelemetrySettings
from sentra_agent.endpoint import (
    read_firewall,
    read_persistence,
    read_protection,
    read_scheduled_tasks,
    read_services,
)
from sentra_agent.pollers import DiffPoller, StatePoller
from sentra_agent.sysmon import SysmonReader
from sentra_agent.tracker import ActivityTracker, HashCache

logger = logging.getLogger("sentra_agent")

COLLECTORS = (
    "process",
    "network",
    "service",
    "scheduled_task",
    "persistence",
    "protection",
    "firewall",
    "sysmon",
    "dns",
)


class Poller(Protocol):
    status: str

    def poll(self, now: float) -> list[dict[str, Any]]: ...


def default_pollers(
    settings: TelemetrySettings, state_dir: Path, platform: str
) -> dict[str, tuple[Poller, int]]:
    policy = settings.cmdline
    return {
        "service": (
            DiffPoller(
                "service",
                "service_poll",
                lambda: read_services(platform),
                state_dir / "baseline_service.json",
            ),
            settings.services_poll_seconds,
        ),
        "scheduled_task": (
            DiffPoller(
                "scheduled_task",
                "task_poll",
                lambda: read_scheduled_tasks(platform, cmdline_policy=policy),
                state_dir / "baseline_scheduled_task.json",
            ),
            settings.services_poll_seconds,
        ),
        "persistence": (
            DiffPoller(
                "persistence",
                "persistence_poll",
                lambda: read_persistence(platform, policy),
                state_dir / "baseline_persistence.json",
            ),
            settings.persistence_poll_seconds,
        ),
        "protection": (
            StatePoller("protection", "protection_poll", lambda: read_protection(platform)),
            settings.state_poll_seconds,
        ),
        "firewall": (
            StatePoller("firewall", "firewall_poll", lambda: read_firewall(platform)),
            settings.state_poll_seconds,
        ),
    }


class TelemetryService:
    def __init__(
        self,
        settings: TelemetrySettings,
        state_dir: Path,
        platform: str | None = None,
        *,
        tracker: ActivityTracker | None = None,
        pollers: dict[str, tuple[Poller, int]] | None = None,
        sysmon: SysmonReader | None = None,
        boot_id: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        health: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self.settings = settings
        self.platform = platform or sys.platform
        self.queue = ActivityQueue(settings.activity_queue_max_events, state_dir)
        self.boot_id = boot_id or read_boot_id()
        hashes = (
            HashCache(settings.hash_max_mb * 1024 * 1024) if settings.hash_executables else None
        )
        self.tracker = tracker or ActivityTracker(
            self.boot_id,
            cmdline_policy=settings.cmdline,
            network=settings.network_enabled,
            hashes=hashes,
        )
        self.pollers = (
            pollers if pollers is not None else default_pollers(settings, state_dir, self.platform)
        )
        if sysmon is None and self.platform == "win32":
            sysmon = SysmonReader(
                state_dir,
                self.boot_id,
                settings.cmdline,
                parent_key=self.tracker.key_for,
                enabled=settings.sysmon_enabled,
            )
        self.sysmon = sysmon
        self._clock = clock
        self._wall = wall
        self._health = health or _self_health
        self._next: dict[str, float] = {}
        # True tras un 404 de /agents/activity: no tiene sentido seguir llenando la cola.
        self.paused = False
        self._thread: threading.Thread | None = None

    # Ritmo -------------------------------------------------------------------------------

    def _intervals(self) -> dict[str, int]:
        intervals = {"process": self.settings.process_poll_seconds}
        intervals.update({name: interval for name, (_, interval) in self.pollers.items()})
        if self.sysmon is not None:
            intervals["sysmon"] = self.settings.sysmon_poll_seconds
        intervals["agent_health"] = self.settings.health_seconds
        return intervals

    def tick(self) -> int:
        """Ejecuta los colectores a los que les toca; devuelve cuántos eventos encoló."""
        if self.paused:
            return 0
        now = self._clock()
        wall = self._wall()
        events: list[dict[str, Any]] = []
        for name, interval in self._intervals().items():
            if now < self._next.get(name, 0.0):
                continue
            self._next[name] = now + interval
            try:
                events.extend(self._run(name, wall))
            except Exception:
                # Un colector roto nunca tumba a los demás ni al agente.
                logger.exception("telemetry collector failed", extra={"collector": name})
        if events:
            self.queue.extend(events)
        return len(events)

    def _run(self, name: str, wall: float) -> list[dict[str, Any]]:
        if name == "process":
            return self.tracker.poll()
        if name == "sysmon" and self.sysmon is not None:
            found = self.sysmon.poll()
            for event in found:
                if event.get("instance_key"):
                    self.tracker.mark_reported(event["instance_key"])
            return found
        if name == "agent_health":
            data = self._health()
            data["queued"] = len(self.queue)
            data["dropped_total"] = self.queue.dropped_total
            return [make_event("agent_health", "state", "agent", data, iso(wall))]
        poller, _ = self.pollers[name]
        return poller.poll(wall)

    def seconds_to_next(self) -> float:
        if not self._next:
            return 0.0
        return max(0.0, min(self._next.values()) - self._clock())

    def start(self, stop_event: threading.Event) -> None:
        """Hilo propio: el sondeo de 5 s no puede depender del ciclo de 30 s del agente."""
        if self._thread is not None:
            return

        def loop() -> None:
            while not stop_event.is_set():
                self.tick()
                self.queue.persist()
                stop_event.wait(min(max(self.seconds_to_next(), 0.5), 5.0))

        self._thread = threading.Thread(target=loop, name="sentra-telemetry", daemon=True)
        self._thread.start()

    @property
    def threaded(self) -> bool:
        return self._thread is not None

    # Estado ------------------------------------------------------------------------------

    def collectors(self) -> dict[str, str]:
        if self.paused:
            return dict.fromkeys(COLLECTORS, DISABLED)
        status = {
            "process": self.tracker.stats.process_status,
            "network": self.tracker.stats.network_status,
        }
        for name in ("service", "scheduled_task", "persistence", "protection", "firewall"):
            poller = self.pollers.get(name)
            status[name] = poller[0].status if poller else UNAVAILABLE
        status["sysmon"] = self.sysmon.status if self.sysmon is not None else UNAVAILABLE
        # DNS por proceso no tiene fuente sin privilegios en 6E (ver docs).
        status["dns"] = UNAVAILABLE
        return status

    def stats(self) -> dict[str, Any]:
        return {
            "queued": len(self.queue),
            "dropped_total": self.queue.dropped_total,
            "dropped_since_last": self.queue.dropped_since_last,
            "oldest_queued_at": self.queue.oldest_occurred_at(),
            "process_poll_seconds": self.settings.process_poll_seconds,
            "collectors": self.collectors(),
        }

    def heartbeat(self) -> dict[str, Any]:
        return {
            "queued": len(self.queue),
            "dropped_total": self.queue.dropped_total,
            "collectors": self.collectors(),
        }

    def capability_flags(self) -> dict[str, bool]:
        collectors = self.collectors()
        return {
            "process_tree": collectors["process"] == ACTIVE,
            "process_network": collectors["network"] == ACTIVE,
            "sysmon": collectors["sysmon"] == ACTIVE,
        }

    def diagnostics(self) -> dict[str, Any]:
        stats = self.tracker.stats
        return {
            "collectors": self.collectors(),
            "queued": len(self.queue),
            "dropped_total": self.queue.dropped_total,
            "tracker": {
                "passes": stats.passes,
                "processes": stats.processes,
                "last_pass_ms": stats.last_pass_ms,
                "max_pass_ms": stats.max_pass_ms,
            },
            "cmdline_policy": self.settings.cmdline,
            "hash_executables": self.settings.hash_executables,
        }


_SELF: psutil.Process | None = None


def _self_health() -> dict[str, Any]:
    """CPU y memoria del propio agente (su coste real, para el panel y el diagnóstico)."""
    # Un único Process para que cpu_percent mida el intervalo entre llamadas.
    global _SELF
    try:
        if _SELF is None:
            _SELF = psutil.Process()
            _SELF.cpu_percent(None)
        return {
            "cpu_percent": round(_SELF.cpu_percent(None), 2),
            "rss_bytes": int(_SELF.memory_info().rss),
        }
    except (psutil.Error, OSError):
        return {"cpu_percent": None, "rss_bytes": None}
