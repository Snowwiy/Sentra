"""Fase 6E.3: servicio de telemetría, envío a /agents/activity y heartbeat ampliado."""

import gzip
from pathlib import Path
from typing import Any

import pytest

from sentra_agent.activity import ACTIVE, PERMISSION_DENIED, UNAVAILABLE
from sentra_agent.client import GZIP_THRESHOLD
from sentra_agent.config import TelemetrySettings
from sentra_agent.runner import Agent
from sentra_agent.telemetry import COLLECTORS, TelemetryService
from sentra_agent.tracker import ActivityTracker
from tests.conftest import FakeApiState, make_client, make_store
from tests.test_runner import HOST, FakeEvents, processes, sample, snapshot
from tests.test_tracker import FakeSource


class FakePoller:
    def __init__(self, status: str = ACTIVE, events: int = 0) -> None:
        self.status = status
        self.events = events
        self.calls = 0

    def poll(self, now: float) -> list[dict[str, Any]]:
        from sentra_agent.activity import make_event

        self.calls += 1
        return [
            make_event(
                "service", "created", "service_poll", {"name": f"s{i}"}, "2026-10-22T10:00:00+00:00"
            )
            for i in range(self.events)
        ]


def service(
    state_dir: Path,
    source: FakeSource | None = None,
    clock: list[float] | None = None,
    pollers: dict[str, tuple[Any, int]] | None = None,
    **settings: Any,
) -> TelemetryService:
    clock = clock if clock is not None else [0.0]
    source = source or FakeSource()
    tracker = ActivityTracker("boot-t", source, wall=lambda: 1_000.0 + clock[0])
    return TelemetryService(
        TelemetrySettings(**settings),
        state_dir,
        "linux",
        tracker=tracker,
        pollers=pollers if pollers is not None else {},
        boot_id="boot-t",
        clock=lambda: clock[0],
        wall=lambda: 1_000.0 + clock[0],
        health=lambda: {"cpu_percent": 0.5, "rss_bytes": 1234},
    )


def agent_with(config: Any, telemetry: TelemetryService | None) -> Agent:
    return Agent(
        config,
        make_client(config),
        make_store(config),
        host_info=lambda: HOST,
        metrics=sample,
        inventory=snapshot,
        events=FakeEvents(),
        processes=processes,
        telemetry=telemetry,
    )


def test_tick_respects_each_collector_interval(tmp_path: Path) -> None:
    clock = [0.0]
    source = FakeSource()
    source.add(1, 0, 10.0)
    slow = FakePoller(events=1)
    telemetry = service(tmp_path, source, clock, {"service": (slow, 120)})

    first = telemetry.tick()
    assert first == 3  # proceso preexistente + servicio + agent_health
    clock[0] = 5.0
    source.add(2, 1, 1_004.0)
    assert telemetry.tick() == 1  # solo procesos: el servicio espera sus 120 s
    clock[0] = 121.0
    telemetry.tick()
    assert slow.calls == 2
    categories = [e["category"] for e in telemetry.queue.peek(100)]
    assert categories.count("agent_health") == 1
    health = next(e for e in telemetry.queue.peek(100) if e["category"] == "agent_health")
    assert health["data"]["rss_bytes"] == 1234 and health["source"] == "agent"


def test_collectors_report_real_states(tmp_path: Path) -> None:
    telemetry = service(
        tmp_path,
        pollers={
            "service": (FakePoller(), 60),
            "protection": (FakePoller(status=PERMISSION_DENIED), 300),
        },
    )
    collectors = telemetry.collectors()
    assert set(collectors) == set(COLLECTORS)
    assert collectors["protection"] == PERMISSION_DENIED
    assert collectors["scheduled_task"] == UNAVAILABLE  # sin colector en esta plataforma
    assert collectors["sysmon"] == UNAVAILABLE and collectors["dns"] == UNAVAILABLE
    assert telemetry.capability_flags() == {
        "process_tree": True,
        "process_network": True,
        "sysmon": False,
    }


def test_activity_is_sent_in_batches_and_acknowledged(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    config = make_config(url)
    telemetry = service(config.state_dir)
    agent = agent_with(config, telemetry)
    telemetry.queue.extend(
        [
            {"event_uid": f"00000000-0000-0000-0000-{i:012d}", "category": "process",
             "action": "start", "occurred_at": "2026-10-22T10:00:00+00:00",
             "source": "psutil_poll", "instance_key": None, "data": {"pid": i}}
            for i in range(2500)
        ]
    )  # fmt: skip

    agent.cycle()

    assert "/agents/activity" in state.paths()
    assert [len(body["events"]) for body in state.activity] == [1000, 1000, 500]
    assert len(telemetry.queue) == 0
    body = state.activity[0]
    assert body["boot_id"] == "boot-t" and body["agent_id"] == str(agent.identity.agent_id)
    assert set(body["stats"]) == {
        "queued", "dropped_total", "dropped_since_last", "oldest_queued_at",
        "process_poll_seconds", "collectors",
    }  # fmt: skip
    # Más de 8 KB: el cuerpo viaja comprimido.
    activity_headers = [h for h in state.headers if h.get("Content-Encoding") == "gzip"]
    assert len(activity_headers) == 3


def test_small_batches_are_not_compressed(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    config = make_config(url)
    source = FakeSource()
    source.add(1, 0, 10.0)
    telemetry = service(config.state_dir, source)
    telemetry.tick()
    agent_with(config, telemetry).cycle()
    [body] = state.activity
    assert len(gzip.compress(str(body).encode())) < GZIP_THRESHOLD
    assert all(h.get("Content-Encoding") != "gzip" for h in state.headers)


def test_outage_keeps_events_queued_on_disk(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    config = make_config(url)
    source = FakeSource()
    source.add(1, 0, 10.0)
    telemetry = service(config.state_dir, source)
    agent = agent_with(config, telemetry)
    agent.cycle()  # enrola
    telemetry.tick()
    state.unavailable = True
    agent.run(once=True)  # el error de transporte no pierde la cola
    assert len(telemetry.queue) >= 1

    restarted = service(config.state_dir, FakeSource())
    assert len(restarted.queue) == len(telemetry.queue)
    state.unavailable = False
    agent_with(config, restarted).cycle()
    assert len(restarted.queue) == 0 and state.activity


def test_old_server_404_disables_activity_but_not_the_rest(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    state.activity_endpoint = False
    config = make_config(url)
    source = FakeSource()
    source.add(1, 0, 10.0)
    telemetry = service(config.state_dir, source)
    telemetry.tick()
    agent = agent_with(config, telemetry)
    queued = len(telemetry.queue)

    agent.cycle()
    assert state.paths().count("/agents/activity") == 1
    assert telemetry.paused is True
    assert "telemetry_activity" not in agent._capabilities()
    assert telemetry.tick() == 0  # deja de recolectar

    agent.cycle()
    assert state.paths().count("/agents/activity") == 1  # no se vuelve a intentar
    assert len(state.telemetry) == 2  # telemetría, heartbeat... siguen
    assert len(telemetry.queue) == queued  # lo encolado se conserva para el próximo arranque


def test_413_halves_the_batch(fake_api: tuple[str, FakeApiState], make_config: Any) -> None:
    url, state = fake_api
    config = make_config(url)
    telemetry = service(config.state_dir)
    telemetry.queue.extend(
        [
            {"event_uid": f"10000000-0000-0000-0000-{i:012d}", "category": "process",
             "action": "start", "occurred_at": "2026-10-22T10:00:00+00:00",
             "source": "psutil_poll", "instance_key": None, "data": {"pid": i, "pad": "x" * 200}}
            for i in range(40)
        ]
    )  # fmt: skip
    state.max_activity_body = 3000  # comprimido o no, 40 eventos no caben
    agent = agent_with(config, telemetry)
    # Cada ciclo hace como mucho ACTIVITY_BATCHES_PER_CYCLE intentos: se repite hasta que un
    # lote reducido cabe; el tamaño reducido se conserva entre ciclos.
    for _ in range(4):
        agent.cycle()
        if state.activity:
            break
    assert agent._activity_batch < 40
    assert state.activity and all(len(b["events"]) <= agent._activity_batch for b in state.activity)


def test_heartbeat_carries_telemetry_and_isolation(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    config = make_config(url)
    agent = agent_with(config, service(config.state_dir))
    agent.cycle()
    heartbeat = dict(state.requests)["/agents/heartbeat"]
    assert set(heartbeat["telemetry"]) == {"queued", "dropped_total", "collectors"}
    assert heartbeat["isolation"]["helper"] == "absent"
    assert heartbeat["isolation"]["state"] == "none"
    caps = heartbeat["host"]["capabilities"]
    assert "telemetry_activity" in caps and "telemetry_process_tree" in caps
    assert "isolate_host" not in caps  # sin helper, nunca


def test_older_server_drops_new_heartbeat_fields(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    """Contrato 6E: un servidor 0.2.0 rechaza `telemetry`/`isolation` y el agente los quita."""
    url, state = fake_api
    state.unknown_heartbeat_fields = {"telemetry", "isolation"}
    config = make_config(url)
    agent = agent_with(config, service(config.state_dir))

    agent.cycle()
    agent.cycle()

    heartbeats = [body for path, body in state.requests if path == "/agents/heartbeat"]
    # Primer intento rechazado, reintento sin los campos y el siguiente ciclo ya sin ellos.
    assert "telemetry" in heartbeats[0] and "isolation" in heartbeats[0]
    assert all("telemetry" not in b and "isolation" not in b for b in heartbeats[1:])
    assert len(heartbeats) == 3
    assert len(state.telemetry) == 2


@pytest.mark.host_telemetry
def test_default_telemetry_follows_config(make_config: Any) -> None:
    from sentra_agent.runner import default_telemetry

    config = make_config("http://127.0.0.1:9")
    assert default_telemetry(config) is not None
    from dataclasses import replace

    disabled = replace(config, telemetry=TelemetrySettings(enabled=False))
    assert default_telemetry(disabled) is None
