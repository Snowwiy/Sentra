from datetime import UTC, datetime
from typing import Any

import pytest

from sentra_agent.client import TransportError
from sentra_agent.collectors import HostInfo
from sentra_agent.runner import Agent, backoff_delay
from tests.conftest import FakeApiState, make_client, make_store

HOST = HostInfo("PC-TEST", "Windows", "11", "AMD64", "192.168.1.20", "0.1.0")


def sample(cpu: float = 10.0) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "cpu_percent": cpu,
        "ram_percent": 50.0,
        "disk_percent": 40.0,
        "uptime_seconds": 100,
    }


def snapshot() -> dict[str, Any]:
    return {"collected_at": datetime.now(UTC).isoformat(), "software": [{"name": "App"}]}


class FakeEvents:
    """In-memory stand-in for the Windows Event Log reader (which needs real logs)."""

    def __init__(self) -> None:
        self.queue: list[dict[str, Any]] = []
        self.committed: dict[str, int] = {}

    def pending(self) -> tuple[list[dict[str, Any]], dict[str, int]]:
        new = [e for e in self.queue if e["record_id"] > self.committed.get("System", 0)]
        cursor = {"System": new[-1]["record_id"]} if new else dict(self.committed)
        return new, cursor

    def commit(self, cursor: dict[str, int]) -> None:
        self.committed = cursor


def build_agent(config: Any, metrics: Any = sample, events: Any = None) -> Agent:
    return Agent(
        config,
        make_client(config),
        make_store(config),
        host_info=lambda: HOST,
        metrics=metrics,
        inventory=snapshot,
        events=events or FakeEvents(),
    )


def test_first_cycle_registers_and_reports(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url))

    agent.cycle()

    assert state.paths() == ["/agents/register", "/agents/heartbeat", "/telemetry", "/inventory"]
    # No events queued: nothing to send, so no /events request.
    assert state.requests[0][1]["hostname"] == "PC-TEST"
    assert len(state.telemetry) == 1
    assert str(agent.identity.asset_id) == state.agents[str(agent.identity.agent_id)]
    assert not agent.buffer


def test_restart_reuses_identity_without_registering_again(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    config = make_config(url)
    first = build_agent(config)
    first.cycle()

    second = build_agent(config)
    second.cycle()

    assert second.identity.agent_id == first.identity.agent_id
    assert state.paths().count("/agents/register") == 1
    assert len(state.agents) == 1


def test_samples_are_buffered_during_outage_and_flushed_in_order(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    cpus = iter([1.0, 2.0, 3.0])
    agent = build_agent(make_config(url), metrics=lambda: sample(next(cpus)))
    state.unavailable = True

    for _ in range(2):
        with pytest.raises(TransportError):
            agent.cycle()
    assert len(agent.buffer) == 2

    state.unavailable = False
    agent.cycle()

    assert [t["cpu_percent"] for t in state.telemetry] == [1.0, 2.0, 3.0]
    assert not agent.buffer


def test_buffer_drops_oldest_samples_when_full(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    cpus = iter(range(10))
    agent = build_agent(make_config(url, buffer_size=3), metrics=lambda: sample(next(cpus)))
    state.unavailable = True
    for _ in range(5):
        with pytest.raises(TransportError):
            agent.cycle()

    state.unavailable = False
    agent.cycle()

    assert [t["cpu_percent"] for t in state.telemetry] == [3, 4, 5]


def test_agent_enrolls_again_when_server_forgets_it(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url))
    agent.cycle()
    agent_id = str(agent.identity.agent_id)
    state.tokens.pop(agent_id)  # e.g. database reset: our token is no longer valid

    agent.cycle()

    assert state.paths().count("/agents/register") == 2
    assert agent.identity.token == state.tokens[agent_id]
    assert len(state.telemetry) == 2


def test_token_survives_restart(fake_api: tuple[str, FakeApiState], make_config: Any) -> None:
    url, state = fake_api
    config = make_config(url)
    build_agent(config).cycle()

    restarted = build_agent(config)
    restarted.cycle()

    assert state.paths().count("/agents/register") == 1
    assert restarted.identity.token == state.tokens[str(restarted.identity.agent_id)]


def test_without_enrollment_key_agent_does_not_contact_api(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url, enrollment_key=None))

    agent.run(once=True)  # logs the configuration problem instead of crashing

    assert state.requests == []
    assert agent.identity.token is None


def test_wrong_enrollment_key_is_reported_not_crashing(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url, enrollment_key="wrong-key-wrong-key-wrong"))

    agent.run(once=True)

    assert state.paths() == ["/agents/register"]
    assert agent.identity.token is None


def test_rejected_sample_does_not_block_newer_ones(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    cpus = iter([500.0, 20.0])
    agent = build_agent(make_config(url), metrics=lambda: sample(next(cpus)))
    state.unavailable = True
    with pytest.raises(TransportError):
        agent.cycle()

    state.unavailable = False
    agent.cycle()

    assert [t["cpu_percent"] for t in state.telemetry] == [20.0]
    assert not agent.buffer


def test_unreachable_api_raises_transport_error(make_config: Any) -> None:
    # Port 1 on localhost refuses connections immediately.
    agent = build_agent(make_config("http://127.0.0.1:1"))

    with pytest.raises(TransportError):
        agent.cycle()
    assert len(agent.buffer) == 1


def test_run_once_survives_outage(fake_api: tuple[str, FakeApiState], make_config: Any) -> None:
    url, state = fake_api
    state.unavailable = True
    agent = build_agent(make_config(url))

    agent.run(once=True)  # must log and return, not raise

    assert len(agent.buffer) == 1


@pytest.mark.parametrize(
    ("failures", "low", "high"), [(1, 24, 36), (2, 48, 72), (3, 96, 144), (10, 240, 360)]
)
def test_backoff_doubles_with_jitter_and_caps(failures: int, low: float, high: float) -> None:
    for _ in range(50):
        assert low <= backoff_delay(failures, interval=30, maximum=300) <= high


def test_heartbeat_carries_current_host_info(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url))

    agent.cycle()

    heartbeat = next(body for path, body in state.requests if path == "/agents/heartbeat")
    assert heartbeat["host"]["primary_ip"] == "192.168.1.20"
    assert heartbeat["host"]["hostname"] == "PC-TEST"


def test_inventory_is_sent_once_per_interval(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url))

    for _ in range(3):
        agent.cycle()

    assert len(state.inventory) == 1
    assert len(state.telemetry) == 3


def test_events_are_sent_once_and_cursor_advances_only_after_acceptance(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    events = FakeEvents()
    events.queue = [{"record_id": 1, "message": "a"}, {"record_id": 2, "message": "b"}]
    agent = build_agent(make_config(url), events=events)
    agent.cycle()
    assert [e["record_id"] for e in state.events] == [1, 2]
    assert events.committed == {"System": 2}

    events.queue.append({"record_id": 3, "message": "c"})
    state.unavailable = True
    agent._events_sent_at = None  # force the next cycle to send events
    with pytest.raises(TransportError):
        agent.cycle()
    assert events.committed == {"System": 2}  # not advanced: record 3 will be re-read

    state.unavailable = False
    agent._events_sent_at = None
    agent.cycle()
    assert [e["record_id"] for e in state.events] == [1, 2, 3]
