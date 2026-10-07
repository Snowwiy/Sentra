"""Fase 5C.1: integración del colector Linux en el runner e identidad del equipo."""

import hashlib
import hmac
from pathlib import Path
from typing import Any

import pytest

from sentra_agent import machine_identity
from sentra_agent.collectors import HostInfo
from sentra_agent.runner import EVENTS_PER_REQUEST, Agent, CredentialsRejectedError
from tests.conftest import FakeApiState, make_client, make_store
from tests.test_runner import HOST, processes, sample, snapshot


class CoverageEvents:
    """Fuente de eventos con cobertura, como LinuxJournalCollector."""

    def __init__(self) -> None:
        self.queue: list[dict[str, Any]] = []
        self.state: dict[str, str] = {"journal": "active", "sshd": "active"}
        self.committed: Any = None
        self.broken = False

    def pending(self) -> tuple[list[dict[str, Any]], Any]:
        if self.broken:
            raise RuntimeError("journal roto")
        return list(self.queue), {"n": len(self.queue)}

    def commit(self, cursor: Any) -> None:
        self.committed = cursor
        self.queue = []

    def coverage(self) -> dict[str, str]:
        return dict(self.state)


def linux_event(i: int) -> dict[str, Any]:
    return {
        "source": "linux_journal",
        "channel": "journal",
        "record_id": i,
        "event_type": "auth_failure",
        "provider": "sshd",
        "level": "warning",
        "message": "Failed password",
        "occurred_at": "2026-10-07T10:00:00+00:00",
    }


def build(config: Any, events: Any) -> Agent:
    return Agent(
        config,
        make_client(config),
        make_store(config),
        host_info=lambda: HOST,
        metrics=sample,
        inventory=snapshot,
        events=events,
        processes=processes,
    )


def test_coverage_is_sent_once_and_again_on_change(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    events = CoverageEvents()
    agent = build(make_config(url), events)
    agent.cycle()
    assert state.coverage == [{"journal": "active", "sshd": "active"}]

    agent._events_sent_at = None
    agent.cycle()  # sin cambios ni eventos: no hay petición
    assert state.paths().count("/events") == 1

    events.state["sshd"] = "no_permission"
    agent._events_sent_at = None
    agent.cycle()
    assert state.coverage[-1]["sshd"] == "no_permission"


def test_large_reads_are_split_in_server_sized_batches(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    events = CoverageEvents()
    events.queue = [linux_event(i) for i in range(EVENTS_PER_REQUEST + 120)]
    agent = build(make_config(url), events)
    agent.cycle()
    bodies = [body for path, body in state.requests if path == "/events"]
    assert [len(b["events"]) for b in bodies] == [EVENTS_PER_REQUEST, 120]
    assert "coverage" in bodies[0] and "coverage" not in bodies[1]
    assert len(state.events) == EVENTS_PER_REQUEST + 120
    assert events.committed == {"n": EVENTS_PER_REQUEST + 120}


def test_broken_event_collector_never_stops_heartbeat_or_telemetry(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    events = CoverageEvents()
    events.broken = True
    agent = build(make_config(url), events)
    agent.cycle()
    assert "/agents/heartbeat" in state.paths() and len(state.telemetry) == 1
    assert "/events" not in state.paths()


def test_older_server_without_coverage_still_gets_events(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    state.accepts_coverage = False
    events = CoverageEvents()
    events.queue = [linux_event(1)]
    agent = build(make_config(url), events)
    agent.cycle()
    assert [e["record_id"] for e in state.events] == [1]
    # Sin eventos, un servidor sin cobertura no recibe lotes vacíos.
    agent._events_sent_at = None
    events.state["sshd"] = "error"
    requests = len(state.requests)
    agent.cycle()
    assert "/events" not in state.paths()[requests:]


def test_archived_asset_refuses_enrollment_with_clear_reason(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build(make_config(url), CoverageEvents())
    state.archived.add(str(agent.identity.agent_id))
    with pytest.raises(CredentialsRejectedError, match="archived"):
        agent.cycle()


def test_default_event_source_follows_platform(tmp_path: Path) -> None:
    import sys

    from sentra_agent import runner
    from sentra_agent.events import EventCollector
    from sentra_agent.linux_events import LinuxJournalCollector

    source = runner.default_event_source(tmp_path)
    expected = LinuxJournalCollector if sys.platform.startswith("linux") else EventCollector
    assert isinstance(source, expected)


# --- Identidad del equipo ------------------------------------------------------------------


def test_machine_id_is_hashed_per_application_and_never_raw(tmp_path: Path) -> None:
    raw = "0123456789abcdef0123456789abcdef"
    path = tmp_path / "machine-id"
    path.write_text(raw + "\n")
    derived = machine_identity.derive(machine_identity._linux_raw((path,)) or "")
    assert derived == hmac.new(raw.encode(), machine_identity.APP_ID, hashlib.sha256).hexdigest()
    assert derived is not None and raw not in derived and len(derived) == 64


@pytest.mark.parametrize(
    "raw", ["", "uninitialized", "0" * 32, "not-an-id", "../../etc/passwd", "ab" * 40]
)
def test_unusable_machine_ids_are_rejected(raw: str) -> None:
    assert machine_identity.derive(raw) is None


def test_windows_guid_is_accepted() -> None:
    assert machine_identity.derive("6F9619FF-8B86-D011-B42D-00C04FC964FF") is not None


def test_missing_machine_id_file(tmp_path: Path) -> None:
    assert machine_identity._linux_raw((tmp_path / "nope",)) is None


def test_host_payload_omits_missing_machine_id() -> None:
    assert "machine_id_hash" not in HOST.as_payload()
    with_id = HostInfo("h", "Linux", "6", "x86_64", "10.0.0.2", "0.2.1", "a" * 64)
    assert with_id.as_payload()["machine_id_hash"] == "a" * 64
