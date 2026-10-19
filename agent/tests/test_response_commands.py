"""Fase 5D: comandos de Response en el agente (allowlist, reentregas, servidor anterior)."""

import uuid
from typing import Any

import pytest

from sentra_agent.commands import (
    COMMAND_TYPES,
    MAX_UNSENT,
    REMEMBERED_RESULTS,
    CommandMemory,
    CommandRejectedError,
    capabilities,
    parse_command,
)
from tests.conftest import FakeApiState
from tests.test_runner import build_agent


def _enrolled(url: str, state: FakeApiState, make_config: Any) -> tuple[Any, str]:
    agent = build_agent(make_config(url))
    agent.cycle()
    return agent, str(agent.identity.agent_id)


def _queue(state: FakeApiState, agent_id: str, kind: str, **extra: Any) -> str:
    request_id = str(uuid.uuid4())
    command = {"request_id": request_id, "type": kind, "params": {}, **extra}
    state.commands.setdefault(agent_id, []).append(command)
    return request_id


def test_no_poll_unless_heartbeat_announces_commands(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent, _ = _enrolled(url, state, make_config)
    agent.cycle()
    assert "/agents/commands/poll" not in state.paths()


def test_allowlisted_command_runs_and_reports_result(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent, agent_id = _enrolled(url, state, make_config)
    inventories = len(state.inventory)
    request_id = _queue(state, agent_id, "collect_inventory")

    agent.cycle()

    assert "/agents/commands/poll" in state.paths()
    assert len(state.inventory) == inventories + 1  # recolección real, no un éxito inventado
    [(rid, body)] = state.command_results
    assert rid == request_id
    assert body["status"] == "succeeded"
    assert body["agent_id"] == agent_id


def test_diagnostics_never_carry_secrets(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent, agent_id = _enrolled(url, state, make_config)
    _queue(state, agent_id, "collect_diagnostics")
    agent.cycle()
    [(_, body)] = state.command_results
    text = str(body).lower()
    assert body["status"] == "succeeded"
    assert state.tokens[agent_id] not in str(body)
    for word in ("token", "enrollment", "password", "secret"):
        assert word not in text


@pytest.mark.parametrize(
    ("command", "code"),
    [
        ({"type": "run_shell", "params": {}}, "unknown_command"),
        ({"type": "powershell", "params": {"cmd": "whoami"}}, "unknown_command"),
        ({"type": "collect_inventory", "params": {"path": "C:/"}}, "invalid_params"),
        ({"type": None}, "unknown_command"),
    ],
)
def test_unknown_or_parameterised_commands_are_rejected_without_running(
    fake_api: tuple[str, FakeApiState], make_config: Any, command: dict[str, Any], code: str
) -> None:
    url, state = fake_api
    agent, agent_id = _enrolled(url, state, make_config)
    inventories = len(state.inventory)
    request_id = str(uuid.uuid4())
    state.commands[agent_id] = [{"request_id": request_id, **command}]

    agent.cycle()

    [(rid, body)] = state.command_results
    assert rid == request_id
    assert body["status"] == "rejected"
    assert body["error_code"] == code
    assert len(state.inventory) == inventories


def test_malformed_request_id_is_ignored(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent, agent_id = _enrolled(url, state, make_config)
    state.commands[agent_id] = [{"request_id": "../../admin", "type": "collect_inventory"}]
    agent.cycle()
    assert state.command_results == []


def test_redelivered_command_reuses_the_stored_result(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent, agent_id = _enrolled(url, state, make_config)
    request_id = _queue(state, agent_id, "collect_processes")
    agent.cycle()
    snapshots = len(state.processes)
    # El servidor no recibió la respuesta y lo reentrega con el mismo request_id.
    state.commands[agent_id] = [{"request_id": request_id, "type": "collect_processes"}]

    agent.cycle()

    assert len(state.processes) == snapshots  # no se recolecta otra vez
    assert [rid for rid, _ in state.command_results] == [request_id, request_id]
    assert state.command_results[0][1] == state.command_results[1][1]


def test_older_server_without_command_endpoint_is_not_asked_again(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent, agent_id = _enrolled(url, state, make_config)
    # El heartbeat anuncia comandos pero /agents/commands/poll responde 404.
    _queue(state, agent_id, "collect_inventory")
    state.commands_endpoint = False
    agent.cycle()
    agent.cycle()
    assert state.paths().count("/agents/commands/poll") == 1


def test_capabilities_are_declared_to_the_server(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    _enrolled(url, state, make_config)
    register = state.requests[0][1]
    assert set(register["capabilities"]) <= COMMAND_TYPES
    assert "collect_inventory" in register["capabilities"]


def test_capabilities_by_platform() -> None:
    assert "collect_events" in capabilities("win32")
    assert "collect_events" in capabilities("linux")
    # Fase 6C.5: macOS tiene una fuente real (Unified Logging); un sistema sin fuente no.
    assert "collect_events" in capabilities("darwin")
    assert "collect_events" not in capabilities("freebsd14")


def test_parse_command_accepts_only_the_allowlist() -> None:
    rid = uuid.uuid4()
    assert parse_command({"request_id": str(rid), "type": "collect_events"}) == (
        rid,
        "collect_events",
    )
    with pytest.raises(CommandRejectedError):
        parse_command({"request_id": str(rid), "type": "exec", "params": {}})
    with pytest.raises(ValueError):
        parse_command({"request_id": "x", "type": "collect_events"})


def test_command_memory_is_bounded() -> None:
    memory = CommandMemory()
    for _ in range(REMEMBERED_RESULTS + 10):
        memory.remember(uuid.uuid4(), {"status": "succeeded"})
    for _ in range(MAX_UNSENT + 10):
        memory.queue_unsent(uuid.uuid4(), {"status": "succeeded"})
    assert len(memory.done) == REMEMBERED_RESULTS
    assert len(memory.unsent) == MAX_UNSENT
