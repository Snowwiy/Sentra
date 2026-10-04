"""Enrollment with a one-time token (recommended) instead of the shared key (legacy)."""

import logging
from pathlib import Path
from typing import Any

import pytest

from sentra_agent.config import load_config
from tests.conftest import FakeApiState
from tests.test_runner import build_agent

TOKEN = "sentra_et_" + "Q" * 43


def test_one_time_token_enrolls_and_is_never_sent_again(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    token_file = tmp_path / "enroll.token"
    token_file.write_text(TOKEN + "\n", encoding="utf-8")
    agent = build_agent(make_config(url, enrollment_key=None, enrollment_token_file=token_file))

    agent.cycle()
    agent.cycle()

    assert agent.identity.token == state.tokens[str(agent.identity.agent_id)]
    assert not token_file.exists()  # deleted once enrolled
    assert state.paths().count("/agents/register") == 1
    register, *others = state.headers
    assert register.get("X-Enrollment-Token") == TOKEN and "X-Enrollment-Key" not in register
    for headers in others:  # heartbeat, telemetry...: only the agent's own token
        assert TOKEN not in str(headers)
        assert headers["Authorization"] == f"Bearer {agent.identity.token}"
    assert agent.config.enrollment_token is None


def test_token_from_environment_is_preferred_over_the_shared_key(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    agent = build_agent(make_config(url, enrollment_token=TOKEN))  # key also configured

    agent.cycle()

    assert state.headers[0].get("X-Enrollment-Token") == TOKEN
    assert "X-Enrollment-Key" not in state.headers[0]
    assert agent.config.enrollment_token is None  # forgotten after use


def test_rejected_token_is_forgotten_and_the_legacy_key_is_the_fallback(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api  # the token is unknown to the server (expired, used...)
    token_file = tmp_path / "enroll.token"
    token_file.write_text(TOKEN, encoding="utf-8")
    agent = build_agent(make_config(url, enrollment_token_file=token_file))

    agent.run(once=True)  # refused: logged, no crash
    assert agent.identity.token is None and not token_file.exists()
    agent.cycle()  # next attempt uses the shared key that is also configured

    assert agent.identity.token is not None
    assert [h.get("X-Enrollment-Token") for h in state.headers[:2]] == [TOKEN, None]
    assert state.headers[1].get("X-Enrollment-Key")


def test_rejected_token_without_key_stops_asking(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url, enrollment_key=None, enrollment_token=TOKEN))

    agent.run(once=True)
    agent.run(once=True)  # nothing left to try: no request at all

    assert state.paths() == ["/agents/register"]
    assert agent.identity.token is None


def test_token_never_reaches_the_logs(
    fake_api: tuple[str, FakeApiState], make_config: Any, caplog: pytest.LogCaptureFixture
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    caplog.set_level(logging.DEBUG, logger="sentra_agent")
    agent = build_agent(make_config(url, enrollment_key=None, enrollment_token=TOKEN))

    agent.cycle()

    assert "agent enrolled" in caplog.text
    assert TOKEN not in caplog.text
    assert TOKEN not in repr(agent.config)


def test_config_reads_token_settings_from_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SENTRA_AGENT_ENROLLMENT_TOKEN", f"  {TOKEN}  ")
    monkeypatch.setenv("SENTRA_AGENT_ENROLLMENT_TOKEN_FILE", str(tmp_path / "t"))
    config = load_config()

    assert config.enrollment_token == TOKEN
    assert config.enrollment_token_file == tmp_path / "t"
