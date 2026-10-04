"""Enrollment with a one-time token (recommended) instead of the shared key (legacy)."""

import logging
from pathlib import Path
from typing import Any

import pytest

from sentra_agent.__main__ import main
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


def _enroll_cli(url: str, state_dir: Path, token_file: Path | None = None) -> int:
    extra = ["--enrollment-token-file", str(token_file)] if token_file else []
    return main(["--api-url", url, "--state-dir", str(state_dir), "--enroll", *extra])


def _write_token(path: Path, token: str) -> Path:
    path.write_text(token + "\n", encoding="utf-8")
    return path


@pytest.fixture
def no_env_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTRA_AGENT_ENROLLMENT_KEY", raising=False)
    monkeypatch.delenv("SENTRA_AGENT_ENROLLMENT_TOKEN", raising=False)


@pytest.mark.usefixtures("no_env_credentials")
def test_new_token_reenrolls_an_agent_whose_own_token_is_dead(
    fake_api: tuple[str, FakeApiState], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Revoked then reinstated (or server reset): the installer run with a new one-time
    token must enroll again as the same agent instead of saying "already enrolled"."""
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    assert _enroll_cli(url, tmp_path, _write_token(tmp_path / "t1", TOKEN)) == 0
    agent_id, asset_id = next(iter(state.agents.items()))
    state.tokens.pop(agent_id)  # the server no longer accepts the stored token
    second = "sentra_et_" + "R" * 43
    state.enrollment_tokens.add(second)
    capsys.readouterr()

    token_file = _write_token(tmp_path / "t2", second)
    assert _enroll_cli(url, tmp_path, token_file) == 0

    assert capsys.readouterr().out.startswith("enrolled:")
    assert list(state.agents.items()) == [(agent_id, asset_id)]  # same agent, same asset
    assert second not in state.enrollment_tokens and not token_file.exists()


@pytest.mark.usefixtures("no_env_credentials")
def test_new_token_is_not_spent_when_the_own_token_still_works(
    fake_api: tuple[str, FakeApiState], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    assert _enroll_cli(url, tmp_path, _write_token(tmp_path / "t1", TOKEN)) == 0
    second = "sentra_et_" + "S" * 43
    state.enrollment_tokens.add(second)
    capsys.readouterr()
    before = state.paths().count("/agents/register")

    assert _enroll_cli(url, tmp_path, _write_token(tmp_path / "t2", second)) == 0

    assert capsys.readouterr().out.startswith("already enrolled:")
    assert state.paths()[-1] == "/agents/heartbeat"  # checked, not enrolled again
    assert state.paths().count("/agents/register") == before
    assert second in state.enrollment_tokens  # still usable elsewhere (or revocable)


@pytest.mark.usefixtures("no_env_credentials")
def test_new_token_cannot_bring_back_a_revoked_agent(
    fake_api: tuple[str, FakeApiState], tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    assert _enroll_cli(url, tmp_path, _write_token(tmp_path / "t1", TOKEN)) == 0
    agent_id = next(iter(state.agents))
    state.tokens.pop(agent_id)
    state.revoked.add(agent_id)
    second = "sentra_et_" + "T" * 43
    state.enrollment_tokens.add(second)

    assert _enroll_cli(url, tmp_path, _write_token(tmp_path / "t2", second)) == 4  # rejected
