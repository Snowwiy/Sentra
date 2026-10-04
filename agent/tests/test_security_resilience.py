"""Credential protection, revocation, throttling, persistent buffering and log redaction."""

import base64
import json
import logging
import sys
import threading
import uuid
from pathlib import Path
from typing import Any

import pytest

from sentra_agent.buffer import BUFFER_FILE, SampleBuffer
from sentra_agent.client import ApiError, SentraClient, TransportError, _retry_after
from sentra_agent.credentials import (
    SCHEME_DPAPI,
    CredentialError,
    protect_token,
    unprotect_token,
)
from sentra_agent.identity import Identity, IdentityStore
from sentra_agent.logs import JsonFormatter, redact, register_secret
from sentra_agent.runner import CredentialsRejectedError
from tests.conftest import FakeApiState
from tests.test_runner import build_agent, sample

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")


# --- Token at rest -----------------------------------------------------------------------


@windows_only
def test_token_is_encrypted_with_dpapi_and_round_trips() -> None:
    token = "tok_" + uuid.uuid4().hex * 2

    stored = protect_token(token)

    assert stored["scheme"] == SCHEME_DPAPI
    assert token not in stored["value"]
    assert token.encode() not in base64.b64decode(stored["value"])
    assert unprotect_token(stored) == token


@windows_only
def test_tampered_dpapi_blob_is_rejected() -> None:
    stored = protect_token("secret-token-value-123456")
    blob = bytearray(base64.b64decode(stored["value"]))
    blob[-5] ^= 0xFF

    with pytest.raises(CredentialError):
        unprotect_token({"scheme": SCHEME_DPAPI, "value": base64.b64encode(blob).decode()})


@pytest.mark.parametrize(
    "stored",
    [None, "x", {"scheme": "rot13", "value": "x"}, {"scheme": SCHEME_DPAPI, "value": "%%"}],
)
def test_malformed_stored_token_is_rejected(stored: Any) -> None:
    with pytest.raises(CredentialError):
        unprotect_token(stored)


def test_identity_file_never_contains_the_plain_token(tmp_path: Path) -> None:
    store = IdentityStore(tmp_path)
    identity = store.load_or_create()
    identity.token = "plain-secret-token-" + uuid.uuid4().hex

    store.save(identity)
    reloaded = IdentityStore(tmp_path).load_or_create()

    if sys.platform == "win32":
        assert identity.token not in store.path.read_text()
    assert reloaded.token == identity.token
    assert reloaded.agent_id == identity.agent_id
    assert "plain-secret" not in repr(reloaded)


def test_legacy_plaintext_identity_is_migrated(tmp_path: Path) -> None:
    agent_id, token = uuid.uuid4(), "legacy-token-" + uuid.uuid4().hex
    (tmp_path / "identity.json").write_text(
        json.dumps({"agent_id": str(agent_id), "asset_id": None, "token": token})
    )

    identity = IdentityStore(tmp_path).load_or_create()

    assert identity.agent_id == agent_id
    assert identity.token == token
    data = json.loads((tmp_path / "identity.json").read_text())
    assert data["version"] == 2
    assert isinstance(data["token"], dict)
    if sys.platform == "win32":
        assert token not in (tmp_path / "identity.json").read_text()


def test_undecryptable_token_keeps_identity_and_drops_token(tmp_path: Path) -> None:
    agent_id = uuid.uuid4()
    (tmp_path / "identity.json").write_text(
        json.dumps(
            {
                "version": 2,
                "agent_id": str(agent_id),
                "token": {"scheme": SCHEME_DPAPI, "value": base64.b64encode(b"junk").decode()},
            }
        )
    )

    identity = IdentityStore(tmp_path).load_or_create()

    assert identity.agent_id == agent_id  # same asset on the server after re-enrolling
    assert identity.token is None


def test_corrupt_identity_is_backed_up_and_replaced(tmp_path: Path) -> None:
    (tmp_path / "identity.json").write_text("{not json")

    identity = IdentityStore(tmp_path).load_or_create()

    assert identity.agent_id
    assert len(list(tmp_path.glob("identity.json.corrupt-*"))) == 1


# --- Enrollment, revocation and auth errors ---------------------------------------------


def test_token_sent_as_bearer_and_enrollment_key_only_on_register(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url))

    agent.cycle()

    register_headers, *other = state.headers
    assert "X-Enrollment-Key" in register_headers
    assert "Authorization" not in register_headers
    for headers in other:
        assert headers["Authorization"] == f"Bearer {agent.identity.token}"
        assert "X-Enrollment-Key" not in headers
        assert headers["User-Agent"].startswith("sentra-agent/")


def test_revoked_agent_stops_and_does_not_loop(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url))
    agent.cycle()
    agent_id = str(agent.identity.agent_id)
    state.revoked.add(agent_id)
    state.tokens.pop(agent_id)
    state.requests.clear()

    with pytest.raises(CredentialsRejectedError) as excinfo:
        agent.cycle()

    assert "revoked" in excinfo.value.reason
    # One rejected data call, one refused enrollment, and nothing more.
    assert state.paths() == ["/agents/heartbeat", "/agents/register"]
    assert agent.identity.token is None
    assert len(agent.buffer) == 1  # the sample is kept for when the agent is reinstated


def test_reinstated_agent_recovers_with_same_identity(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url))
    agent.cycle()
    agent_id = str(agent.identity.agent_id)
    asset_id = agent.identity.asset_id
    state.revoked.add(agent_id)
    state.tokens.pop(agent_id)
    with pytest.raises(CredentialsRejectedError):
        agent.cycle()

    state.revoked.clear()
    agent.cycle()

    assert agent.identity.asset_id == asset_id
    assert agent.identity.token == state.tokens[agent_id]
    assert len(state.telemetry) == 3  # both samples taken while revoked were delivered
    assert not agent.buffer


def test_revoked_agent_backs_off_to_maximum_interval(
    fake_api: tuple[str, FakeApiState], make_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, state = fake_api
    config = make_config(url, max_backoff_seconds=300)
    agent = build_agent(config)
    state.revoked.add(str(agent.identity.agent_id))
    waits: list[float] = []

    def fake_wait(timeout: float) -> bool:
        waits.append(timeout)
        agent.stop_event.set()
        return True

    monkeypatch.setattr(agent.stop_event, "wait", fake_wait)
    agent.run()

    assert len(waits) == 1
    assert 240 <= waits[0] <= 360


def test_wrong_enrollment_key_raises_credentials_rejected(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, _ = fake_api
    agent = build_agent(make_config(url, enrollment_key="wrong-key-wrong-key-wrong"))

    with pytest.raises(CredentialsRejectedError) as excinfo:
        agent.cycle()

    assert excinfo.value.status == 401


# --- Transport policy -----------------------------------------------------------------


def test_throttling_is_retryable_and_honors_retry_after(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    state.throttle_retry_after = "120"
    client = SentraClient(url, timeout=2)

    with pytest.raises(TransportError) as excinfo:
        client.heartbeat(uuid.uuid4(), "token")

    assert excinfo.value.retry_after == 120


@pytest.mark.parametrize(
    ("value", "expected"), [(None, None), ("5", 5.0), ("-3", 0.0), ("99999", 3600.0), ("x", None)]
)
def test_retry_after_parsing_is_clamped(value: str | None, expected: float | None) -> None:
    assert _retry_after(value) == expected


def test_timeout_on_hung_server_is_a_transport_error() -> None:
    import socket

    # A listening socket that accepts but never answers: urlopen must give up on its own.
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        client = SentraClient(f"http://127.0.0.1:{server.getsockname()[1]}", timeout=0.5)
        with pytest.raises(TransportError):
            client.heartbeat(uuid.uuid4(), "token")
    finally:
        server.close()


def test_api_error_exposes_error_code() -> None:
    error = ApiError(403, {"error": {"code": "agent_revoked", "message": "x"}})

    assert error.code == "agent_revoked"
    assert ApiError(400, {}).code is None


# --- Persistent buffer ----------------------------------------------------------------


def test_buffer_survives_agent_restart_during_outage(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    config = make_config(url)
    cpus = iter([1.0, 2.0, 3.0])
    first = build_agent(config, metrics=lambda: sample(next(cpus)))
    first.cycle()  # enroll while the API is up
    state.unavailable = True
    first.run(once=True)
    first.run(once=True)
    assert (config.state_dir / BUFFER_FILE).exists()

    state.unavailable = False
    restarted = build_agent(config, metrics=lambda: sample(next(cpus, 9.0)))
    assert len(restarted.buffer) == 2
    restarted.run(once=True)

    assert [t["cpu_percent"] for t in state.telemetry] == [1.0, 2.0, 3.0, 9.0]
    assert not (config.state_dir / BUFFER_FILE).exists()


def test_persisted_buffer_respects_its_cap(tmp_path: Path) -> None:
    path = tmp_path / BUFFER_FILE
    big = SampleBuffer(10, path)
    for index in range(10):
        big.append({"n": index})
    big.persist()

    small = SampleBuffer(3, path)

    assert [item["n"] for item in small] == [7, 8, 9]


def test_corrupt_buffer_file_is_discarded(tmp_path: Path) -> None:
    (tmp_path / BUFFER_FILE).write_text("[{broken")

    assert len(SampleBuffer(5, tmp_path / BUFFER_FILE)) == 0


# --- Inventory compatibility -----------------------------------------------------------


def test_inventory_sections_unknown_to_server_are_dropped_not_lost(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    state.unknown_sections = {"disks", "connections"}
    agent = build_agent(make_config(url))
    agent.inventory = lambda: {
        "collected_at": sample()["timestamp"],
        "software": [{"name": "App"}],
        "disks": [{"device": "C:\\"}],
        "connections": [],
    }

    agent.cycle()
    agent._inventory_sent_at = None
    agent.cycle()

    assert len(state.inventory) == 2
    assert all("disks" not in snap and snap["software"] for snap in state.inventory)
    # Second time the agent already knows: no extra rejected request.
    assert state.paths().count("/inventory") == 3


# --- Logs -------------------------------------------------------------------------------


def test_secrets_and_bearer_headers_are_redacted_from_logs() -> None:
    secret = "super-secret-token-" + uuid.uuid4().hex
    register_secret(secret)
    record = logging.LogRecord(
        "sentra_agent", logging.ERROR, __file__, 1, "failed with %s", (secret,), None
    )
    record.header = "Authorization: Bearer abc.DEF-123"

    line = JsonFormatter().format(record)

    assert secret not in line
    assert "abc.DEF-123" not in line
    assert "[REDACTED]" in line
    assert redact("nothing here") == "nothing here"


def test_token_never_written_to_log_file(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    from sentra_agent.logs import configure_logging

    url, state = fake_api
    config = make_config(url, log_level="DEBUG")
    log_file = configure_logging(config.state_dir, "DEBUG")
    try:
        agent = build_agent(config)
        agent.cycle()
        state.tokens.pop(str(agent.identity.agent_id))
        agent.cycle()  # 401 + re-enrollment path logs too
        logging.getLogger("sentra_agent").error("oops %s", agent.identity.token)
    finally:
        for handler in logging.getLogger().handlers:
            handler.flush()
    text = log_file.read_text(encoding="utf-8")
    for token in state.tokens.values():
        assert token not in text
    assert "[REDACTED]" in text
    logging.getLogger().handlers.clear()


def test_stop_event_interrupts_the_wait_promptly(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, _ = fake_api
    agent = build_agent(make_config(url, interval_seconds=3600, max_backoff_seconds=3600))
    thread = threading.Thread(target=agent.run)
    thread.start()
    agent.stop_event.set()
    thread.join(timeout=10)

    assert not thread.is_alive()


def test_identity_repr_hides_token() -> None:
    identity = Identity(agent_id=uuid.uuid4(), token="do-not-print-me-123456")

    assert "do-not-print-me" not in repr(identity)


# --- Idempotent telemetry and size limits ---------------------------------------------


def test_lost_response_does_not_duplicate_the_sample(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url))
    agent.cycle()
    state.lose_next_response = True

    with pytest.raises(TransportError):
        agent.cycle()  # stored server side, but the agent saw a dropped connection
    assert len(agent.buffer) == 1
    agent.cycle()

    ids = [t["sample_id"] for t in state.telemetry]
    assert len(ids) == len(set(ids)) == 3
    assert not agent.buffer


def test_sample_id_is_kept_through_the_disk_buffer(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    config = make_config(url)
    first = build_agent(config)
    first.cycle()
    state.unavailable = True
    first.run(once=True)
    pending_id = first.buffer.peek()["sample_id"]

    state.unavailable = False
    restarted = build_agent(config)
    assert restarted.buffer.peek()["sample_id"] == pending_id
    restarted.cycle()

    assert pending_id in [t["sample_id"] for t in state.telemetry]


def test_legacy_spool_samples_get_an_id(tmp_path: Path) -> None:
    (tmp_path / BUFFER_FILE).write_text(json.dumps([{"cpu_percent": 1}]))

    buffer = SampleBuffer(5, tmp_path / BUFFER_FILE)

    uuid.UUID(buffer.peek()["sample_id"])


def test_oversized_payload_is_not_retried_in_a_loop(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url))
    agent.cycle()
    state.max_body = 2000  # small telemetry fits, the big inventory below does not
    agent.inventory = lambda: {
        "collected_at": sample()["timestamp"],
        "software": [{"name": "x" * 500}] * 20,
    }
    agent._inventory_sent_at = None
    state.requests.clear()

    agent.cycle()
    agent.cycle()

    assert state.paths().count("/inventory") == 1  # rejected once, next try at next interval
    assert len(state.telemetry) == 3
