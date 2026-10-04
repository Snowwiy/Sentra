"""One-time agent enrollment tokens: creation, use, rejection, storage and compatibility."""

import hashlib
import logging
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app import cli
from app.core.config import Settings, get_settings
from app.core.exceptions import UnauthorizedError
from app.models.asset import Asset, MonitoringMethod
from app.models.enrollment import AgentEnrollmentToken
from app.models.exposure import AssetPort, PortStateValue
from app.schemas.agent import AgentRegisterRequest
from app.schemas.enrollment import EnrollmentTokenCreate
from app.services.enrollment_token_service import EnrollmentTokenService
from tests.conftest import TEST_ADMIN_KEY, agent_payload

TOKENS = "/api/v1/agent-enrollment-tokens"
REGISTER = "/api/v1/agents/register"
ADMIN = {"X-Admin-Key": TEST_ADMIN_KEY}


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    # `client` for its cleanup: tables are truncated after each test.
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _create(client: TestClient, **body: Any) -> dict[str, Any]:
    response = client.post(TOKENS, json=body, headers=ADMIN)
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def _enroll(client: TestClient, token: str, **host: Any) -> Any:
    return client.post(REGISTER, json=agent_payload(**host), headers={"X-Enrollment-Token": token})


def _state(client: TestClient, token_id: str) -> dict[str, Any]:
    items = client.get(TOKENS, headers=ADMIN).json()["items"]
    found: dict[str, Any] = next(i for i in items if i["token_id"] == token_id)
    return found


def test_token_enrolls_once_and_the_agent_keeps_its_own_token(client: TestClient) -> None:
    created = _create(client)
    token = created["token"]
    assert token.startswith("sentra_et_") and len(token) >= 50
    assert created["max_uses"] == 1 and created["state"] == "active"
    expires = datetime.fromisoformat(created["expires_at"])
    assert timedelta(minutes=14) < expires - datetime.now(UTC) <= timedelta(minutes=15)

    payload = agent_payload()
    response = client.post(REGISTER, json=payload, headers={"X-Enrollment-Token": token})

    assert response.status_code == 201
    agent_token = response.json()["agent_token"]
    assert agent_token and agent_token != token
    heartbeat = client.post(
        "/api/v1/agents/heartbeat",
        json={"agent_id": payload["agent_id"]},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert heartbeat.status_code == 200  # the individual token keeps working
    state = _state(client, created["token_id"])
    assert state["state"] == "consumed" and state["use_count"] == 1
    assert state["last_asset_id"] == response.json()["asset_id"]
    assert state["consumed_at"] is not None

    second = _enroll(client, token)  # another host trying the same token
    assert second.status_code == 401
    assert second.json()["error"]["message"] == "Invalid enrollment token"


def test_only_the_hash_is_stored(client: TestClient, db: Session) -> None:
    created = _create(client, note="Laptop de Ana")
    token = created["token"]

    row = db.scalar(select(AgentEnrollmentToken))
    assert row is not None
    assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
    dump = db.execute(text("SELECT row_to_json(t)::text FROM agent_enrollment_tokens t")).scalar()
    assert dump is not None and token not in dump and token[10:] not in dump
    listing = client.get(TOKENS, headers=ADMIN)
    assert token not in listing.text and "token" not in listing.json()["items"][0]


def test_expired_revoked_and_unknown_tokens_are_rejected_alike(
    client: TestClient, db: Session
) -> None:
    expired = _create(client)
    db.execute(update(AgentEnrollmentToken).values(expires_at=datetime.now(UTC)))
    db.commit()
    revoked = _create(client)
    assert (
        client.post(f"{TOKENS}/{revoked['token_id']}/revoke", headers=ADMIN).json()["state"]
        == "revoked"
    )

    bodies = []
    for token in (
        expired["token"],
        revoked["token"],
        "sentra_et_" + "A" * 43,  # well formed, never issued
        "not-a-sentra-token",
        "sentra_et_" + "x" * 300,  # absurdly long
    ):
        response = _enroll(client, token)
        assert response.status_code == 401, token
        assert token not in response.text
        bodies.append(response.json())
    assert all(body == bodies[0] for body in bodies)  # no hint which check failed

    assert _state(client, expired["token_id"])["state"] == "expired"
    assert _state(client, expired["token_id"])["use_count"] == 0


def test_revocation_rules(client: TestClient) -> None:
    created = _create(client)
    assert _enroll(client, created["token"]).status_code == 201
    used = client.post(f"{TOKENS}/{created['token_id']}/revoke", headers=ADMIN)
    assert used.status_code == 409  # used up: revoke the agent instead
    missing = client.post(f"{TOKENS}/00000000-0000-0000-0000-000000000000/revoke", headers=ADMIN)
    assert missing.status_code == 404


def test_bootstrap_token_is_never_an_agent_credential(client: TestClient) -> None:
    created = _create(client, max_uses=2)
    payload = agent_payload()
    assert (
        client.post(
            REGISTER, json=payload, headers={"X-Enrollment-Token": created["token"]}
        ).status_code
        == 201
    )
    bearer = {"Authorization": f"Bearer {created['token']}"}
    now = datetime.now(UTC).isoformat()
    agent_id = payload["agent_id"]
    calls = {
        "/api/v1/agents/heartbeat": {"agent_id": agent_id},
        "/api/v1/telemetry": {
            "agent_id": agent_id, "timestamp": now, "cpu_percent": 1, "ram_percent": 1,
            "disk_percent": 1, "uptime_seconds": 1,
        },
        "/api/v1/inventory": {"agent_id": agent_id, "collected_at": now},
        "/api/v1/processes": {"agent_id": agent_id, "collected_at": now, "processes": []},
        "/api/v1/events": {"agent_id": agent_id, "events": []},
    }  # fmt: skip
    for path, body in calls.items():
        assert client.post(path, json=body, headers=bearer).status_code in (401, 422), path
    # And sent as an enrollment header elsewhere it is simply ignored (still 401).
    with_header = {"X-Enrollment-Token": created["token"]}
    assert (
        client.post(
            "/api/v1/agents/heartbeat", json={"agent_id": agent_id}, headers=with_header
        ).status_code
        == 401
    )


def test_platform_and_hostname_restrictions(client: TestClient) -> None:
    linux_only = _create(client, expected_platform="linux", expected_hostname="srv-01")
    assert _enroll(client, linux_only["token"], hostname="srv-01").status_code == 401  # Windows
    assert (
        _enroll(client, linux_only["token"], os_name="Linux", hostname="other").status_code == 401
    )
    assert _state(client, linux_only["token_id"])["use_count"] == 0  # failures cost nothing
    assert (
        _enroll(client, linux_only["token"], os_name="Linux", hostname="SRV-01").status_code == 201
    )


def test_multi_use_token_counts_uses(client: TestClient) -> None:
    created = _create(client, max_uses=2)
    assert _enroll(client, created["token"]).status_code == 201
    assert _state(client, created["token_id"])["state"] == "active"
    assert _enroll(client, created["token"]).status_code == 201
    assert _enroll(client, created["token"]).status_code == 401
    assert _state(client, created["token_id"])["state"] == "consumed"


def test_concurrent_use_of_one_token_admits_one_agent(engine: Engine, db: Session) -> None:
    # Two real sessions: the second blocks on the row lock until the first commits, then
    # sees the token used up. No sleeps decide the outcome, only the database lock.
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    created = EnrollmentTokenService(db).create(EnrollmentTokenCreate(), "api")
    host = AgentRegisterRequest.model_validate(agent_payload())
    first = factory()
    outcome: list[str] = []

    def second_attempt() -> None:
        with factory() as session:
            try:
                EnrollmentTokenService(session).lock_for_enrollment(created.token, host)
                outcome.append("admitted")
            except UnauthorizedError:
                outcome.append("rejected")

    thread = threading.Thread(target=second_attempt, daemon=True)
    try:
        row = EnrollmentTokenService(first).lock_for_enrollment(created.token, host)
        thread.start()
        thread.join(timeout=1)
        assert thread.is_alive()  # waiting on the lock held by the first enrollment
        asset = Asset(
            agent_id=host.agent_id, hostname="x", os_name="Windows", os_version="11",
            architecture="x86_64", primary_ip="10.9.9.9", agent_version="0.1.0",
            first_seen_at=datetime.now(UTC),
        )  # fmt: skip
        first.add(asset)
        first.flush()
        EnrollmentTokenService(first).consume(row, asset)
        first.commit()
    finally:
        # Always release the lock, or a failure here would block every later test.
        first.close()
        thread.join(timeout=10)

    assert outcome == ["rejected"]


def test_discovered_host_becomes_managed_with_a_token(client: TestClient, db: Session) -> None:
    discovered_at = datetime.now(UTC) - timedelta(days=3)
    host = Asset(
        monitoring_method=MonitoringMethod.DISCOVERED, primary_ip="192.168.50.66",
        first_seen_at=discovered_at, discovered_at=discovered_at,
        exposure_baseline_at=discovered_at,
    )  # fmt: skip
    db.add(host)
    db.flush()
    db.add(
        AssetPort(
            asset_id=host.id, protocol="tcp", port=22, state=PortStateValue.OPEN,
            first_seen_at=discovered_at, opened_at=discovered_at, last_seen_at=discovered_at,
        )
    )  # fmt: skip
    db.commit()

    created = _create(client)
    response = _enroll(client, created["token"], primary_ip="192.168.50.66", os_name="Linux")

    assert response.status_code == 201
    db.expire_all()
    rows = list(db.scalars(select(Asset)))
    assert len(rows) == 1  # one asset, not two
    [asset] = rows
    assert asset.monitoring_method == MonitoringMethod.AGENT
    assert str(asset.public_id) == response.json()["asset_id"]
    assert asset.discovered_at == discovered_at
    assert [
        p.port for p in db.scalars(select(AssetPort).where(AssetPort.asset_id == asset.id))
    ] == [22]


def test_revoked_agent_does_not_burn_the_token(client: TestClient, db: Session) -> None:
    payload = agent_payload()
    assert client.post(REGISTER, json=payload).status_code == 201  # legacy key
    db.execute(update(Asset).values(agent_token_revoked_at=datetime.now(UTC)))
    db.commit()
    created = _create(client)

    response = client.post(REGISTER, json=payload, headers={"X-Enrollment-Token": created["token"]})

    assert response.status_code == 403 and response.json()["error"]["code"] == "agent_revoked"
    assert _state(client, created["token_id"])["use_count"] == 0


def test_legacy_shared_key_still_works(client: TestClient) -> None:
    response = client.post(REGISTER, json=agent_payload())  # AgentClient adds the key
    assert response.status_code == 201
    # A token header takes precedence: a bad token is not rescued by a good key.
    created = _create(client)
    both = client.post(
        REGISTER,
        json=agent_payload(),
        headers={"X-Enrollment-Token": "sentra_et_wrong", "X-Enrollment-Key": "irrelevant"},
    )
    assert both.status_code == 401
    assert _state(client, created["token_id"])["use_count"] == 0


def test_tokens_work_without_the_shared_key(client: TestClient) -> None:
    created = _create(client)
    settings = get_settings()
    client.app.dependency_overrides[get_settings] = lambda: Settings(  # type: ignore[attr-defined]
        **{**settings.model_dump(), "agent_enrollment_key": None}
    )
    try:
        assert client.post(REGISTER, json=agent_payload()).status_code == 403  # key disabled
        assert _enroll(client, created["token"]).status_code == 201
    finally:
        client.app.dependency_overrides.pop(get_settings)  # type: ignore[attr-defined]


def test_admin_api_requires_its_key_and_fails_closed(client: TestClient) -> None:
    assert client.post(TOKENS, json={}).status_code == 401
    assert client.post(TOKENS, json={}, headers={"X-Admin-Key": "wrong"}).status_code == 401
    assert client.get(TOKENS, headers={"X-Admin-Key": "x" * 1000}).status_code == 401
    settings = get_settings()
    client.app.dependency_overrides[get_settings] = lambda: Settings(  # type: ignore[attr-defined]
        **{**settings.model_dump(), "admin_api_key": None}
    )
    try:
        disabled = client.post(TOKENS, json={}, headers=ADMIN)
        assert disabled.status_code == 403
        assert "ADMIN_API_KEY" in disabled.json()["error"]["message"]
    finally:
        client.app.dependency_overrides.pop(get_settings)  # type: ignore[attr-defined]
    for bad in ({"ttl_minutes": 0}, {"ttl_minutes": 1441}, {"max_uses": 0},
                {"expected_platform": "macos"}, {"token": "chosen"}):  # fmt: skip
        assert client.post(TOKENS, json=bad, headers=ADMIN).status_code == 422, bad


def test_tokens_never_reach_the_logs(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    created = _create(client)
    token = created["token"]
    _enroll(client, token)
    _enroll(client, token)  # rejected: logged with a reason, without the token

    records = " ".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)
    assert "enrollment token used" in records and "enrollment token rejected" in records
    assert token not in records and token[10:] not in records


def test_cli_creates_lists_and_revokes(
    engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "get_sessionmaker", lambda: sessionmaker(bind=engine))
    assert cli.main(["create-enrollment-token", "--platform", "linux", "--note", "srv"]) == 0
    out = capsys.readouterr().out
    token = next(line.split()[1] for line in out.splitlines() if line.startswith("token:"))
    token_id = next(line.split()[2] for line in out.splitlines() if line.startswith("token id:"))
    assert token.startswith("sentra_et_")

    assert cli.main(["list-enrollment-tokens"]) == 0
    listing = capsys.readouterr().out
    assert token_id in listing and "active" in listing and token not in listing
    assert cli.main(["revoke-enrollment-token", token_id]) == 0
    assert "revoked" in capsys.readouterr().out
    assert cli.main(["create-enrollment-token", "--ttl-minutes", "0"]) == 2
