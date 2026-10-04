from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app import cli
from app.core.config import get_settings
from app.services.agent_service import reinstate_agent, revoke_agent
from tests.conftest import agent_payload

AGENT_ENDPOINTS = ["/api/v1/agents/heartbeat", "/api/v1/telemetry", "/api/v1/inventory"]


def body_for(path: str, agent_id: str) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    if path.endswith("/telemetry"):
        return {
            "agent_id": agent_id,
            "timestamp": now,
            "cpu_percent": 1,
            "ram_percent": 1,
            "disk_percent": 1,
            "uptime_seconds": 1,
        }
    if path.endswith("/inventory"):
        return {"agent_id": agent_id, "collected_at": now}
    return {"agent_id": agent_id}


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Enrollment-Key": "wrong-key-wrong-key-wrong-key"},
        {"X-Enrollment-Key": ""},
        {},
    ],
)
def test_registration_requires_valid_enrollment_key(
    client: TestClient, headers: dict[str, str]
) -> None:
    response = client.post("/api/v1/agents/register", json=agent_payload(), headers=headers)

    assert response.status_code == 401
    assert client.get("/api/v1/assets").json()["total"] == 0


def test_registration_is_disabled_without_configured_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "agent_enrollment_key", None)

    response = client.post("/api/v1/agents/register", json=agent_payload())

    assert response.status_code == 403


def test_token_is_returned_once_and_stored_only_as_hash(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    token = registered_agent["response"]["agent_token"]
    assert len(token) >= 40

    with engine.connect() as connection:
        stored = connection.execute(text("SELECT agent_token_hash FROM assets")).scalar_one()
    assert stored != token
    assert len(stored) == 64
    asset = client.get(f"/api/v1/assets/{registered_agent['response']['asset_id']}").json()
    assert "agent_token" not in asset
    assert "agent_token_hash" not in asset


@pytest.mark.parametrize("path", AGENT_ENDPOINTS)
@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong-token"}, {"Authorization": "Basic abc"}],
)
def test_agent_endpoints_reject_missing_or_wrong_token(
    client: TestClient, registered_agent: dict[str, Any], path: str, headers: dict[str, str]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]

    response = client.post(path, json=body_for(path, agent_id), headers=headers)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    asset = client.get(f"/api/v1/assets/{registered_agent['response']['asset_id']}").json()
    assert asset["last_seen_at"] is None


def test_token_of_one_agent_cannot_report_for_another(client: TestClient) -> None:
    first, second = agent_payload(), agent_payload(hostname="OTHER")
    first_token = client.post("/api/v1/agents/register", json=first).json()["agent_token"]
    client.post("/api/v1/agents/register", json=second)

    response = client.post(
        "/api/v1/agents/heartbeat",
        json={"agent_id": second["agent_id"]},
        headers={"Authorization": f"Bearer {first_token}"},
    )

    assert response.status_code == 401


def _heartbeat(client: TestClient, agent_id: str, token: str) -> Any:
    return client.post(
        "/api/v1/agents/heartbeat",
        json={"agent_id": agent_id},
        headers={"Authorization": f"Bearer {token}"},
    )


def _revoke(engine: Engine, asset_id: str) -> None:
    with Session(engine) as session:
        revoke_agent(session, UUID(asset_id))


def test_issue_time_is_recorded_on_enrollment(
    engine: Engine, registered_agent: dict[str, Any]
) -> None:
    with engine.connect() as connection:
        issued = connection.execute(text("SELECT agent_token_issued_at FROM assets")).scalar_one()
    assert issued is not None


@pytest.mark.parametrize("path", AGENT_ENDPOINTS)
def test_revoked_token_is_rejected_on_every_agent_endpoint(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any], path: str
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    token = registered_agent["response"]["agent_token"]
    _revoke(engine, registered_agent["response"]["asset_id"])

    response = client.post(
        path, json=body_for(path, agent_id), headers={"Authorization": f"Bearer {token}"}
    )

    # Same 401 as any bad token: a revoked credential gives no extra information.
    assert response.status_code == 401


def test_revoked_agent_cannot_re_enroll_even_with_the_key(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    _revoke(engine, registered_agent["response"]["asset_id"])

    response = client.post("/api/v1/agents/register", json=registered_agent["payload"])

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "agent_revoked"
    with engine.connect() as connection:
        stored = connection.execute(text("SELECT agent_token_hash FROM assets")).scalar_one()
    assert stored is None


def test_revocation_status_is_hidden_from_callers_without_the_key(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    _revoke(engine, registered_agent["response"]["asset_id"])

    response = client.post(
        "/api/v1/agents/register",
        json=registered_agent["payload"],
        headers={"X-Enrollment-Key": "wrong-key-wrong-key-wrong-key"},
    )

    assert response.status_code == 401


def test_revocation_is_individual(client: TestClient, engine: Engine) -> None:
    first, second = agent_payload(), agent_payload(hostname="OTHER")
    first_reg = client.post("/api/v1/agents/register", json=first).json()
    second_reg = client.post("/api/v1/agents/register", json=second).json()

    _revoke(engine, first_reg["asset_id"])

    assert _heartbeat(client, first["agent_id"], first_reg["agent_token"]).status_code == 401
    assert _heartbeat(client, second["agent_id"], second_reg["agent_token"]).status_code == 200
    third = client.post("/api/v1/agents/register", json=agent_payload(hostname="NEW"))
    assert third.status_code == 201  # the shared enrollment key keeps working


def test_reinstated_agent_enrolls_again_and_keeps_its_asset(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    asset_id = registered_agent["response"]["asset_id"]
    old_token = registered_agent["response"]["agent_token"]
    agent_id = registered_agent["payload"]["agent_id"]
    _revoke(engine, asset_id)
    with Session(engine) as session:
        reinstate_agent(session, UUID(asset_id))

    response = client.post("/api/v1/agents/register", json=registered_agent["payload"])

    assert response.status_code == 200
    assert response.json()["asset_id"] == asset_id
    new_token = response.json()["agent_token"]
    assert new_token != old_token
    assert _heartbeat(client, agent_id, old_token).status_code == 401
    assert _heartbeat(client, agent_id, new_token).status_code == 200


def test_cli_revokes_and_reinstates_by_public_id(
    client: TestClient,
    engine: Engine,
    registered_agent: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    asset_id = registered_agent["response"]["asset_id"]
    payload = registered_agent["payload"]
    monkeypatch.setattr(cli, "get_sessionmaker", lambda: sessionmaker(bind=engine))

    assert cli.main(["revoke-agent", asset_id]) == 0
    assert client.post("/api/v1/agents/register", json=payload).status_code == 403
    assert cli.main(["list-agents"]) == 0
    assert asset_id in capsys.readouterr().out
    assert cli.main(["reinstate-agent", asset_id]) == 0
    assert client.post("/api/v1/agents/register", json=payload).status_code == 200
    assert cli.main(["revoke-agent", str(uuid4())]) == 1
