from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from tests.conftest import agent_payload


def test_register_creates_asset_with_unknown_status(client: TestClient) -> None:
    payload = agent_payload()

    response = client.post("/api/v1/agents/register", json=payload)

    assert response.status_code == 201
    body = response.json()
    assert body["agent_id"] == payload["agent_id"]
    assert body["status"] == "unknown"
    UUID(body["asset_id"])
    assert datetime.fromisoformat(body["first_seen_at"]).utcoffset() == timedelta(0)

    asset = client.get(f"/api/v1/assets/{body['asset_id']}").json()
    assert asset["hostname"] == "PC-ADMIN-01"
    assert asset["primary_ip"] == "192.168.1.20"
    assert asset["last_seen_at"] is None


def test_reenrolling_existing_agent_rotates_token_without_duplicating_asset(
    client: TestClient,
) -> None:
    payload = agent_payload()
    first = client.post("/api/v1/agents/register", json=payload).json()

    response = client.post("/api/v1/agents/register", json={**payload, "hostname": "RENAMED"})

    assert response.status_code == 200
    second = response.json()
    assert second["asset_id"] == first["asset_id"]
    assert second["agent_token"] != first["agent_token"]
    assets = client.get("/api/v1/assets").json()
    assert assets["total"] == 1
    assert assets["items"][0]["hostname"] == "RENAMED"
    # The old token is revoked by the rotation.
    old = client.post(
        "/api/v1/agents/heartbeat",
        json={"agent_id": payload["agent_id"]},
        headers={"Authorization": f"Bearer {first['agent_token']}"},
    )
    assert old.status_code == 401


@pytest.mark.parametrize(
    "overrides",
    [
        {"primary_ip": "999.1.1.1"},
        {"agent_id": "not-a-uuid"},
        {"hostname": "   "},
        {"hostname": "x" * 256},
        {"unexpected_field": "value"},
    ],
)
def test_register_rejects_invalid_payload(client: TestClient, overrides: dict[str, Any]) -> None:
    response = client.post("/api/v1/agents/register", json=agent_payload(**overrides))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert client.get("/api/v1/assets").json()["total"] == 0


def test_register_rejects_missing_fields(client: TestClient) -> None:
    payload = agent_payload()
    del payload["os_name"]

    assert client.post("/api/v1/agents/register", json=payload).status_code == 422


def test_heartbeat_marks_asset_online(client: TestClient, registered_agent: dict[str, Any]) -> None:
    agent_id = registered_agent["payload"]["agent_id"]

    response = client.post("/api/v1/agents/heartbeat", json={"agent_id": agent_id})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "online"
    assert body["asset_id"] == registered_agent["response"]["asset_id"]

    asset = client.get(f"/api/v1/assets/{body['asset_id']}").json()
    assert asset["status"] == "online"
    assert datetime.fromisoformat(asset["last_seen_at"]) == datetime.fromisoformat(
        body["last_seen_at"]
    )


def test_heartbeat_from_unknown_agent_is_unauthorized(client: TestClient) -> None:
    response = client.post(
        "/api/v1/agents/heartbeat",
        json={"agent_id": str(uuid4())},
        headers={"Authorization": "Bearer made-up-token"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_heartbeat_rejects_invalid_agent_id(client: TestClient) -> None:
    response = client.post("/api/v1/agents/heartbeat", json={"agent_id": "123"})

    assert response.status_code == 422


def test_heartbeat_with_host_info_refreshes_inventory(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    payload = registered_agent["payload"]
    host = {k: v for k, v in payload.items() if k != "agent_id"}
    host.update(primary_ip="10.8.0.7", agent_version="0.2.0")

    response = client.post(
        "/api/v1/agents/heartbeat", json={"agent_id": payload["agent_id"], "host": host}
    )

    assert response.status_code == 200
    asset = client.get(f"/api/v1/assets/{registered_agent['response']['asset_id']}").json()
    assert asset["primary_ip"] == "10.8.0.7"
    assert asset["agent_version"] == "0.2.0"
    assert asset["hostname"] == payload["hostname"]


def test_heartbeat_with_invalid_host_info_changes_nothing(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    payload = registered_agent["payload"]
    host = {k: v for k, v in payload.items() if k != "agent_id"}
    host["primary_ip"] = "not-an-ip"

    response = client.post(
        "/api/v1/agents/heartbeat", json={"agent_id": payload["agent_id"], "host": host}
    )

    assert response.status_code == 422
    asset = client.get(f"/api/v1/assets/{registered_agent['response']['asset_id']}").json()
    assert asset["primary_ip"] == payload["primary_ip"]
    assert asset["last_seen_at"] is None
