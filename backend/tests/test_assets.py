from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.core.config import get_settings
from app.schemas.asset import AssetList
from app.services.asset_service import AssetService
from tests.conftest import agent_payload


def test_list_assets_is_empty_initially(client: TestClient) -> None:
    response = client.get("/api/v1/assets")

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0}


def test_list_assets_includes_status_and_latest_telemetry(client: TestClient) -> None:
    online = agent_payload(hostname="PC-ADMIN-01")
    idle = agent_payload(hostname="SRV-DB-01", primary_ip="10.0.0.5")
    for payload in (online, idle):
        assert client.post("/api/v1/agents/register", json=payload).status_code == 201

    now = datetime.now(UTC)
    for cpu, offset in ((10.0, 60), (24.0, 0)):
        response = client.post(
            "/api/v1/telemetry",
            json={
                "agent_id": online["agent_id"],
                "timestamp": (now - timedelta(seconds=offset)).isoformat(),
                "cpu_percent": cpu,
                "ram_percent": 61,
                "disk_percent": 48,
                "uptime_seconds": 3600,
            },
        )
        assert response.status_code == 201

    body = client.get("/api/v1/assets").json()

    assert body["total"] == 2
    by_host = {item["hostname"]: item for item in body["items"]}
    assert by_host["PC-ADMIN-01"]["status"] == "online"
    assert by_host["PC-ADMIN-01"]["latest_telemetry"]["cpu_percent"] == 24.0
    assert by_host["SRV-DB-01"]["status"] == "unknown"
    assert by_host["SRV-DB-01"]["latest_telemetry"] is None


def test_latest_telemetry_ignores_late_samples_and_breaks_ties_by_arrival(
    client: TestClient,
) -> None:
    first, second = agent_payload(hostname="PC-A"), agent_payload(hostname="PC-B")
    for payload in (first, second):
        assert client.post("/api/v1/agents/register", json=payload).status_code == 201

    now = datetime.now(UTC).replace(microsecond=0)
    # (agent, measured at, cpu) in arrival order: PC-A gets a sample buffered during an outage
    # after a newer one; PC-B sends two samples with the same timestamp.
    sends = (
        (first, now, 30.0),
        (first, now - timedelta(minutes=10), 99.0),
        (second, now, 40.0),
        (second, now, 41.0),
    )
    for agent, measured_at, cpu in sends:
        response = client.post(
            "/api/v1/telemetry",
            json={
                "agent_id": agent["agent_id"],
                "timestamp": measured_at.isoformat(),
                "cpu_percent": cpu,
                "ram_percent": 50,
                "disk_percent": 50,
                "uptime_seconds": 60,
            },
        )
        assert response.status_code == 201

    by_host = {item["hostname"]: item for item in client.get("/api/v1/assets").json()["items"]}

    assert by_host["PC-A"]["latest_telemetry"]["cpu_percent"] == 30.0
    assert by_host["PC-B"]["latest_telemetry"]["cpu_percent"] == 41.0


def test_asset_detail_returns_all_fields(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    asset_id = registered_agent["response"]["asset_id"]
    payload = registered_agent["payload"]

    response = client.get(f"/api/v1/assets/{asset_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["asset_id"] == asset_id
    for field in ("hostname", "os_name", "os_version", "architecture", "agent_version"):
        assert body[field] == payload[field]
    assert body["status"] == "unknown"
    assert "agent_id" not in body
    assert "id" not in body


def test_asset_becomes_offline_after_heartbeat_timeout(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    asset_id = registered_agent["response"]["asset_id"]
    client.post("/api/v1/agents/heartbeat", json={"agent_id": agent_id})

    stale = datetime.now(UTC) - timedelta(seconds=get_settings().heartbeat_timeout_seconds + 5)
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE assets SET last_seen_at = :ts WHERE public_id = :id"),
            {"ts": stale, "id": asset_id},
        )

    assert client.get(f"/api/v1/assets/{asset_id}").json()["status"] == "offline"

    client.post("/api/v1/agents/heartbeat", json={"agent_id": agent_id})
    assert client.get(f"/api/v1/assets/{asset_id}").json()["status"] == "online"


def test_nonexistent_asset_returns_not_found(client: TestClient) -> None:
    response = client.get(f"/api/v1/assets/{uuid4()}")

    assert response.status_code == 404
    assert response.json() == {"error": {"code": "not_found", "message": "Asset not found"}}


def test_malformed_asset_id_returns_validation_error(client: TestClient) -> None:
    assert client.get("/api/v1/assets/not-a-uuid").status_code == 422


def test_unhandled_errors_do_not_leak_details(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(self: AssetService) -> AssetList:
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(AssetService, "list_assets", explode)
    with TestClient(client.app, raise_server_exceptions=False) as raw_client:
        raw_client.cookies = client.cookies
        response = raw_client.get("/api/v1/assets")

    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "internal_error", "message": "Internal server error"}
    }
    assert "secret" not in response.text
