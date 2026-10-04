from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient


def test_history_returns_samples_oldest_first_and_respects_limit(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    asset_id = registered_agent["response"]["asset_id"]
    start = datetime.now(UTC) - timedelta(minutes=10)
    # Sent out of order, as a reconnecting agent flushing its buffer might.
    for minute in (2, 0, 1, 3):
        client.post(
            "/api/v1/telemetry",
            json={
                "agent_id": agent_id,
                "timestamp": (start + timedelta(minutes=minute)).isoformat(),
                "cpu_percent": float(minute),
                "ram_percent": 50,
                "disk_percent": 40,
                "uptime_seconds": 60,
            },
        )

    response = client.get(f"/api/v1/assets/{asset_id}/telemetry", params={"limit": 3})

    assert response.status_code == 200
    body = response.json()
    assert body["asset_id"] == asset_id
    assert [item["cpu_percent"] for item in body["items"]] == [1.0, 2.0, 3.0]


def test_history_for_unknown_asset_is_not_found(client: TestClient) -> None:
    assert client.get(f"/api/v1/assets/{uuid4()}/telemetry").status_code == 404


def test_history_limit_is_bounded(client: TestClient, registered_agent: dict[str, Any]) -> None:
    asset_id = registered_agent["response"]["asset_id"]

    response = client.get(f"/api/v1/assets/{asset_id}/telemetry", params={"limit": 5000})

    assert response.status_code == 422
