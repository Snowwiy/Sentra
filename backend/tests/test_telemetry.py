from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text


def telemetry_payload(agent_id: str, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "agent_id": agent_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "cpu_percent": 24.5,
        "ram_percent": 61.0,
        "disk_percent": 48.2,
        "uptime_seconds": 86400,
    }
    payload.update(overrides)
    return payload


def test_ingest_telemetry_stores_history_and_marks_online(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    asset_id = registered_agent["response"]["asset_id"]

    for _ in range(3):
        response = client.post("/api/v1/telemetry", json=telemetry_payload(agent_id))
        assert response.status_code == 201
        assert response.json()["asset_id"] == asset_id

    with engine.connect() as connection:
        stored = connection.execute(text("SELECT count(*) FROM telemetry_samples")).scalar_one()
    assert stored == 3

    asset = client.get(f"/api/v1/assets/{asset_id}").json()
    assert asset["status"] == "online"
    assert asset["last_seen_at"] is not None
    assert asset["latest_telemetry"]["ram_percent"] == 61.0
    assert asset["latest_telemetry"]["uptime_seconds"] == 86400


def test_telemetry_timestamp_is_normalized_to_utc(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    local = datetime.now(timezone(timedelta(hours=-6))).replace(microsecond=0)

    response = client.post(
        "/api/v1/telemetry", json=telemetry_payload(agent_id, timestamp=local.isoformat())
    )

    assert response.status_code == 201
    recorded = datetime.fromisoformat(response.json()["recorded_at"])
    assert recorded.utcoffset() == timedelta(0)
    assert recorded == local


def test_telemetry_from_unknown_agent_is_unauthorized(client: TestClient) -> None:
    response = client.post("/api/v1/telemetry", json=telemetry_payload(str(uuid4())))

    assert response.status_code == 401


@pytest.mark.parametrize(
    "overrides",
    [
        {"cpu_percent": 150},
        {"ram_percent": -1},
        {"disk_percent": "full"},
        {"uptime_seconds": -10},
        # Beyond PostgreSQL BIGINT: must be a 422, not a database overflow (500).
        {"uptime_seconds": 2**63},
        {"timestamp": "2026-01-01T10:00:00"},  # no timezone offset
        {"timestamp": "not-a-date"},
        {"timestamp": (datetime.now(UTC) + timedelta(hours=1)).isoformat()},
        {"extra": True},
    ],
)
def test_invalid_telemetry_is_rejected(
    client: TestClient,
    engine: Engine,
    registered_agent: dict[str, Any],
    overrides: dict[str, Any],
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]

    response = client.post("/api/v1/telemetry", json=telemetry_payload(agent_id, **overrides))

    assert response.status_code == 422
    with engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM telemetry_samples")).scalar() == 0


def test_telemetry_with_missing_fields_is_rejected(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    payload = telemetry_payload(registered_agent["payload"]["agent_id"])
    del payload["cpu_percent"]

    assert client.post("/api/v1/telemetry", json=payload).status_code == 422


def test_resent_sample_id_is_stored_once(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    payload = telemetry_payload(agent_id, sample_id=str(uuid4()))

    first = client.post("/api/v1/telemetry", json=payload)
    retry = client.post("/api/v1/telemetry", json=payload)

    assert first.status_code == retry.status_code == 201
    assert first.json()["stored"] is True
    assert retry.json()["stored"] is False
    with engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM telemetry_samples")).scalar() == 1


def test_samples_without_sample_id_are_all_stored(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    payload = telemetry_payload(agent_id)

    client.post("/api/v1/telemetry", json=payload)
    client.post("/api/v1/telemetry", json=payload)

    with engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM telemetry_samples")).scalar() == 2
