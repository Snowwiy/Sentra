from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.services.alert_service import AlertService, AlertThresholds
from tests.conftest import agent_payload


def send(client: TestClient, agent_id: str, **metrics: float) -> None:
    payload = {
        "agent_id": agent_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "cpu_percent": 10.0,
        "ram_percent": 20.0,
        "disk_percent": 30.0,
        "uptime_seconds": 100,
        **metrics,
    }
    assert client.post("/api/v1/telemetry", json=payload).status_code == 201


def alerts(client: TestClient, **params: str) -> list[dict[str, Any]]:
    response = client.get("/api/v1/alerts", params=params)
    assert response.status_code == 200
    items: list[dict[str, Any]] = response.json()["items"]
    return items


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    with Session(engine, expire_on_commit=False) as session:
        yield session


def test_short_cpu_spike_does_not_alert(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    sustained = get_settings().alert_sustained_samples

    for _ in range(sustained - 1):
        send(client, agent_id, cpu_percent=99)
    send(client, agent_id, cpu_percent=20)

    assert alerts(client) == []


def test_sustained_cpu_opens_one_alert_and_recovery_resolves_it(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    sustained = get_settings().alert_sustained_samples

    for _ in range(sustained + 2):
        send(client, agent_id, cpu_percent=97)

    open_alerts = alerts(client, status="open")
    assert len(open_alerts) == 1  # deduplicated while the condition persists
    assert open_alerts[0]["rule"] == "high_cpu"
    assert open_alerts[0]["severity"] == "warning"
    assert open_alerts[0]["hostname"] == registered_agent["payload"]["hostname"]
    assert open_alerts[0]["asset_id"] == registered_agent["response"]["asset_id"]

    send(client, agent_id, cpu_percent=15)

    assert alerts(client, status="open") == []
    resolved = alerts(client, status="resolved")
    assert len(resolved) == 1
    assert resolved[0]["resolved_at"] is not None


def test_disk_alerts_on_first_critical_sample(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    send(client, registered_agent["payload"]["agent_id"], disk_percent=96)

    open_alerts = alerts(client, status="open")
    assert [a["rule"] for a in open_alerts] == ["disk_critical"]
    assert open_alerts[0]["severity"] == "critical"
    assert open_alerts[0]["value"] == 96


def test_offline_sweep_opens_alert_and_heartbeat_resolves_it(
    client: TestClient, engine: Engine, session: Session, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    client.post("/api/v1/agents/heartbeat", json={"agent_id": agent_id})
    stale = datetime.now(UTC) - timedelta(seconds=get_settings().heartbeat_timeout_seconds + 5)
    with engine.begin() as connection:
        connection.execute(text("UPDATE assets SET last_seen_at = :ts"), {"ts": stale})

    service = AlertService(session, AlertThresholds.from_settings(get_settings()))
    assert service.sweep_offline() == 1
    assert service.sweep_offline() == 0  # already open: no duplicate

    offline = alerts(client, status="open")
    assert [a["rule"] for a in offline] == ["asset_offline"]

    client.post("/api/v1/agents/heartbeat", json={"agent_id": agent_id})
    assert alerts(client, status="open") == []


def test_never_seen_assets_are_not_reported_offline(
    client: TestClient, session: Session, registered_agent: dict[str, Any]
) -> None:
    service = AlertService(session, AlertThresholds.from_settings(get_settings()))

    assert service.sweep_offline() == 0


def test_alerts_can_be_filtered_by_asset(client: TestClient) -> None:
    first, second = agent_payload(), agent_payload(hostname="SRV-02")
    for payload in (first, second):
        client.post("/api/v1/agents/register", json=payload)
        send(client, payload["agent_id"], disk_percent=99)
    asset_id = client.get("/api/v1/assets").json()["items"][0]["asset_id"]

    filtered = alerts(client, asset_id=asset_id)

    assert len(filtered) == 1
    assert filtered[0]["asset_id"] == asset_id


def test_alert_filters_are_validated(client: TestClient) -> None:
    assert client.get("/api/v1/alerts", params={"status": "bogus"}).status_code == 422
    assert client.get("/api/v1/alerts", params={"limit": 0}).status_code == 422
    missing = client.get(
        "/api/v1/alerts", params={"asset_id": "6f1c8a52-3b8e-4f3a-9d2e-1d6f0b7c2a11"}
    )
    assert missing.status_code == 404
