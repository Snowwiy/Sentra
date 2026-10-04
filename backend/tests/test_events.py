from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.conftest import agent_payload


def event(record_id: int, level: str = "error", **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source": "windows_eventlog",
        "channel": "System",
        "record_id": record_id,
        "event_code": 7034,
        "provider": "Service Control Manager",
        "level": level,
        "message": f"Service terminated unexpectedly ({record_id})",
        "occurred_at": (datetime.now(UTC) - timedelta(minutes=record_id)).isoformat(),
    }
    payload.update(overrides)
    return payload


def send(client: TestClient, agent_id: str, events: list[dict[str, Any]]) -> Any:
    return client.post("/api/v1/events", json={"agent_id": agent_id, "events": events})


def test_events_are_stored_and_listed_newest_first(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]

    response = send(client, agent_id, [event(3), event(1), event(2, level="warning")])

    assert response.status_code == 201
    assert response.json()["stored"] == 3
    items = client.get("/api/v1/events").json()["items"]
    assert [i["message"][-2] for i in items] == ["1", "2", "3"]
    assert items[0]["hostname"] == registered_agent["payload"]["hostname"]
    assert items[0]["asset_id"] == registered_agent["response"]["asset_id"]


def test_resent_events_are_not_duplicated(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    send(client, agent_id, [event(1), event(2)])

    response = send(client, agent_id, [event(2), event(3)])

    assert response.json() == {
        "asset_id": registered_agent["response"]["asset_id"],
        "received": 2,
        "stored": 1,
    }
    assert client.get("/api/v1/events").json()["total"] == 3


def test_same_record_id_on_different_channels_is_distinct(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]

    send(client, agent_id, [event(1), event(1, channel="Application")])

    assert client.get("/api/v1/events").json()["total"] == 2


def test_events_filter_by_min_level_and_asset(client: TestClient) -> None:
    first, second = agent_payload(), agent_payload(hostname="SRV-02")
    for payload in (first, second):
        client.post("/api/v1/agents/register", json=payload)
    send(client, first["agent_id"], [event(1, "info"), event(2, "warning"), event(3, "critical")])
    send(client, second["agent_id"], [event(1, "error")])

    warnings_up = client.get("/api/v1/events", params={"min_level": "warning"}).json()["items"]
    assert sorted(i["level"] for i in warnings_up) == ["critical", "error", "warning"]

    asset_id = next(
        a["asset_id"]
        for a in client.get("/api/v1/assets").json()["items"]
        if a["hostname"] == "SRV-02"
    )
    only_second = client.get("/api/v1/events", params={"asset_id": asset_id}).json()["items"]
    assert [i["level"] for i in only_second] == ["error"]
    assert client.get("/api/v1/events", params={"asset_id": str(uuid4())}).status_code == 404


def test_events_require_agent_token(client: TestClient, registered_agent: dict[str, Any]) -> None:
    response = client.post(
        "/api/v1/events",
        json={"agent_id": registered_agent["payload"]["agent_id"], "events": [event(1)]},
        headers={},
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    "events",
    [
        [],
        [event(1, level="debug")],
        [event(1, occurred_at="2026-01-01T00:00:00")],
        [event(1, message="x" * 4001)],
        [event(i) for i in range(501)],
        # Beyond PostgreSQL BIGINT: must be a 422, not a database overflow (500).
        [{**event(1), "record_id": 2**63}],
    ],
)
def test_invalid_event_batches_are_rejected(
    client: TestClient, registered_agent: dict[str, Any], events: list[dict[str, Any]]
) -> None:
    assert send(client, registered_agent["payload"]["agent_id"], events).status_code == 422
