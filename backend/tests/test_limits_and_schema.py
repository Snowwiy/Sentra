from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.core.config import get_settings
from tests.conftest import agent_payload


def test_oversized_body_is_rejected_before_authentication(client: TestClient) -> None:
    limit = get_settings().max_request_bytes
    body = b'{"agent_id": "' + b"x" * (limit + 10) + b'"}'

    response = client.post(
        "/api/v1/telemetry",
        content=body,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_streamed_oversized_body_without_content_length_is_rejected(client: TestClient) -> None:
    limit = get_settings().max_request_bytes

    def chunks() -> Any:
        for _ in range(limit // 65536 + 2):
            yield b"x" * 65536

    response = client.post(
        "/api/v1/inventory",
        content=chunks(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
    )

    assert response.status_code == 413


def test_normal_bodies_are_unaffected(client: TestClient, registered_agent: dict[str, Any]) -> None:
    response = client.post(
        "/api/v1/agents/heartbeat", json={"agent_id": registered_agent["payload"]["agent_id"]}
    )

    assert response.status_code == 200


def test_health_reports_pending_migrations(client: TestClient, engine: Engine) -> None:
    with engine.begin() as connection:
        current = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
        connection.execute(text("UPDATE alembic_version SET version_num = '0001'"))
    try:
        response = client.get("/api/v1/health/ready")
        # Liveness no depende de la base ni del esquema (Fase 4M).
        assert client.get("/api/v1/health").status_code == 200
    finally:
        with engine.begin() as connection:
            connection.execute(text("UPDATE alembic_version SET version_num = :v"), {"v": current})

    assert response.status_code == 503
    assert response.json()["checks"]["migrations"] == "error"
    assert client.get("/api/v1/health/ready").json()["checks"]["migrations"] == "ok"


def _nul_cases(agent_id: str) -> list[tuple[str, dict[str, Any], list[Any]]]:
    host = agent_payload(agent_id=agent_id)
    host_without_id = {k: v for k, v in host.items() if k != "agent_id"}
    event = {
        "source": "windows_eventlog",
        "channel": "System",
        "record_id": 1,
        "event_code": 7034,
        "provider": "Service Control Manager",
        "level": "error",
        "message": "bad\x00message",
        "occurred_at": datetime.now(UTC).isoformat(),
    }
    return [
        ("/api/v1/agents/register", {**host, "hostname": "bad\x00host"}, ["body", "hostname"]),
        (
            "/api/v1/agents/heartbeat",
            {"agent_id": agent_id, "host": {**host_without_id, "os_version": "11\x00"}},
            ["body", "host", "os_version"],
        ),
        (
            "/api/v1/events",
            {"agent_id": agent_id, "events": [event]},
            ["body", "events", 0, "message"],
        ),
        (
            "/api/v1/inventory",
            {
                "agent_id": agent_id,
                "collected_at": datetime.now(UTC).isoformat(),
                "software": [{"name": "App\x00", "publisher": None}],
            },
            ["body", "software", 0, "name"],
        ),
    ]


@pytest.mark.parametrize("case", range(4))
def test_nul_characters_are_a_validation_error_not_a_500(
    client: TestClient, registered_agent: dict[str, Any], case: int
) -> None:
    # PostgreSQL text/JSONB cannot store U+0000. Reaching the database used to answer 500,
    # which agents retry forever; it must be a final 422 pointing at the field.
    path, body, loc = _nul_cases(registered_agent["payload"]["agent_id"])[case]

    response = client.post(path, json=body)

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert [detail["loc"] for detail in error["details"]] == [loc]
    assert "\x00" not in response.text  # the rejected value is not echoed back


def test_other_control_characters_are_still_accepted(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    # Only NUL is unstorable; tabs or other control characters in host data are kept as sent.
    agent_id = registered_agent["payload"]["agent_id"]
    host = {k: v for k, v in agent_payload().items() if k != "agent_id"}

    response = client.post(
        "/api/v1/agents/heartbeat",
        json={"agent_id": agent_id, "host": {**host, "os_version": "11\tPro\x01"}},
    )

    assert response.status_code == 200
    asset = client.get(f"/api/v1/assets/{registered_agent['response']['asset_id']}").json()
    assert asset["os_version"] == "11\tPro\x01"


@pytest.mark.parametrize(
    ("path", "param"),
    [("/api/v1/alerts", "q"), ("/api/v1/events", "q"), ("/api/v1/events", "channel")],
)
def test_nul_in_a_search_parameter_is_a_validation_error(
    client: TestClient, path: str, param: str
) -> None:
    # Same database limitation as in bodies: a NUL in a search term used to answer 500.
    response = client.get(path, params={param: "a\x00b"})

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert [detail["loc"] for detail in error["details"]] == [["query", param]]
    assert "\x00" not in response.text
    # LIKE wildcards are plain text, not an error.
    assert client.get(path, params={param: "%_\\"}).status_code == 200


def test_integers_beyond_bigint_are_rejected_in_snapshots(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    # Stored in JSONB (no column overflow), but no OS reports such values and JavaScript
    # cannot represent them: out of range is a validation error, not stored data.
    agent_id = registered_agent["payload"]["agent_id"]
    process = {"pid": 1, "name": "x", "memory_bytes": 2**63}
    now = datetime.now(UTC).isoformat()

    snapshot = client.post(
        "/api/v1/processes",
        json={"agent_id": agent_id, "collected_at": now, "processes": [process]},
    )
    inventory = client.post(
        "/api/v1/inventory",
        json={"agent_id": agent_id, "collected_at": now, "processes": [process]},
    )

    assert snapshot.status_code == 422
    assert inventory.status_code == 422
    process["memory_bytes"] = 2**63 - 1
    accepted = client.post(
        "/api/v1/processes",
        json={"agent_id": agent_id, "collected_at": now, "processes": [process]},
    )
    assert accepted.status_code == 201
