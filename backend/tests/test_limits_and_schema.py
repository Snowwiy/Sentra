from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.core.config import get_settings


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
        response = client.get("/api/v1/health")
    finally:
        with engine.begin() as connection:
            connection.execute(text("UPDATE alembic_version SET version_num = :v"), {"v": current})

    assert response.status_code == 503
    assert response.json()["checks"]["migrations"] == "error"
    assert client.get("/api/v1/health").json()["checks"]["migrations"] == "ok"
