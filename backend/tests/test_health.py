from collections.abc import Iterator

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.session import build_engine, get_db
from app.main import create_app


def test_health_reports_ok_when_database_is_reachable(client: TestClient) -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"] == {"api": "ok", "database": "ok", "migrations": "ok"}
    assert body["version"]


def test_health_reports_degraded_when_database_is_unreachable() -> None:
    # Nothing listens on port 1, so the connection is refused immediately.
    unreachable = build_engine("postgresql+psycopg://sentra:invalid@127.0.0.1:1/sentra")
    app = create_app()

    def broken_db() -> Iterator[Session]:
        with Session(unreachable) as session:
            yield session

    app.dependency_overrides[get_db] = broken_db
    with TestClient(app) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["checks"]["database"] == "error"
    unreachable.dispose()


def test_read_endpoints_answer_503_when_database_is_unreachable() -> None:
    # A database outage is transient: clients (dashboard, agents) must see a retryable 503
    # with the standard error envelope, not a generic 500 "Internal server error".
    unreachable = build_engine("postgresql+psycopg://sentra:invalid@127.0.0.1:1/sentra")
    app = create_app()

    def broken_db() -> Iterator[Session]:
        with Session(unreachable) as session:
            yield session

    app.dependency_overrides[get_db] = broken_db
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/assets")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "database_unavailable"
    assert "psycopg" not in response.text
    unreachable.dispose()
