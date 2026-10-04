from collections.abc import Iterator

from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine
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


def test_exhausted_connection_pool_answers_503_not_500(engine: Engine) -> None:
    # Every pooled connection busy (load spike, slow queries) is as transient as an outage:
    # agents must get a retryable 503, not a generic 500 with a traceback in the log.
    tiny = create_engine(
        engine.url.render_as_string(hide_password=False),
        pool_size=1,
        max_overflow=0,
        pool_timeout=0.1,
    )
    held = tiny.connect()  # the pool's only connection
    app = create_app()

    def exhausted_db() -> Iterator[Session]:
        with Session(tiny) as session:
            yield session

    app.dependency_overrides[get_db] = exhausted_db
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get("/api/v1/assets")
    finally:
        held.close()
        tiny.dispose()

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "database_unavailable"
