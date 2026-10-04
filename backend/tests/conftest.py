import os

# Must run before the app (and its cached settings) is imported: tests drive background jobs
# explicitly, and a live sweeper thread would race with assertions.
os.environ["BACKGROUND_JOBS_ENABLED"] = "false"
# Fixed test-only key so tests never depend on (or reveal) the developer's real .env value.
TEST_ENROLLMENT_KEY = "test-enrollment-key-0123456789abcdef"
os.environ["AGENT_ENROLLMENT_KEY"] = TEST_ENROLLMENT_KEY

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.session import build_engine, get_db
from app.main import create_app

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _alembic_config(url: str) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.attributes["database_url"] = url
    config.attributes["configure_logger"] = False
    return config


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    settings = get_settings()
    url = settings.test_database_url
    if not url:
        pytest.exit("TEST_DATABASE_URL is not set; see README (Tests).", returncode=2)
    # Tests truncate tables; refusing to share the main database prevents wiping real data.
    if url == settings.database_url:
        pytest.exit("TEST_DATABASE_URL must differ from DATABASE_URL.", returncode=2)

    # Run the real migrations (down then up) so tests also validate them.
    config = _alembic_config(url)
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    engine = build_engine(url)
    yield engine
    engine.dispose()


class AgentClient(TestClient):
    """TestClient that behaves like a well-configured agent.

    It adds the enrollment key to registrations and remembers each issued token, then sends it
    as a Bearer credential on agent calls, so feature tests stay focused on their behavior.
    Passing explicit `headers` disables this, which is how the authentication tests send
    missing or wrong credentials.
    """

    tokens: dict[str, str]

    def post(self, url: Any, *, json: Any = None, headers: Any = None, **kwargs: Any) -> Any:
        agent_id = json.get("agent_id") if isinstance(json, dict) else None
        is_register = str(url).endswith("/agents/register")
        if headers is None:
            if is_register:
                headers = {"X-Enrollment-Key": TEST_ENROLLMENT_KEY}
            elif agent_id in self.tokens:
                headers = {"Authorization": f"Bearer {self.tokens[agent_id]}"}
        response = super().post(url, json=json, headers=headers, **kwargs)
        if is_register and response.status_code in (200, 201):
            self.tokens[str(agent_id)] = response.json()["agent_token"]
        return response


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    app = create_app()
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_db() -> Iterator[Session]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    with AgentClient(app) as test_client:
        test_client.tokens = {}
        yield test_client

    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE system_events, asset_inventories, alerts, telemetry_samples, assets"
                " RESTART IDENTITY CASCADE"
            )
        )


def agent_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "agent_id": str(uuid4()),
        "hostname": "PC-ADMIN-01",
        "os_name": "Windows",
        "os_version": "11 Pro 24H2",
        "architecture": "x86_64",
        "primary_ip": "192.168.1.20",
        "agent_version": "0.1.0",
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def registered_agent(client: TestClient) -> dict[str, Any]:
    """Register an agent and return its registration payload plus the API response."""
    payload = agent_payload()
    response = client.post("/api/v1/agents/register", json=payload)
    assert response.status_code == 201
    return {"payload": payload, "response": response.json()}
