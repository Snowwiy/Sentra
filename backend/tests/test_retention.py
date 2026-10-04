from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app import cli
from app.core.config import Settings, get_settings
from app.models.alert import Alert
from app.models.change import AssetChange
from app.models.event import SystemEvent
from app.models.telemetry import TelemetrySample
from app.services.retention_service import RetentionPolicy, RetentionService

NOW = datetime.now(UTC)


def _send_samples(client: TestClient, agent_id: str, ages_in_days: list[float]) -> None:
    for age in ages_in_days:
        response = client.post(
            "/api/v1/telemetry",
            json={
                "agent_id": agent_id,
                "timestamp": (NOW - timedelta(days=age)).isoformat(),
                "cpu_percent": 10.0,
                "ram_percent": 20.0,
                "disk_percent": 99.0,  # opens a disk alert, which must survive the purge
                "uptime_seconds": 100,
            },
        )
        assert response.status_code == 201


def _send_events(client: TestClient, agent_id: str, ages_in_days: list[float]) -> None:
    events = [
        {
            "source": "windows_eventlog",
            "channel": "System",
            "record_id": record_id,
            "event_code": 7034,
            "provider": "Service Control Manager",
            "level": "error",
            "message": "Service terminated unexpectedly",
            "occurred_at": (NOW - timedelta(days=age)).isoformat(),
        }
        for record_id, age in enumerate(ages_in_days, start=1)
    ]
    response = client.post("/api/v1/events", json={"agent_id": agent_id, "events": events})
    assert response.status_code == 201


def _count(engine: Engine, model: type[Any]) -> int:
    with Session(engine) as session:
        return session.scalar(select(func.count()).select_from(model)) or 0


@pytest.fixture
def history(client: TestClient, registered_agent: dict[str, Any]) -> str:
    """An agent with 3 samples and 3 events: 40, 31 and 1 days old."""
    agent_id: str = registered_agent["payload"]["agent_id"]
    _send_samples(client, agent_id, [40, 31, 1])
    _send_events(client, agent_id, [40, 31, 1])
    return agent_id


def test_purge_deletes_only_what_is_older_than_the_policy(engine: Engine, history: str) -> None:
    with Session(engine) as session:
        result = RetentionService(session, RetentionPolicy(30, 35)).purge(NOW)

    assert (result.telemetry_samples, result.system_events) == (2, 1)
    with Session(engine) as session:
        ages = sorted(
            round((NOW - recorded).total_seconds() / 86400)
            for recorded in session.scalars(select(TelemetrySample.recorded_at))
        )
        event_ages = sorted(
            round((NOW - occurred).total_seconds() / 86400)
            for occurred in session.scalars(select(SystemEvent.occurred_at))
        )
    assert ages == [1]
    assert event_ages == [1, 31]


def test_alerts_are_never_purged(engine: Engine, history: str) -> None:
    alerts_before = _count(engine, Alert)
    assert alerts_before > 0

    with Session(engine) as session:
        RetentionService(session, RetentionPolicy(1, 1)).purge(NOW + timedelta(days=365))

    assert _count(engine, TelemetrySample) == 0
    assert _count(engine, Alert) == alerts_before


def test_without_a_policy_nothing_is_deleted(engine: Engine, history: str) -> None:
    policy = RetentionPolicy(None, None)

    with Session(engine) as session:
        result = RetentionService(session, policy).purge(NOW + timedelta(days=365))

    assert not policy.enabled
    assert result.total == 0
    assert (_count(engine, TelemetrySample), _count(engine, SystemEvent)) == (3, 3)


def test_purge_works_in_batches_until_done(engine: Engine, history: str) -> None:
    with Session(engine) as session:
        result = RetentionService(session, RetentionPolicy(1, 1), batch_size=2).purge(
            NOW + timedelta(days=60)
        )

    # 3 rows of each with batches of 2: a full batch, then a partial one ends the loop.
    assert (result.telemetry_samples, result.system_events) == (3, 3)
    assert (_count(engine, TelemetrySample), _count(engine, SystemEvent)) == (0, 0)


def test_retention_periods_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Settings(database_url="postgresql+psycopg://x@localhost/x", telemetry_retention_days=0)


def test_cli_purges_with_the_configured_policy(
    engine: Engine,
    history: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "get_sessionmaker", lambda: sessionmaker(bind=engine))
    monkeypatch.setattr(cli, "get_settings", lambda: get_settings().model_copy())

    # Not configured: refuses instead of deleting anything.
    assert cli.main(["purge-old-data"]) == 1
    assert _count(engine, TelemetrySample) == 3

    configured = get_settings().model_copy(update={"telemetry_retention_days": 30})
    monkeypatch.setattr(cli, "get_settings", lambda: configured)
    assert cli.main(["purge-old-data"]) == 0
    assert "deleted 2 telemetry samples, 0 events" in capsys.readouterr().out
    assert _count(engine, TelemetrySample) == 1


def test_change_history_and_resolved_alerts_are_purged_only_when_configured(
    client: TestClient, engine: Engine, history: str
) -> None:
    # history: its 99 % disk samples left a disk alert open. Resolve it with a good sample
    # and add one inventory change.
    now = datetime.now(UTC)
    for at, software in ((now - timedelta(minutes=1), [{"name": "A"}]), (now, [{"name": "B"}])):
        client.post(
            "/api/v1/inventory",
            json={"agent_id": history, "collected_at": at.isoformat(), "software": software},
        )
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO alerts (public_id, asset_id, rule, severity, status, message,"
                " opened_at, resolved_at) SELECT gen_random_uuid(), id, 'high_cpu', 'warning',"
                " 'resolved', 'old', now() - interval '90 days', now() - interval '90 days'"
                " FROM assets"
            )
        )
    changes_before = _count(engine, AssetChange)
    assert changes_before == 2

    with Session(engine) as session:
        nothing = RetentionService(session, RetentionPolicy(None, None)).purge(NOW)
        result = RetentionService(session, RetentionPolicy(None, None, 1, 30)).purge(
            NOW + timedelta(days=2)
        )

    assert nothing.total == 0
    assert (result.asset_changes, result.alerts) == (2, 1)  # only the old resolved alert
    with Session(engine) as session:
        statuses = sorted(a.status.value for a in session.scalars(select(Alert)))
    assert "open" in statuses  # an active alert is never deleted, whatever its age
