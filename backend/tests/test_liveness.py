"""Online/offline lifecycle: heartbeats, timeouts, offline alerts and restarts.

Status is derived at read time from last_seen_at (server clock) and the heartbeat timeout;
the offline alert is opened by the sweeper and resolved by the next agent contact.
"""

import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.main import create_app
from app.models.alert import Alert, AlertRule, AlertSeverity, AlertStatus
from app.models.asset import Asset
from app.services.agent_service import record_contact
from app.services.alert_service import AlertService, AlertThresholds
from tests.conftest import AgentClient

TIMEOUT = timedelta(seconds=get_settings().heartbeat_timeout_seconds)


def _heartbeat(client: TestClient, agent: dict[str, Any]) -> Any:
    return client.post("/api/v1/agents/heartbeat", json={"agent_id": agent["payload"]["agent_id"]})


def _status(client: TestClient, agent: dict[str, Any]) -> str:
    asset = client.get(f"/api/v1/assets/{agent['response']['asset_id']}").json()
    status: str = asset["status"]
    return status


def _age(engine: Engine, agent: dict[str, Any], by: timedelta) -> None:
    """Pretend the asset's last contact happened `by` ago."""
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE assets SET last_seen_at = :at WHERE public_id = :id"),
            {"at": datetime.now(UTC) - by, "id": agent["response"]["asset_id"]},
        )


def _sweep(engine: Engine) -> int:
    with Session(engine) as session:
        return AlertService(session, AlertThresholds.from_settings(get_settings())).sweep_offline()


def _offline_alerts(engine: Engine) -> list[Alert]:
    with Session(engine) as session:
        return list(
            session.scalars(
                select(Alert).where(Alert.rule == AlertRule.ASSET_OFFLINE).order_by(Alert.id)
            )
        )


def test_full_cycle_online_offline_online_without_duplicate_alerts(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    assert _status(client, registered_agent) == "unknown"  # enrolled, never reported
    assert _heartbeat(client, registered_agent).status_code == 200
    assert _status(client, registered_agent) == "online"

    _age(engine, registered_agent, TIMEOUT + timedelta(seconds=5))
    assert _status(client, registered_agent) == "offline"
    assert _sweep(engine) == 1
    assert _sweep(engine) == 0  # still offline: the same alert stays open, no second one

    # A late heartbeat (well past the timeout) brings it back and closes the incident.
    assert _heartbeat(client, registered_agent).status_code == 200
    assert _status(client, registered_agent) == "online"
    (alert,) = _offline_alerts(engine)
    assert alert.status == AlertStatus.RESOLVED
    assert alert.resolved_at is not None

    # A second outage is a new incident.
    _age(engine, registered_agent, TIMEOUT * 2)
    assert _sweep(engine) == 1
    _heartbeat(client, registered_agent)
    assert [a.status for a in _offline_alerts(engine)] == [AlertStatus.RESOLVED] * 2


@pytest.mark.parametrize("call", ["telemetry", "events", "inventory"])
def test_any_agent_call_proves_liveness_and_resolves_the_offline_alert(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any], call: str
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    now = datetime.now(UTC).isoformat()
    bodies = {
        "telemetry": {
            "agent_id": agent_id,
            "timestamp": now,
            "cpu_percent": 1,
            "ram_percent": 1,
            "disk_percent": 1,
            "uptime_seconds": 1,
        },
        "events": {
            "agent_id": agent_id,
            "events": [
                {
                    "source": "windows_eventlog",
                    "channel": "System",
                    "record_id": 1,
                    "event_code": 1,
                    "provider": "p",
                    "level": "error",
                    "message": "m",
                    "occurred_at": now,
                }
            ],
        },
        "inventory": {"agent_id": agent_id, "collected_at": now},
    }
    _heartbeat(client, registered_agent)
    _age(engine, registered_agent, TIMEOUT * 2)
    assert _sweep(engine) == 1

    assert client.post(f"/api/v1/{call}", json=bodies[call]).status_code == 201

    assert _status(client, registered_agent) == "online"
    # Used to stay open until the next heartbeat while the asset already showed online.
    assert [a.status for a in _offline_alerts(engine)] == [AlertStatus.RESOLVED]


def test_duplicate_heartbeats_are_harmless(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    first = _heartbeat(client, registered_agent).json()
    second = _heartbeat(client, registered_agent).json()

    assert first["asset_id"] == second["asset_id"]
    assert second["last_seen_at"] >= first["last_seen_at"]
    with Session(engine) as session:
        assert session.query(Asset).count() == 1
    assert _offline_alerts(engine) == []


def test_last_seen_never_moves_backwards_with_out_of_order_contacts(
    engine: Engine, registered_agent: dict[str, Any]
) -> None:
    # Two calls of the same agent take `now` before committing; the one with the older
    # timestamp may commit last. It must not rewind last_seen_at.
    newer = datetime.now(UTC)
    older = newer - timedelta(seconds=40)
    with Session(engine) as session:
        asset = session.scalars(select(Asset)).one()
        record_contact(session, asset, newer)
        session.commit()
        record_contact(session, asset, older)
        session.commit()
        session.refresh(asset)

        assert asset.last_seen_at == newer


def test_sweeper_skips_an_asset_that_is_reporting_at_that_moment(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    # The committed last_seen_at is stale, but an agent call is updating the row right now
    # (uncommitted, row locked). The sweeper must not open an offline alert for it.
    _heartbeat(client, registered_agent)
    _age(engine, registered_agent, TIMEOUT * 2)
    with engine.connect() as in_flight:
        transaction = in_flight.begin()
        in_flight.execute(
            text("UPDATE assets SET last_seen_at = now() WHERE public_id = :id"),
            {"id": registered_agent["response"]["asset_id"]},
        )
        assert _sweep(engine) == 0  # locked: alive, skipped without waiting
        transaction.commit()

    assert _sweep(engine) == 0  # fresh after the commit
    assert _offline_alerts(engine) == []


def test_heartbeat_waits_for_a_running_sweep_and_resolves_its_alert(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    # The opposite order: the sweeper locked the asset and is opening an alert when the
    # heartbeat arrives. The heartbeat waits for the lock, then sees and resolves the alert.
    _heartbeat(client, registered_agent)
    _age(engine, registered_agent, TIMEOUT * 2)
    result: dict[str, Any] = {}
    with Session(engine) as sweeper:
        alerts = AlertService(sweeper, AlertThresholds.from_settings(get_settings()))
        stale = alerts._alerts.stale_assets_without_active_alert(  # locks the asset row
            AlertRule.ASSET_OFFLINE, datetime.now(UTC) - TIMEOUT
        )
        assert len(stale) == 1
        request = threading.Thread(
            target=lambda: result.setdefault("response", _heartbeat(client, registered_agent))
        )
        request.start()
        time.sleep(0.5)  # the heartbeat is now waiting on the row lock
        assert "response" not in result
        alerts._open(
            stale[0],
            AlertRule.ASSET_OFFLINE,
            AlertSeverity.CRITICAL,
            "test",
            datetime.now(UTC),
        )
        sweeper.commit()
        request.join(timeout=10)

    assert result["response"].status_code == 200
    assert [a.status for a in _offline_alerts(engine)] == [AlertStatus.RESOLVED]


def test_state_survives_a_backend_restart(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    _heartbeat(client, registered_agent)
    _age(engine, registered_agent, TIMEOUT * 2)
    assert _sweep(engine) == 1

    # A new API process: nothing is kept in memory, status and alerts come from PostgreSQL.
    restarted = create_app()
    restarted.dependency_overrides = client.app.dependency_overrides  # type: ignore[attr-defined]
    with AgentClient(restarted) as after:
        after.tokens = dict(client.tokens)  # type: ignore[attr-defined]
        # Fase 4G: reiniciar no vuelve públicos los endpoints, y la sesión web (guardada en
        # PostgreSQL) sigue valiendo tras el reinicio.
        assert (
            after.get(f"/api/v1/assets/{registered_agent['response']['asset_id']}").status_code
            == 401
        )
        after.cookies = client.cookies
        after.headers.update(client.headers)
        assert _status(after, registered_agent) == "offline"
        assert _sweep(engine) == 0  # the open alert is found, not duplicated
        # The agent's token was stored hashed: it keeps working across the restart.
        assert _heartbeat(after, registered_agent).status_code == 200
        assert _status(after, registered_agent) == "online"
    assert [a.status for a in _offline_alerts(engine)] == [AlertStatus.RESOLVED]


def test_agent_restart_keeps_its_asset_and_status(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    # A restarted agent reuses its stored identity and token: no new enrollment, same asset.
    _heartbeat(client, registered_agent)
    response = _heartbeat(client, registered_agent)

    assert response.json()["asset_id"] == registered_agent["response"]["asset_id"]
    assert client.get("/api/v1/assets").json()["total"] == 1
    # And one that lost its token re-enrolls into the same asset (token rotated).
    again = client.post("/api/v1/agents/register", json=registered_agent["payload"])
    assert again.status_code == 200
    assert again.json()["asset_id"] == registered_agent["response"]["asset_id"]
    assert _heartbeat(client, registered_agent).status_code == 200
