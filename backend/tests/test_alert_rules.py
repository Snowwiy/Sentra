"""Alert lifecycle (open → acknowledged → resolved) and the inventory/event-based rules."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app import cli
from app.core.config import Settings, get_settings
from app.services.alert_service import AlertService, AlertThresholds

THRESHOLDS = AlertThresholds.from_settings(get_settings())


def _agent_id(agent: dict[str, Any]) -> str:
    agent_id: str = agent["payload"]["agent_id"]
    return agent_id


def _inventory(client: TestClient, agent: dict[str, Any], **sections: Any) -> None:
    body = {"agent_id": _agent_id(agent), "collected_at": datetime.now(UTC).isoformat()}
    response = client.post("/api/v1/inventory", json={**body, **sections})
    assert response.status_code == 201, response.text


def _service(name: str, status: str, start_type: str = "automatic") -> dict[str, Any]:
    return {"name": name, "display_name": name, "status": status, "start_type": start_type}


def _event(record_id: int, **overrides: Any) -> dict[str, Any]:
    event = {
        "source": "windows_eventlog",
        "channel": "System",
        "record_id": record_id,
        "event_code": 7036,
        "provider": "Service Control Manager",
        "level": "error",
        "message": f"error {record_id}",
        "occurred_at": datetime.now(UTC).isoformat(),
    }
    event.update(overrides)
    return event


def _events(client: TestClient, agent: dict[str, Any], events: list[dict[str, Any]]) -> Any:
    response = client.post("/api/v1/events", json={"agent_id": _agent_id(agent), "events": events})
    assert response.status_code == 201, response.text
    return response.json()


def _alerts(client: TestClient, **params: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = client.get("/api/v1/alerts", params=params).json()["items"]
    return items


# --- Watched services ------------------------------------------------------------------------


def test_watched_service_stopped_opens_one_alert_and_recovery_resolves_it(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    running = [_service("WinDefend", "running"), _service("Spooler", "running")]
    _inventory(client, registered_agent, services=running)
    assert _alerts(client, rule="service_stopped") == []

    stopped = [_service("WinDefend", "stopped"), _service("Spooler", "stopped")]
    _inventory(client, registered_agent, services=stopped)
    _inventory(client, registered_agent, services=stopped)  # still stopped: same alert

    (alert,) = _alerts(client, rule="service_stopped")
    assert alert["status"] == "open"
    assert alert["severity"] == "critical"
    assert [s["name"] for s in alert["details"]["services"]] == ["WinDefend"]  # not watched

    _inventory(client, registered_agent, services=running)
    (alert,) = _alerts(client, rule="service_stopped")
    assert alert["status"] == "resolved"


@pytest.mark.parametrize(
    "services",
    [
        [_service("WinDefend", "stopped", start_type="disabled")],  # disabled on purpose
        [_service("Spooler", "stopped")],  # not on the watch list
        [],  # services not collected: nothing can be concluded
    ],
)
def test_service_rule_ignores_what_is_not_an_incident(
    client: TestClient, registered_agent: dict[str, Any], services: list[dict[str, Any]]
) -> None:
    _inventory(client, registered_agent, services=services)

    assert _alerts(client, rule="service_stopped") == []


# --- Host events -----------------------------------------------------------------------------


def test_critical_event_opens_an_alert_linked_to_the_event_and_counts_repeats(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    shutdown = _event(1, provider="EventLog", event_code=6008, message="Unexpected shutdown")
    reboot = _event(2, provider="Microsoft-Windows-Kernel-Power", event_code=41, level="critical")
    _events(client, registered_agent, [shutdown])
    _events(client, registered_agent, [shutdown])  # resent batch: not counted again
    _events(client, registered_agent, [reboot])

    (alert,) = _alerts(client, rule="critical_event")
    assert alert["occurrences"] == 2
    assert alert["details"]["event_code"] == 41
    event_ids = {e["event_id"] for e in client.get("/api/v1/events").json()["items"]}
    assert alert["event_id"] in event_ids


def test_ordinary_errors_do_not_alert_until_they_burst(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    count = THRESHOLDS.event_burst_count
    _events(client, registered_agent, [_event(i) for i in range(1, count)])
    assert _alerts(client, rule="event_burst") == []

    _events(client, registered_agent, [_event(count)])
    (alert,) = _alerts(client, rule="event_burst")
    assert alert["details"]["count"] == count

    # Old events (an agent's first-run backlog) are outside the window: no new burst.
    old = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    _events(client, registered_agent, [_event(1000 + i, occurred_at=old) for i in range(count)])
    (alert,) = _alerts(client, rule="event_burst")
    assert alert["occurrences"] == 1


def test_event_alerts_resolve_after_the_quiet_window(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    _events(client, registered_agent, [_event(1, provider="EventLog", event_code=6008)])
    with Session(engine) as session:
        assert AlertService(session, THRESHOLDS).resolve_quiet_event_alerts() == 0
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE alerts SET last_triggered_at = :at"),
            {"at": datetime.now(UTC) - THRESHOLDS.event_quiet - timedelta(minutes=1)},
        )
    with Session(engine) as session:
        assert AlertService(session, THRESHOLDS).resolve_quiet_event_alerts() == 1

    (alert,) = _alerts(client, rule="critical_event")
    assert alert["status"] == "resolved"


# --- Accounts --------------------------------------------------------------------------------


def _account(name: str, *, admin: bool, enabled: bool = True) -> dict[str, Any]:
    return {"name": name, "enabled": enabled, "is_admin": admin, "last_logon": None}


def test_administrator_changes_alert_and_ordinary_account_changes_do_not(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    accounts = [_account("Administrator", admin=True), _account("ana", admin=False)]
    _inventory(client, registered_agent, accounts=accounts)  # baseline: nothing to compare
    _inventory(
        client,
        registered_agent,
        accounts=[
            _account("Administrator", admin=True),
            _account("ana", admin=False, enabled=False),
        ],
    )
    assert _alerts(client, rule="admin_changed") == []  # disabling a user is a change, not an alert

    _inventory(
        client,
        registered_agent,
        accounts=[_account("Administrator", admin=True), _account("ana", admin=True)],
    )
    (alert,) = _alerts(client, rule="admin_changed")
    assert alert["details"]["changes"] == [{"account": "ana", "change": "admin_granted"}]


# --- Lifecycle and listing -------------------------------------------------------------------


def test_acknowledged_alert_stays_active_and_deduplicated_until_resolved(
    client: TestClient,
    engine: Engine,
    registered_agent: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "get_sessionmaker", lambda: sessionmaker(bind=engine))
    shutdown = _event(1, provider="EventLog", event_code=6008)
    _events(client, registered_agent, [shutdown])
    (alert,) = _alerts(client)

    assert cli.main(["ack-alert", alert["alert_id"]]) == 0
    _events(client, registered_agent, [{**shutdown, "record_id": 2}])
    (acknowledged,) = _alerts(client, active="true")
    assert acknowledged["status"] == "acknowledged"
    assert acknowledged["acknowledged_at"]
    assert acknowledged["occurrences"] == 2  # counted on the same alert, no duplicate

    assert cli.main(["resolve-alert", alert["alert_id"]]) == 0
    assert _alerts(client, active="true") == []
    assert cli.main(["ack-alert", alert["alert_id"]]) == 1  # resolved: cannot acknowledge
    assert cli.main(["ack-alert", str(uuid4())]) == 1
    assert "not found" in capsys.readouterr().err


def test_alert_list_filters_search_and_pagination(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    _events(client, registered_agent, [_event(1, provider="EventLog", event_code=6008)])
    _inventory(client, registered_agent, services=[_service("WinDefend", "running")])
    _inventory(client, registered_agent, services=[_service("WinDefend", "stopped")])

    assert {a["rule"] for a in _alerts(client)} == {"critical_event", "service_stopped"}
    assert [a["rule"] for a in _alerts(client, severity="critical", q="windefend")] == [
        "service_stopped"
    ]
    assert _alerts(client, q="100%_literal") == []  # LIKE wildcards are escaped
    page = client.get("/api/v1/alerts", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 2  # all matching alerts, not just this page
    assert len(page["items"]) == 1
    detail = client.get(f"/api/v1/alerts/{page['items'][0]['alert_id']}")
    assert detail.status_code == 200
    assert client.get(f"/api/v1/alerts/{uuid4()}").status_code == 404
    assert client.get("/api/v1/alerts", params={"q": "x" * 201}).status_code == 422


def test_invalid_critical_event_configuration_fails_at_startup() -> None:
    with pytest.raises(ValueError, match="Provider:EventID"):
        Settings(database_url="postgresql+psycopg://x@localhost/x", alert_critical_events="41")
