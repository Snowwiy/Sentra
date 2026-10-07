"""Fase 5C.1: eventos Linux del journal de extremo a extremo (ingesta, filtros, reglas, riesgo).

Los eventos tienen la forma exacta que produce agent/sentra_agent/linux_events.py.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from itertools import count
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.models.asset import Asset
from app.risk.queue import request_recalculation
from tests.test_detections import _agent, _ago, _by_rule, _run, _send, fail
from tests.test_risk import _risk

API = "/api/v1"
_records = count(1)


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def lx(
    event_type: str,
    at: datetime,
    *,
    provider: str = "sshd",
    level: str = "warning",
    message: str | None = None,
    **data: str,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "source": "linux_journal",
        "channel": "journal",
        "record_id": next(_records),
        "event_type": event_type,
        "provider": provider,
        "level": level,
        "message": message or f"{provider}: {event_type}",
        "computer": "mint",
        "occurred_at": at.isoformat(),
    }
    if data:
        event["data"] = data
    return event


def ssh_fail(user: str, at: datetime, ip: str = "203.0.113.9") -> dict[str, Any]:
    return lx("auth_failure", at, user=user, source_ip=ip, auth_method="password")


def ssh_ok(user: str, at: datetime, ip: str = "203.0.113.9") -> dict[str, Any]:
    return lx("auth_success", at, level="info", user=user, source_ip=ip, auth_method="password")


def _linux(client: TestClient) -> str:
    return _agent(client, hostname="mint", os_name="Linux")


def _events(client: TestClient, **params: Any) -> list[dict[str, Any]]:
    response = client.get(f"{API}/events", params=params)
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


# --- Ingesta y API -------------------------------------------------------------------------


def test_linux_events_are_stored_without_windows_event_id(client: TestClient) -> None:
    agent = _linux(client)
    accepted = _send(client, agent, [ssh_fail("ana", _ago(1)), ssh_ok("ana", _ago(0.5))])
    assert accepted["stored"] == 2
    items = _events(client)
    assert {e["event_code"] for e in items} == {None}
    assert {e["event_type"] for e in items} == {"auth_failure", "auth_success"}
    assert {e["source"] for e in items} == {"linux_journal"}


def test_resent_linux_events_are_deduplicated(client: TestClient) -> None:
    agent = _linux(client)
    event = ssh_fail("ana", _ago(1))
    _send(client, agent, [event])
    assert _send(client, agent, [event])["stored"] == 0


def test_filters_by_source_provider_and_event_type(client: TestClient) -> None:
    agent = _linux(client)
    _send(
        client,
        agent,
        [
            ssh_fail("ana", _ago(3)),
            lx("sudo_command", _ago(2), provider="sudo", level="info", user="ana", command="ls"),
            lx("service_failed", _ago(1), provider="systemd", level="error", unit="x.service"),
        ],
    )
    assert [e["event_type"] for e in _events(client, provider="sudo")] == ["sudo_command"]
    assert [e["provider"] for e in _events(client, event_type="service_failed")] == ["systemd"]
    assert len(_events(client, min_level="error")) == 1
    assert len(_events(client, q="sudo")) == 1
    bad = client.get(f"{API}/events", params={"event_type": "DROP TABLE"})
    assert bad.status_code == 422


def test_invalid_linux_payloads_are_rejected(client: TestClient) -> None:
    agent = _linux(client)
    bad_type = lx("Auth Failure!", _ago(1))
    for body in (
        {"agent_id": agent, "events": [bad_type]},
        {"agent_id": agent, "events": []},
        {"agent_id": agent, "events": [], "coverage": {"journal": "bogus"}},
        {"agent_id": agent, "events": [], "coverage": {"../x": "active"}},
    ):
        response = client.post(f"{API}/events", json=body)
        assert response.status_code == 422, body


def test_coverage_only_batch_updates_the_asset(client: TestClient, db: Session) -> None:
    agent = _linux(client)
    coverage = {"journal": "no_permission", "sshd": "no_permission", "auditd": "unavailable"}
    response = client.post(
        f"{API}/events", json={"agent_id": agent, "events": [], "coverage": coverage}
    )
    assert response.status_code == 201, response.text
    assert response.json()["received"] == 0
    asset_id = response.json()["asset_id"]
    body = client.get(f"{API}/assets/{asset_id}").json()
    assert body["event_coverage"]["journal"] == "no_permission"
    assert body["event_coverage_at"] is not None


# --- Detección -----------------------------------------------------------------------------


def test_ssh_brute_force_opens_lin_auth_001_and_not_the_windows_rule(
    client: TestClient, engine: Engine
) -> None:
    agent = _linux(client)
    _send(client, agent, [ssh_fail("root", _ago(4 - i * 0.5)) for i in range(6)])
    _run(engine)
    rules = _by_rule(client)
    assert "LIN-AUTH-001" in rules and "AUTH-001" not in rules
    assert "203.0.113.9" in rules["LIN-AUTH-001"]["summary"]


def test_windows_failures_still_open_auth_001_only(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    _send(client, agent, [fail("ana", _ago(4 - i * 0.5)) for i in range(6)])
    _run(engine)
    rules = _by_rule(client)
    assert "AUTH-001" in rules and "LIN-AUTH-001" not in rules


def test_failures_below_threshold_do_not_alert(client: TestClient, engine: Engine) -> None:
    agent = _linux(client)
    _send(client, agent, [ssh_fail("ana", _ago(3)), ssh_fail("ana", _ago(2))])
    _run(engine)
    assert "LIN-AUTH-001" not in _by_rule(client)


def test_failures_then_success_then_sudo_is_critical_lin_auth_002(
    client: TestClient, engine: Engine
) -> None:
    agent = _linux(client)
    events = [ssh_fail("ana", _ago(6 - i * 0.5)) for i in range(5)]
    events.append(ssh_ok("ana", _ago(2)))
    events.append(
        lx(
            "sudo_command",
            _ago(1),
            provider="sudo",
            level="info",
            user="ana",
            target_user="root",
            command="/usr/bin/bash",
        )
    )
    _send(client, agent, events)
    _run(engine)
    detection = _by_rule(client)["LIN-AUTH-002"]
    assert detection["severity"] == "critical"
    assert "sudo" in detection["summary"]


def test_success_without_previous_failures_is_quiet(client: TestClient, engine: Engine) -> None:
    agent = _linux(client)
    _send(client, agent, [ssh_ok("ana", _ago(2))])
    _run(engine)
    assert "LIN-AUTH-002" not in _by_rule(client)


def test_linux_account_and_privileged_group_changes(client: TestClient, engine: Engine) -> None:
    agent = _linux(client)
    _send(
        client,
        agent,
        [
            lx("account_created", _ago(3), provider="useradd", user="backdoor", uid="1001"),
            lx("group_member_added", _ago(2), provider="usermod", user="backdoor", group="sudo"),
            # Un grupo sin privilegios no es ACCT-002.
            lx("group_member_added", _ago(1), provider="usermod", user="ana", group="audio"),
        ],
    )
    _run(engine)
    rules = _by_rule(client)
    assert "ACCT-001" in rules and "ACCT-002" in rules
    assert "backdoor" in rules["ACCT-002"]["summary"]


def test_failed_service_and_kernel_errors(client: TestClient, engine: Engine) -> None:
    agent = _linux(client)
    failures = [
        lx("service_failed", _ago(5 - i), provider="systemd", level="error",
           unit="nginx.service", result="exit-code")
        for i in range(3)
    ]  # fmt: skip
    _send(
        client,
        agent,
        [
            *failures,
            lx("oom_kill", _ago(1), provider="kernel", level="error", process="java", pid="42"),
            lx("service_started", _ago(1), provider="systemd", level="info", unit="x.service"),
        ],
    )
    _run(engine)
    rules = _by_rule(client)
    assert "SYS-002" in rules and "nginx.service" in rules["SYS-002"]["summary"]
    assert "LIN-SYS-001" in rules and "java" in rules["LIN-SYS-001"]["summary"]


def test_informational_linux_events_create_no_detections(
    client: TestClient, engine: Engine
) -> None:
    agent = _linux(client)
    _send(
        client,
        agent,
        [
            lx("session_opened", _ago(2), level="info", user="ana"),
            lx("service_started", _ago(1), provider="systemd", level="info", unit="x.service"),
            lx("ssh_invalid_user", _ago(1), user="oracle", source_ip="198.51.100.4"),
        ],
    )
    _run(engine)
    assert _by_rule(client) == {}


# --- Riesgo: cobertura ----------------------------------------------------------------------


def _coverage_text(client: TestClient, asset_id: str) -> str:
    """Texto del detalle de riesgo: la cobertura aparece en los factores de confianza."""
    response = client.get(f"{API}/risk/assets/{asset_id}")
    assert response.status_code == 200, response.text
    return response.text


def _recalculate(engine: Engine) -> None:
    with sessionmaker(bind=engine)() as session:
        request_recalculation(session, session.scalars(select(Asset.id)).all())
        session.commit()
    _risk(engine)


def test_linux_risk_confidence_follows_journal_coverage(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _linux(client)
    coverage = {"journal": "no_permission", "sshd": "no_permission"}
    response = client.post(
        f"{API}/events", json={"agent_id": agent, "events": [], "coverage": coverage}
    )
    asset_id = response.json()["asset_id"]
    _recalculate(engine)
    assert "Journal de Linux sin permiso de lectura" in _coverage_text(client, asset_id)

    full = {"journal": "active", "sshd": "active", "sudo": "active", "auditd": "unavailable"}
    client.post(f"{API}/events", json={"agent_id": agent, "events": [], "coverage": full})
    _recalculate(engine)
    text = _coverage_text(client, asset_id)
    assert "journal (sin auditd)" in text and "Sin eventos del sistema" not in text

    asset = db.scalars(select(Asset).where(Asset.public_id == asset_id)).one()
    asset.event_coverage_at = datetime.now(UTC) - timedelta(days=2)
    db.commit()
    _recalculate(engine)
    assert "Sin eventos del sistema de este equipo Linux" in _coverage_text(client, asset_id)
