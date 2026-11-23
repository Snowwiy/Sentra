"""Fase 7D.2 (H06, retención): purgas auditadas e informe de capacidad de solo lectura."""

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.services.capacity_service import capacity_report
from app.services.retention_service import RetentionPolicy, RetentionService, record_purge_audit


def old_event(record_id: int, days: int) -> dict[str, Any]:
    return {
        "source": "windows_eventlog",
        "channel": "System",
        "record_id": record_id,
        "event_code": 7034,
        "provider": "Service Control Manager",
        "level": "error",
        "message": "Service terminated unexpectedly",
        "occurred_at": (datetime.now(UTC) - timedelta(days=days)).isoformat(),
    }


def seed_events(client: TestClient, agent: dict[str, Any]) -> None:
    agent_id = agent["payload"]["agent_id"]
    events = [old_event(1, 40), old_event(2, 35), old_event(3, 1)]
    response = client.post("/api/v1/events", json={"agent_id": agent_id, "events": events})
    assert response.status_code == 201, response.text


def purge_audits(session: Session) -> list[AuditEvent]:
    return list(session.scalars(select(AuditEvent).where(AuditEvent.action == "retention_purge")))


def test_a_purge_that_deletes_rows_is_audited_with_counts_only(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    seed_events(client, registered_agent)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        result = RetentionService(session, RetentionPolicy(None, 30)).purge()
        record_purge_audit(session, result.counts(), "cli")

        assert result.system_events == 2
        audits = purge_audits(session)
        assert len(audits) == 1
        assert audits[0].actor == "system"
        details = audits[0].details or {}
        assert details["trigger"] == "cli"
        assert details["deleted"] == {"system_events": 2}
        assert details["total"] == 2
        # Ni mensajes ni identificadores de lo borrado en la auditoría.
        assert "Service terminated" not in str(details)


def test_an_empty_purge_writes_no_audit(client: TestClient, engine: Engine) -> None:
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        result = RetentionService(session, RetentionPolicy(None, 30)).purge()
        record_purge_audit(session, result.counts(), "scheduled")
        assert purge_audits(session) == []


def test_capacity_report_is_read_only_and_previews_the_retention(
    client: TestClient, engine: Engine, registered_agent: dict[str, Any]
) -> None:
    seed_events(client, registered_agent)
    settings = get_settings().model_copy(update={"event_retention_days": 30})
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        quick = capacity_report(session, settings)
        exact = capacity_report(session, settings, exact=True)

    tables = {item["table"]: item for item in exact["tables"]}
    events = tables["system_events"]
    assert events["retention_setting"] == "EVENT_RETENTION_DAYS"
    assert events["retention_days"] == 30
    assert events["rows_beyond_retention"] == 2
    assert events["oldest_at"] is not None
    # Sin retención configurada: se informa, pero no hay vista previa de borrado.
    assert tables["telemetry_samples"]["retention_days"] is None
    assert tables["telemetry_samples"]["rows_beyond_retention"] is None
    assert tables["audit_events"]["note"] == "sin retención automática"
    # El modo rápido no recorre tablas.
    assert all(item["oldest_at"] is None for item in quick["tables"])
    assert quick["database_bytes"] > 0
    # Nada se borró.
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM system_events")).scalar_one() == 3
