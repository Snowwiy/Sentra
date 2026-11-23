"""Fase 7D.1 (H02, H03): evidencias de endpoint y resultados históricos de herramientas.

Reproducciones controladas con datos sintéticos contra PostgreSQL (sentra_test). Una
detección de comportamiento (BEH-*) copia la línea de comandos, el usuario y el ejecutable
de la telemetría avanzada (que exige telemetry:read) a su resumen, `details` y evidencias.
Antes, un viewer (sin telemetry:read) los leía por /detections, incidentes, informes,
búsqueda e IA. Ahora solo ve la allowlist de campos operativos; la evidencia original no
se modifica y quien tiene el permiso la sigue viendo completa.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.ai.context import ContextBuilder
from app.ai.redaction import Redactor
from app.core.config import get_settings
from app.core.evidence_policy import FULL, RESTRICTED, WITHHELD_NOTE
from app.models.alert import Alert, AlertRule, AlertSeverity, AlertStatus
from app.models.detection import Detection, DetectionEvidence
from app.models.incident import Incident
from app.models.report import Report
from app.models.tool import ToolExecution
from app.models.user import User
from app.risk.config import RiskConfig
from app.services.report_service import ReportWorker
from tests.conftest import _alembic_config, authenticate
from tests.test_risk import _detection, _discovered

API = "/api/v1"
SECRET_CMD = "powershell.exe -enc U0VDUkVULUNNRC03RDE="
SECRET_USER = "CORP\\ana.garcia"
SECRET_EXE = "C:\\Users\\ana.garcia\\AppData\\Roaming\\upd\\svch0st.exe"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _as(client: TestClient, engine: Engine, role: str) -> tuple[TestClient, User]:
    other = TestClient(client.app)
    user = authenticate(other, engine, role)
    return other, user


def _ok(response: Any, status: int = 200) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


def _secret_free(payload: Any) -> bool:
    dumped = json.dumps(payload, ensure_ascii=False, default=str)
    return all(s not in dumped for s in ("U0VDUkVULUNNRC03RDE", "ana.garcia", "svch0st"))


def _endpoint_detection(db: Session) -> Detection:
    asset = _discovered(db, name="PC-FINANZAS")
    detection = _detection(
        db,
        asset,
        rule_id="BEH-003",
        details={
            "cmdline": SECRET_CMD,
            "user": SECRET_USER,
            "exe": SECRET_EXE,
            "findings": ["encoded_command"],
            "rule_version": 1,
        },
    )
    detection.rule_category = "behavior"
    detection.summary = f"{SECRET_EXE} ejecutó {SECRET_CMD} como {SECRET_USER}"
    db.add(
        DetectionEvidence(
            detection_id=detection.id,
            signal_kind="process_start",
            role="trigger",
            source_type="endpoint_activity",
            source_id="1",
            occurred_at=datetime.now(UTC) - timedelta(minutes=3),
            created_at=datetime.now(UTC),
            summary=f"Proceso {SECRET_EXE} ({SECRET_USER})",
            data={
                "cmdline": SECRET_CMD,
                "user": SECRET_USER,
                "exe": SECRET_EXE,
                "cmdline_findings": ["encoded_command"],
                "unusual_location": True,
            },
        )
    )
    db.commit()
    return detection


# --- H02: detecciones, búsqueda e incidentes -------------------------------------------------


def test_h02_viewer_gets_only_the_operational_allowlist(
    client: TestClient, engine: Engine, db: Session
) -> None:
    detection = _endpoint_detection(db)
    viewer, _ = _as(client, engine, "viewer")
    url = f"{API}/detections/{detection.public_id}"

    restricted = _ok(viewer.get(url))
    listed = _ok(viewer.get(f"{API}/detections"))

    assert _secret_free(restricted) and _secret_free(listed)
    assert restricted["restricted"] is True
    assert WITHHELD_NOTE in restricted["summary"]
    assert restricted["details"] == {"findings": ["encoded_command"], "rule_version": 1}
    assert restricted["withheld_details"] == ["cmdline", "exe", "user"]
    evidence = restricted["evidence"][0]
    assert evidence["restricted"] is True
    assert evidence["data"] == {"cmdline_findings": ["encoded_command"], "unusual_location": True}
    assert evidence["withheld_fields"] == ["cmdline", "exe", "user"]
    assert listed["items"][0]["restricted"] is True

    # Quien tiene telemetry:read (analyst) sigue viendo la evidencia completa e intacta.
    analyst, _ = _as(client, engine, "analyst")
    full = _ok(analyst.get(url))
    assert full["restricted"] is False
    assert full["details"]["cmdline"] == SECRET_CMD
    assert full["evidence"][0]["data"]["user"] == SECRET_USER
    db.expire_all()
    stored = db.scalar(
        select(DetectionEvidence).where(DetectionEvidence.detection_id == detection.id)
    )
    assert stored is not None and (stored.data or {})["cmdline"] == SECRET_CMD  # nunca se destruye


def test_h02_search_is_not_an_oracle_for_withheld_text(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _endpoint_detection(db)
    viewer, _ = _as(client, engine, "viewer")
    analyst, _ = _as(client, engine, "analyst")
    for query in ("svch0st", "ana.garcia"):
        assert _ok(viewer.get(f"{API}/detections", params={"q": query}))["total"] == 0
        assert _ok(viewer.get(f"{API}/search", params={"q": query}))["detections"] == []
        assert _ok(analyst.get(f"{API}/detections", params={"q": query}))["total"] == 1
        assert len(_ok(analyst.get(f"{API}/search", params={"q": query}))["detections"]) == 1
    # El título de la regla sí es buscable (es texto fijo del catálogo).
    assert _ok(viewer.get(f"{API}/detections", params={"q": "BEH-003"}))["total"] == 1


def test_h02_incident_copies_and_views_follow_the_reader(
    client: TestClient, engine: Engine, db: Session
) -> None:
    detection = _endpoint_detection(db)
    analyst, _ = _as(client, engine, "analyst")
    incident = _ok(analyst.post(f"{API}/detections/{detection.public_id}/incident"), 201)
    # La descripción por defecto es una copia que lee cualquiera con incidents:read: segura.
    assert _secret_free(incident["description"])
    viewer, _ = _as(client, engine, "viewer")
    base = f"{API}/incidents/{incident['incident_id']}"
    for path in ("", "/timeline", "/evidence"):
        assert _secret_free(_ok(viewer.get(base + path))), path
    full = _ok(analyst.get(base + "/evidence"))
    assert not _secret_free(full)


def test_h02_ai_context_only_contains_what_the_reader_may_read(db: Session) -> None:
    detection = _endpoint_detection(db)
    settings = get_settings()

    def build(access: Any) -> tuple[Any, bool]:
        builder = ContextBuilder(
            db, RiskConfig.from_settings(settings), timedelta(minutes=5), 50, Redactor([]),
            access=access,
        )  # fmt: skip
        return builder.detection(detection.public_id).data, builder.endpoint_content

    restricted, flagged = build(RESTRICTED)
    assert _secret_free(restricted) and flagged is False
    full, flagged = build(FULL)
    assert not _secret_free(full) and flagged is True


# --- H02: informes ---------------------------------------------------------------------------


def test_h02_report_with_endpoint_content_requires_telemetry_read(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _endpoint_detection(db)
    analyst, _ = _as(client, engine, "analyst")
    created = _ok(
        analyst.post(f"{API}/reports", json={"report_type": "detection", "format": "csv"}), 202
    )
    ReportWorker(engine, get_settings()).run_once()
    report = _ok(analyst.get(f"{API}/reports/{created['id']}"))
    assert report["status"] == "succeeded"
    db.expire_all()
    row = db.scalar(select(Report).where(Report.public_id == UUID(created["id"])))
    assert row is not None and row.content_permissions == ["telemetry:read"]

    viewer, _ = _as(client, engine, "viewer")
    assert viewer.get(f"{API}/reports/{created['id']}").status_code in (403, 404)
    assert viewer.get(f"{API}/reports/{created['id']}/artifact").status_code in (403, 404)
    assert all(r["id"] != created["id"] for r in _ok(viewer.get(f"{API}/reports"))["items"])

    # El administrador (con telemetry:read) lo sigue leyendo.
    assert client.get(f"{API}/reports/{created['id']}/artifact").status_code == 200


# --- H03: historial de herramientas ----------------------------------------------------------


def test_h03_tool_history_revalidates_current_permissions(
    client: TestClient, engine: Engine, db: Session
) -> None:
    detection = _endpoint_detection(db)
    analyst, user = _as(client, engine, "analyst")
    run = _ok(
        analyst.post(
            f"{API}/tools/detections.get/execute",
            json={"input": {"detection_id": str(detection.public_id)}},
        )
    )
    assert run["content_withheld"] is False
    assert not _secret_free(run["output"])
    db.expire_all()
    stored = db.scalar(
        select(ToolExecution).where(ToolExecution.public_id == UUID(run["execution_id"]))
    )
    assert stored is not None
    assert "telemetry:read" in stored.read_permissions

    # El rol del analista se degrada: su historial deja de entregar el contenido.
    db.execute(update(User).where(User.id == user.id).values(role="viewer"))
    db.commit()
    detail = _ok(analyst.get(f"{API}/tools/executions/{run['execution_id']}"))
    assert detail["content_withheld"] is True
    assert "telemetry:read" in detail["withheld_permissions"]
    for field in ("input", "output", "summary", "evidence", "provenance"):
        assert not detail.get(field), field
    listing = _ok(analyst.get(f"{API}/tools/executions"))
    assert listing["items"] and all(i["content_withheld"] for i in listing["items"])
    assert _secret_free(listing)
    # La fila original se conserva (y el admin la sigue leyendo completa).
    full = _ok(client.get(f"{API}/tools/executions/{run['execution_id']}"))
    assert full["content_withheld"] is False and not _secret_free(full["output"])


def test_h03_tools_needing_endpoint_detail_deny_restricted_callers(
    client: TestClient, engine: Engine, db: Session
) -> None:
    detection = _endpoint_detection(db)
    analyst, user = _as(client, engine, "analyst")
    db.execute(update(User).where(User.id == user.id).values(role="viewer"))
    db.commit()
    # Un viewer no ejecuta herramientas (tools:execute): la política de 7C-Security-Fix1 sigue.
    denied = analyst.post(
        f"{API}/tools/attribution.explain/execute",
        json={"input": {"detection_id": str(detection.public_id)}},
    )
    assert denied.status_code == 403


# --- Migración 0051: backfill de copias y reversibilidad -------------------------------------


def test_migration_0051_backfills_copies_and_downgrade_restores_them(
    client: TestClient, engine: Engine, db: Session
) -> None:
    detection = _endpoint_detection(db)
    now = datetime.now(UTC)
    alert = Alert(
        asset_id=detection.asset_id,
        rule=AlertRule.SECURITY_DETECTION,
        severity=AlertSeverity.WARNING,
        status=AlertStatus.OPEN,
        message="BEH-003: Detección BEH-003",
        opened_at=now,
        last_triggered_at=now,
        occurrences=1,
        details={"detection_id": str(detection.public_id), "summary": detection.summary[:300]},
    )
    db.add(alert)
    db.commit()
    analyst, _ = _as(client, engine, "analyst")
    created = _ok(analyst.post(f"{API}/detections/{detection.public_id}/incident"), 201)
    # Dato anterior a 7D.1: la descripción era una copia literal del resumen.
    db.execute(
        update(Incident)
        .where(Incident.public_id == UUID(created["incident_id"]))
        .values(description=detection.summary)
    )
    db.commit()
    config = _alembic_config(engine.url.render_as_string(hide_password=False))

    def state() -> tuple[str, str]:
        with engine.connect() as connection:
            summary = connection.execute(
                text("SELECT details->>'summary' FROM alerts WHERE id = :id"), {"id": alert.id}
            ).scalar_one()
            description = connection.execute(
                text("SELECT description FROM incidents WHERE public_id = :id"),
                {"id": created["incident_id"]},
            ).scalar_one()
        return summary, description

    try:
        command.downgrade(config, "0050")
        command.upgrade(config, "0051")
        summary, description = state()
        assert WITHHELD_NOTE in summary and _secret_free(summary)
        assert WITHHELD_NOTE in description and _secret_free(description)
        command.downgrade(config, "0050")
        summary, description = state()
        assert summary == detection.summary[:300]
        assert description == detection.summary
    finally:
        command.upgrade(config, "head")
