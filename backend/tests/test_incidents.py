"""Gestión de incidentes SOC (Fase 4K): API de extremo a extremo con PostgreSQL real.

Los datos son sintéticos (activos y detecciones de test), nunca de un entorno real. Cubre
creación manual y por promoción, state machine, asignación, notas, resolución, cierre,
reapertura, merge, RBAC, CSRF, auditoría, concurrencia (409), timeline, evidencia, riesgo,
sugerencias de duplicados, búsqueda, filtros, orden y paginación.
"""

import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.incidents import workflow
from app.models.alert import Alert, AlertRule, AlertSeverity, AlertStatus
from app.models.asset import Asset, AssetCriticality
from app.models.audit import AuditEvent
from app.models.detection import (
    DetectionConfidence,
    DetectionEvidence,
    DetectionSeverity,
)
from app.models.incident import (
    IncidentFeedback,
    IncidentLevel,
    IncidentStatus,
)
from app.models.risk import AssetRisk
from app.models.user import User
from tests.conftest import authenticate, create_user
from tests.test_risk import _detection, _discovered, _port, _risk

API = "/api/v1"
S = IncidentStatus


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _ok(response: Any, status: int = 200) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


def _error(response: Any, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()["error"]
    assert body["code"] == code, body
    return body


def _audit(db: Session, action: str, result: str | None = None) -> list[AuditEvent]:
    db.expire_all()
    stmt = select(AuditEvent).where(AuditEvent.action == action)
    if result:
        stmt = stmt.where(AuditEvent.result == result)
    return list(db.scalars(stmt.order_by(AuditEvent.id)))


def _create(client: TestClient, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "title": "Actividad sospechosa en servidor de ficheros",
        "severity": "high",
        "priority": "medium",
        **overrides,
    }
    return _ok(client.post(f"{API}/incidents", json=payload), 201)


def _patch(client: TestClient, incident: dict[str, Any], **fields: Any) -> Any:
    return client.patch(
        f"{API}/incidents/{incident['incident_id']}",
        json={"version": incident["version"], **fields},
    )


def _post(client: TestClient, incident: dict[str, Any], action: str, **body: Any) -> Any:
    return client.post(
        f"{API}/incidents/{incident['incident_id']}/{action}",
        json={"version": incident["version"], **body},
    )


def _get(client: TestClient, incident_id: str) -> dict[str, Any]:
    return _ok(client.get(f"{API}/incidents/{incident_id}"))


def _second_client(client: TestClient, engine: Engine, role: str, name: str) -> TestClient:
    """Otro navegador (otra sesión) contra la misma app: varios operadores a la vez."""
    other = TestClient(client.app)
    authenticate(other, engine, role, name)
    return other


# --- State machine (unidad, sin base de datos) ------------------------------------------------


def test_state_machine_is_explicit_and_closed() -> None:
    assert workflow.patch_targets(S.OPEN) == [S.TRIAGE, S.INVESTIGATING]
    assert workflow.patch_targets(S.TRIAGE) == [S.INVESTIGATING]
    assert workflow.patch_targets(S.INVESTIGATING) == [S.CONTAINED]
    assert workflow.patch_targets(S.CONTAINED) == [S.INVESTIGATING]
    assert workflow.patch_targets(S.RESOLVED) == [S.INVESTIGATING]
    assert workflow.patch_targets(S.CLOSED) == []
    assert workflow.patch_targets(S.MERGED) == []
    assert workflow.can_resolve(S.TRIAGE) and not workflow.can_resolve(S.OPEN)
    assert workflow.can_close(S.RESOLVED) and not workflow.can_close(S.INVESTIGATING)
    assert workflow.can_reopen(S.CLOSED) and not workflow.can_reopen(S.RESOLVED)
    # Todos los estados tienen entrada: un estado nuevo sin transiciones definidas falla aquí.
    assert set(workflow.TRANSITIONS) == set(IncidentStatus)


def test_priority_suggestion_is_context_not_a_rigid_mapping() -> None:
    lv = IncidentLevel
    assert workflow.suggested_priority(lv.MEDIUM, None, None) == lv.MEDIUM
    assert workflow.suggested_priority(lv.MEDIUM, "critical", None) == lv.HIGH
    assert workflow.suggested_priority(lv.MEDIUM, "low", "high") == lv.HIGH
    # Nunca más de un escalón ni por encima de critical; el riesgo bajo no la reduce.
    assert workflow.suggested_priority(lv.CRITICAL, "critical", "high") == lv.CRITICAL
    assert workflow.suggested_priority(lv.HIGH, "informational", "low") == lv.HIGH
    assert workflow.incident_key(42) == "INC-000042"
    assert workflow.confidence_from_detections([]) is None


# --- Creación manual ---------------------------------------------------------------------------


def test_manual_creation_numbers_audits_and_relates_assets(client: TestClient, db: Session) -> None:
    asset = _discovered(db, name="srv-files")
    first = _create(client, asset_ids=[str(asset.public_id)], description="Accesos raros")
    second = _create(client, title="Otro caso")

    assert first["key"] == "INC-000001" and second["key"] == "INC-000002"
    assert first["number"] == 1 and first["status"] == "open" and first["version"] == 1
    assert first["created_by"]["username"] == "admin"
    # Sin evidencia, la confianza no se inventa.
    assert first["confidence"] is None
    assert first["first_seen_at"] is None and first["last_seen_at"] is None
    assert [a["name"] for a in first["asset_refs"]] == ["srv-files"]
    assert first["assets"] == ["srv-files"] and first["asset_count"] == 1
    assert first["allowed_transitions"] == ["triage", "investigating"]
    (event,) = [e for e in _audit(db, "incident_created") if e.target_id == first["incident_id"]]
    assert event.result == "success" and event.details is not None
    assert event.details["incident"] == "INC-000001" and event.details["source"] == "manual"


def test_forged_or_unknown_asset_relation_is_rejected(client: TestClient, db: Session) -> None:
    response = client.post(
        f"{API}/incidents",
        json={"title": "Caso", "severity": "low", "priority": "low", "asset_ids": [str(uuid4())]},
    )
    _error(response, 422, "incident_invalid_reference")
    assert _ok(client.get(f"{API}/incidents"))["total"] == 0
    assert _audit(db, "incident_created", "failure")
    # Campos desconocidos (p. ej. evidencia inyectada) se rechazan por contrato.
    response = client.post(
        f"{API}/incidents",
        json={"title": "Caso", "severity": "low", "priority": "low", "evidence": [{"x": 1}]},
    )
    assert response.status_code == 422
    incident = _create(client)
    _error(
        client.post(f"{API}/incidents/{incident['incident_id']}/assets/{uuid4()}"),
        422,
        "incident_invalid_reference",
    )


# --- Promoción desde detección y alerta ---------------------------------------------------------


def test_detection_promotion_reuses_detection_and_never_copies_evidence(
    client: TestClient, db: Session
) -> None:
    asset = _discovered(db, name="pc-ana", criticality=AssetCriticality.HIGH)
    detection = _detection(
        db, asset, rule_id="AUTH-001", severity=DetectionSeverity.MEDIUM,
        confidence=DetectionConfidence.MEDIUM, details={"account": "ana"},
    )  # fmt: skip
    for i in range(3):
        db.add(
            DetectionEvidence(
                detection_id=detection.id, signal_kind="auth_failure", role="failure",
                source_type="system_event", source_id=f"ev-{i}",
                occurred_at=detection.first_seen_at,
                summary=f"Fallo {i}", data={"account": "ana"}, created_at=datetime.now(UTC),
            )
        )  # fmt: skip
    db.commit()
    _risk(engine_of(db))
    evidence_before = db.scalar(select(func.count()).select_from(DetectionEvidence))

    incident = _ok(client.post(f"{API}/detections/{detection.public_id}/incident"), 201)

    assert incident["title"] == detection.title
    assert incident["severity"] == "medium"
    # Activo con criticidad alta: prioridad sugerida un escalón por encima de la gravedad.
    assert incident["priority"] == "high"
    assert incident["confidence"] == "medium"
    assert [d["detection_id"] for d in incident["detections"]] == [str(detection.public_id)]
    assert incident["asset_refs"][0]["asset_id"] == str(asset.public_id)
    assert incident["first_seen_at"] is not None
    # La evidencia se referencia; no se duplica ninguna fila.
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(DetectionEvidence)) == evidence_before
    evidence = _ok(client.get(f"{API}/incidents/{incident['incident_id']}/evidence"))
    assert evidence["events_total"] == 3
    assert {e["source_id"] for e in evidence["events"]} == {"ev-0", "ev-1", "ev-2"}

    # Promover otra vez la misma detección: 409 con el caso existente (sin incident flood).
    body = _error(
        client.post(f"{API}/detections/{detection.public_id}/incident"),
        409,
        "incident_already_linked",
    )
    assert body["details"][0]["key"] == incident["key"]
    assert _ok(client.get(f"{API}/incidents"))["total"] == 1


def engine_of(db: Session) -> Engine:
    bind = db.get_bind()
    assert isinstance(bind, Engine)
    return bind


def _alert(db: Session, asset: Asset, **overrides: Any) -> Alert:
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "asset_id": asset.id,
        "rule": AlertRule.SECURITY_DETECTION,
        "severity": AlertSeverity.CRITICAL,
        "status": AlertStatus.OPEN,
        "message": "Detección grave en el activo",
        "opened_at": now - timedelta(minutes=5),
        "last_triggered_at": now - timedelta(minutes=1),
        **overrides,
    }
    alert = Alert(**values)
    db.add(alert)
    db.commit()
    return alert


def test_alert_promotion_reuses_its_detection_without_creating_one(
    client: TestClient, db: Session
) -> None:
    asset = _discovered(db, name="srv-db")
    alert = _alert(db, asset)
    detection = _detection(db, asset, rule_id="DEF-001", severity=DetectionSeverity.CRITICAL)
    detection.alert_id = alert.id
    db.commit()
    detections_before = _ok(client.get(f"{API}/detections"))["total"]

    incident = _ok(
        client.post(f"{API}/alerts/{alert.public_id}/incident", json={"priority": "low"}), 201
    )

    assert _ok(client.get(f"{API}/detections"))["total"] == detections_before
    assert incident["severity"] == "critical"
    # La prioridad explícita del analista manda (no hay mapeo rígido desde la severidad).
    assert incident["priority"] == "low"
    assert [a["alert_id"] for a in incident["alerts"]] == [str(alert.public_id)]
    assert [d["detection_id"] for d in incident["detections"]] == [str(detection.public_id)]
    _error(client.post(f"{API}/alerts/{alert.public_id}/incident"), 409, "incident_already_linked")
    _error(client.post(f"{API}/alerts/{uuid4()}/incident"), 404, "not_found")
    _error(client.post(f"{API}/detections/{uuid4()}/incident"), 404, "not_found")


def test_alert_without_detection_and_attach_alert(client: TestClient, db: Session) -> None:
    asset = _discovered(db, name="nas")
    alert = _alert(db, asset, rule=AlertRule.ASSET_OFFLINE, severity=AlertSeverity.WARNING)
    incident = _ok(client.post(f"{API}/alerts/{alert.public_id}/incident"), 201)
    assert incident["severity"] == "medium" and incident["confidence"] is None
    assert incident["detections"] == []

    other = _create(client)
    second = _alert(db, asset, rule=AlertRule.PORT_EXPOSED)
    after = _ok(client.post(f"{API}/incidents/{other['incident_id']}/alerts/{second.public_id}"))
    assert [a["alert_id"] for a in after["alerts"]] == [str(second.public_id)]
    assert after["asset_refs"][0]["name"] == "nas"
    # Idempotente: repetirlo no duplica la relación.
    again = _ok(client.post(f"{API}/incidents/{other['incident_id']}/alerts/{second.public_id}"))
    assert again["alerts_total"] == 1
    assert len(_audit(db, "incident_alert_attached")) == 1


# --- Sugerencias y adjuntar ---------------------------------------------------------------------


def test_related_detection_suggests_existing_incident_and_attaches_without_duplicate(
    client: TestClient, db: Session
) -> None:
    asset = _discovered(db, name="pc-ana")
    first = _detection(db, asset, rule_id="AUTH-001", details={"account": "ana"})
    incident = _ok(client.post(f"{API}/detections/{first.public_id}/incident"), 201)
    related = _detection(db, asset, rule_id="CORR-001", kind="correlation",
                         details={"account": "ANA"})  # fmt: skip

    suggestions = _ok(client.get(f"{API}/detections/{related.public_id}/related-incidents"))
    (item,) = suggestions["items"]
    assert item["incident"]["incident_id"] == incident["incident_id"]
    assert {"same_asset", "same_account", "time_window"} <= set(item["reasons"])
    assert suggestions["suggested_severity"] == "high"

    attached = _ok(
        client.post(f"{API}/incidents/{incident['incident_id']}/detections/{related.public_id}")
    )
    assert attached["detections_total"] == 2
    # Ya adjunta: la sugerencia lo dice y promoverla de nuevo no crea otro caso.
    suggestions = _ok(client.get(f"{API}/detections/{related.public_id}/related-incidents"))
    assert "already_linked" in suggestions["items"][0]["reasons"]
    _error(
        client.post(f"{API}/detections/{related.public_id}/incident"),
        409,
        "incident_already_linked",
    )
    assert _ok(client.get(f"{API}/incidents"))["total"] == 1
    assert _audit(db, "incident_detection_attached")


def test_unrelated_detection_gets_no_suggestion(client: TestClient, db: Session) -> None:
    a = _discovered(db, name="pc-a")
    b = _discovered(db, name="pc-b")
    _ok(
        client.post(f"{API}/detections/{_detection(db, a, rule_id='AUTH-001').public_id}/incident"),
        201,
    )
    lonely = _detection(db, b, rule_id="NET-001", minutes_ago=60 * 24 * 5)
    assert _ok(client.get(f"{API}/detections/{lonely.public_id}/related-incidents"))["items"] == []
    _error(client.get(f"{API}/detections/{uuid4()}/related-incidents"), 404, "not_found")


def test_evidence_overlap_is_a_reason(client: TestClient, db: Session) -> None:
    asset = _discovered(db, name="pc-x")
    other_asset = _discovered(db, name="pc-y")
    d1 = _detection(db, asset, rule_id="AUTH-001")
    d2 = _detection(db, other_asset, rule_id="PROC-001")
    now = datetime.now(UTC)
    for d in (d1, d2):
        db.add(DetectionEvidence(detection_id=d.id, signal_kind="s", source_type="system_event",
                                 source_id="shared-event", occurred_at=now, summary="x",
                                 created_at=now))  # fmt: skip
    db.commit()
    incident = _ok(client.post(f"{API}/detections/{d1.public_id}/incident"), 201)
    (item,) = _ok(client.get(f"{API}/detections/{d2.public_id}/related-incidents"))["items"]
    assert item["incident"]["incident_id"] == incident["incident_id"]
    assert "evidence_overlap" in item["reasons"]


# --- Workflow completo y auditoría ---------------------------------------------------------------


def test_full_workflow_detection_to_closed_with_complete_audit(
    client: TestClient, db: Session, engine: Engine
) -> None:
    """QA e2e principal: detección -> caso -> asignar -> triage -> investigar -> nota ->
    evidencia -> riesgo -> resolver -> cerrar, con auditoría completa."""
    asset = _discovered(db, name="srv-erp")
    _port(db, asset, 3389)
    detection = _detection(db, asset, rule_id="AUTH-002", severity=DetectionSeverity.HIGH)
    _risk(engine)
    risk_before = db.get(AssetRisk, asset.id)
    assert risk_before is not None and risk_before.calculated_at is not None
    score_before, dirty_before = risk_before.score, risk_before.dirty_at

    incident = _ok(client.post(f"{API}/detections/{detection.public_id}/incident"), 201)
    assert incident["risk"]["snapshot"]["score"] == score_before
    analyst = create_user(db, "ana-analyst", "analyst")

    incident = _ok(_post(client, incident, "assign", user_id=str(analyst.public_id)))
    assert incident["owner"]["username"] == "ana-analyst"
    assert incident["assigned_by"]["username"] == "admin"
    incident = _ok(_patch(client, incident, status="triage"))
    assert incident["triaged_at"] is not None
    incident = _ok(_patch(client, incident, status="investigating"))
    note = _ok(
        client.post(f"{API}/incidents/{incident['incident_id']}/notes", json={"body": "Revisado"}),
        201,
    )
    assert note["author"] == "admin" and note["incident_key"] == incident["key"]
    evidence = _ok(client.get(f"{API}/incidents/{incident['incident_id']}/evidence"))
    assert [d["rule_id"] for d in evidence["detections"]] == ["AUTH-002"]
    assert [p["port"] for p in evidence["exposure"]] == [3389]
    incident = _get(client, incident["incident_id"])
    (risk,) = incident["risk"]["assets"]
    assert risk["evaluated"] and risk["score"] == score_before and risk["top_contributors"]
    incident = _ok(
        _post(client, incident, "resolve", category="true_positive", summary="Contraseña rotada")
    )
    assert incident["status"] == "resolved" and incident["resolution_category"] == "true_positive"
    assert incident["metrics"]["time_to_resolve_seconds"] is not None
    incident = _ok(_post(client, incident, "close"))
    assert incident["status"] == "closed" and incident["allowed_transitions"] == []

    # El módulo de incidentes nunca recalcula ni encola el riesgo (4I es la única fuente).
    db.expire_all()
    risk_after = db.get(AssetRisk, asset.id)
    assert risk_after is not None
    assert (risk_after.score, risk_after.dirty_at) == (score_before, dirty_before)

    actions = [
        e.action
        for e in db.scalars(
            select(AuditEvent)
            .where(AuditEvent.target_id == incident["incident_id"])
            .order_by(AuditEvent.id)
        )
    ]
    assert actions == [
        "incident_created",
        "incident_assigned",
        "incident_status_changed",
        "incident_status_changed",
        "incident_note_added",
        "incident_resolved",
        "incident_closed",
    ]
    audit = _ok(client.get(f"{API}/incidents/{incident['incident_id']}/audit"))
    assert audit["total"] == 7
    # El texto de la nota nunca va a la auditoría.
    assert all("Revisado" not in str(e["details"]) for e in audit["items"])

    timeline = _ok(client.get(f"{API}/incidents/{incident['incident_id']}/timeline?limit=200"))
    sources = {i["source_type"] for i in timeline["items"]}
    assert {"incident", "note", "detection"} <= sources
    actions_tl = {i["action"] for i in timeline["items"] if i["source_type"] == "incident"}
    assert {"created", "assigned", "status_changed", "resolved", "closed", "risk_snapshot"} <= (
        actions_tl
    )
    stamps = [i["occurred_at"] for i in timeline["items"]]
    assert stamps == sorted(stamps, reverse=True)
    detection_item = next(i for i in timeline["items"] if i["source_type"] == "detection")
    # Hora real de la detección, no la del adjunto.
    assert detection_item["occurred_at"].startswith(detection.first_seen_at.isoformat()[:16])


def test_invalid_transitions_are_rejected(client: TestClient, db: Session) -> None:
    incident = _create(client)
    for target in ("contained", "resolved", "closed", "merged"):
        _error(_patch(client, incident, status=target), 409, "incident_invalid_state")
    _error(_post(client, incident, "resolve", category="other"), 409, "incident_invalid_state")
    _error(_post(client, incident, "close"), 409, "incident_invalid_state")
    _error(_post(client, incident, "reopen"), 409, "incident_invalid_state")
    _error(_patch(client, incident, status="bogus"), 422, "validation_error")
    assert _get(client, incident["incident_id"])["version"] == 1
    assert _audit(db, "incident_status_changed", "failure")


def test_resolution_requires_category_and_duplicate_reference(
    client: TestClient, db: Session
) -> None:
    main = _create(client, title="Principal")
    dup = _create(client, title="Duplicado")
    dup = _ok(_patch(client, dup, status="triage"))
    assert _post(client, dup, "resolve").status_code == 422
    _error(
        _post(client, dup, "resolve", category="other", duplicate_of=main["incident_id"]),
        422,
        "incident_invalid_reference",
    )
    _error(
        _post(client, dup, "resolve", category="duplicate", duplicate_of=dup["incident_id"]),
        422,
        "incident_invalid_reference",
    )
    resolved = _ok(
        _post(client, dup, "resolve", category="duplicate", duplicate_of=main["incident_id"])
    )
    assert resolved["duplicate_of"]["key"] == main["key"]
    # Duplicate no es merge: nada se mueve al principal y el duplicado no queda "merged".
    assert resolved["status"] == "resolved"
    assert _get(client, main["incident_id"])["merged_from"] == []
    # Volver a investigar invalida la resolución vigente.
    reopened = _ok(_patch(client, resolved, status="investigating"))
    assert reopened["resolution_category"] is None and reopened["duplicate_of"] is None


def test_false_positive_feedback_is_stored_without_touching_rules(
    client: TestClient, db: Session
) -> None:
    asset = _discovered(db)
    detection = _detection(db, asset, rule_id="AUTH-001", severity=DetectionSeverity.HIGH)
    incident = _ok(client.post(f"{API}/detections/{detection.public_id}/incident"), 201)
    incident = _ok(_patch(client, incident, status="triage"))
    _ok(_post(client, incident, "resolve", category="false_positive", summary="Backup nocturno"))

    (feedback,) = db.scalars(select(IncidentFeedback)).all()
    assert (feedback.rule_id, feedback.verdict, feedback.reason) == (
        "AUTH-001",
        "false_positive",
        "Backup nocturno",
    )
    db.expire_all()
    # Ni severidad ni estado de la detección cambian; las reglas siguen activas.
    refreshed = _ok(client.get(f"{API}/detections/{detection.public_id}"))
    assert refreshed["severity"] == "high" and refreshed["status"] == "open"
    rules = _ok(client.get(f"{API}/detection-rules"))["items"]
    assert next(r for r in rules if r["rule_id"] == "AUTH-001")["enabled"] is True


def test_closed_incident_cannot_be_silently_modified_and_reopen(
    client: TestClient, db: Session
) -> None:
    incident = _create(client)
    incident = _ok(_patch(client, incident, status="triage"))
    incident = _ok(_post(client, incident, "resolve", category="benign_activity"))
    incident = _ok(_post(client, incident, "close"))
    iid = incident["incident_id"]
    _error(_patch(client, incident, title="Nuevo título"), 409, "incident_invalid_state")
    _error(client.post(f"{API}/incidents/{iid}/notes", json={"body": "x"}), 409,
           "incident_invalid_state")  # fmt: skip
    _error(_post(client, incident, "assign"), 409, "incident_invalid_state")
    asset = _discovered(db)
    _error(client.post(f"{API}/incidents/{iid}/assets/{asset.public_id}"), 409,
           "incident_invalid_state")  # fmt: skip
    assert _get(client, iid)["title"] == incident["title"]

    reopened = _ok(_post(client, incident, "reopen"))
    assert reopened["status"] == "open"
    assert reopened["resolution_category"] is None and reopened["closed_at"] is None
    assert _audit(db, "incident_reopened")


# --- Asignación ---------------------------------------------------------------------------------


def test_assignment_policy_inactive_and_viewer_owners(
    client: TestClient, db: Session, engine: Engine
) -> None:
    incident = _create(client)
    viewer = create_user(db, "vera", "viewer")
    inactive = create_user(db, "old-analyst", "analyst", active=False)
    _error(_post(client, incident, "assign", user_id=str(viewer.public_id)), 422,
           "incident_invalid_reference")  # fmt: skip
    _error(_post(client, incident, "assign", user_id=str(inactive.public_id)), 422,
           "incident_invalid_reference")  # fmt: skip
    _error(_post(client, incident, "assign", user_id=str(uuid4())), 422,
           "incident_invalid_reference")  # fmt: skip
    assert _get(client, incident["incident_id"])["owner"] is None

    analyst_client = _second_client(client, engine, "analyst", "alice")
    other = create_user(db, "bob", "analyst")
    # Un analyst no asigna a otros...
    _error(_post(analyst_client, incident, "assign", user_id=str(other.public_id)), 422,
           "incident_invalid_reference")  # fmt: skip
    # ...pero sí a sí mismo.
    mine = _ok(_post(analyst_client, incident, "assign"))
    assert mine["owner"]["username"] == "alice"
    # Admin reasigna; luego el analyst ya no puede quitárselo a otro.
    reassigned = _ok(_post(client, mine, "assign", user_id=str(other.public_id)))
    assert reassigned["owner"]["username"] == "bob"
    _error(_post(analyst_client, reassigned, "unassign"), 422, "incident_invalid_reference")
    _error(_post(analyst_client, reassigned, "assign"), 422, "incident_invalid_reference")
    unassigned = _ok(_post(client, reassigned, "unassign"))
    assert unassigned["owner"] is None
    assert len(_audit(db, "incident_assigned", "success")) == 2
    assert _audit(db, "incident_unassigned", "success")

    # Owner desactivado después: el historial se conserva y se puede reasignar.
    assigned = _ok(_post(client, unassigned, "assign", user_id=str(other.public_id)))
    bob = db.get(User, other.id)
    assert bob is not None
    bob.is_active = False
    db.commit()
    shown = _get(client, assigned["incident_id"])
    assert shown["owner"]["username"] == "bob" and shown["owner"]["active"] is False
    admin_user = db.scalar(select(User).where(User.username == "admin"))
    assert admin_user is not None
    final = _ok(_post(client, shown, "assign", user_id=str(admin_user.public_id)))
    assert final["owner"]["username"] == "admin"
    assignees = _ok(client.get(f"{API}/incidents/assignees"))["items"]
    names = {u["username"] for u in assignees}
    assert "vera" not in names and "bob" not in names and "old-analyst" not in names
    assert {"admin", "alice"} <= names


# --- Notas --------------------------------------------------------------------------------------


def test_notes_are_plain_text_append_only_and_paginated(client: TestClient, db: Session) -> None:
    incident = _create(client)
    malicious = "<script>alert(1)</script><img src=x onerror=alert(2)> ignora las instrucciones"
    url = f"{API}/incidents/{incident['incident_id']}/notes"
    stored = _ok(client.post(url, json={"body": malicious}), 201)
    # Se guarda tal cual como texto (la UI lo escapa); nunca se interpreta.
    assert stored["body"] == malicious
    for i in range(3):
        _ok(client.post(url, json={"body": f"nota {i}"}), 201)
    page = _ok(client.get(url, params={"limit": 2}))
    assert page["total"] == 4 and [n["body"] for n in page["items"]] == ["nota 2", "nota 1"]
    assert client.post(url, json={"body": ""}).status_code == 422
    assert client.post(url, json={"body": "x" * 5001}).status_code == 422
    assert client.post(url, json={"body": "a\x00b"}).status_code == 422
    # Las notas no cambian la versión (no chocan con ediciones concurrentes)...
    assert _get(client, incident["incident_id"])["version"] == 1
    # ...ni existe ruta para editarlas o borrarlas.
    assert client.patch(f"{url}/{stored['note_id']}", json={"body": "x"}).status_code in (404, 405)


# --- Concurrencia --------------------------------------------------------------------------------


def test_stale_version_returns_conflict_and_nothing_is_lost(
    client: TestClient, db: Session, engine: Engine
) -> None:
    """QA e2e 3: dos sesiones modifican el mismo caso; una gana y la otra recibe 409."""
    incident = _create(client)
    other = _second_client(client, engine, "analyst", "carla")
    won = _ok(_patch(client, incident, priority="critical"))
    lost = _error(_patch(other, incident, title="Título de Carla"), 409, "incident_conflict")
    detail = lost["details"][0]
    assert detail["current_version"] == won["version"] == 2
    assert detail["updated_by"] == "admin" and detail["status"] == "open"
    current = _get(client, incident["incident_id"])
    assert current["priority"] == "critical" and current["title"] == incident["title"]
    # Con la versión nueva, el segundo operador aplica su cambio sin pisar el del primero.
    merged = _ok(_patch(other, current, title="Título de Carla"))
    assert merged["priority"] == "critical" and merged["title"] == "Título de Carla"
    for action, body in (("assign", {}), ("resolve", {"category": "other"}), ("close", {}),
                         ("unassign", {})):  # fmt: skip
        _error(_post(client, incident, action, **body), 409, "incident_conflict")
    assert _audit(db, "incident_updated", "failure")


def test_concurrent_status_changes_serialize(
    client: TestClient, engine: Engine, db: Session
) -> None:
    incident = _create(client)
    clients = [client, _second_client(client, engine, "analyst", "dani")]
    results: list[int] = []
    barrier = threading.Barrier(2)

    def change(c: TestClient, target: str) -> None:
        barrier.wait()
        results.append(_patch(c, incident, status=target).status_code)

    threads = [
        threading.Thread(target=change, args=(c, t))
        for c, t in zip(clients, ("triage", "investigating"), strict=True)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [200, 409]
    final = _get(client, incident["incident_id"])
    assert final["version"] == 2 and final["status"] in ("triage", "investigating")


# --- Merge --------------------------------------------------------------------------------------


def test_merge_preserves_history_and_rejects_invalid_merges(
    client: TestClient, db: Session
) -> None:
    asset_a = _discovered(db, name="pc-a")
    asset_b = _discovered(db, name="pc-b")
    det_a = _detection(db, asset_a, rule_id="AUTH-001")
    det_b = _detection(db, asset_b, rule_id="AUTH-002")
    target = _ok(client.post(f"{API}/detections/{det_a.public_id}/incident"), 201)
    source = _ok(client.post(f"{API}/detections/{det_b.public_id}/incident"), 201)
    _ok(client.post(f"{API}/incidents/{source['incident_id']}/notes", json={"body": "Nota B"}), 201)
    source = _get(client, source["incident_id"])

    _error(_post(client, source, "merge", target_id=source["incident_id"], target_version=1), 422,
           "incident_invalid_reference")  # fmt: skip
    _error(_post(client, source, "merge", target_id=str(uuid4()), target_version=1), 422,
           "incident_invalid_reference")  # fmt: skip
    _error(_post(client, source, "merge", target_id=target["incident_id"], target_version=99),
           409, "incident_conflict")  # fmt: skip

    merged = _ok(
        _post(client, source, "merge", target_id=target["incident_id"],
              target_version=target["version"])
    )  # fmt: skip
    assert merged["incident_id"] == target["incident_id"]
    assert merged["detections_total"] == 2
    assert {a["name"] for a in merged["asset_refs"]} == {"pc-a", "pc-b"}
    assert [m["key"] for m in merged["merged_from"]] == [source["key"]]
    notes = _ok(client.get(f"{API}/incidents/{target['incident_id']}/notes"))
    assert [(n["body"], n["incident_key"]) for n in notes["items"]] == [("Nota B", source["key"])]
    timeline = _ok(client.get(f"{API}/incidents/{target['incident_id']}/timeline?limit=200"))
    assert source["key"] in {i["incident_key"] for i in timeline["items"]}
    # Una detección presente en ambos no aparece duplicada.
    assert len([i for i in timeline["items"] if i["source_type"] == "detection"]) == 2

    absorbed = _get(client, source["incident_id"])
    assert absorbed["status"] == "merged" and absorbed["merged_into"]["key"] == target["key"]
    assert absorbed["key"] == source["key"] and absorbed["detections_total"] == 1
    # Merge repetido o circular: rechazado.
    _error(_post(client, absorbed, "merge", target_id=target["incident_id"],
                 target_version=merged["version"]), 409, "incident_invalid_state")  # fmt: skip
    _error(_post(client, merged, "merge", target_id=source["incident_id"],
                 target_version=absorbed["version"]), 409, "incident_invalid_state")  # fmt: skip
    _error(_patch(client, absorbed, title="Nuevo título"), 409, "incident_invalid_state")
    (event,) = _audit(db, "incident_merged", "success")
    assert event.details is not None
    assert event.details["target"] == target["key"] and event.details["detections"] == 1


# --- RBAC y CSRF --------------------------------------------------------------------------------


def test_viewer_is_read_only(client: TestClient, db: Session, engine: Engine) -> None:
    asset = _discovered(db)
    detection = _detection(db, asset)
    incident = _create(client, asset_ids=[str(asset.public_id)])
    viewer = _second_client(client, engine, "viewer", "victor")
    iid = incident["incident_id"]
    for path in ("", "/timeline", "/evidence", "/notes", "/audit"):
        assert viewer.get(f"{API}/incidents/{iid}{path}").status_code == 200
    assert viewer.get(f"{API}/incidents").status_code == 200
    assert viewer.get(f"{API}/incidents/overview").status_code == 200
    denied = [
        viewer.post(
            f"{API}/incidents", json={"title": "abc", "severity": "low", "priority": "low"}
        ),
        _patch(viewer, incident, title="x"),
        _post(viewer, incident, "assign"),
        _post(viewer, incident, "resolve", category="other"),
        viewer.post(f"{API}/incidents/{iid}/notes", json={"body": "x"}),
        viewer.post(f"{API}/detections/{detection.public_id}/incident"),
        viewer.post(f"{API}/incidents/{iid}/detections/{detection.public_id}"),
        viewer.get(f"{API}/incidents/assignees"),
    ]
    assert {r.status_code for r in denied} == {403}
    assert _get(client, iid)["version"] == 1
    assert _audit(db, "permission_denied")


def test_analyst_cannot_close_reopen_or_merge(
    client: TestClient, db: Session, engine: Engine
) -> None:
    analyst = _second_client(client, engine, "analyst", "anna")
    incident = _create(analyst)
    incident = _ok(_patch(analyst, incident, status="triage"))
    incident = _ok(_post(analyst, incident, "resolve", category="other"))
    other = _create(analyst)
    assert _post(analyst, incident, "close").status_code == 403
    assert _post(analyst, incident, "merge", target_id=other["incident_id"],
                 target_version=1).status_code == 403  # fmt: skip
    closed = _ok(_post(client, incident, "close"))
    assert _post(analyst, closed, "reopen").status_code == 403


def test_mutations_require_csrf(client: TestClient, engine: Engine) -> None:
    incident = _create(client)
    token = client.headers.pop("X-CSRF-Token")
    try:
        response = _patch(client, incident, title="sin csrf")
        _error(response, 403, "csrf_failed")
        anonymous = TestClient(client.app)
        assert anonymous.get(f"{API}/incidents").status_code == 401
    finally:
        client.headers["X-CSRF-Token"] = token


# --- Listado, filtros, búsqueda, orden, paginación y overview -----------------------------------


def test_list_filters_search_sorting_pagination_and_overview(
    client: TestClient, db: Session
) -> None:
    web = _discovered(db, name="web-01")
    web.primary_ip = "10.9.9.9"
    db.commit()
    detection = _detection(db, web, rule_id="NET-002")
    detection.title = "Puerto RDP expuesto"
    db.commit()
    a = _ok(client.post(f"{API}/detections/{detection.public_id}/incident",
                        json={"title": "Exposición web", "priority": "low"}), 201)  # fmt: skip
    b = _create(client, title="Phishing a finanzas", severity="critical", priority="critical")
    c = _create(client, title="Malware en portátil", severity="low", priority="high")
    _ok(_post(client, b, "assign"))
    c = _ok(_patch(client, c, status="triage"))
    _ok(_post(client, c, "resolve", category="false_positive"))

    def keys(**params: Any) -> list[str]:
        return [i["key"] for i in _ok(client.get(f"{API}/incidents", params=params))["items"]]

    assert keys(status="resolved") == [c["key"]]
    assert set(keys(active=True)) == {a["key"], b["key"]}
    assert keys(severity="critical") == [b["key"]]
    assert keys(priority="low") == [a["key"]]
    assert keys(owner="me") == [b["key"]]
    assert set(keys(owner="unassigned")) == {a["key"], c["key"]}
    assert keys(asset_id=str(web.public_id)) == [a["key"]]
    assert keys(q="web-01") == [a["key"]]
    assert keys(q="10.9.9.9") == [a["key"]]
    assert keys(q="RDP expuesto") == [a["key"]]
    assert keys(q="phishing") == [b["key"]]
    assert keys(q=b["key"]) == [b["key"]]
    assert keys(q=str(b["number"])) == [b["key"]]
    assert keys(q="100%_") == []
    assert keys(sort="severity", order="desc")[0] == b["key"]
    assert keys(sort="number", order="asc") == [a["key"], b["key"], c["key"]]
    assert keys(since=(datetime.now(UTC) + timedelta(hours=1)).isoformat()) == []
    page = _ok(
        client.get(
            f"{API}/incidents", params={"sort": "number", "order": "asc", "limit": 2, "offset": 2}
        )
    )
    assert page["total"] == 3 and [i["key"] for i in page["items"]] == [c["key"]]
    assert client.get(f"{API}/incidents", params={"sort": "title; DROP"}).status_code == 422
    assert client.get(f"{API}/incidents", params={"owner": "x' OR 1=1"}).status_code == 422
    _error(client.get(f"{API}/incidents", params={"asset_id": str(uuid4())}), 404, "not_found")

    overview = _ok(client.get(f"{API}/incidents/overview"))
    assert overview["open"] == 2 and overview["critical"] == 1
    assert overview["unassigned"] == 1 and overview["assigned_to_me"] == 1
    assert overview["mean_age_seconds"] is not None and overview["recent_activity"]


def test_timeline_cursor_pagination_and_time_range(client: TestClient, db: Session) -> None:
    incident = _create(client)
    url = f"{API}/incidents/{incident['incident_id']}/notes"
    for i in range(7):
        _ok(client.post(url, json={"body": f"n{i}"}), 201)
    tl_url = f"{API}/incidents/{incident['incident_id']}/timeline"
    seen: list[str] = []
    cursor = None
    while True:
        params: dict[str, Any] = {"limit": 3}
        if cursor:
            params["cursor"] = cursor
        page = _ok(client.get(tl_url, params=params))
        seen.extend(i["item_id"] for i in page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert len(seen) == len(set(seen)) == 8  # 7 notas + creación
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert _ok(client.get(tl_url, params={"since": future}))["items"] == []
    _error(client.get(tl_url, params={"cursor": "not-a-cursor"}), 422, "incident_invalid_reference")


def test_incident_404s(client: TestClient) -> None:
    missing = str(uuid4())
    for path in ("", "/timeline", "/evidence", "/notes", "/audit"):
        _error(client.get(f"{API}/incidents/{missing}{path}"), 404, "not_found")
    _error(client.patch(f"{API}/incidents/{missing}", json={"version": 1, "title": "abc"}), 404,
           "not_found")  # fmt: skip
    assert client.get(f"{API}/incidents/not-a-uuid").status_code == 422


def test_migration_0022_round_trip_with_existing_data(
    client: TestClient, engine: Engine, db: Session
) -> None:
    """0022 ↔ 0021 con datos: el downgrade solo pierde lo de 4K (documentado en la migración)."""
    from alembic import command
    from sqlalchemy import text

    from tests.conftest import _alembic_config

    asset = _discovered(db)
    detection = _detection(db, asset)
    incident = _ok(client.post(f"{API}/detections/{detection.public_id}/incident", json={}), 201)
    _ok(client.post(f"{API}/incidents/{incident['incident_id']}/notes", json={"body": "Nota"}), 201)

    def counts() -> dict[str, int]:
        with engine.connect() as connection:
            return {
                table: connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()  # noqa: S608
                for table in ("assets", "detections", "users", "audit_events")
            }

    before = counts()
    config = _alembic_config(str(engine.url.render_as_string(hide_password=False)))
    try:
        command.downgrade(config, "0021")
        # Lo previo a 4K se conserva (incluida la auditoría incident_*).
        assert counts() == before
        with engine.connect() as connection:
            assert connection.execute(text("SELECT to_regclass('incidents')")).scalar() is None
            assert (
                connection.execute(text("SELECT to_regclass('incident_number_seq')")).scalar()
                is None
            )
    finally:
        command.upgrade(config, "head")
    assert counts() == before
    # Tras volver a subir, la numeración arranca de nuevo y la app funciona.
    again = _create(client)
    assert again["key"] == "INC-000001"
