"""Fase 7A.6: responsable al crear casos, casos desde riesgo, tareas y controles de red.

Todo contra PostgreSQL (sentra_test) y la API real, como test_incidents.py.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.incidents.network_controls import ControlTargetError, normalize_target
from app.models.audit import AuditEvent
from app.models.case_operations import NetworkControlRequest
from app.models.detection import DetectionSeverity
from app.models.incident import Incident, IncidentActivity, IncidentAsset
from app.models.risk import AssetRisk
from app.models.user import User
from app.services.case_operations_service import expire_controls
from tests.conftest import authenticate, create_user
from tests.test_risk import _detection, _discovered, _port, _risk

API = "/api/v1"


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


def _client(client: TestClient, engine: Engine, role: str, name: str) -> TestClient:
    return _login(client, engine, role, name)[0]


def _login(client: TestClient, engine: Engine, role: str, name: str) -> tuple[TestClient, User]:
    """Otro navegador (otra sesión) contra la misma app, con su usuario."""
    other = TestClient(client.app)
    user = authenticate(other, engine, role, name)
    return other, user


def _case(client: TestClient, **overrides: Any) -> dict[str, Any]:
    payload = {"title": "Puerto expuesto en servidor", "severity": "high", "priority": "high"}
    return _ok(client.post(f"{API}/incidents", json={**payload, **overrides}), 201)


def _audit(db: Session, action: str, result: str | None = None) -> list[AuditEvent]:
    db.expire_all()
    stmt = select(AuditEvent).where(AuditEvent.action == action)
    if result:
        stmt = stmt.where(AuditEvent.result == result)
    return list(db.scalars(stmt.order_by(AuditEvent.id)))


# --- Responsable al crear ----------------------------------------------------------------------


def test_owner_is_chosen_when_the_case_is_created(
    client: TestClient, db: Session, engine: Engine
) -> None:
    analyst_user = create_user(db, "ana-7a6", "analyst")
    viewer_user = create_user(db, "vic-7a6", "viewer")
    # Un admin asigna a cualquier analyst activo desde la creación.
    case = _case(client, owner_user_id=str(analyst_user.public_id))
    assert case["owner"]["username"] == "ana-7a6"
    assert case["assigned_at"] is not None and case["version"] == 1
    assigned = _audit(db, "incident_assigned")[-1].details
    assert assigned is not None and assigned["previous"] is None
    # Un viewer nunca es owner; el caso no queda creado a medias.
    before = db.scalar(select(func.count()).select_from(Incident))
    _error(
        client.post(
            f"{API}/incidents",
            json={
                "title": "Otro caso",
                "severity": "low",
                "priority": "low",
                "owner_user_id": str(viewer_user.public_id),
            },
        ),
        422,
        "incident_invalid_reference",
    )
    assert db.scalar(select(func.count()).select_from(Incident)) == before
    # Un analyst solo se elige a sí mismo.
    analyst, me = _login(client, engine, "analyst", "otro-analyst")
    own = _case(analyst, owner_user_id=str(me.public_id))
    assert own["owner"]["username"] == "otro-analyst"
    _error(
        analyst.post(
            f"{API}/incidents",
            json={
                "title": "Para otra persona",
                "severity": "low",
                "priority": "low",
                "owner_user_id": str(analyst_user.public_id),
            },
        ),
        422,
        "incident_invalid_reference",
    )


def test_promoting_a_detection_can_set_the_owner(
    client: TestClient, db: Session, engine: Engine
) -> None:
    asset = _discovered(db, name="srv-7a6")
    detection = _detection(db, asset, rule_id="AUTH-002", severity=DetectionSeverity.HIGH)
    analyst_user = create_user(db, "dana-7a6", "analyst")
    case = _ok(
        client.post(
            f"{API}/detections/{detection.public_id}/incident",
            json={"owner_user_id": str(analyst_user.public_id)},
        ),
        201,
    )
    assert case["owner"]["username"] == "dana-7a6"


# --- Caso desde el riesgo -----------------------------------------------------------------------


def test_case_from_asset_risk(client: TestClient, db: Session, engine: Engine) -> None:
    asset = _discovered(db, name="srv-riesgo")
    _port(db, asset, 3389)
    _detection(db, asset, rule_id="AUTH-002", severity=DetectionSeverity.HIGH)
    calm = _discovered(db, name="sin-calcular")
    _risk(engine)
    analyst_user = create_user(db, "eva-7a6", "analyst")
    case = _ok(
        client.post(
            f"{API}/assets/{asset.public_id}/risk/incident",
            json={"owner_user_id": str(analyst_user.public_id)},
        ),
        201,
    )
    assert case["title"].startswith("Riesgo ") and "srv-riesgo" in case["title"]
    assert case["description"].startswith("Riesgo ") and "/100" in case["description"]
    assert case["owner"]["username"] == "eva-7a6"
    assert case["risk"]["snapshot"]["score"] is not None
    sources = db.scalars(select(IncidentAsset.source).where(IncidentAsset.asset_id == asset.id))
    assert list(sources) == ["risk"]
    # El mismo activo no abre un segundo caso por riesgo mientras el primero siga activo.
    _error(
        client.post(f"{API}/assets/{asset.public_id}/risk/incident"),
        409,
        "incident_already_linked",
    )
    # Sin riesgo calculado no hay de qué abrir el caso.
    db.execute(update(AssetRisk).where(AssetRisk.asset_id == calm.id).values(calculated_at=None))
    db.commit()
    _error(
        client.post(f"{API}/assets/{calm.public_id}/risk/incident"),
        409,
        "incident_invalid_state",
    )
    viewer = _client(client, engine, "viewer", "viewer-7a6")
    assert viewer.post(f"{API}/assets/{asset.public_id}/risk/incident").status_code == 403


# --- Tareas --------------------------------------------------------------------------------------


def _task(client: TestClient, case: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    payload = {"kind": "investigate_port", "title": "Revisar el puerto 3389 expuesto"}
    return _ok(
        client.post(f"{API}/incidents/{case['incident_id']}/tasks", json={**payload, **overrides}),
        201,
    )


def test_task_lifecycle_assignment_and_evidence(
    client: TestClient, db: Session, engine: Engine
) -> None:
    asset = _discovered(db, name="srv-tareas")
    detection = _detection(db, asset, rule_id="AUTH-002", severity=DetectionSeverity.HIGH)
    case = _ok(client.post(f"{API}/detections/{detection.public_id}/incident"), 201)
    analyst, me = _login(client, engine, "analyst", "tina-7a6")
    analyst_id = str(me.public_id)

    # El owner/admin delega en un analyst; la tarea no ejecuta nada, solo existe.
    task = _task(client, case, assignee_user_id=analyst_id, asset_id=str(asset.public_id))
    assert task["status"] == "open" and task["assignee"]["username"] == "tina-7a6"
    assert task["asset"]["name"] == "srv-tareas" and task["incident_key"].startswith("INC-")
    assert set(task["allowed_transitions"]) == {"in_progress", "blocked", "done", "cancelled"}

    # Un activo que no está en el caso no se acepta.
    other = _discovered(db, name="fuera-del-caso")
    _error(
        client.post(
            f"{API}/incidents/{case['incident_id']}/tasks",
            json={"kind": "other", "title": "Algo", "asset_id": str(other.public_id)},
        ),
        422,
        "incident_invalid_reference",
    )

    url = f"{API}/tasks/{task['task_id']}"
    started = _ok(analyst.patch(url, json={"version": task["version"], "status": "in_progress"}))
    assert started["started_at"] is not None
    # Terminar exige resultado.
    _error(
        analyst.patch(url, json={"version": started["version"], "status": "done"}),
        409,
        "task_invalid_state",
    )
    # Versión vieja: conflicto, nunca se pisa el cambio de otro.
    _error(
        analyst.patch(url, json={"version": task["version"], "title": "Otro título"}),
        409,
        "task_conflict",
    )
    evidence = _ok(
        analyst.post(
            f"{url}/evidence",
            json={
                "version": started["version"],
                "type": "detection",
                "id": str(detection.public_id),
            },
        )
    )
    assert evidence["evidence"][0]["label"].startswith("Detección AUTH-002")
    assert evidence["evidence"][0]["added_by"] == "tina-7a6"
    _error(
        analyst.post(
            f"{url}/evidence",
            json={"version": evidence["version"], "type": "alert", "id": str(asset.public_id)},
        ),
        422,
        "incident_invalid_reference",
    )
    done = _ok(
        analyst.patch(
            url,
            json={
                "version": evidence["version"],
                "status": "done",
                "result": "RDP cerrado en el firewall perimetral.",
            },
        )
    )
    assert done["status"] == "done" and done["completed_by"] == "tina-7a6"
    assert done["allowed_transitions"] == ["open"]
    _error(
        analyst.patch(url, json={"version": done["version"], "title": "Cambio tardío"}),
        409,
        "task_invalid_state",
    )
    reopened = _ok(analyst.patch(url, json={"version": done["version"], "status": "open"}))
    assert reopened["completed_at"] is None

    # Contadores del caso, "mis tareas", timeline y auditoría.
    detail = _ok(client.get(f"{API}/incidents/{case['incident_id']}"))
    assert detail["tasks_total"] == 1 and detail["tasks_open"] == 1
    mine = _ok(analyst.get(f"{API}/tasks", params={"mine": "true", "status": "open"}))
    assert [t["task_id"] for t in mine["items"]] == [task["task_id"]]
    actions = set(
        db.scalars(select(IncidentActivity.action).where(IncidentActivity.entity_type == "task"))
    )
    assert {"task_created", "task_updated", "task_evidence_added"} <= actions
    assert _audit(db, "incident_task_created", "success")
    assert _audit(db, "incident_task_updated", "failure")


def test_task_assignment_policy(client: TestClient, db: Session, engine: Engine) -> None:
    case = _case(client)
    lead = create_user(db, "lead-7a6", "analyst")
    analyst = _client(client, engine, "analyst", "uma-7a6")
    viewer = _client(client, engine, "viewer", "val-7a6")
    task = _task(client, case)
    url = f"{API}/tasks/{task['task_id']}"
    # Un analyst que no es owner no delega en otros...
    _error(
        analyst.post(
            f"{url}/assign", json={"version": task["version"], "user_id": str(lead.public_id)}
        ),
        403,
        "permission_denied",
    )
    # ...pero puede tomar una tarea sin responsable.
    taken = _ok(analyst.post(f"{url}/assign", json={"version": task["version"]}))
    assert taken["assignee"]["username"] == "uma-7a6"
    # Ya tomada: otro analyst no se la quita; el admin sí la reasigna.
    other = _client(client, engine, "analyst", "otra-7a6")
    _error(
        other.post(f"{url}/assign", json={"version": taken["version"]}),
        403,
        "permission_denied",
    )
    _error(
        other.patch(url, json={"version": taken["version"], "status": "in_progress"}),
        403,
        "permission_denied",
    )
    moved = _ok(
        client.post(
            f"{url}/assign", json={"version": taken["version"], "user_id": str(lead.public_id)}
        )
    )
    assert moved["assignee"]["username"] == "lead-7a6"
    released = _ok(client.post(f"{url}/unassign", json={"version": moved["version"]}))
    assert released["assignee"] is None
    # Un viewer lee pero no trabaja tareas.
    assert viewer.get(url).status_code == 200
    assert viewer.post(f"{url}/assign", json={"version": released["version"]}).status_code == 403
    # Un caso cerrado no admite tareas nuevas.
    triaged = _ok(
        client.patch(
            f"{API}/incidents/{case['incident_id']}",
            json={"version": case["version"], "status": "triage"},
        )
    )
    resolved = _ok(
        client.post(
            f"{API}/incidents/{case['incident_id']}/resolve",
            json={"version": triaged["version"], "category": "true_positive"},
        )
    )
    _ok(
        client.post(
            f"{API}/incidents/{case['incident_id']}/close", json={"version": resolved["version"]}
        )
    )
    _error(
        client.post(
            f"{API}/incidents/{case['incident_id']}/tasks",
            json={"kind": "other", "title": "Tarde"},
        ),
        409,
        "incident_invalid_state",
    )


def test_merge_moves_pending_work_to_the_target(client: TestClient, db: Session) -> None:
    source = _case(client, title="Caso origen")
    target = _case(client, title="Caso destino")
    pending = _task(client, source, title="Pendiente de revisar")
    finished = _task(client, source, title="Ya revisada")
    _ok(
        client.patch(
            f"{API}/tasks/{finished['task_id']}",
            json={"version": finished["version"], "status": "done", "result": "Sin hallazgos."},
        )
    )
    control = _control(client, source)
    merged = _ok(
        client.post(
            f"{API}/incidents/{source['incident_id']}/merge",
            json={
                "version": source["version"],
                "target_id": target["incident_id"],
                "target_version": target["version"],
            },
        )
    )
    assert merged["tasks_open"] == 1 and merged["network_controls_open"] == 1
    moved = _ok(client.get(f"{API}/tasks/{pending['task_id']}"))
    assert moved["incident_id"] == target["incident_id"]
    kept = _ok(client.get(f"{API}/tasks/{finished['task_id']}"))
    assert kept["incident_id"] == source["incident_id"]
    assert (
        _ok(client.get(f"{API}/network-controls/{control['control_id']}"))["incident_id"]
        == (target["incident_id"])
    )


# --- Solicitudes de control de red -------------------------------------------------------------


def _control(client: TestClient, case: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    payload = {
        "control_type": "block_port",
        "target": {"port": 3389, "protocol": "tcp"},
        "direction": "inbound",
        "justification": "RDP expuesto sin necesidad de negocio.",
    }
    return _ok(
        client.post(
            f"{API}/incidents/{case['incident_id']}/network-controls",
            json={**payload, **overrides},
        ),
        201,
    )


@pytest.mark.parametrize(
    ("control_type", "target", "expected"),
    [
        ("block_port", {"port": 445, "protocol": "tcp"}, {"port": 445, "protocol": "tcp"}),
        ("block_service", {"service": "SMB"}, {"service": "smb"}),
        ("block_address", {"cidr": "203.0.113.7"}, {"cidr": "203.0.113.7/32"}),
        ("block_address", {"cidr": "198.51.100.9/24"}, {"cidr": "198.51.100.0/24"}),
        ("block_domain", {"domain": "*.Ejemplo-Malo.com."}, {"domain": "*.ejemplo-malo.com"}),
        ("block_domain", {"domain": "bücher.example"}, {"domain": "xn--bcher-kva.example"}),
        (
            "prevent_upload",
            {"destination": "files.example.net"},
            {"destination": "files.example.net"},
        ),
    ],
)
def test_control_targets_are_normalized(
    control_type: str, target: dict[str, Any], expected: dict[str, Any]
) -> None:
    assert normalize_target(control_type, target) == expected


@pytest.mark.parametrize(
    ("control_type", "target"),
    [
        ("block_port", {"port": 0, "protocol": "tcp"}),
        ("block_port", {"port": 80, "protocol": "icmp"}),
        ("block_port", {"port": 80, "protocol": "tcp", "command": "x"}),
        ("block_address", {"cidr": "0.0.0.0/0"}),
        ("block_address", {"cidr": "10.0.0.0/8"}),
        ("block_address", {"cidr": "127.0.0.1"}),
        ("block_address", {"cidr": "no-es-ip"}),
        ("block_domain", {"domain": "com"}),
        ("block_domain", {"domain": "a.*.example.com"}),
        ("block_domain", {"domain": "192.168.1.1"}),
        ("restrict_site_access", {"domain": "-malo.example"}),
        ("block_service", {"service": "rm -rf /"}),
    ],
)
def test_broad_or_ambiguous_targets_are_rejected(control_type: str, target: dict[str, Any]) -> None:
    with pytest.raises(ControlTargetError):
        normalize_target(control_type, target)


def test_control_request_approval_flow(client: TestClient, db: Session, engine: Engine) -> None:
    analyst = _client(client, engine, "analyst", "nora-7a6")
    case = _case(client)
    control = _control(analyst, case)
    assert control["status"] == "pending_approval"
    assert control["enforcement_status"] == "not_evaluated"
    assert control["scope"]["type"] == "global"
    # Validación en la API: dirección obligatoria en puertos, nada de claves extra.
    _error(
        analyst.post(
            f"{API}/incidents/{case['incident_id']}/network-controls",
            json={
                "control_type": "block_port",
                "target": {"port": 22, "protocol": "tcp"},
                "justification": "Sin dirección indicada.",
            },
        ),
        422,
        "validation_error",
    )
    # Solo un admin (network_controls:approve) decide.
    url = f"{API}/network-controls/{control['control_id']}"
    assert analyst.post(f"{url}/approve", json={"version": 1}).status_code == 403
    approved = _ok(client.post(f"{url}/approve", json={"version": 1, "note": "De acuerdo."}))
    assert approved["status"] == "approved"
    # Sentra no aplica nada: lo dice y explica qué haría falta.
    assert approved["enforcement_status"] == "no_enforcement_point"
    assert approved["enforcement"]["points"] == []
    assert approved["enforcement"]["applied_by_sentra"] is False
    assert "Firewall" in approved["enforcement"]["needs"]
    assert approved["self_approved"] is False
    _error(client.post(f"{url}/approve", json={"version": 2}), 409, "network_control_invalid_state")
    applied = _ok(
        client.post(
            f"{url}/mark-applied",
            json={"version": approved["version"], "note": "Regla 42 del firewall perimetral."},
        )
    )
    assert applied["enforcement_status"] == "applied_manually"
    assert applied["applied_by"] == "admin"
    # Rechazar exige motivo.
    second = _control(
        analyst,
        case,
        control_type="block_domain",
        target={"domain": "malo.example"},
        direction=None,
    )
    second_url = f"{API}/network-controls/{second['control_id']}"
    assert client.post(f"{second_url}/reject", json={"version": 1}).status_code == 422
    rejected = _ok(
        client.post(f"{second_url}/reject", json={"version": 1, "note": "Falso positivo."})
    )
    assert rejected["status"] == "rejected" and rejected["decision_note"] == "Falso positivo."
    # Cancelar: quien la pidió o un aprobador; otro analyst no.
    third = _control(analyst, case, target={"port": 23, "protocol": "tcp"})
    other = _client(client, engine, "analyst", "otro-7a6")
    third_url = f"{API}/network-controls/{third['control_id']}"
    _error(other.post(f"{third_url}/cancel", json={"version": 1}), 403, "permission_denied")
    assert _ok(analyst.post(f"{third_url}/cancel", json={"version": 1}))["status"] == "cancelled"
    # Listado por caso y estado, capacidades y auditoría.
    listed = _ok(
        client.get(
            f"{API}/network-controls",
            params={"incident_id": case["incident_id"], "status": "approved"},
        )
    )
    assert [c["control_id"] for c in listed["items"]] == [control["control_id"]]
    caps = _ok(client.get(f"{API}/network-controls/capabilities"))
    assert caps["any_available"] is False and len(caps["items"]) == 6
    upload = next(i for i in caps["items"] if i["control_type"] == "prevent_upload")
    assert "DNS" in upload["note"]
    assert _audit(db, "network_control_approved", "success")
    assert _audit(db, "network_control_approved", "failure")


def test_self_approval_is_visible_and_controls_expire(
    client: TestClient, db: Session, engine: Engine
) -> None:
    case = _case(client)
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    _error(
        client.post(
            f"{API}/incidents/{case['incident_id']}/network-controls",
            json={
                "control_type": "block_address",
                "target": {"cidr": "203.0.113.0/24"},
                "direction": "outbound",
                "justification": "Servidor de mando y control conocido.",
                "expires_at": past,
            },
        ),
        422,
        "incident_invalid_reference",
    )
    soon = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    control = _control(
        client,
        case,
        control_type="block_address",
        target={"cidr": "203.0.113.0/24"},
        direction="outbound",
        expires_at=soon,
    )
    approved = _ok(
        client.post(f"{API}/network-controls/{control['control_id']}/approve", json={"version": 1})
    )
    # Una instalación con un solo admin puede aprobar lo suyo, pero queda a la vista.
    assert approved["self_approved"] is True
    db.execute(
        update(NetworkControlRequest).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    db.commit()
    assert expire_controls(db) == 1
    expired = _ok(client.get(f"{API}/network-controls/{control['control_id']}"))
    assert expired["status"] == "expired"


def test_risk_never_creates_cases_or_controls(
    client: TestClient, db: Session, engine: Engine
) -> None:
    asset = _discovered(db, name="srv-critico")
    _port(db, asset, 3389)
    _port(db, asset, 445)
    for rule in ("AUTH-002", "DEF-001"):
        _detection(db, asset, rule_id=rule, severity=DetectionSeverity.CRITICAL)
    _risk(engine)
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(Incident)) == 0
    assert db.scalar(select(func.count()).select_from(NetworkControlRequest)) == 0
