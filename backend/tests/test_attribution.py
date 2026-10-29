"""Fase 7B.1: atribución verificable de detecciones a operaciones de mantenimiento.

Dos niveles:
- cálculo puro (app/detection/attribution.py): cada comprobación y cada forma de no casar
  (suplantación de nombre, hash cambiado, script copiado, evidencia incompleta, actividad
  extra en la ventana, cuenta distinta...);
- extremo a extremo con eventos sintéticos del agente 0.6.0: la instalación del agente en el
  equipo de desarrollo (caso ravenslg de la auditoría 7B.0) antes y después de registrar la
  operación, una persistencia maliciosa simulada que nunca se verifica, el veredicto del
  analista, RBAC y validación.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.detection import attribution as calc
from app.models.alert import Alert, AlertStatus
from app.models.attribution import DetectionAttributionEvent, MaintenanceOperation
from app.models.audit import AuditEvent
from app.models.detection import Detection
from tests.conftest import authenticate
from tests.test_powershell_detections import (
    SCRIPT,
    SHA,
    _agent,
    _ago,
    _block,
    _detections,
    _run,
    _send,
    _service,
)
from tests.test_risk import _detail, _risk

API = "/api/v1"
OPS = f"{API}/maintenance-operations"
SID = "S-1-5-21-1-2-3-500"
IMAGE = '"C:\\Program Files\\Sentra Agent\\runtime\\python.exe" -I -m sentra_agent'
T0 = datetime(2026, 10, 25, 10, 0, tzinfo=UTC)


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


# --- Cálculo puro -------------------------------------------------------------------------


def _op(**overrides: Any) -> calc.OperationRef:
    values: dict[str, Any] = {
        "id": 1,
        "public_id": str(uuid4()),
        "operation_key": str(uuid4()),
        "version": 1,
        "title": "Instalación del agente 0.6.0",
        "window_start": T0 - timedelta(hours=1),
        "window_end": T0 + timedelta(hours=1),
        "accounts": frozenset({SID.lower()}),
        "interpreters": frozenset(),
        "parents": frozenset(),
        "signer": None,
        "artifacts": (
            calc.ArtifactRef(kind="script", path=calc.canonical_path(SCRIPT), sha256=SHA),
            calc.ArtifactRef(
                kind="service",
                service_name="sentraagent",
                service_display_name="sentra agent",
                image_path=IMAGE,
                service_account="localsystem",
            ),
        ),
    }
    values.update(overrides)
    return calc.OperationRef(**values)


def _script_ev(
    at: datetime = T0, path: str | None = SCRIPT, sha: str | None = SHA, **data: Any
) -> calc.EvidenceItem:
    values: dict[str, Any] = {
        "script_block_id": str(uuid4()),
        "script_path": path,
        "script_sha256": sha,
        "script_origin": "file" if path else "inline",
        "user_sid": SID,
        "pid": 4242,
    }
    values.update(data)
    return calc.EvidenceItem("powershell_suspicious", at, values, "powershell")


def _service_ev(
    at: datetime = T0 + timedelta(minutes=1),
    name: str = "SentraAgent",
    image: str | None = IMAGE,
    account: str | None = "LocalSystem",
) -> calc.EvidenceItem:
    return calc.EvidenceItem(
        "service_installed",
        at,
        {"service": name, "image_path": image, "account": account},
        "persistence",
    )


def _checks(result: calc.AttributionResult) -> dict[str, str]:
    found: dict[str, str] = {}
    for item in result.items:
        for check in item.checks:
            found.setdefault(check.check, check.result)
            if check.result == calc.FAIL:
                found[check.check] = calc.FAIL
    return found


def test_canonical_path_normalizes_and_rejects_traversal() -> None:
    assert (
        calc.canonical_path('"C:/Sentra//Agent\\Install.PS1"') == "c:\\sentra\\agent\\install.ps1"
    )
    assert calc.canonical_path("\\\\?\\C:\\x\\y.ps1") == "c:\\x\\y.ps1"
    assert calc.canonical_path("C:\\Sentra\\..\\Windows\\evil.ps1") is None
    assert calc.canonical_path("/opt/Sentra/./x.sh") is None
    assert calc.canonical_path("/opt/Sentra/x.sh") == "/opt/Sentra/x.sh"
    assert calc.canonical_path("") is None


def test_install_that_matches_the_operation_is_verified() -> None:
    result = calc.evaluate("CORR-002", [_script_ev(), _service_ev()], [_op()])
    assert result.verdict == calc.VERIFIED
    assert result.operation is not None
    assert result.missing == []
    assert result.to_json(T0)["risk_effect"] == "excluded"


def test_the_engine_never_concludes_malicious() -> None:
    cases = [[_script_ev(sha="f" * 64)], [_script_ev(sha=None)], [_service_ev(image="x.exe")]]
    for evidence in cases:
        for ops in ([], [_op()]):
            assert calc.evaluate("CORR-002", evidence, ops).verdict != calc.MALICIOUS


def test_service_name_spoofing_is_not_verified() -> None:
    # Un servicio malicioso que se llama igual que el de Sentra: el nombre no prueba nada.
    evil = _service_ev(image="C:\\Users\\Public\\SentraAgent.exe")
    result = calc.evaluate("CORR-002", [_script_ev(), evil], [_op()])
    assert result.verdict == calc.SUSPICIOUS
    assert _checks(result)["image_path"] == calc.FAIL
    assert result.tamper_suspected


def test_changed_script_hash_is_flagged_as_possible_tampering() -> None:
    result = calc.evaluate("SCR-001", [_script_ev(sha="c" * 64)], [_op()])
    assert result.verdict == calc.SUSPICIOUS
    assert _checks(result)["sha256"] == calc.FAIL
    assert result.tamper_suspected


def test_authorized_script_copied_elsewhere_is_not_verified() -> None:
    copied = _script_ev(path="C:\\Users\\Public\\install-sentra-agent.ps1")
    result = calc.evaluate("SCR-001", [copied], [_op()])
    assert result.verdict == calc.SUSPICIOUS
    assert _checks(result)["path"] == calc.FAIL


def test_missing_hash_is_insufficient_and_says_how_to_obtain_it() -> None:
    result = calc.evaluate("SCR-001", [_script_ev(sha=None)], [_op()])
    assert result.verdict == calc.INSUFFICIENT
    payload = result.to_json(T0)
    (missing,) = payload["missing_evidence"]
    assert missing["code"] == "script_hash"
    assert "Get-FileHash" in missing["how_to_obtain"]


def test_old_agent_without_script_context_is_insufficient() -> None:
    bare = calc.EvidenceItem("powershell_suspicious", T0, {"keywords": ["Marshal"]})
    result = calc.evaluate("SCR-001", [bare], [_op()])
    assert result.verdict == calc.INSUFFICIENT
    assert result.missing == ["script_context"]


def test_an_extra_script_in_the_window_keeps_the_correlation_suspicious() -> None:
    # La operación legítima no tapa otro script que no describe.
    other = _script_ev(path="C:\\Temp\\other.ps1", sha="d" * 64)
    result = calc.evaluate("CORR-002", [_script_ev(), other, _service_ev()], [_op()])
    assert result.verdict == calc.SUSPICIOUS


def test_activity_outside_the_window_is_not_verified() -> None:
    late = _script_ev(at=T0 + timedelta(hours=3))
    result = calc.evaluate("SCR-001", [late], [_op()])
    assert result.verdict == calc.SUSPICIOUS
    assert _checks(result)["window"] == calc.FAIL


def test_inline_block_cannot_be_attributed() -> None:
    result = calc.evaluate("SCR-001", [_script_ev(path=None, sha=None)], [_op()])
    assert result.verdict == calc.SUSPICIOUS
    assert _checks(result)["origin"] == calc.FAIL


def test_other_account_is_not_verified() -> None:
    result = calc.evaluate("SCR-001", [_script_ev(user_sid="S-1-5-21-9-9-9-1001")], [_op()])
    assert result.verdict == calc.SUSPICIOUS
    assert _checks(result)["account"] == calc.FAIL


def test_required_interpreter_and_parent_must_match_when_present() -> None:
    op = _op(
        interpreters=frozenset({"c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"}),
        parents=frozenset({"c:\\windows\\explorer.exe"}),
    )
    good = _script_ev(
        process_exe="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_exe="C:\\Windows\\explorer.exe",
    )
    assert calc.evaluate("SCR-001", [good], [op]).verdict == calc.VERIFIED
    bad_parent = _script_ev(
        process_exe="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_exe="C:\\Windows\\System32\\wscript.exe",
    )
    assert calc.evaluate("SCR-001", [bad_parent], [op]).verdict == calc.SUSPICIOUS
    # Sin telemetría de procesos no se puede comprobar lo que la operación exige.
    unknown = calc.evaluate("SCR-001", [_script_ev()], [op])
    assert unknown.verdict == calc.INSUFFICIENT
    assert "process" in unknown.missing


def test_inventory_only_service_is_insufficient_but_corroborates_a_verified_7045() -> None:
    inventory = calc.EvidenceItem(
        "service_added", T0 + timedelta(minutes=5), {"service": "SentraAgent"}
    )
    alone = calc.evaluate("PER-001", [inventory], [_op()])
    assert alone.verdict == calc.INSUFFICIENT
    assert alone.missing == ["service_image_path"]
    both = calc.evaluate("PER-001", [_service_ev(), inventory], [_op()])
    assert both.verdict == calc.VERIFIED


def test_artifacts_of_two_operations_are_never_mixed() -> None:
    script_only = _op(id=1, artifacts=(_op().artifacts[0],))
    service_only = _op(id=2, artifacts=(_op().artifacts[1],))
    result = calc.evaluate("CORR-002", [_script_ev(), _service_ev()], [script_only, service_only])
    assert result.verdict != calc.VERIFIED


def test_without_operations_the_verdict_never_claims_verification() -> None:
    assert calc.evaluate("CORR-002", [_script_ev(), _service_ev()], []).verdict == calc.SUSPICIOUS
    assert calc.evaluate("SCR-001", [_script_ev(sha=None)], []).verdict == calc.INSUFFICIENT


def test_exposure_stays_in_risk_even_with_a_verified_owner() -> None:
    port = calc.EvidenceItem(
        "port_exposed",
        T0,
        {"port": 8000, "exe": "C:\\Sentra\\backend\\.venv\\Scripts\\python.exe", "sha256": SHA},
    )
    op = _op(
        artifacts=(
            calc.ArtifactRef(
                kind="binary",
                path=calc.canonical_path("C:\\Sentra\\backend\\.venv\\Scripts\\python.exe"),
                sha256=SHA,
            ),
        )
    )
    result = calc.evaluate("NET-001", [port], [op])
    assert result.verdict == calc.VERIFIED
    assert result.to_json(T0)["risk_effect"] == "kept_exposure"


# --- Extremo a extremo -------------------------------------------------------------------


def _operation_body(asset_id: str, **overrides: Any) -> dict[str, Any]:
    now = datetime.now(UTC)
    body: dict[str, Any] = {
        "asset_id": asset_id,
        "kind": "agent_install",
        "title": "Instalación del agente 0.6.0 en el equipo de desarrollo",
        "reason": "Reinstalación planificada del agente para validar la fase 7A",
        "window_start": (now - timedelta(hours=2)).isoformat(),
        "window_end": (now + timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "accounts": [SID],
        "artifacts": [
            {"kind": "script", "path": SCRIPT, "sha256": SHA},
            {
                "kind": "service",
                "service_name": "SentraAgent",
                "service_display_name": "Sentra Agent",
                "image_path": IMAGE,
                "service_account": "LocalSystem",
            },
        ],
    }
    body.update(overrides)
    return body


def _asset_public_id(db: Session, asset_id: int) -> str:
    from app.models.asset import Asset

    asset = db.get(Asset, asset_id)
    assert asset is not None
    return str(asset.public_id)


def _create_and_approve(client: TestClient, body: dict[str, Any]) -> dict[str, Any]:
    response = client.post(OPS, json=body)
    assert response.status_code == 201, response.text
    op: dict[str, Any] = response.json()
    assert op["status"] == "pending_review" and not op["active"]
    approved = client.post(f"{OPS}/{op['id']}/approve", json={"note": "revisado"})
    assert approved.status_code == 200, approved.text
    result: dict[str, Any] = approved.json()
    return result


def _approved_ago(db: Session, op: dict[str, Any], minutes: float) -> None:
    """Fecha la aprobación en el pasado: el admin aprobó ANTES de la instalación.

    Los eventos de los tests se fechan "hace N minutos"; aprobar en el propio test deja la
    aprobación después de la actividad, que es justo el caso histórico de la política.
    """
    row = db.scalar(select(MaintenanceOperation).where(MaintenanceOperation.public_id == op["id"]))
    assert row is not None
    row.approved_at = datetime.now(UTC) - timedelta(minutes=minutes)
    db.commit()


def _install(client: TestClient, agent: str, minutes: float = 30) -> None:
    _send(client, agent, [_block(_ago(minutes)), _service(_ago(minutes - 1))])


def test_dev_install_is_verified_after_review_and_risk_drops(
    client: TestClient, engine: Engine, db: Session
) -> None:
    """Caso ravenslg (auditoría 7B.0): instalación propia de Sentra en el equipo."""
    agent, asset_id = _agent(client, db)
    _install(client, agent)
    _run(engine)
    (corr,) = _detections(client, "CORR-002")
    assert corr["status"] == "open"
    # Sin operación: la detección sigue activa y su veredicto dice por qué.
    attribution = client.get(f"{API}/detections/{corr['detection_id']}/attribution").json()
    assert attribution["verdict"] == "suspicious_unverified"
    _risk(engine)
    asset = _asset_public_id(db, asset_id)
    before = _detail(client, asset)
    assert before["score"] > 0

    op = _create_and_approve(client, _operation_body(asset))
    # Aprobada DESPUÉS de la actividad: ni el motor ni una reevaluación la reclasifican solos.
    evaluated = client.post(f"{API}/detections/{corr['detection_id']}/attribution/evaluate")
    assert evaluated.status_code == 200, evaluated.text
    assert evaluated.json()["verdict"] == "suspicious_unverified"
    review = evaluated.json()["attribution"]["review_required"]
    assert review == {
        "operation_id": op["id"],
        "title": op["title"],
        "reason": "approved_after_activity",
    }
    assert _detections(client, "CORR-002")[0]["status"] == "open"
    preview = client.post(f"{OPS}/{op['id']}/preview")
    assert preview.status_code == 200, preview.text
    items = {i["rule_id"]: i for i in preview.json()["items"]}
    assert items["CORR-002"]["verdict"] == "verified_benign"
    assert items["CORR-002"]["would_resolve"]
    assert items["SCR-001"]["verdict"] == "verified_benign"
    assert items["PER-001"]["verdict"] == "verified_benign"
    # La vista previa no cambia nada.
    assert _detections(client, "CORR-002")[0]["status"] == "open"

    assert client.post(f"{OPS}/{op['id']}/apply", json={}).status_code == 422
    applied = client.post(f"{OPS}/{op['id']}/apply", json={"confirm": True})
    assert applied.status_code == 200, applied.text
    assert applied.json()["resolved"] == 3

    for rule in ("CORR-002", "SCR-001", "PER-001"):
        (item,) = _detections(client, rule)
        assert item["status"] == "resolved" and item["resolved_by"] == "attribution"
        assert "Mantenimiento verificado" in item["resolution_note"]
    # Historial inmutable: el veredicto anterior y el nuevo.
    history = client.get(f"{API}/detections/{corr['detection_id']}/attribution").json()["history"]
    assert [h["verdict"] for h in history][:2] == ["verified_benign", "suspicious_unverified"]
    alert = db.scalar(select(Alert).where(Alert.asset_id == asset_id))
    if alert is not None:
        db.refresh(alert)
        assert alert.status == AlertStatus.RESOLVED

    _risk(engine)
    after = _detail(client, asset)
    assert after["score"] < before["score"]
    attribution_lines = [c for c in after["contributions"] if c["factor"] == "attribution"]
    assert {c["rule_id"] for c in attribution_lines} == {"CORR-002", "SCR-001", "PER-001"}
    assert all(c["points"] == 0 for c in attribution_lines)
    components = after["breakdown"]["components"]
    assert components["without_attribution"] > after["score"]
    assert components["residual"] == after["score"]

    # Una segunda instalación dentro de la ventana, posterior a la aprobación, se reconoce
    # sola al detectarse (política de autorización: aprobación inicial, después automático).
    _approved_ago(db, op, 20)
    _install(client, agent, minutes=5)
    _run(engine)
    # La misma oleada se suma a la detección ya verificada (no abre otra) y sigue casando.
    (latest,) = _detections(client, "CORR-002")
    assert latest["status"] == "resolved"
    assert client.get(f"{OPS}/{op['id']}").json()["matches"] == 3


def test_simulated_malicious_persistence_is_never_verified(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    op = _create_and_approve(client, _operation_body(_asset_public_id(db, asset_id)))
    _approved_ago(db, op, 60)
    # Mismo nombre de servicio que el de Sentra, otro ejecutable; script con otro hash en la
    # MISMA ruta (el instalador modificado): nada debe verificarse.
    evil_service = _service(_ago(9))
    evil_service["data"]["ImagePath"] = "C:\\Users\\Public\\svc.exe"
    _send(client, agent, [_block(_ago(10), sha="e" * 64), evil_service])
    _run(engine)
    (corr,) = _detections(client, "CORR-002")
    assert corr["status"] == "open" and corr["severity"] == "high"
    body = client.get(f"{API}/detections/{corr['detection_id']}/attribution").json()
    assert body["verdict"] == "suspicious_unverified"
    assert body["attribution"]["tamper_suspected"] is True
    (per,) = _detections(client, "PER-001")
    assert per["status"] == "open" and per["severity"] == "high"


def test_per001_counts_7045_and_inventory_of_one_install_once(
    client: TestClient, engine: Engine, db: Session
) -> None:
    from tests.test_detections import _inventory

    agent, _ = _agent(client, db)
    _inventory(client, agent, _ago(40), services=[{"name": "Spooler", "status": "running"}])
    # El 7045 usa el nombre visible; el inventario, la clave del SCM.
    _send(client, agent, [_service(_ago(20), name="Sentra Agent")])
    _run(engine)
    _inventory(
        client,
        agent,
        _ago(15),
        services=[
            {"name": "Spooler", "status": "running"},
            {"name": "SentraAgent", "display_name": "Sentra Agent", "status": "running"},
        ],
    )
    _run(engine)
    (per,) = _detections(client, "PER-001")
    assert per["occurrence_count"] == 1


def test_analyst_verdict_is_immutable_and_wins_over_the_system(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    _install(client, agent)
    _run(engine)
    (corr,) = _detections(client, "CORR-002")
    url = f"{API}/detections/{corr['detection_id']}/attribution"
    short = client.post(f"{url}/verdict", json={"verdict": "confirmed_malicious", "reason": "x"})
    assert short.status_code == 422
    benign = client.post(
        f"{url}/verdict", json={"verdict": "verified_benign", "reason": "lo digo yo, sin pruebas"}
    )
    assert benign.status_code == 422
    decided = client.post(
        f"{url}/verdict",
        json={"verdict": "confirmed_malicious", "reason": "El servicio contacta con un C2"},
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["verdict"] == "confirmed_malicious"
    # Aunque después se apruebe una operación que lo cubriría, manda el analista.
    op = _create_and_approve(client, _operation_body(_asset_public_id(db, asset_id)))
    client.post(f"{OPS}/{op['id']}/apply", json={"confirm": True})
    again = client.post(f"{url}/evaluate")
    assert again.status_code == 200
    assert again.json()["verdict"] == "confirmed_malicious"
    assert _detections(client, "CORR-002")[0]["status"] == "open"
    sources = [h["source"] for h in again.json()["history"]]
    assert "analyst" in sources and "system" in sources
    # El motor no puede escribir un compromiso confirmado (restricción de la base de datos).
    detection_id = db.scalar(select(Detection.id).where(Detection.rule_id == "CORR-002"))
    assert detection_id is not None
    db.add(
        DetectionAttributionEvent(
            detection_id=detection_id,
            verdict="confirmed_malicious",
            source="system",
            actor="attribution",
            created_at=datetime.now(UTC),
        )
    )
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_operations_are_admin_only_and_validated(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _, asset_id = _agent(client, db)
    asset = _asset_public_id(db, asset_id)
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        assert analyst.post(OPS, json=_operation_body(asset)).status_code == 403
        assert analyst.get(OPS).status_code == 200
    now = datetime.now(UTC)
    bad: list[dict[str, Any]] = [
        _operation_body(asset, window_end=(now + timedelta(hours=80)).isoformat()),
        _operation_body(asset, expires_at=(now + timedelta(days=120)).isoformat()),
        _operation_body(asset, accounts=[]),
        _operation_body(
            asset,
            artifacts=[
                {
                    "kind": "binary",
                    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "sha256": SHA,
                }
            ],
        ),
        _operation_body(asset, artifacts=[{"kind": "script", "path": SCRIPT}]),
        _operation_body(asset, artifacts=[{"kind": "service", "service_name": "x"}]),
        _operation_body(
            asset, artifacts=[{"kind": "script", "path": "C:\\a\\..\\b.ps1", "sha256": SHA}]
        ),
    ]
    for body in bad:
        response = client.post(OPS, json=body)
        assert response.status_code == 422, body
    op = _create_and_approve(client, _operation_body(asset))
    # No se puede aprobar dos veces ni aplicar una revocada.
    assert client.post(f"{OPS}/{op['id']}/approve").status_code == 409
    revoked = client.post(f"{OPS}/{op['id']}/revoke", json={"reason": "ya no aplica"})
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    assert client.post(f"{OPS}/{op['id']}/preview").status_code == 409
    actions = {row.action for row in db.scalars(select(AuditEvent))}
    assert {"maintenance_operation_created", "maintenance_operation_approved"} <= actions
    assert "maintenance_operation_revoked" in actions


def test_new_version_supersedes_the_previous_one(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _, asset_id = _agent(client, db)
    asset = _asset_public_id(db, asset_id)
    first = _create_and_approve(client, _operation_body(asset))
    second = _create_and_approve(
        client, _operation_body(asset, supersedes=first["id"], title="Instalación corregida v2")
    )
    assert second["version"] == 2 and second["operation_key"] == first["operation_key"]
    assert second["supersedes"] == first["id"]
    assert client.get(f"{OPS}/{first['id']}").json()["status"] == "superseded"


def test_reference_catalog_hashes_files_shipped_with_the_server(client: TestClient) -> None:
    body = client.get(f"{OPS}/reference-artifacts").json()
    names = {item["name"] for item in body["items"]}
    assert "install-sentra-agent.ps1" in names
    assert all(len(item["sha256"]) == 64 for item in body["items"])


# --- Política de autorización de mantenimiento ----------------------------------------------


def test_policy_new_matching_detections_are_recognized_automatically(
    client: TestClient, engine: Engine, db: Session
) -> None:
    """Aprobación explícita primero; después, lo nuevo que casa se reconoce solo."""
    agent, asset_id = _agent(client, db)
    op = _create_and_approve(client, _operation_body(_asset_public_id(db, asset_id)))
    _approved_ago(db, op, 60)
    _install(client, agent)
    _run(engine)
    for rule in ("SCR-001", "PER-001", "CORR-002"):
        found = _detections(client, rule)
        assert len(found) == 1, (rule, [(d["status"], d["summary"]) for d in found])
        item = found[0]
        assert item["status"] == "resolved" and item["resolved_by"] == "attribution", rule
        body = client.get(f"{API}/detections/{item['detection_id']}/attribution").json()
        # Se conserva todo: evidencia, veredicto, operación e historial.
        assert body["verdict"] == "verified_benign"
        assert body["attribution"]["operation"]["operation_id"] == op["id"]
        assert body["attribution"]["review_required"] is None
        assert [h["source"] for h in body["history"]] == ["system"]
    assert client.get(f"{OPS}/{op['id']}").json()["matches"] == 3


def test_policy_mismatching_evidence_reopens_a_recognized_detection(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    op = _create_and_approve(client, _operation_body(_asset_public_id(db, asset_id)))
    _approved_ago(db, op, 60)
    _install(client, agent)
    _run(engine)
    (per,) = _detections(client, "PER-001")
    assert per["status"] == "resolved"
    # El mismo servicio reaparece con otro ejecutable: la operación no lo describe.
    evil = _service(_ago(20))
    evil["data"]["ImagePath"] = "C:\\Users\\Public\\svc.exe"
    _send(client, agent, [evil])
    _run(engine)
    (per,) = _detections(client, "PER-001")
    assert per["status"] == "open"
    body = client.get(f"{API}/detections/{per['detection_id']}/attribution").json()
    assert body["verdict"] == "suspicious_unverified"
    assert [h["verdict"] for h in body["history"]][:2] == [
        "suspicious_unverified",
        "verified_benign",
    ]


def test_policy_pending_operation_recognizes_nothing(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    created = client.post(OPS, json=_operation_body(_asset_public_id(db, asset_id)))
    assert created.status_code == 201
    _install(client, agent)
    _run(engine)
    (corr,) = _detections(client, "CORR-002")
    assert corr["status"] == "open"
    body = client.get(f"{API}/detections/{corr['detection_id']}/attribution").json()
    assert body["verdict"] == "suspicious_unverified"
    assert body["attribution"]["review_required"] is None


def test_policy_revoked_or_expired_operation_stops_recognizing(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    op = _create_and_approve(client, _operation_body(_asset_public_id(db, asset_id)))
    _approved_ago(db, op, 60)
    revoked = client.post(f"{OPS}/{op['id']}/revoke", json={"reason": "instalación cancelada"})
    assert revoked.status_code == 200, revoked.text
    _install(client, agent)
    _run(engine)
    assert _detections(client, "CORR-002")[0]["status"] == "open"

    other, other_asset = _agent(client, db)
    second = _create_and_approve(client, _operation_body(_asset_public_id(db, other_asset)))
    _approved_ago(db, second, 60)
    row = db.scalar(
        select(MaintenanceOperation).where(MaintenanceOperation.public_id == second["id"])
    )
    assert row is not None
    row.window_end = datetime.now(UTC) - timedelta(minutes=2)
    row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()
    _install(client, other)
    _run(engine)
    corr = [d for d in _detections(client, "CORR-002") if d["status"] == "open"]
    assert len(corr) == 2


def test_policy_new_or_modified_script_is_never_recognized(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    op = _create_and_approve(client, _operation_body(_asset_public_id(db, asset_id)))
    _approved_ago(db, op, 60)
    # Script nuevo (otra ruta, otro hash) y el autorizado modificado (misma ruta, otro hash).
    _send(
        client,
        agent,
        [
            _block(_ago(12), path="C:\\Users\\Public\\nuevo.ps1", sha="d" * 64),
            _block(_ago(11), sha="e" * 64),
        ],
    )
    _run(engine)
    detections = _detections(client, "SCR-001")
    assert detections and all(d["status"] == "open" for d in detections)
    for item in detections:
        body = client.get(f"{API}/detections/{item['detection_id']}/attribution").json()
        assert body["verdict"] == "suspicious_unverified"
        assert "requiere investigación" in " ".join(body["attribution"]["explanation"])


def test_policy_disabled_requires_explicit_review_for_everything(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MAINTENANCE_AUTO_RECOGNITION", "false")
    get_settings.cache_clear()
    try:
        agent, asset_id = _agent(client, db)
        op = _create_and_approve(client, _operation_body(_asset_public_id(db, asset_id)))
        _approved_ago(db, op, 60)
        _install(client, agent)
        _run(engine)
        (corr,) = _detections(client, "CORR-002")
        assert corr["status"] == "open"
        body = client.get(f"{API}/detections/{corr['detection_id']}/attribution").json()
        assert body["attribution"]["review_required"]["reason"] == "auto_recognition_disabled"
        applied = client.post(f"{OPS}/{op['id']}/apply", json={"confirm": True})
        assert applied.status_code == 200 and applied.json()["resolved"] == 3
    finally:
        monkeypatch.delenv("MAINTENANCE_AUTO_RECOGNITION")
        get_settings.cache_clear()
    audit = db.scalars(
        select(AuditEvent).where(AuditEvent.action == "maintenance_operation_applied")
    ).all()
    assert len(audit) == 1


def test_policy_does_not_hide_a_real_exposure() -> None:
    """PostgreSQL en 5432 sigue contando aunque la instalación esté verificada."""
    port = calc.EvidenceItem(
        "port_exposed",
        T0,
        {"port": 5432, "exe": "C:\\Program Files\\PostgreSQL\\16\\bin\\postgres.exe"},
    )
    op = _op(
        artifacts=(
            calc.ArtifactRef(
                kind="binary",
                path=calc.canonical_path("C:\\Program Files\\PostgreSQL\\16\\bin\\postgres.exe"),
                sha256=SHA,
            ),
        )
    )
    result = calc.evaluate("NET-001", [port], [op])
    assert result.to_json(T0)["risk_effect"] == "kept_exposure"
