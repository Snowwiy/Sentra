"""Asset Context (Fase 4L): modelo, API, RBAC, auditoría, concurrencia, filtros, Risk,
incidentes, IA, detecciones, resumen de amenaza interno y migración 0023.

Datos sintéticos de test (nunca demos en producción).
"""

import json
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, event, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.asset import Asset, AssetCriticality
from app.models.asset_context import (
    AssetBusinessContext,
    AssetContextChange,
    AssetEnvironment,
    AssetTag,
    DataSensitivity,
)
from app.models.audit import AuditEvent
from app.models.change import AssetChange, ChangeCategory, ChangeKind
from app.models.detection import DetectionConfidence, DetectionSeverity, DetectionStatus
from app.risk.calculator import AssetContext, DetectionInput, RiskInputs, calculate
from app.risk.config import CONTEXT_FACTOR_CAP, RiskConfig
from app.services import asset_context_service
from app.services.reconciliation import merge_into
from tests.conftest import _alembic_config, authenticate
from tests.test_ai import _enable
from tests.test_risk import _detection, _discovered, _risk

API = "/api/v1"
CONFIG = RiskConfig()


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


def _context(client: TestClient, asset: Asset) -> dict[str, Any]:
    return _ok(client.get(f"{API}/assets/{asset.public_id}/context"))


def _patch(client: TestClient, asset: Asset, version: int | None = None, **fields: Any) -> Any:
    if version is None:
        version = _context(client, asset)["version"]
    return client.patch(
        f"{API}/assets/{asset.public_id}/context", json={"version": version, **fields}
    )


def _audit(db: Session, action: str | None = None) -> list[AuditEvent]:
    db.expire_all()
    stmt = select(AuditEvent).where(AuditEvent.target_type == "asset")
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    return list(db.scalars(stmt.order_by(AuditEvent.id)))


def _viewer(client: TestClient, engine: Engine, role: str = "viewer") -> TestClient:
    other = TestClient(client.app)
    authenticate(other, engine, role)
    return other


# --- Defaults y lectura -----------------------------------------------------------------------


def test_defaults_are_unknown_and_conservative(client: TestClient, db: Session) -> None:
    asset = _discovered(db, name="NUEVO")
    ctx = _context(client, asset)
    assert ctx["version"] == 0
    assert ctx["criticality"] == "medium" and ctx["criticality_confirmed"] is False
    for field in ("role", "environment", "data_sensitivity", "network_zone"):
        assert ctx[field] == "unknown", field
    # Tri-estado: desconocido es null, nunca false.
    assert ctx["internet_exposed"] is None
    assert ctx["owner"] is None and ctx["department"] is None and ctx["tags"] == []
    assert ctx["provenance"] == {}
    assert ctx["managed_state"] == "DISCOVERED"
    assert ctx["completeness"] == {
        "percent": 0,
        "complete": False,
        "known": [],
        "missing": list(asset_context_service.COMPLETENESS_FIELDS),
    }
    # Leer no crea fila (no se inventa contexto).
    assert db.get(AssetBusinessContext, asset.id) is None
    assert _error(client.get(f"{API}/assets/{uuid4()}/context"), 404, "not_found")


def test_admin_sets_full_context_with_provenance_history_and_one_audit_event(
    client: TestClient, db: Session
) -> None:
    asset = _discovered(db, name="SRV-AUTH")
    body = _ok(
        _patch(
            client,
            asset,
            criticality="high",
            criticality_rationale="Servidor de autenticación",
            role="server",
            environment="production",
            owner="  Equipo   IT ",
            department="IT",
            data_sensitivity="confidential",
            network_zone="server",
            internet_exposed=False,
            tags=["Critical Service", "vpn", "VPN", "backup"],
        )
    )
    assert body["version"] == 1
    assert body["criticality"] == "high" and body["criticality_confirmed"] is True
    assert body["criticality_rationale"] == "Servidor de autenticación"
    assert body["criticality_updated_by"] == "admin" and body["criticality_updated_at"]
    assert body["owner"] == "Equipo IT"  # espacios normalizados
    assert body["internet_exposed"] is False
    # Normalizadas, sin duplicados y ordenadas.
    assert body["tags"] == ["backup", "critical-service", "vpn"]
    assert body["completeness"]["percent"] == 100 and body["completeness"]["complete"]
    prov = body["provenance"]["role"]
    assert prov["source"] == "manual" and prov["kind"] == "configured"
    assert prov["confidence"] is None  # sin confianza artificial en datos manuales
    assert prov["updated_by"] == "admin"
    assert "manual" in body["visibility_sources"]
    # La criticidad de 4I se reutiliza: misma columna, visible en el activo.
    assert _ok(client.get(f"{API}/assets/{asset.public_id}"))["criticality"] == "high"
    assert _ok(client.get(f"{API}/assets/{asset.public_id}"))["role"] == "server"

    (event_,) = _audit(db)  # una operación = un evento
    assert event_.action == "asset_context_updated" and event_.result == "success"
    details = event_.details or {}
    assert set(details["fields"]) == {
        "criticality",
        "criticality_rationale",
        "role",
        "environment",
        "owner",
        "department",
        "data_sensitivity",
        "network_zone",
        "internet_exposed",
        "tags",
    }
    role = next(c for c in details["changes"] if c["field"] == "role")
    assert role == {"field": "role", "from": "unknown", "to": "server"}
    assert event_.actor == "admin" and event_.target_id == str(asset.public_id)

    history = _ok(client.get(f"{API}/assets/{asset.public_id}/context/history"))
    assert history["total"] == 10
    by_field = {h["field"]: h for h in history["items"]}
    assert by_field["environment"]["old_value"] == "unknown"
    assert by_field["environment"]["new_value"] == "production"
    assert by_field["internet_exposed"]["new_value"] == "false"
    assert {h["source"] for h in history["items"]} == {"manual"}


def test_single_field_change_uses_its_specific_audit_action(
    client: TestClient, db: Session
) -> None:
    asset = _discovered(db)
    for fields, action in (
        ({"role": "database"}, "asset_role_changed"),
        ({"owner": "DBA"}, "asset_owner_changed"),
        ({"department": "Finance"}, "asset_owner_changed"),
        ({"environment": "staging"}, "asset_environment_changed"),
        ({"data_sensitivity": "restricted"}, "asset_data_sensitivity_changed"),
        ({"network_zone": "dmz"}, "asset_network_zone_changed"),
        ({"internet_exposed": True}, "asset_internet_exposure_changed"),
        ({"tags": ["pci"]}, "asset_tags_changed"),
        ({"criticality": "critical"}, "asset_criticality_changed"),
    ):
        _ok(_patch(client, asset, **fields))
        assert _audit(db)[-1].action == action, fields
    assert _context(client, asset)["version"] == 9


def test_no_op_patch_does_not_bump_version_or_audit(client: TestClient, db: Session) -> None:
    asset = _discovered(db)
    _ok(_patch(client, asset, role="server", tags=["a", "b"]))
    before = len(_audit(db))
    again = _ok(_patch(client, asset, role="server", tags=["b", "a"]))
    assert again["version"] == 1 and len(_audit(db)) == before


def test_unknown_clears_value_and_its_provenance(client: TestClient, db: Session) -> None:
    asset = _discovered(db)
    _ok(_patch(client, asset, role="server", internet_exposed=True, owner="IT"))
    body = _ok(_patch(client, asset, role="unknown", internet_exposed=None, owner=""))
    assert body["role"] == "unknown" and body["internet_exposed"] is None
    assert body["owner"] is None
    assert body["provenance"] == {}


# --- Validación y entradas negativas ----------------------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {"role": "mainframe"},
        {"environment": "prod"},
        {"network_zone": "vlan10"},
        {"data_sensitivity": "secret"},
        {"criticality": "extreme"},
        {"owner": "x" * 129},
        {"department": "d" * 65},
        {"criticality_rationale": "r" * 201},
        {"owner": "<script>alert(1)</script>"},
        {"department": "IT\x07"},
        {"tags": [f"t{i}" for i in range(21)]},
        {"tags": ["no valid!"]},
        {"tags": ["x" * 33]},
        {"tags": None},
        {"role": None},
        {"criticality": None},
        # Origen forjado: la API solo acepta datos manuales.
        {"role": "server", "source": "snmp"},
        {"role": "server", "provenance": {"role": {"source": "discovery"}}},
        {"internet_exposed": "maybe"},
        {},
    ],
)
def test_invalid_input_is_rejected(client: TestClient, db: Session, fields: Any) -> None:
    asset = _discovered(db)
    response = _patch(client, asset, version=0, **fields)
    _error(response, 422, "validation_error")
    assert db.get(AssetBusinessContext, asset.id) is None


def test_version_is_required(client: TestClient, db: Session) -> None:
    asset = _discovered(db)
    response = client.patch(f"{API}/assets/{asset.public_id}/context", json={"role": "server"})
    _error(response, 422, "validation_error")


def test_html_like_text_is_never_stored_and_safe_text_round_trips(
    client: TestClient, db: Session
) -> None:
    asset = _discovered(db)
    body = _ok(_patch(client, asset, owner="O'Brien & Co. (IT-Ops)", department="R&D"))
    assert body["owner"] == "O'Brien & Co. (IT-Ops)" and body["department"] == "R&D"


def test_distinct_tag_budget_prevents_tag_flood(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(asset_context_service, "MAX_DISTINCT_TAGS", 3)
    one, two = _discovered(db), _discovered(db)
    _ok(_patch(client, one, tags=["a", "b", "c"]))
    # Reutilizar etiquetas existentes siempre se puede.
    _ok(_patch(client, two, tags=["a", "c"]))
    _error(_patch(client, two, tags=["a", "d"]), 422, "asset_tag_limit")
    assert _context(client, two)["tags"] == ["a", "c"]


# --- RBAC y CSRF ------------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_viewer_and_analyst_read_but_cannot_modify(
    client: TestClient, engine: Engine, db: Session, role: str
) -> None:
    asset = _discovered(db)
    _ok(_patch(client, asset, role="server", owner="IT"))
    with _viewer(client, engine, role) as other:
        ctx = _ok(other.get(f"{API}/assets/{asset.public_id}/context"))
        assert ctx["role"] == "server" and ctx["owner"] == "IT"
        _ok(other.get(f"{API}/assets/{asset.public_id}/context/history"))
        _ok(other.get(f"{API}/assets/{asset.public_id}/threat-summary"))
        _ok(other.get(f"{API}/assets/context/options"))
        denied = other.patch(
            f"{API}/assets/{asset.public_id}/context", json={"version": 1, "role": "workstation"}
        )
        _error(denied, 403, "permission_denied")
    assert _context(client, asset)["role"] == "server"


def test_context_mutation_requires_csrf(client: TestClient, db: Session) -> None:
    asset = _discovered(db)
    response = client.patch(
        f"{API}/assets/{asset.public_id}/context",
        json={"version": 0, "role": "server"},
        headers={"X-CSRF-Token": "0" * 64},
    )
    _error(response, 403, "csrf_failed")
    assert db.get(AssetBusinessContext, asset.id) is None


def test_context_endpoints_require_a_session(client: TestClient, db: Session) -> None:
    asset = _discovered(db)
    client.cookies.clear()
    for path in ("context", "context/history", "threat-summary"):
        _error(client.get(f"{API}/assets/{asset.public_id}/{path}"), 401, "not_authenticated")
    _error(client.get(f"{API}/assets/context/options"), 401, "not_authenticated")


# --- Concurrencia -----------------------------------------------------------------------------


def test_stale_version_returns_409_without_silent_overwrite(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    _ok(_patch(client, asset, version=0, role="server"))
    conflict = _error(_patch(client, asset, version=0, role="workstation"), 409,
                      "asset_context_conflict")  # fmt: skip
    assert conflict["details"][0]["current_version"] == 1
    assert conflict["details"][0]["updated_by"] == "admin"
    assert _context(client, asset)["role"] == "server"
    failure = _audit(db, "asset_context_updated")[-1]
    assert failure.result == "failure"
    assert (failure.details or {})["error"] == "asset_context_conflict"


def test_two_admins_editing_at_once_one_wins_one_gets_409(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    second = _viewer(client, engine, "admin")
    results: list[int] = []
    barrier = threading.Barrier(2)

    def edit(c: TestClient, role: str) -> None:
        barrier.wait()
        results.append(_patch(c, asset, version=0, role=role).status_code)

    threads = [
        threading.Thread(target=edit, args=(c, r))
        for c, r in ((client, "server"), (second, "database"))
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    second.close()
    assert sorted(results) == [200, 409]
    ctx = _context(client, asset)
    assert ctx["version"] == 1 and ctx["role"] in ("server", "database")
    assert _ok(client.get(f"{API}/assets/{asset.public_id}/context/history"))["total"] == 1


def test_criticality_route_bumps_context_version_and_records_who(
    client: TestClient, db: Session
) -> None:
    asset = _discovered(db)
    ctx = _context(client, asset)
    _ok(client.patch(f"{API}/assets/{asset.public_id}/criticality", json={"criticality": "high"}))
    after = _context(client, asset)
    assert after["version"] == ctx["version"] + 1
    assert after["criticality_updated_by"] == "admin" and after["criticality_confirmed"]
    assert after["provenance"]["criticality"]["source"] == "manual"
    # Un editor de contexto con la versión anterior no devuelve la criticidad a medium.
    _error(_patch(client, asset, version=ctx["version"], criticality="medium"), 409,
           "asset_context_conflict")  # fmt: skip
    history = _ok(client.get(f"{API}/assets/{asset.public_id}/context/history"))
    assert history["items"][0]["field"] == "criticality"
    assert history["items"][0]["new_value"] == "high"


# --- Manual override vs inferencia ------------------------------------------------------------


def test_inferred_role_is_a_suggestion_and_never_overrides_manual(
    client: TestClient, db: Session
) -> None:
    asset = _discovered(db, device_type="pc")
    ctx = _context(client, asset)
    assert ctx["role"] == "unknown"  # no se infiere un rol confirmado sin evidencia humana
    assert ctx["role_suggestion"]["value"] == "workstation"
    assert ctx["role_suggestion"]["kind"] == "inferred"
    assert ctx["role_suggestion"]["source"] == "discovery"

    _ok(_patch(client, asset, role="server"))
    # Discovery vuelve a clasificar el equipo como "probable workstation".
    asset.device_type = "laptop"
    db.commit()
    ctx = _context(client, asset)
    assert ctx["role"] == "server"
    assert ctx["provenance"]["role"]["source"] == "manual"
    assert ctx["role_suggestion"]["value"] == "workstation"  # guardada aparte
    # Sin sugerencia si coincide con lo confirmado o el tipo no tiene rol directo.
    asset.device_type = "server"
    db.commit()
    assert _context(client, asset)["role_suggestion"] is None
    asset.device_type = "nas"
    db.commit()
    assert _context(client, asset)["role_suggestion"] is None


def test_reconciliation_keeps_context_of_the_discovered_asset(
    client: TestClient, engine: Engine, db: Session
) -> None:
    discovered = _discovered(db, name="PC-01")
    target = _discovered(db, name="PC-01-AGENT")
    _ok(_patch(client, discovered, role="server", environment="lab", tags=["legacy"]))
    _ok(_patch(client, target, environment="production", tags=["soc"]))
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        source = session.get(Asset, discovered.id)
        dest = session.get(Asset, target.id)
        assert source is not None and dest is not None
        merge_into(session, source=source, target=dest)
        session.commit()
    ctx = _context(client, target)
    assert ctx["role"] == "server"  # desconocido en el destino: se toma del descubierto
    assert ctx["environment"] == "production"  # conocido en el destino: manda
    assert ctx["tags"] == ["legacy", "soc"]
    assert db.scalar(select(AssetTag).where(AssetTag.asset_id == discovered.id)) is None
    history = db.scalars(
        select(AssetContextChange).where(AssetContextChange.asset_id == target.id)
    ).all()
    assert {h.field for h in history} >= {"role", "environment", "tags"}


# --- Filtros, orden y paginación --------------------------------------------------------------


def _fleet(client: TestClient, db: Session) -> dict[str, Asset]:
    assets = {
        "web": _discovered(db, name="WEB-01"),
        "db": _discovered(db, name="DB-01"),
        "pc": _discovered(db, name="PC-01"),
        "bare": _discovered(db, name="ZZ-SIN-CONTEXTO"),
    }
    _ok(_patch(client, assets["web"], role="web_server", environment="production",
               network_zone="dmz", internet_exposed=True, department="IT",
               tags=["internet-facing", "pci"], criticality="high"))  # fmt: skip
    _ok(_patch(client, assets["db"], role="database", environment="production",
               network_zone="server", internet_exposed=False, department="Finance",
               data_sensitivity="restricted", tags=["pci"], criticality="critical"))  # fmt: skip
    _ok(_patch(client, assets["pc"], role="workstation", environment="development",
               network_zone="user", department="it"))  # fmt: skip
    return assets


def _names(client: TestClient, **params: Any) -> list[str]:
    body = _ok(client.get(f"{API}/assets", params=params))
    return [item["display_name"] for item in body["items"]]


def test_asset_list_filters_by_context(client: TestClient, db: Session) -> None:
    _fleet(client, db)
    assert _names(client, criticality="critical") == ["DB-01"]
    assert _names(client, role="web_server") == ["WEB-01"]
    assert _names(client, environment="production") == ["DB-01", "WEB-01"]
    assert _names(client, environment="unknown") == ["ZZ-SIN-CONTEXTO"]
    assert _names(client, network_zone="dmz") == ["WEB-01"]
    assert _names(client, data_sensitivity="restricted") == ["DB-01"]
    assert _names(client, internet_exposed="true") == ["WEB-01"]
    assert _names(client, internet_exposed="false") == ["DB-01"]
    # Desconocido no es "no expuesto".
    assert _names(client, internet_exposed="unknown") == ["PC-01", "ZZ-SIN-CONTEXTO"]
    assert _names(client, department="IT") == ["PC-01", "WEB-01"]  # sin distinguir mayúsculas
    assert _names(client, tag="PCI") == ["DB-01", "WEB-01"]
    assert _names(client, tag="pci", environment="production", role="database") == ["DB-01"]
    assert _names(client, method="discovered", role="workstation") == ["PC-01"]
    assert _error(client.get(f"{API}/assets", params={"role": "x"}), 422, "validation_error")
    assert _error(client.get(f"{API}/assets", params={"tag": "no valid!"}), 422,
                  "validation_error")  # fmt: skip
    assert _error(client.get(f"{API}/assets", params={"internet_exposed": "yes"}), 422,
                  "validation_error")  # fmt: skip


def test_asset_list_sorting_and_pagination(client: TestClient, db: Session) -> None:
    _fleet(client, db)
    assert _names(client, sort="criticality") == ["DB-01", "WEB-01", "PC-01", "ZZ-SIN-CONTEXTO"]
    page = _ok(client.get(f"{API}/assets", params={"limit": 2, "offset": 1}))
    assert page["total"] == 4 and [i["display_name"] for i in page["items"]] == [
        "PC-01",
        "WEB-01",
    ]
    # Paginado en SQL (sin filtros de Python) y en Python (con estado): mismo orden y total.
    sql = _ok(client.get(f"{API}/assets", params={"sort": "criticality", "limit": 3}))
    assert [i["display_name"] for i in sql["items"]] == ["DB-01", "WEB-01", "PC-01"]
    assert sql["total"] == 4
    statuses = {i["status"] for i in _ok(client.get(f"{API}/assets"))["items"]}
    status = sorted(statuses)[0]
    by_status = _ok(client.get(f"{API}/assets", params={"status": status, "limit": 1}))
    assert by_status["total"] == sum(
        1 for i in _ok(client.get(f"{API}/assets"))["items"] if i["status"] == status
    )
    # Sin limit: todos (contrato anterior a 4L).
    assert _ok(client.get(f"{API}/assets"))["total"] == 4
    assert _error(client.get(f"{API}/assets", params={"limit": 0}), 422, "validation_error")
    assert _error(client.get(f"{API}/assets", params={"sort": "risk"}), 422, "validation_error")


def test_options_list_enums_limits_and_used_values(client: TestClient, db: Session) -> None:
    _fleet(client, db)
    options = _ok(client.get(f"{API}/assets/context/options"))
    assert "domain_controller" in options["role"] and "unknown" in options["role"]
    assert options["environment"][-1] == "unknown" and "production" in options["environment"]
    assert options["network_zone"][0] == "unknown"
    assert options["limits"]["max_tags"] == 20 and options["limits"]["owner_max"] == 128
    assert options["tags"][0] == "pci"  # la más usada primero
    assert {d.lower() for d in options["departments"]} == {"it", "finance"}


def test_asset_list_with_context_uses_a_bounded_number_of_queries(
    client: TestClient, engine: Engine, db: Session
) -> None:
    for i in range(12):
        asset = _discovered(db, name=f"N-{i:02d}")
        _ok(_patch(client, asset, role="server", tags=["soc"], environment="lab"))
    statements: list[str] = []

    def count(*args: Any) -> None:
        statements.append(str(args[2]))

    event.listen(engine, "before_cursor_execute", count)
    try:
        _ok(client.get(f"{API}/assets", params={"tag": "soc", "environment": "lab"}))
    finally:
        event.remove(engine, "before_cursor_execute", count)
    # Sesión + activos + telemetría + puertos + riesgo + roles (sin una consulta por activo).
    assert len(statements) <= 10, statements


# --- Risk Engine ------------------------------------------------------------------------------


def _inputs(
    asset: AssetContext, severity: DetectionSeverity = DetectionSeverity.HIGH
) -> RiskInputs:
    now = datetime.now(UTC)
    detection = DetectionInput(
        id=1,
        public_id=uuid4(),
        rule_id="DEF-001",
        title="t",
        category="defense",
        kind="single",
        severity=severity,
        confidence=DetectionConfidence.HIGH,
        status=DetectionStatus.OPEN,
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
    )
    return RiskInputs(asset=asset, detections=[detection])


def test_unknown_context_is_neutral_and_never_adds_risk() -> None:
    now = datetime.now(UTC)
    base = calculate(_inputs(AssetContext()), CONFIG, now)
    unknown = calculate(
        _inputs(
            AssetContext(
                environment=AssetEnvironment.UNKNOWN,
                data_sensitivity=DataSensitivity.UNKNOWN,
                internet_exposed=None,
            )
        ),
        CONFIG,
        now,
    )
    assert unknown.score == base.score
    assert not [c for c in unknown.contributions if c.factor == "business_context"]
    # Entornos no productivos y datos públicos no restan (los atacantes pivotan desde ahí).
    lab = calculate(
        _inputs(
            AssetContext(environment=AssetEnvironment.LAB, data_sensitivity=DataSensitivity.PUBLIC)
        ),
        CONFIG,
        now,
    )
    assert lab.score == base.score
    # internet_exposed=False tampoco resta ni suma.
    exposed_false = calculate(_inputs(AssetContext(internet_exposed=False)), CONFIG, now)
    assert exposed_false.score == base.score


def test_context_alone_never_creates_risk() -> None:
    now = datetime.now(UTC)
    clean = calculate(
        RiskInputs(
            asset=AssetContext(
                criticality=AssetCriticality.CRITICAL,
                device_type="server",
                environment=AssetEnvironment.PRODUCTION,
                data_sensitivity=DataSensitivity.RESTRICTED,
                internet_exposed=True,
            )
        ),
        CONFIG,
        now,
    )
    assert clean.score == 0 and clean.contributions == ()


def test_context_amplifies_evidence_within_a_documented_cap() -> None:
    now = datetime.now(UTC)
    medium = DetectionSeverity.MEDIUM
    base = calculate(_inputs(AssetContext(), medium), CONFIG, now)
    production = calculate(
        _inputs(AssetContext(environment=AssetEnvironment.PRODUCTION), medium), CONFIG, now
    )
    assert production.score > base.score
    line = next(c for c in production.contributions if c.factor == "business_context")
    assert line.label.startswith("Contexto: entorno de producción") and line.points > 0
    everything = calculate(
        _inputs(
            AssetContext(
                environment=AssetEnvironment.PRODUCTION,
                data_sensitivity=DataSensitivity.RESTRICTED,
                internet_exposed=True,
            ),
            medium,
        ),
        CONFIG,
        now,
    )
    lines = [c for c in everything.contributions if c.factor == "business_context"]
    assert len(lines) == 4  # tres factores + el tope
    assert lines[-1].points < 0 and "Tope" in lines[-1].label
    assert everything.breakdown["context_factor"] == CONTEXT_FACTOR_CAP
    # El ledger sigue sumando exactamente el score antes de redondear.
    total = sum(c.points for c in everything.contributions)
    assert abs(total - everything.breakdown["saturated_points"]) < 0.05
    # Una detección media con todo el contexto posible no llega a crítico.
    assert everything.level.value in ("medium", "high")


def test_context_change_recalculates_risk_and_explains_it(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db, name="SRV-PROD")
    _detection(db, asset, severity=DetectionSeverity.MEDIUM)
    _risk(engine)
    before = _ok(client.get(f"{API}/risk/assets/{asset.public_id}"))
    assert before["explanation"]["context"] == []

    _ok(_patch(client, asset, environment="production", internet_exposed=True,
               criticality="high"))  # fmt: skip
    after = _ok(client.get(f"{API}/risk/assets/{asset.public_id}"))
    assert after["score"] > before["score"]  # recalculado en la misma petición
    assert after["formula_version"] == 2
    labels = [item["label"] for item in after["explanation"]["context"]]
    assert any(label.startswith("Criticidad del activo") for label in labels)
    assert any("producción" in label for label in labels)
    assert any("exposición a Internet confirmada" in label for label in labels)
    # El contexto no es un "motivo" del riesgo: los motivos son evidencia.
    assert not any("Contexto:" in reason for reason in after["explanation"]["reasons"])

    # Cambios que no son entrada del riesgo no lo recalculan.
    calculated = after["calculated_at"]
    _ok(_patch(client, asset, owner="IT", tags=["soc"], role="server", network_zone="server"))
    assert _ok(client.get(f"{API}/risk/assets/{asset.public_id}"))["calculated_at"] == calculated


def test_critical_server_without_evidence_stays_at_zero(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db, name="DC-01", device_type="server")
    _ok(_patch(client, asset, criticality="critical", environment="production",
               data_sensitivity="restricted", internet_exposed=True,
               role="domain_controller"))  # fmt: skip
    _risk(engine)
    risk = _ok(client.get(f"{API}/risk/assets/{asset.public_id}"))
    assert risk["score"] == 0 and risk["level"] == "informational"
    assert risk["explanation"]["context"] == []


# --- Incidentes -------------------------------------------------------------------------------


def test_incident_shows_current_context_and_snapshots(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db, name="SRV-FIN")
    detection = _detection(db, asset)
    _ok(_patch(client, asset, role="server", criticality="high", environment="production",
               owner="IT", network_zone="server", tags=["pci"]))  # fmt: skip
    incident = _ok(client.post(f"{API}/detections/{detection.public_id}/incident", json={}), 201)
    detail = _ok(client.get(f"{API}/incidents/{incident['incident_id']}"))
    (ref,) = detail["asset_refs"]
    assert ref["context"]["role"] == "server" and ref["context"]["owner"] == "IT"
    assert ref["context"]["internet_exposed"] is None
    snapshot = ref["context_snapshot"]
    assert snapshot["criticality"] == "high" and snapshot["environment"] == "production"
    # Snapshot mínimo: sin responsable ni etiquetas.
    assert "owner" not in snapshot and "tags" not in snapshot
    assert ref["resolved_context_snapshot"] is None

    # El contexto cambia después: el detalle muestra el actual y conserva el histórico.
    _ok(_patch(client, asset, environment="staging"))
    triaged = _ok(
        client.patch(
            f"{API}/incidents/{incident['incident_id']}",
            json={"version": detail["version"], "status": "triage"},
        )
    )
    resolved = _ok(
        client.post(
            f"{API}/incidents/{incident['incident_id']}/resolve",
            json={"version": triaged["version"], "category": "true_positive"},
        )
    )
    (ref,) = _ok(client.get(f"{API}/incidents/{resolved['incident_id']}"))["asset_refs"]
    assert ref["context"]["environment"] == "staging"
    assert ref["context_snapshot"]["environment"] == "production"
    assert ref["resolved_context_snapshot"]["environment"] == "staging"


# --- Detecciones ------------------------------------------------------------------------------


def test_detection_detail_separates_severity_from_business_impact(
    client: TestClient, db: Session
) -> None:
    asset = _discovered(db)
    detection = _detection(db, asset, severity=DetectionSeverity.LOW)
    _ok(_patch(client, asset, criticality="critical", environment="production"))
    body = _ok(client.get(f"{API}/detections/{detection.public_id}"))
    assert body["severity"] == "low"  # la regla manda; el activo no la cambia
    assert body["asset_context"]["criticality"] == "critical"
    assert body["asset_context"]["environment"] == "production"


# --- IA ---------------------------------------------------------------------------------------


def test_ai_receives_grounded_context_with_provenance(
    client: TestClient, engine: Engine, db: Session
) -> None:
    ai, _ = _enable(client)
    asset = _discovered(db, name="SRV-AI", device_type="pc")
    _detection(db, asset)
    _risk(engine)
    _ok(_patch(client, asset, environment="production", owner="Ana Pérez", department="SOC"))
    _ok(client.post(f"{API}/ai/assets/{asset.public_id}/analyze"))
    data = json.loads(ai.requests[0].user)["sentra_data"]
    context = data["asset"]["business_context"]
    assert context["confirmed"]["environment"] == {"value": "production", "source": "manual"}
    # Proveedor local sin AI_REDACT=owners: el responsable viaja en claro (dato local).
    assert context["confirmed"]["owner"]["value"] == "Ana Pérez"
    # Lo desconocido se declara como tal: la IA no puede inventarlo.
    assert {"role", "network_zone", "internet_exposed", "criticality"} <= set(context["unknown"])
    assert "role" not in context["confirmed"] and "criticality" not in context["confirmed"]
    assert context["suggested_role"] == {
        "value": "workstation",
        "kind": "inferred",
        "source": "discovery",
        "confidence": None,
    }
    assert "unknown" in ai.requests[0].system  # la política explica cómo tratarlo


def test_ai_context_change_makes_cached_insight_stale(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _enable(client)
    asset = _discovered(db, name="SRV-CACHE")
    _detection(db, asset)
    _risk(engine)
    first = _ok(client.post(f"{API}/ai/assets/{asset.public_id}/analyze"))
    assert _ok(client.post(f"{API}/ai/assets/{asset.public_id}/analyze"))["cached"] is True
    _ok(_patch(client, asset, role="server"))
    again = _ok(client.post(f"{API}/ai/assets/{asset.public_id}/analyze"))
    assert again["cached"] is False and again["insight_id"] != first["insight_id"]


def test_ai_redacts_owner_and_department(client: TestClient, engine: Engine, db: Session) -> None:
    ai, _ = _enable(client, ai_redact="owners")
    asset = _discovered(db, name="SRV-RED")
    _detection(db, asset)
    _risk(engine)
    _ok(_patch(client, asset, owner="Ana Pérez", department="Finanzas"))
    _ok(client.post(f"{API}/ai/assets/{asset.public_id}/analyze"))
    sent = ai.requests[0].user
    assert "Ana Pérez" not in sent and "Finanzas" not in sent and "[owner-" in sent


def test_external_provider_always_pseudonymizes_owners(
    client: TestClient, engine: Engine, db: Session
) -> None:
    ai, _ = _enable(client, ai_base_url="https://api.example.com/v1", ai_allow_external=True)
    asset = _discovered(db, name="SRV-EXT")
    _detection(db, asset)
    _risk(engine)
    _ok(_patch(client, asset, owner="Ana Pérez", department="Finanzas"))
    _ok(client.post(f"{API}/ai/assets/{asset.public_id}/analyze"))
    sent = ai.requests[0].user
    assert "Ana Pérez" not in sent and "Finanzas" not in sent
    assert "owners" in _ok(client.get(f"{API}/ai/status"))["redaction"]


def test_ai_never_writes_context(client: TestClient, engine: Engine, db: Session) -> None:
    _enable(client)
    asset = _discovered(db, name="SRV-RO")
    _detection(db, asset)
    _risk(engine)
    before = _context(client, asset)
    _ok(client.post(f"{API}/ai/assets/{asset.public_id}/analyze"))
    assert _context(client, asset) == before
    assert db.get(AssetBusinessContext, asset.id) is None


def test_invalid_redaction_value_is_still_rejected() -> None:
    with pytest.raises(ValueError, match="AI_REDACT"):
        get_settings().model_validate({**get_settings().model_dump(), "ai_redact": "owners,x"})


# --- Resumen de amenaza interno ---------------------------------------------------------------


def test_threat_summary_is_computed_from_existing_data(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db, name="SRV-THREAT")
    empty = _ok(client.get(f"{API}/assets/{asset.public_id}/threat-summary"))
    assert empty["active_detection_count"] == 0 and empty["open_incident_count"] == 0
    assert empty["current_risk"] is None and empty["last_security_activity"] is None
    assert empty["highest_incident_severity"] is None

    high = _detection(db, asset, severity=DetectionSeverity.HIGH)
    _detection(db, asset, severity=DetectionSeverity.LOW, rule_id="NET-001")
    _detection(
        db,
        asset,
        severity=DetectionSeverity.CRITICAL,
        rule_id="AUTH-001",
        status=DetectionStatus.RESOLVED,
    )
    now = datetime.now(UTC)
    db.add(
        AssetChange(
            asset_id=asset.id,
            category=ChangeCategory.EXPOSURE,
            kind=ChangeKind.PORT_OPENED,
            item="tcp/3389",
            collected_at=now,
            detected_at=now - timedelta(days=1),
        )
    )
    db.add(
        AssetChange(
            asset_id=asset.id,
            category=ChangeCategory.EXPOSURE,
            kind=ChangeKind.PORT_OPENED,
            item="tcp/22",
            collected_at=now,
            detected_at=now - timedelta(days=30),
        )
    )
    db.commit()
    _risk(engine)
    _ok(client.post(f"{API}/detections/{high.public_id}/incident", json={}), 201)
    _ok(_patch(client, asset, environment="production"))
    summary = _ok(client.get(f"{API}/assets/{asset.public_id}/threat-summary"))
    assert summary["active_detection_count"] == 2
    assert summary["high_critical_detection_count"] == 1  # la crítica está resuelta
    assert summary["open_incident_count"] == 1
    assert summary["highest_incident_severity"] in ("high", "critical")
    assert summary["current_risk"]["score"] > 0
    assert summary["recent_exposure_changes"] == 1  # solo dentro de la ventana
    assert summary["recent_context_changes"] == 1
    assert summary["environment"] == "production" and summary["managed_state"] == "DISCOVERED"
    assert summary["last_security_activity"] is not None
    _error(client.get(f"{API}/assets/{uuid4()}/threat-summary"), 404, "not_found")


# --- Migración 0023 ---------------------------------------------------------------------------


def test_migration_0023_round_trip_with_existing_data(
    client: TestClient, engine: Engine, db: Session
) -> None:
    from alembic import command

    asset = _discovered(db, name="SRV-MIG")
    detection = _detection(db, asset)
    _risk(engine)
    _ok(_patch(client, asset, role="server", tags=["pci"], criticality="high"))
    _ok(client.post(f"{API}/detections/{detection.public_id}/incident", json={}), 201)

    tables = ("assets", "detections", "asset_risk", "incidents", "incident_assets", "users",
              "audit_events")  # fmt: skip

    def counts() -> dict[str, int]:
        with engine.connect() as connection:
            return {
                table: connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()  # noqa: S608
                for table in tables
            }

    before = counts()
    config = _alembic_config(str(engine.url.render_as_string(hide_password=False)))
    try:
        command.downgrade(config, "0022")
        assert counts() == before
        with engine.connect() as connection:
            for table in ("asset_context", "asset_tags", "asset_context_changes"):
                assert connection.execute(text(f"SELECT to_regclass('{table}')")).scalar() is None
            # La criticidad (4I) sobrevive al downgrade.
            assert (
                connection.execute(
                    text("SELECT criticality::text FROM assets WHERE id = :id"), {"id": asset.id}
                ).scalar_one()
                == "high"
            )
        command.upgrade(config, "0023")
        assert counts() == before
        command.downgrade(config, "0022")
    finally:
        command.upgrade(config, "head")
    assert counts() == before
    # Tras volver a subir el contexto está vacío (pérdida documentada) y la API funciona.
    ctx = _context(client, asset)
    assert ctx["role"] == "unknown" and ctx["tags"] == [] and ctx["criticality"] == "high"
    _ok(_patch(client, asset, role="database"))
