"""Risk Engine (Fase 4I) con base de datos: motor 4H real -> cola -> cálculo -> API.

Los datos son sintéticos (fixtures de test, nunca demos en producción). El job se ejecuta a
mano (`_risk`) con un `now` explícito cuando el test necesita que pase el tiempo (decay).
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from itertools import count
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, event, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.alert import Alert, AlertRule, AlertStatus
from app.models.asset import Asset, AssetCriticality, AssetStatus, MonitoringMethod
from app.models.audit import AuditEvent
from app.models.detection import (
    Detection,
    DetectionConfidence,
    DetectionSeverity,
    DetectionStatus,
)
from app.models.exposure import AssetPort, PortStateValue
from app.models.risk import (
    AssetRisk,
    RiskConfidence,
    RiskContributionRecord,
    RiskLevel,
    RiskSnapshot,
)
from app.risk import engine as risk_engine_module
from app.risk.calculator import calculate
from app.risk.config import RiskConfig
from app.risk.engine import RiskEngine, RiskRun
from app.risk.queue import request_recalculation
from app.services.alert_service import AlertThresholds
from app.services.retention_service import RetentionPolicy, RetentionService
from tests.conftest import authenticate
from tests.test_detections import _agent, _ago, _run, _send, admin_add, ev, fail, success

API = "/api/v1"
CONFIG = RiskConfig()
_ips = count(10)


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _risk(
    engine: Engine,
    now: datetime | None = None,
    config: RiskConfig = CONFIG,
    decay: bool = False,
) -> RiskRun:
    """Una vuelta del job: filas nuevas, cola y (opcional) decay."""
    with sessionmaker(bind=engine)() as session:
        risk = RiskEngine(session, config, AlertThresholds.from_settings(get_settings()))
        risk.seed_missing()
        run = risk.process_dirty(now)
        if decay:
            run.add(risk.process_decay(now))
        return run


def _queue_all(engine: Engine) -> None:
    with sessionmaker(bind=engine)() as session:
        request_recalculation(session, session.scalars(select(Asset.id)).all())
        session.commit()


def _asset_id(client: TestClient) -> str:
    """El único activo con agente del test."""
    (item,) = [
        a for a in client.get(f"{API}/assets").json()["items"] if a["monitoring_method"] == "agent"
    ]
    return str(item["asset_id"])


def _detail(client: TestClient, asset_id: str) -> dict[str, Any]:
    response = client.get(f"{API}/risk/assets/{asset_id}")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _discovered(
    db: Session,
    *,
    name: str | None = None,
    device_type: str | None = None,
    criticality: AssetCriticality = AssetCriticality.MEDIUM,
    online: bool = True,
) -> Asset:
    now = datetime.now(UTC)
    asset = Asset(
        monitoring_method=MonitoringMethod.DISCOVERED,
        primary_ip=f"10.20.0.{next(_ips)}",
        status=AssetStatus.UNKNOWN,
        network_status=AssetStatus.ONLINE if online else AssetStatus.OFFLINE,
        last_network_seen_at=now,
        first_seen_at=now,
        device_name=name,
        device_type=device_type,
        criticality=criticality,
    )
    db.add(asset)
    db.commit()
    return asset


def _detection(
    db: Session,
    asset: Asset,
    *,
    rule_id: str = "DEF-001",
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    confidence: DetectionConfidence = DetectionConfidence.HIGH,
    status: DetectionStatus = DetectionStatus.OPEN,
    kind: str = "single",
    minutes_ago: float = 2,
    occurrences: int = 1,
    details: dict[str, Any] | None = None,
) -> Detection:
    now = datetime.now(UTC)
    seen = now - timedelta(minutes=minutes_ago)
    detection = Detection(
        asset_id=asset.id,
        rule_id=rule_id,
        rule_version=1,
        kind=kind,
        dedup_key=uuid4().hex,
        severity=severity,
        confidence=confidence,
        status=status,
        title=f"Detección {rule_id}",
        summary="Sintética de test",
        details=details,
        occurrence_count=occurrences,
        first_seen_at=seen,
        last_seen_at=seen,
        created_at=now,
        updated_at=now,
        resolved_at=now if status == DetectionStatus.RESOLVED else None,
    )
    db.add(detection)
    db.commit()
    return detection


def _port(db: Session, asset: Asset, port: int, *, days_open: float = 10) -> AssetPort:
    now = datetime.now(UTC)
    opened = now - timedelta(days=days_open)
    row = AssetPort(
        asset_id=asset.id,
        protocol="tcp",
        port=port,
        state=PortStateValue.OPEN,
        first_seen_at=opened,
        opened_at=opened,
        last_seen_at=now,
        misses=0,
    )
    db.add(row)
    db.commit()
    return row


# --- Escenario QA de extremo a extremo (sección 34) -----------------------------------------


def test_qa_scenario_rise_correlate_resolve_decay(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _agent(client)
    asset_id = _asset_id(client)

    # 1. Sin detecciones: riesgo bajo (0, informativo).
    _risk(engine)
    clean = _detail(client, asset_id)
    assert clean["evaluated"] and clean["score"] == 0 and clean["level"] == "informational"

    # 2. Detección high (registro de eventos borrado): el score sube a high.
    _send(client, agent, [ev(1102, _ago(3), level="critical")])
    _run(engine)
    _risk(engine)
    high = _detail(client, asset_id)
    assert high["level"] == "high" and high["score"] >= 60
    assert high["contributions"][0]["rule_id"] == "DEF-001"
    assert high["explanation"]["headline"].startswith(f"{high['score']} / Alto")

    # 3. Correlación (fallos -> acceso -> grupo de administradores): sube de forma material.
    failures = [fail("ana", _ago(2.5 - i * 0.3)) for i in range(5)]
    _send(client, agent, [*failures, success("ana", _ago(1)), admin_add(_ago(0.5))])
    _run(engine)
    _risk(engine)
    correlated = _detail(client, asset_id)
    assert correlated["score"] >= high["score"] + 10
    assert correlated["level"] == "critical"
    rules = {c["rule_id"]: c for c in correlated["contributions"] if c["rule_id"]}
    assert rules["CORR-001"]["points"] > 0
    # AUTH-001 ya está dentro de CORR-001: aparece, pero sin sumar (sin doble conteo).
    assert rules["AUTH-001"]["points"] == 0
    assert rules["AUTH-001"]["details"]["absorbed_by"]["rule_id"] == "CORR-001"
    # Cruzar a critical abre UNA alerta risk_critical.
    alert = db.scalars(select(Alert).where(Alert.rule == AlertRule.RISK_CRITICAL)).one()
    assert alert.status == AlertStatus.OPEN

    # 4. Resolver todas las detecciones: el riesgo empieza a bajar, pero no a cero.
    for detection in client.get(f"{API}/detections", params={"active": True}).json()["items"]:
        response = client.post(f"{API}/detections/{detection['detection_id']}/resolve")
        assert response.status_code == 200
    _risk(engine)
    resolved = _detail(client, asset_id)
    assert 0 < resolved["score"] < correlated["score"]
    assert any("resueltas" in item["label"] for item in resolved["explanation"]["reduced"])
    db.expire_all()
    assert db.get(Alert, alert.id).status == AlertStatus.RESOLVED  # type: ignore[union-attr]

    # 5. Decay: dos días después el riesgo casi ha desaparecido.
    _risk(engine, now=datetime.now(UTC) + timedelta(days=2), decay=True)
    decayed = _detail(client, asset_id)
    assert decayed["score"] < resolved["score"]
    assert decayed["level"] == "informational"

    # Historial: cada paso material es un punto, con transiciones de subida y bajada.
    history = db.scalars(
        select(RiskSnapshot)
        .join(Asset, Asset.id == RiskSnapshot.asset_id)
        .where(Asset.public_id == asset_id)
        .order_by(RiskSnapshot.calculated_at)
    ).all()
    assert [s.score for s in history] == [
        0,
        high["score"],
        correlated["score"],
        resolved["score"],
        decayed["score"],
    ]
    assert [s.transition for s in history] == [None, "up", "up", "down", "down"]
    assert history[0].reason == "initial"
    # Solo una alerta de riesgo: los descensos no alertan.
    assert (
        db.scalar(
            select(func.count()).select_from(Alert).where(Alert.rule == AlertRule.RISK_CRITICAL)
        )
        == 1
    )


def test_detection_engine_and_analyst_actions_queue_recalculation(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _agent(client)
    _risk(engine)
    _send(client, agent, [ev(1102, _ago(2), level="critical")])
    _run(engine)
    (row,) = db.scalars(select(AssetRisk)).all()
    assert row.dirty_at is not None  # el motor 4H avisó
    _risk(engine)
    db.expire_all()
    assert db.scalars(select(AssetRisk)).one().dirty_at is None
    (detection,) = client.get(f"{API}/detections").json()["items"]
    client.post(f"{API}/detections/{detection['detection_id']}/acknowledge")
    db.expire_all()
    assert db.scalars(select(AssetRisk)).one().dirty_at is not None  # reconocer también


def test_acknowledged_detection_keeps_most_of_its_risk(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    asset_id = _asset_id(client)
    _send(client, agent, [ev(1102, _ago(2), level="critical")])
    _run(engine)
    _risk(engine)
    before = _detail(client, asset_id)["score"]
    (detection,) = client.get(f"{API}/detections").json()["items"]
    client.post(f"{API}/detections/{detection['detection_id']}/acknowledge")
    _risk(engine)
    after = _detail(client, asset_id)
    assert before * 0.8 <= after["score"] < before
    assert after["active_detections_total"] == 1  # reconocida sigue activa


# --- RBAC, auditoría y criticidad -----------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_only_admin_changes_criticality(
    client: TestClient, engine: Engine, db: Session, role: str
) -> None:
    asset = _discovered(db, name="SRV-01")
    _risk(engine)
    with TestClient(client.app) as other:
        authenticate(other, engine, role)
        assert other.get(f"{API}/risk/overview").status_code == 200
        assert other.get(f"{API}/risk/assets").status_code == 200
        assert other.get(f"{API}/risk/assets/{asset.public_id}").status_code == 200
        response = other.patch(
            f"{API}/assets/{asset.public_id}/criticality", json={"criticality": "low"}
        )
        assert response.status_code == 403
    db.refresh(asset)
    assert asset.criticality == AssetCriticality.MEDIUM
    denied = db.scalars(select(AuditEvent).where(AuditEvent.action == "permission_denied")).one()
    assert denied.details == {"permission": "assets:manage"}


def test_admin_changes_criticality_with_audit_and_immediate_recalculation(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db, name="SRV-02")
    _detection(db, asset, severity=DetectionSeverity.MEDIUM)
    _risk(engine)
    before = _detail(client, str(asset.public_id))
    assert before["criticality"] == "medium"

    response = client.patch(
        f"{API}/assets/{asset.public_id}/criticality", json={"criticality": "critical"}
    )
    assert response.status_code == 200, response.text
    after = response.json()
    assert after["criticality"] == "critical"
    assert after["score"] > before["score"]  # recalculado en la misma petición
    assert any(c["factor"] == "criticality" for c in after["contributions"])
    assert client.get(f"{API}/assets/{asset.public_id}").json()["criticality"] == "critical"

    audit = db.scalars(
        select(AuditEvent).where(AuditEvent.action == "asset_criticality_changed")
    ).one()
    assert (audit.result, audit.target_id) == ("success", str(asset.public_id))
    assert audit.details == {"from": "medium", "to": "critical"}


def test_criticality_validation_and_unknown_asset(client: TestClient, db: Session) -> None:
    asset = _discovered(db)
    bad = client.patch(f"{API}/assets/{asset.public_id}/criticality", json={"criticality": "x"})
    assert bad.status_code == 422
    extra = client.patch(
        f"{API}/assets/{asset.public_id}/criticality",
        json={"criticality": "low", "score": 0},
    )
    assert extra.status_code == 422  # no se pueden colar otros campos
    missing = client.patch(f"{API}/assets/{uuid4()}/criticality", json={"criticality": "low"})
    assert missing.status_code == 404
    failure = db.scalars(
        select(AuditEvent).where(AuditEvent.action == "asset_criticality_changed")
    ).one()
    assert failure.result == "failure"


def test_risk_endpoints_require_a_session(client: TestClient, db: Session) -> None:
    asset = _discovered(db)
    client.cookies.clear()
    assert client.get(f"{API}/risk/overview").status_code == 401
    assert client.get(f"{API}/risk/assets/{asset.public_id}/history").status_code == 401


# --- Historial, transiciones y alertas ------------------------------------------------------


def test_history_is_written_only_on_material_changes(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    _detection(db, asset)
    _risk(engine)
    now = datetime.now(UTC)
    # Recalcular sin cambios (cola y decay de pocos minutos) no añade puntos al historial.
    for minutes in (1, 2, 3):
        _queue_all(engine)
        _risk(engine, now=now + timedelta(minutes=minutes))
    assert db.scalar(select(func.count()).select_from(RiskSnapshot)) == 1
    # Tras el intervalo, un cambio pequeño (decay) sí deja un punto ("interval").
    _queue_all(engine)
    _risk(engine, now=now + timedelta(minutes=90))
    reasons = db.scalars(select(RiskSnapshot.reason).order_by(RiskSnapshot.id)).all()
    assert reasons == ["initial", "interval"]
    # Los snapshots guardan sus contribuciones normalizadas, con la detección enlazada.
    records = db.scalars(select(RiskContributionRecord)).all()
    assert records and all(r.detection_public_id for r in records if r.factor == "detection")


def test_new_contribution_creates_a_history_point(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    _detection(db, asset)
    _risk(engine)
    # Una detección nueva que apenas mueve el score (rendimientos decrecientes) se registra.
    _detection(
        db,
        asset,
        rule_id="NET-003",
        severity=DetectionSeverity.LOW,
        confidence=DetectionConfidence.LOW,
    )
    _queue_all(engine)
    _risk(engine)
    reasons = db.scalars(select(RiskSnapshot.reason).order_by(RiskSnapshot.id)).all()
    assert reasons == ["initial", "new_contribution"]


def test_level_transitions_are_recorded_and_only_rises_alert(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    _risk(engine)
    critical = _detection(db, asset, rule_id="CORR-004", kind="correlation",
                          severity=DetectionSeverity.CRITICAL)  # fmt: skip
    _queue_all(engine)
    _risk(engine)
    critical.status = DetectionStatus.RESOLVED
    critical.resolved_at = datetime.now(UTC)
    db.commit()
    _queue_all(engine)
    _risk(engine)
    transitions = db.execute(
        select(RiskSnapshot.previous_level, RiskSnapshot.level, RiskSnapshot.transition)
        .where(RiskSnapshot.transition.is_not(None))
        .order_by(RiskSnapshot.id)
    ).all()
    assert [t.transition for t in transitions] == ["up", "down"]
    assert transitions[0].level == RiskLevel.CRITICAL
    alerts = db.scalars(select(Alert).where(Alert.rule == AlertRule.RISK_CRITICAL)).all()
    assert len(alerts) == 1 and alerts[0].status == AlertStatus.RESOLVED
    overview = client.get(f"{API}/risk/overview").json()
    assert [t["transition"] for t in overview["recent_transitions"]] == ["down", "up"]


def test_risk_alert_respects_cooldown(client: TestClient, engine: Engine, db: Session) -> None:
    asset = _discovered(db)
    _risk(engine)
    for _ in range(3):  # sube a critical y baja tres veces seguidas
        d = _detection(db, asset, rule_id="CORR-004", kind="correlation",
                       severity=DetectionSeverity.CRITICAL)  # fmt: skip
        _queue_all(engine)
        _risk(engine)
        d.status = DetectionStatus.RESOLVED
        d.resolved_at = datetime.now(UTC) - timedelta(hours=70)
        db.commit()
        _queue_all(engine)
        _risk(engine)
    assert (
        db.scalar(
            select(func.count()).select_from(Alert).where(Alert.rule == AlertRule.RISK_CRITICAL)
        )
        == 1
    )


def test_first_evaluation_never_alerts(client: TestClient, engine: Engine, db: Session) -> None:
    # Desplegar la fase con detecciones ya existentes no debe generar una avalancha.
    asset = _discovered(db)
    _detection(db, asset, rule_id="CORR-004", kind="correlation",
               severity=DetectionSeverity.CRITICAL)  # fmt: skip
    _risk(engine)
    assert _detail(client, str(asset.public_id))["level"] == "critical"
    assert db.scalar(select(func.count()).select_from(Alert)) == 0


# --- Decay periódico y aislamiento de fallos ---------------------------------------------------


def test_periodic_decay_lowers_risk_without_new_input(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    _detection(db, asset)
    clean = _discovered(db)
    _risk(engine)
    start = _detail(client, str(asset.public_id))["score"]
    later = datetime.now(UTC) + timedelta(hours=3)
    run = _risk(engine, now=later, decay=True)
    # Solo el activo con riesgo entra en el decay (el limpio se refresca cada 6 h).
    assert run.assets == 1
    assert _detail(client, str(asset.public_id))["score"] < start
    db.expire_all()
    clean_risk = db.get(AssetRisk, clean.id)
    assert clean_risk is not None and clean_risk.calculated_at is not None
    assert clean_risk.calculated_at < later


def test_a_failing_asset_does_not_stop_the_others_or_the_api(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = _discovered(db, name="GOOD")
    bad = _discovered(db, name="BAD")
    _detection(db, good)
    _detection(db, bad)
    real = calculate

    def flaky(inputs: Any, config: RiskConfig, now: datetime) -> Any:
        if inputs.detections and inputs.detections[0].id == bad_detection_id:
            raise RuntimeError("boom")
        return real(inputs, config, now)

    bad_detection_id = db.scalar(select(Detection.id).where(Detection.asset_id == bad.id))
    monkeypatch.setattr(risk_engine_module, "calculate", flaky)
    run = _risk(engine)
    assert run.errors == 1 and run.failed_assets == [bad.id]
    db.expire_all()
    failed = db.get(AssetRisk, bad.id)
    assert failed is not None and failed.error_count == 1 and failed.dirty_at is not None
    assert _detail(client, str(good.public_id))["score"] > 0
    # La API sigue respondiendo y muestra el activo fallido como pendiente.
    pending = _detail(client, str(bad.public_id))
    assert pending["evaluated"] is False and pending["pending_recalculation"] is True
    assert client.get(f"{API}/risk/overview").status_code == 200
    # Arreglado el fallo, la siguiente vuelta lo calcula.
    monkeypatch.setattr(risk_engine_module, "calculate", real)
    assert _risk(engine).errors == 0
    assert _detail(client, str(bad.public_id))["evaluated"] is True


def test_risk_job_failure_does_not_break_the_api(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services import background

    asset = _discovered(db)
    _detection(db, asset)
    _risk(engine)

    def broken(self: RiskEngine, *args: Any, **kwargs: Any) -> RiskRun:
        raise RuntimeError("database hiccup")

    monkeypatch.setattr(RiskEngine, "process_dirty", broken)
    # El job usa la base de datos de test, no la configurada en DATABASE_URL.
    monkeypatch.setattr(background, "get_sessionmaker", lambda: sessionmaker(bind=engine))
    with pytest.raises(RuntimeError):
        background.run_risk_engine()  # PeriodicJob._loop lo registra y reintenta
    response = client.get(f"{API}/risk/assets/{asset.public_id}")
    assert response.status_code == 200 and response.json()["score"] > 0


# --- Exposición y activos desconocidos -----------------------------------------------------


def test_unknown_device_without_evidence_is_not_risky(
    client: TestClient, engine: Engine, db: Session
) -> None:
    unknown = _discovered(db, device_type=None)
    _risk(engine)
    detail = _detail(client, str(unknown.public_id))
    assert detail["score"] == 0 and detail["level"] == "informational"
    assert detail["explanation"]["reasons"] == [
        "No hay detecciones ni exposición sensible que aporten riesgo."
    ]


def test_sensitive_exposure_adds_bounded_risk_and_closing_removes_it(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    rdp = _port(db, asset, 3389)
    _port(db, asset, 443)  # no sensible: no suma
    _risk(engine)
    detail = _detail(client, str(asset.public_id))
    assert 0 < detail["score"] < 20
    (contribution,) = [c for c in detail["contributions"] if c["factor"] == "exposure"]
    assert contribution["port"] == 3389 and "rdp" in contribution["label"]
    rdp.state = PortStateValue.CLOSED
    db.commit()
    with sessionmaker(bind=engine)() as session:
        request_recalculation(session, [asset.id])
        session.commit()
    _risk(engine)
    assert _detail(client, str(asset.public_id))["score"] == 0


# --- Listado, filtros, orden, paginación y overview ------------------------------------------


def _fleet(db: Session) -> dict[str, Asset]:
    fleet = {
        "critical": _discovered(
            db, name="alpha", device_type="server", criticality=AssetCriticality.CRITICAL
        ),
        "high": _discovered(db, name="bravo", device_type="pc"),
        "medium": _discovered(db, name="charlie", device_type="printer", online=False),
        "clean": _discovered(db, name="delta"),
    }
    _detection(db, fleet["critical"], rule_id="CORR-004", kind="correlation",
               severity=DetectionSeverity.CRITICAL)  # fmt: skip
    _detection(db, fleet["high"])
    _detection(db, fleet["medium"], confidence=DetectionConfidence.LOW)
    return fleet


def test_list_sorts_filters_and_paginates(client: TestClient, engine: Engine, db: Session) -> None:
    fleet = _fleet(db)
    _risk(engine)

    def names(**params: Any) -> list[str]:
        response = client.get(f"{API}/risk/assets", params=params)
        assert response.status_code == 200, response.text
        return [item["display_name"] for item in response.json()["items"]]

    assert names() == ["alpha", "bravo", "charlie", "delta"]  # riesgo descendente
    assert names(order="asc") == ["delta", "charlie", "bravo", "alpha"]
    assert names(sort="name", order="asc") == ["alpha", "bravo", "charlie", "delta"]
    page = client.get(f"{API}/risk/assets", params={"limit": 2, "offset": 2}).json()
    assert page["total"] == 4 and [i["display_name"] for i in page["items"]] == ["charlie", "delta"]
    assert names(level="critical") == ["alpha"]
    assert names(criticality="critical") == ["alpha"]
    assert names(device_type="printer") == ["charlie"]
    assert names(device_type="unknown") == ["delta"]
    assert names(status="offline") == ["charlie"]
    assert names(confidence="low") == ["charlie", "delta"]
    assert names(min_score=60) == ["alpha", "bravo"]
    assert names(q="ALP") == ["alpha"]
    assert client.get(f"{API}/risk/assets", params={"limit": 500}).status_code == 422
    assert client.get(f"{API}/risk/assets", params={"sort": "x"}).status_code == 422
    first = client.get(f"{API}/risk/assets").json()["items"][0]
    assert first["level"] == "critical" and first["top_factor"].startswith("CORR-004")
    assert first["asset_id"] == str(fleet["critical"].public_id)


def test_overview_counts_and_top_factors(client: TestClient, engine: Engine, db: Session) -> None:
    fleet = _fleet(db)
    _port(db, fleet["clean"], 3389)
    _discovered(db)  # sin fila de riesgo todavía hasta la vuelta del job
    overview = client.get(f"{API}/risk/overview").json()
    assert overview["evaluated"] == 0 and overview["pending"] == 5
    _risk(engine)
    overview = client.get(f"{API}/risk/overview").json()
    assert overview["total_assets"] == 5 and overview["evaluated"] == 5
    assert overview["pending"] == 0
    assert overview["by_level"]["critical"] == 1 and overview["by_level"]["high"] == 1
    assert sum(overview["by_level"].values()) == 5
    categories = [f["category"] for f in overview["top_factors"]]
    assert {"account", "defense", "exposure"} <= set(categories)
    assert overview["top_factors"][0]["points"] >= overview["top_factors"][-1]["points"]
    assert overview["top_assets"][0]["display_name"] == "alpha"
    assert [t["level"] for t in overview["thresholds"]] == [lvl.value for lvl in RiskLevel]


def test_asset_list_shows_risk_and_criticality(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _fleet(db)
    before = {a["display_name"]: a for a in client.get(f"{API}/assets").json()["items"]}
    assert before["alpha"]["risk_score"] is None and before["alpha"]["criticality"] == "critical"
    _risk(engine)
    after = {a["display_name"]: a for a in client.get(f"{API}/assets").json()["items"]}
    assert after["alpha"]["risk_level"] == "critical" and after["alpha"]["risk_confidence"]
    assert after["delta"]["risk_score"] == 0


def test_risk_list_uses_a_bounded_number_of_queries(
    client: TestClient, engine: Engine, db: Session
) -> None:
    for i in range(30):
        asset = _discovered(db, name=f"host-{i:02d}")
        _detection(db, asset, severity=DetectionSeverity.MEDIUM)
    _risk(engine)
    statements: list[str] = []

    def count_statement(*args: Any) -> None:
        statements.append(str(args[2]))

    event.listen(engine, "before_cursor_execute", count_statement)
    try:
        assert len(client.get(f"{API}/risk/assets").json()["items"]) == 30
    finally:
        event.remove(engine, "before_cursor_execute", count_statement)
    risk_queries = [s for s in statements if "asset_risk" in s]
    assert len(risk_queries) <= 2  # total + página, nunca una consulta por activo


# --- Contribuciones e historial por rangos ----------------------------------------------------


def test_contributions_current_and_of_a_past_snapshot(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    detection = _detection(db, asset)
    _risk(engine)
    path = f"{API}/risk/assets/{asset.public_id}/contributions"
    current = client.get(path).json()
    assert current["snapshot_id"] is None
    assert current["items"][0]["detection_id"] == str(detection.public_id)
    snapshot = db.scalars(select(RiskSnapshot)).one()
    past = client.get(path, params={"snapshot_id": str(snapshot.public_id)}).json()
    assert past["score"] == snapshot.score and past["items"][0]["rule_id"] == "DEF-001"
    other = _discovered(db)
    wrong = client.get(
        f"{API}/risk/assets/{other.public_id}/contributions",
        params={"snapshot_id": str(snapshot.public_id)},
    )
    assert wrong.status_code == 404


def test_history_ranges_are_bounded_and_bucketed(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    _risk(engine)
    now = datetime.now(UTC)
    # 30 días de historial: un punto cada 20 minutos (2160 puntos).
    db.add_all(
        RiskSnapshot(
            asset_id=asset.id,
            calculated_at=now - timedelta(minutes=20 * i),
            score=i % 100,
            level=CONFIG.level_for(i % 100),
            confidence=RiskConfidence.MEDIUM,
            reason="interval",
            formula_version=1,
        )
        for i in range(1, 2161)
    )
    db.commit()
    path = f"{API}/risk/assets/{asset.public_id}/history"
    day = client.get(path, params={"range": "24h"}).json()
    week = client.get(path, params={"range": "7d"}).json()
    month = client.get(path, params={"range": "30d"}).json()
    assert day["bucket_minutes"] is None and 70 <= len(day["points"]) <= 74
    assert week["bucket_minutes"] == 60 and 165 <= len(week["points"]) <= 170
    assert month["bucket_minutes"] == 240 and len(month["points"]) <= 181
    times = [p["calculated_at"] for p in month["points"]]
    assert times == sorted(times)
    assert day["start_score"] is not None and day["current_score"] == 0
    assert client.get(path, params={"range": "1y"}).status_code == 422
    assert client.get(f"{API}/risk/assets/{uuid4()}/history").status_code == 404


# --- Retención y migración ------------------------------------------------------------------


def test_retention_purges_old_snapshots_but_not_current_risk(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    _detection(db, asset)
    _risk(engine)
    old = db.scalars(select(RiskSnapshot)).one()
    old.calculated_at = datetime.now(UTC) - timedelta(days=200)
    db.commit()
    with sessionmaker(bind=engine)() as session:
        policy = RetentionPolicy(None, None, risk_history_days=180)
        assert RetentionService(session, policy).purge().risk_snapshots == 1
    assert db.scalar(select(func.count()).select_from(RiskContributionRecord)) == 0
    assert _detail(client, str(asset.public_id))["score"] > 0


def test_migration_0019_round_trip_keeps_existing_data(
    client: TestClient, engine: Engine, db: Session
) -> None:
    from alembic import command

    from tests.conftest import _alembic_config

    asset = _discovered(db, criticality=AssetCriticality.HIGH)
    _detection(db, asset, rule_id="CORR-004", kind="correlation",
               severity=DetectionSeverity.CRITICAL)  # fmt: skip
    _risk(engine)

    def counts() -> dict[str, int]:
        with engine.connect() as connection:
            return {
                table: connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()  # noqa: S608
                for table in ("assets", "detections", "alerts", "users", "audit_events")
            }

    before = counts()
    config = _alembic_config(str(engine.url.render_as_string(hide_password=False)))
    try:
        command.downgrade(config, "0018")
        assert counts() == before
        with engine.connect() as connection:
            assert connection.execute(text("SELECT to_regclass('asset_risk')")).scalar() is None
    finally:
        command.upgrade(config, "head")
    assert counts() == before
    # El upgrade encola el primer cálculo de los activos existentes (criticidad: medium).
    with engine.connect() as connection:
        queued = connection.execute(
            text("SELECT count(*) FROM asset_risk WHERE dirty_at IS NOT NULL")
        ).scalar_one()
    assert queued == before["assets"]
    _risk(engine)
    assert _detail(client, str(asset.public_id))["level"] == "critical"
