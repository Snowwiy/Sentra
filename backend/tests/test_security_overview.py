"""Vista de seguridad del dashboard (Fase 7A.7): GET /dashboard/security-overview.

Comprueba que cada bloque sale de datos reales con el filtro de activos actuales, que la
postura documenta su fórmula y no inventa un valor sin datos, y que el historial reconstruye
el riesgo de cada día desde el ledger (risk_snapshots).
"""

from datetime import UTC, datetime, time, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.asset import Asset, AssetCriticality, MonitoringMethod
from app.models.detection import (
    Detection,
    DetectionConfidence,
    DetectionSeverity,
    DetectionStatus,
)
from app.models.exposure import AssetPort, PortStateValue
from app.models.risk import AssetRisk, RiskConfidence, RiskLevel, RiskSnapshot
from app.risk.config import RiskConfig
from app.services.security_overview_service import SecurityOverviewService
from tests.conftest import authenticate

API = "/api/v1"
URL = f"{API}/dashboard/security-overview"


def _asset(db: Session, ip: str, **fields: object) -> Asset:
    fields.setdefault("first_seen_at", datetime.now(UTC) - timedelta(days=30))
    asset = Asset(primary_ip=ip, monitoring_method=MonitoringMethod.DISCOVERED, **fields)
    db.add(asset)
    db.commit()
    return asset


def _risk(db: Session, asset: Asset, score: int, level: RiskLevel) -> None:
    db.add(
        AssetRisk(
            asset_id=asset.id,
            score=score,
            level=level,
            confidence=RiskConfidence.HIGH,
            calculated_at=datetime.now(UTC),
        )
    )
    db.commit()


def _snapshot(db: Session, asset: Asset, at: datetime, score: int, level: RiskLevel) -> None:
    db.add(
        RiskSnapshot(
            asset_id=asset.id,
            calculated_at=at,
            score=score,
            level=level,
            confidence=RiskConfidence.HIGH,
            reason="material_change",
            formula_version=5,
        )
    )
    db.commit()


def _detection(
    db: Session, asset: Asset, rule_id: str, minutes_ago: int, status: DetectionStatus
) -> None:
    now = datetime.now(UTC)
    seen = now - timedelta(minutes=minutes_ago)
    db.add(
        Detection(
            asset_id=asset.id,
            rule_id=rule_id,
            rule_version=1,
            kind="single",
            dedup_key=uuid4().hex,
            severity=DetectionSeverity.HIGH,
            confidence=DetectionConfidence.HIGH,
            status=status,
            title=f"Detección {rule_id}",
            summary="Sintética de test",
            occurrence_count=1,
            first_seen_at=seen,
            last_seen_at=seen,
            created_at=now,
            updated_at=now,
            resolved_at=now if status == DetectionStatus.RESOLVED else None,
        )
    )
    db.commit()


def _port(db: Session, asset: Asset, port: int, state: PortStateValue) -> None:
    now = datetime.now(UTC)
    db.add(
        AssetPort(
            asset_id=asset.id,
            protocol="tcp",
            port=port,
            state=state,
            first_seen_at=now - timedelta(days=2),
            opened_at=now - timedelta(days=2),
            last_seen_at=now,
        )
    )
    db.commit()


def _service(db: Session) -> SecurityOverviewService:
    settings = get_settings()
    return SecurityOverviewService(
        db,
        timedelta(seconds=settings.heartbeat_timeout_seconds),
        RiskConfig.from_settings(settings),
    )


def test_without_data_nothing_is_invented(client: TestClient) -> None:
    body = client.get(URL).json()
    posture = body["posture"]
    assert posture["state"] == "no_data"
    assert posture["score"] is None and posture["level"] is None
    assert (posture["assets_current"], posture["assets_scored"], posture["coverage"]) == (0, 0, 0)
    # La fórmula, la población, los pesos y el tratamiento de los datos que faltan viajan
    # con el indicador para que la UI los enseñe.
    method = posture["method"]
    assert method["weights"] == {"low": 1, "medium": 2, "high": 3, "critical": 4}
    assert method["thresholds"] == {"low": 20, "medium": 40, "high": 60, "critical": 80}
    assert method["formula"] and method["population"] and method["missing_data"]
    assert len(body["risk_history"]) == body["window_days"] == 30
    assert all(point["average_score"] is None for point in body["risk_history"])
    assert body["exposed_ports"] == {"open_ports": 0, "assets_with_open_ports": 0, "top": []}
    assert body["new_devices"]["count"] == 0
    assert body["detections_recent"] == []
    assert set(body["incidents_by_status"]) >= {"open", "resolved", "closed", "merged"}


def test_posture_is_weighted_by_criticality(client: TestClient, engine: Engine) -> None:
    with Session(engine) as db:
        critical = _asset(db, "10.1.0.1", criticality=AssetCriticality.CRITICAL)
        low = _asset(db, "10.1.0.2", criticality=AssetCriticality.LOW)
        _asset(db, "10.1.0.3")  # sin riesgo calculado: no cuenta como cero
        archived = _asset(db, "10.1.0.4", archived_at=datetime.now(UTC))
        _risk(db, critical, 80, RiskLevel.CRITICAL)
        _risk(db, low, 20, RiskLevel.LOW)
        _risk(db, archived, 100, RiskLevel.CRITICAL)
    posture = client.get(URL).json()["posture"]
    # (80 x 4 + 20 x 1) / (4 + 1) = 68; el archivado no entra.
    assert posture["score"] == 68
    assert posture["level"] == "high"
    assert posture["peak_score"] == 80
    assert posture["high_or_critical"] == 1
    assert (posture["assets_current"], posture["assets_scored"]) == (3, 2)
    assert posture["coverage"] == pytest.approx(0.667)
    assert posture["state"] == "ok"


def test_low_coverage_is_partial(client: TestClient, engine: Engine) -> None:
    with Session(engine) as db:
        scored = _asset(db, "10.2.0.1")
        for index in range(2, 5):
            _asset(db, f"10.2.0.{index}")
        _risk(db, scored, 45, RiskLevel.MEDIUM)
    posture = client.get(URL).json()["posture"]
    assert posture["state"] == "partial"
    assert posture["score"] == 45
    assert posture["coverage"] == 0.25


def test_risk_history_replays_the_ledger(client: TestClient, engine: Engine) -> None:
    now = datetime.now(UTC)
    today = datetime.combine(now.date(), time.min, tzinfo=UTC)
    with Session(engine) as db:
        server = _asset(db, "10.3.0.1")
        laptop = _asset(db, "10.3.0.2")
        archived = _asset(db, "10.3.0.3", archived_at=now)
        # Antes de la ventana: es el valor de partida.
        _snapshot(db, server, today - timedelta(days=10), 30, RiskLevel.LOW)
        _snapshot(db, server, today - timedelta(days=2, hours=-3), 85, RiskLevel.CRITICAL)
        _snapshot(db, laptop, today, 50, RiskLevel.MEDIUM)
        _snapshot(db, archived, today - timedelta(days=5), 99, RiskLevel.CRITICAL)
        # Posterior a `now`: no existe todavía para esta lectura.
        _snapshot(db, laptop, now + timedelta(hours=1), 70, RiskLevel.HIGH)
        history = _service(db).risk_history(7, now)
    assert [point.day for point in history] == [today - timedelta(days=d) for d in range(6, -1, -1)]
    first, two_days_ago, last = history[0], history[4], history[-1]
    assert (first.assets_scored, first.average_score, first.critical) == (1, 30.0, 0)
    assert (two_days_ago.assets_scored, two_days_ago.average_score) == (1, 85.0)
    assert two_days_ago.critical == 1
    assert (last.assets_scored, last.average_score, last.critical, last.high) == (2, 67.5, 1, 0)


def test_recent_detections_new_devices_and_exposed_ports(
    client: TestClient, engine: Engine
) -> None:
    now = datetime.now(UTC)
    with Session(engine) as db:
        web = _asset(db, "10.4.0.1", hostname="web-01")
        db_host = _asset(db, "10.4.0.2", first_seen_at=now - timedelta(days=3), device_type="nas")
        archived = _asset(db, "10.4.0.3", archived_at=now, first_seen_at=now)
        _detection(db, web, "AUTH-001", 30, DetectionStatus.OPEN)
        _detection(db, db_host, "NET-002", 5, DetectionStatus.ACKNOWLEDGED)
        _detection(db, web, "OLD-001", 1, DetectionStatus.RESOLVED)
        _detection(db, archived, "ARC-001", 1, DetectionStatus.OPEN)
        _port(db, web, 443, PortStateValue.OPEN)
        _port(db, db_host, 443, PortStateValue.OPEN)
        _port(db, db_host, 22, PortStateValue.OPEN)
        _port(db, web, 80, PortStateValue.CLOSED)
        _port(db, archived, 3389, PortStateValue.OPEN)
    body = client.get(URL).json()
    recent = body["detections_recent"]
    assert [d["rule_id"] for d in recent] == ["NET-002", "AUTH-001"]
    assert recent[1]["asset_name"] == "web-01"
    new = body["new_devices"]
    assert new["window_days"] == 7 and new["count"] == 1
    assert [(d["name"], d["device_type"]) for d in new["items"]] == [("10.4.0.2", "nas")]
    ports = body["exposed_ports"]
    assert (ports["open_ports"], ports["assets_with_open_ports"]) == (3, 2)
    assert ports["top"] == [
        {"port": 443, "protocol": "tcp", "assets": 2},
        {"port": 22, "protocol": "tcp", "assets": 1},
    ]


def test_access_and_validation(client: TestClient, engine: Engine) -> None:
    assert client.get(URL, params={"days": 6}).status_code == 422
    assert client.get(URL, params={"days": 91}).status_code == 422
    assert client.get(URL, params={"days": 90}).json()["window_days"] == 90
    assert client.get(URL, params={"site_id": str(uuid4())}).status_code == 404
    with TestClient(client.app) as anonymous:
        assert anonymous.get(URL).status_code == 401
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        assert viewer.get(URL).status_code == 200
