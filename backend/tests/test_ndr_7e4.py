"""Fase 7E.4: correlación de anomalías NDR con activos, topología, detecciones, riesgo e
incidentes.

Las anomalías se generan con el protocolo real del sensor; los activos y la tabla FDB del
switch se insertan como los dejarían el inventario y el sondeo SNMP.
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.detection.config import DetectionConfig
from app.detection.engine import DetectionEngine
from app.models.asset import Asset, AssetStatus, MonitoringMethod
from app.models.detection import Detection, DetectionSignal
from app.models.ndr import NdrAnomaly
from app.models.network import NetworkDevice, NetworkMacEntry
from app.models.site import Sensor
from app.services.alert_service import AlertThresholds
from tests.test_ndr_7e1 import NDR, approve, ndr_sensor, send
from tests.test_ndr_7e2 import arp, batch
from tests.test_ndr_7e3 import SCANNER, flow, scan_flows
from tests.test_risk import _risk
from tests.test_sites_sensors import SensorSim, _error, _ok

API = "/api/v1"
MAC_EVIL = "02:00:00:00:00:66"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def sensor(client: TestClient) -> SensorSim:
    sim = ndr_sensor(client)
    approve(client, sim)
    return sim


def _site_id(db: Session, sensor: SensorSim) -> int:
    row = db.scalar(select(Sensor).where(Sensor.public_id == uuid.UUID(sensor.sensor_id)))
    assert row is not None
    return row.site_id


def _asset(
    db: Session, site_id: int, ip: str, mac: str | None = None, archived: bool = False
) -> Asset:
    now = datetime.now(UTC)
    asset = Asset(
        monitoring_method=MonitoringMethod.DISCOVERED,
        site_id=site_id,
        primary_ip=ip,
        mac_address=mac,
        status=AssetStatus.UNKNOWN,
        network_status=AssetStatus.ONLINE,
        last_network_seen_at=now,
        first_seen_at=now,
        device_name=f"equipo-{ip}",
        archived_at=now if archived else None,
    )
    db.add(asset)
    db.commit()
    return asset


def _detect(engine: Engine) -> None:
    with sessionmaker(bind=engine)() as session:
        thresholds = AlertThresholds.from_settings(get_settings())
        DetectionEngine(session, DetectionConfig(), thresholds).process_pending()


def _signals(db: Session) -> list[DetectionSignal]:
    db.expire_all()
    return list(db.scalars(select(DetectionSignal).where(DetectionSignal.kind == "ndr_anomaly")))


def _anomaly(db: Session, rule_id: str) -> NdrAnomaly:
    db.expire_all()
    row = db.scalar(select(NdrAnomaly).where(NdrAnomaly.rule_id == rule_id))
    assert row is not None
    return row


def test_scan_is_attributed_signaled_and_becomes_a_detection(
    client: TestClient, engine: Engine, sensor: SensorSim, db: Session
) -> None:
    asset = _asset(db, _site_id(db, sensor), SCANNER)
    _ok(send(sensor, batch(flows=scan_flows(60))))
    anomaly = _anomaly(db, "NDR-SCAN-001")
    assert anomaly.asset_id == asset.id and anomaly.signaled_rank == 1
    [signal] = _signals(db)
    assert signal.asset_id == asset.id and signal.data is not None
    assert signal.data["rule_id"] == "NDR-SCAN-001" and signal.data["verdict"] == "suspicious"
    # Misma anomalía, mismo veredicto: no hay otra señal.
    _ok(send(sensor, batch(flows=scan_flows(60))))
    assert len(_signals(db)) == 1
    # Sube a probable: una señal más (un escalón de veredicto).
    _ok(send(sensor, batch(flows=scan_flows(260))))
    assert len(_signals(db)) == 2

    _detect(engine)
    db.expire_all()
    [detection] = db.scalars(select(Detection).where(Detection.rule_id == "NET-NDR-001"))
    assert detection.asset_id == asset.id
    assert detection.dedup_key == f"ndr:{anomaly.public_id}"
    assert detection.details is not None and detection.details["ndr_rule_id"] == "NDR-SCAN-001"

    listed = _ok(client.get(f"{NDR}/anomalies", params={"asset_id": str(asset.public_id)}))
    assert listed["total"] == 1 and listed["items"][0]["asset_name"] == f"equipo-{SCANNER}"
    assert listed["items"][0]["context"] is None
    detail = _ok(client.get(f"{NDR}/anomalies/{anomaly.public_id}"))
    assert detail["context"]["asset"]["asset_id"] == str(asset.public_id)
    [ref] = detail["context"]["detections"]
    assert ref["detection_id"] == str(detection.public_id) and ref["rule_id"] == "NET-NDR-001"
    assert detail["context"]["incidents"] == []

    # La detección se promueve a incidente con el flujo normal; la anomalía lo muestra.
    incident = _ok(client.post(f"{API}/detections/{detection.public_id}/incident"), 201)
    detail = _ok(client.get(f"{NDR}/anomalies/{anomaly.public_id}"))
    [linked] = detail["context"]["incidents"]
    assert linked["incident_id"] == incident["incident_id"]

    # La detección ya alimenta el riesgo del activo como cualquier otra.
    _risk(engine)
    risk = client.get(f"{API}/risk/assets/{asset.public_id}")
    assert risk.status_code == 200 and "NET-NDR-001" in risk.text
    assert risk.json()["score"] > 0


def test_observed_findings_never_signal(sensor: SensorSim, db: Session) -> None:
    _asset(db, _site_id(db, sensor), "10.70.0.5")
    _ok(send(sensor, batch(flows=[flow("10.70.0.20", "10.70.0.5", 23)])))
    anomaly = _anomaly(db, "NDR-PROTO-001")
    assert anomaly.asset_id is not None and anomaly.verdict == "observed"
    assert anomaly.signaled_rank == 0 and _signals(db) == []


def test_mac_wins_over_ip_and_archived_assets_are_ignored(
    client: TestClient, sensor: SensorSim, db: Session
) -> None:
    site_id = _site_id(db, sensor)
    _asset(db, site_id, "10.70.0.66", MAC_EVIL, archived=True)
    attacker = _asset(db, site_id, "10.70.0.67", MAC_EVIL)
    # La IP anunciada (10.70.0.10-12) pertenece a otros; el sujeto es la MAC que anuncia.
    _asset(db, site_id, "10.70.0.10")
    claims = [arp(f"10.70.0.{10 + i}", MAC_EVIL, unsolicited=5) for i in range(3)]
    _ok(send(sensor, batch(arp=claims)))
    anomaly = _anomaly(db, "NDR-ARP-002")
    assert anomaly.subject_mac == MAC_EVIL and anomaly.asset_id == attacker.id

    device = NetworkDevice(site_id=site_id, management_address="10.70.0.2", name="core-sw")
    db.add(device)
    db.flush()
    now = datetime.now(UTC)
    db.add(
        NetworkMacEntry(
            device_id=device.id,
            site_id=site_id,
            mac=MAC_EVIL,
            fdb_key=0,
            bridge_port=7,
            status="learned",
            vlan_id=20,
            location="access",
            first_seen_at=now,
            last_seen_at=now,
        )
    )
    db.commit()
    detail = _ok(client.get(f"{NDR}/anomalies/{anomaly.public_id}"))
    [where] = detail["context"]["switch_locations"]
    assert where["device_name"] == "core-sw" and where["vlan"] == 20
    assert where["location"] == "access"


def test_unattributed_anomaly_has_empty_context(
    client: TestClient, sensor: SensorSim, db: Session
) -> None:
    _ok(send(sensor, batch(flows=scan_flows(60))))
    anomaly = _anomaly(db, "NDR-SCAN-001")
    assert anomaly.asset_id is None and _signals(db) == []
    detail = _ok(client.get(f"{NDR}/anomalies/{anomaly.public_id}"))
    assert detail["asset_id"] is None
    assert detail["context"] == {
        "asset": None,
        "switch_locations": [],
        "detections": [],
        "incidents": [],
    }
    _error(client.get(f"{NDR}/anomalies", params={"asset_id": str(uuid.uuid4())}), 404, "not_found")
