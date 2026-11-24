"""Fase 7E.3: reglas de protocolos y movimiento por lote, y job ndr-engine (líneas base
horarias y beaconing).

Las reglas por lote se prueban con el protocolo real del sensor. El job se prueba insertando
flujos ya guardados (lo que habría dejado la ingesta) con horas calculadas dentro del test.
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.discovery import DiscoveryJob, DiscoveryJobStatus, DiscoveryTrigger
from app.models.ndr import NdrAnomaly, NdrBaseline, NdrEngineCursor, NdrFlow
from app.models.site import Sensor
from app.ndr.addresses import is_external, is_internal
from app.ndr.engine import run_ndr_engine
from app.ndr.retention import purge_ndr
from tests.test_ndr_7e1 import approve, ndr_sensor, send
from tests.test_ndr_7e2 import at, batch
from tests.test_sites_sensors import SensorSim, _ok

SCANNER = "10.70.0.99"
HOST = "10.70.0.20"
C2 = "203.0.113.10"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def sensor(client: TestClient) -> SensorSim:
    sim = ndr_sensor(client)
    approve(client, sim)
    return sim


def flow(
    src: str,
    dst: str,
    port: int,
    *,
    transport: str = "tcp",
    failed: bool = False,
    reset: bool = False,
    midstream: bool = False,
) -> dict[str, Any]:
    flags = []
    if failed:
        flags.append("no_handshake_reply")
    if midstream:
        flags.append("midstream")
    answered = not failed and not reset
    return {
        "uid": uuid.uuid4().hex,
        "segment": 0,
        "ip_version": 4,
        "transport": transport,
        "src_ip": src,
        "src_port": 50000,
        "dst_ip": dst,
        "dst_port": port,
        "vlan": None,
        "src_mac": None,
        "dst_mac": None,
        "first_seen": at(2),
        "last_seen": at(1),
        "packets_out": 3 if answered else 1,
        "packets_in": 3 if answered else (1 if reset else 0),
        "bytes_out": 300,
        "bytes_in": 300 if answered else 0,
        "tcp_flags_out": 2,
        "tcp_flags_in": 4 if reset else (18 if answered else 0),
        "state": "reset" if reset else ("closed" if answered else "timeout"),
        "final": True,
        "flags": flags,
        "retransmissions": 0,
        "fragments": 0,
        "icmp_type": None,
        "app_hints": [],
    }


def anomalies(db: Session, rule_id: str) -> list[NdrAnomaly]:
    db.expire_all()
    return list(db.scalars(select(NdrAnomaly).where(NdrAnomaly.rule_id == rule_id)))


def scan_flows(count: int) -> list[dict[str, Any]]:
    # Barrido horizontal: un puerto, muchos equipos; la mitad rechazados con RST.
    return [
        flow(SCANNER, f"10.70.1.{i % 250 + 1}", 445 + i // 250, failed=i % 2 == 0, reset=i % 2 == 1)
        for i in range(count)
    ]


def test_scan_suspicious_and_probable(sensor: SensorSim, db: Session) -> None:
    _ok(send(sensor, batch(flows=scan_flows(60))))
    [found] = anomalies(db, "NDR-SCAN-001")
    assert found.verdict == "suspicious" and found.subject_ip == SCANNER
    assert found.evidence["shape"] == "horizontal"
    assert found.evidence["authorized_discovery"] is False
    _ok(send(sensor, batch(flows=scan_flows(260))))
    [found] = anomalies(db, "NDR-SCAN-001")
    assert found.verdict == "probable" and found.severity == "high"


def test_midstream_and_answered_flows_are_not_scan(sensor: SensorSim, db: Session) -> None:
    flows = [flow(SCANNER, f"10.70.1.{i + 1}", 80, failed=True, midstream=True) for i in range(60)]
    flows += [flow(SCANNER, f"10.70.2.{i + 1}", 80) for i in range(60)]
    _ok(send(sensor, batch(flows=flows)))
    assert anomalies(db, "NDR-SCAN-001") == []


def test_sentra_discovery_window_is_observed(sensor: SensorSim, db: Session) -> None:
    sensor_row = db.scalar(select(Sensor).where(Sensor.public_id == uuid.UUID(sensor.sensor_id)))
    assert sensor_row is not None
    now = datetime.now(UTC)
    db.add(
        DiscoveryJob(
            target="10.70.1.0/24",
            site_id=sensor_row.site_id,
            trigger=DiscoveryTrigger.MANUAL,
            status=DiscoveryJobStatus.COMPLETED,
            started_at=now - timedelta(minutes=10),
            completed_at=now,
        )
    )
    db.commit()
    _ok(send(sensor, batch(flows=scan_flows(260))))
    [found] = anomalies(db, "NDR-SCAN-001")
    assert found.verdict == "observed" and found.severity == "low"
    assert found.evidence["authorized_discovery"] is True


def test_cleartext_protocols_are_observed(sensor: SensorSim, db: Session) -> None:
    flows = [
        flow(HOST, "10.70.0.5", 23),
        flow(HOST, "10.70.0.6", 21),
        flow(HOST, "10.70.0.7", 69, transport="udp"),
        # Sin respuesta: nadie habló telnet, no hay nada en claro que señalar.
        flow(HOST, "10.70.0.8", 23, failed=True),
    ]
    _ok(send(sensor, batch(flows=flows)))
    found = {a.evidence["service"]: a for a in anomalies(db, "NDR-PROTO-001")}
    assert set(found) == {"telnet", "ftp", "tftp"}
    assert found["telnet"].severity == "medium" and found["ftp"].severity == "low"
    assert all(a.verdict == "observed" for a in found.values())
    assert found["telnet"].subject_ip == "10.70.0.5"


def test_lateral_movement(sensor: SensorSim, db: Session) -> None:
    few = [flow(HOST, f"10.70.3.{i + 1}", 445) for i in range(4)]
    _ok(send(sensor, batch(flows=few)))
    assert anomalies(db, "NDR-PROTO-002") == []
    many = [flow(HOST, f"10.70.3.{i + 1}", 445) for i in range(16)]
    # Destinos externos no cuentan como movimiento lateral.
    many += [flow(HOST, f"203.0.113.{i + 1}", 3389) for i in range(20)]
    _ok(send(sensor, batch(flows=many)))
    [found] = anomalies(db, "NDR-PROTO-002")
    assert found.verdict == "probable" and found.evidence["service"] == "smb"
    assert found.evidence["hosts"] == 16


# --- job ndr-engine -------------------------------------------------------------------------


def _ids(db: Session, sensor: SensorSim) -> tuple[int, int]:
    row = db.scalar(select(Sensor).where(Sensor.public_id == uuid.UUID(sensor.sensor_id)))
    assert row is not None
    return row.id, row.site_id


def _store(
    db: Session,
    ids: tuple[int, int],
    src: str,
    dst: str,
    port: int,
    seen: datetime,
    sent: int = 1000,
) -> None:
    sensor_id, site_id = ids
    db.add(
        NdrFlow(
            sensor_id=sensor_id,
            site_id=site_id,
            interface="lan",
            uid=uuid.uuid4().hex,
            ip_version=4,
            transport="tcp",
            src_ip=src,
            src_port=50000,
            dst_ip=dst,
            dst_port=port,
            first_seen=seen,
            last_seen=seen + timedelta(seconds=2),
            packets_out=10,
            packets_in=10,
            bytes_out=sent,
            bytes_in=500,
            state="closed",
            final=True,
            flags=[],
            app_hints=[],
            updated_at=seen,
        )
    )


def test_hourly_baseline_learns_and_flags_exfiltration(sensor: SensorSim, db: Session) -> None:
    ids = _ids(db, sensor)
    now = datetime.now(UTC)
    current = now.replace(minute=0, second=0, microsecond=0)
    mb = 1024 * 1024
    for hours_ago in range(30, 1, -1):
        bucket = current - timedelta(hours=hours_ago)
        # Uso habitual: ~10-12 MB por hora hacia dos destinos.
        _store(db, ids, HOST, "203.0.113.20", 443, bucket + timedelta(minutes=5), 10 * mb)
        _store(
            db, ids, HOST, "203.0.113.21", 443, bucket + timedelta(minutes=9), hours_ago % 3 * mb
        )
    last = current - timedelta(hours=1)
    _store(db, ids, HOST, "203.0.113.30", 443, last + timedelta(minutes=5), 900 * mb)
    for i in range(80):
        _store(db, ids, HOST, f"198.51.100.{i + 1}", 443, last + timedelta(minutes=10))
    db.add(NdrEngineCursor(name="hourly", position=current - timedelta(hours=30), updated_at=now))
    db.commit()
    settings = get_settings().model_copy(update={"ndr_baseline_min_samples": 12})

    assert run_ndr_engine(db, settings, now)["hours"] == 24
    assert anomalies(db, "NDR-BEH-001") == []
    assert run_ndr_engine(db, settings, now)["hours"] == 6
    [exfil] = anomalies(db, "NDR-BEH-001")
    assert exfil.verdict == "probable" and exfil.subject_ip == HOST
    assert exfil.evidence["value"] == 900 * mb + 1000 * 80
    [fanout] = anomalies(db, "NDR-BEH-002")
    assert fanout.evidence["value"] == 81
    # La hora anómala no se aprende: la línea base sigue reflejando el uso habitual.
    db.expire_all()
    baseline = db.scalar(
        select(NdrBaseline).where(NdrBaseline.entity_ip == HOST, NdrBaseline.metric == "bytes_out")
    )
    assert baseline is not None and baseline.samples == 29
    assert baseline.mean < 20 * mb
    # Idempotente: la misma hora no se vuelve a agregar.
    assert run_ndr_engine(db, settings, now)["hours"] == 0
    assert anomalies(db, "NDR-BEH-001")[0].occurrences == 1


def test_baseline_does_not_alert_before_min_samples(sensor: SensorSim, db: Session) -> None:
    ids = _ids(db, sensor)
    now = datetime.now(UTC)
    current = now.replace(minute=0, second=0, microsecond=0)
    for hours_ago in range(5, 1, -1):
        _store(db, ids, HOST, C2, 443, current - timedelta(hours=hours_ago), 1024 * 1024)
    _store(db, ids, HOST, C2, 443, current - timedelta(minutes=50), 900 * 1024 * 1024)
    db.add(NdrEngineCursor(name="hourly", position=current - timedelta(hours=5), updated_at=now))
    db.commit()
    assert run_ndr_engine(db, get_settings(), now)["hours"] == 5
    assert anomalies(db, "NDR-BEH-001") == []


def test_beaconing_regular_interval(sensor: SensorSim, db: Session) -> None:
    ids = _ids(db, sensor)
    now = datetime.now(UTC)
    jitter = [0, 3, -2, 4, -4, 1, 2, -3, 0, 5, -1, 2, -2, 3, 0, 1, -5, 2, 0, -1]
    start = now - timedelta(hours=2)
    for i, offset in enumerate(jitter):
        _store(db, ids, HOST, C2, 443, start + timedelta(seconds=300 * i + offset))
    # Mismo número de conexiones, a intervalos irregulares: tráfico normal de un usuario.
    gaps = [30, 900, 45, 400, 1200, 60, 15, 700, 90, 300, 2000, 20, 600, 75, 150, 1000, 40, 500]
    seen = start
    for gap in gaps:
        seen += timedelta(seconds=gap)
        _store(db, ids, "10.70.0.21", C2, 443, seen)
    # Destino interno: no es beaconing hacia Internet.
    for i in range(20):
        _store(db, ids, HOST, "10.70.0.53", 53, start + timedelta(seconds=300 * i))
    db.commit()
    result = run_ndr_engine(db, get_settings(), now)
    assert result["beacons"] == 1
    [found] = anomalies(db, "NDR-BEH-003")
    assert found.subject_ip == HOST and found.evidence["dst_ip"] == C2
    assert 295 <= found.evidence["mean_interval_seconds"] <= 305
    assert found.evidence["coefficient_of_variation"] < 0.05
    # Una segunda pasada actualiza la misma anomalía activa, no crea otra.
    run_ndr_engine(db, get_settings(), now)
    assert len(anomalies(db, "NDR-BEH-003")) == 1


@pytest.mark.parametrize(
    ("ip", "internal", "external"),
    [
        ("10.1.2.3", True, False),
        ("172.20.0.1", True, False),
        ("192.168.1.1", True, False),
        ("fd00::1", True, False),
        ("::ffff:192.168.1.1", True, False),
        ("203.0.113.10", False, True),
        ("2001:db8::1", False, True),
        ("127.0.0.1", False, False),
        ("224.0.0.251", False, False),
        ("::", False, False),
        ("not-an-ip", False, False),
    ],
)
def test_address_classes(ip: str, internal: bool, external: bool) -> None:
    assert is_internal(ip) is internal
    assert is_external(ip) is external


def test_stale_baselines_are_purged(sensor: SensorSim, db: Session) -> None:
    _, site_id = _ids(db, sensor)
    now = datetime.now(UTC)
    for ip, age in (("10.70.0.30", 60), ("10.70.0.31", 1)):
        db.add(
            NdrBaseline(
                site_id=site_id,
                entity_ip=ip,
                metric="bytes_out",
                samples=10,
                mean=1.0,
                m2=0.0,
                updated_at=now - timedelta(days=age),
            )
        )
    db.commit()
    counts = purge_ndr(db, get_settings(), now)
    db.commit()
    assert counts["ndr_baselines"] == 1
    assert [b.entity_ip for b in db.scalars(select(NdrBaseline))] == ["10.70.0.31"]
