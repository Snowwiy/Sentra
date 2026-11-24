"""Fase 7E.5: Threat Intelligence sobre el tráfico NDR, mapeo MITRE por regla y reglas
Sigma de la categoría `dns` evaluadas con lo que ven los sensores.

Los indicadores entran por la importación local de la Fase 5C (sentra-ioc/1) y las reglas
Sigma por la importación de la Fase 5A, como lo haría un analista.
"""

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.detection.custom import runtime
from app.models.asset import Asset, AssetStatus, MonitoringMethod
from app.models.detection import Detection, DetectionSignal
from app.models.ndr import NdrAnomaly
from app.models.site import Sensor
from tests.test_detection_rules import _enable
from tests.test_ndr_7e1 import NDR, approve, ndr_sensor, send
from tests.test_ndr_7e2 import batch, dns
from tests.test_ndr_7e3 import flow, scan_flows
from tests.test_ndr_7e4 import _detect
from tests.test_sites_sensors import SensorSim, _ok

API = "/api/v1"
TI = f"{API}/threat-intel"
HOST = "10.70.0.20"
BAD_IP = "203.0.113.66"
BAD_DOMAIN = "malo.example.net"

SIGMA_DNS = """
title: Consulta a dominio de pruebas prohibido
id: 0b5f1b1e-5c1a-4e44-9d3c-7e0a5a6f7e01
tags: [attack.command_and_control, attack.t1071.004]
logsource:
  category: dns
detection:
  selection:
    query|endswith: '.prohibido.example'
  condition: selection
level: high
"""


@pytest.fixture(autouse=True)
def _fresh_rule_caches() -> Iterator[None]:
    runtime.reset_caches()
    yield
    runtime.reset_caches()


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session
    # El TRUNCATE general no toca las tablas de la Fase 5C (ver tests/test_threat_intel.py):
    # los indicadores importados aquí no deben verse en otros tests.
    with engine.begin() as connection:
        connection.execute(
            text("TRUNCATE threat_indicators, threat_intel_changes RESTART IDENTITY CASCADE")
        )


@pytest.fixture
def sensor(client: TestClient) -> SensorSim:
    sim = ndr_sensor(client)
    approve(client, sim)
    return sim


def _import_iocs(client: TestClient, *indicators: dict[str, Any]) -> None:
    items = _ok(client.get(f"{TI}/sources"))["items"]
    (source,) = [s for s in items if s["source_key"] == "local-iocs"]
    content = json.dumps({"format": "sentra-ioc/1", "indicators": list(indicators)})
    body = {"source_id": source["id"], "format": "sentra-ioc", "content": content}
    preview = _ok(client.post(f"{TI}/import/preview", json=body))
    _ok(client.post(f"{TI}/import", json={**body, "expected_sha256": preview["sha256"]}))


def _anomalies(db: Session, rule_id: str) -> list[NdrAnomaly]:
    db.expire_all()
    return list(db.scalars(select(NdrAnomaly).where(NdrAnomaly.rule_id == rule_id)))


def _asset(db: Session, sensor: SensorSim, ip: str) -> Asset:
    site_id = db.scalar(
        select(Sensor.site_id).where(Sensor.public_id == uuid.UUID(sensor.sensor_id))
    )
    assert site_id is not None
    now = datetime.now(UTC)
    asset = Asset(
        monitoring_method=MonitoringMethod.DISCOVERED,
        site_id=site_id,
        primary_ip=ip,
        status=AssetStatus.UNKNOWN,
        network_status=AssetStatus.ONLINE,
        last_network_seen_at=now,
        first_seen_at=now,
    )
    db.add(asset)
    db.commit()
    return asset


def tls(client: str, server: str, sni: str) -> dict[str, Any]:
    record = dns(client, sni)
    return {
        "client_ip": client,
        "server_ip": server,
        "server_port": 443,
        "sni": sni,
        "count": 1,
        "first_seen": record["first_seen"],
        "last_seen": record["last_seen"],
    }


def test_flow_dns_and_sni_match_indicators(
    client: TestClient, sensor: SensorSim, db: Session
) -> None:
    _import_iocs(
        client,
        {"type": "ipv4", "value": BAD_IP, "classification": "malicious", "confidence": "high"},
        {"type": "domain", "value": BAD_DOMAIN, "classification": "suspicious"},
        {"type": "cidr", "value": "198.51.100.0/24", "classification": "malicious"},
        {"type": "ipv4", "value": "203.0.113.1", "classification": "benign"},
    )
    flows = [
        flow(HOST, BAD_IP, 443),
        flow(HOST, "198.51.100.9", 8443),
        flow(HOST, "203.0.113.1", 443),
    ]
    queries = [dns(HOST, f"cdn.{BAD_DOMAIN}")]
    hellos = [tls("10.70.0.21", "203.0.113.70", f"api.{BAD_DOMAIN}")]
    _ok(send(sensor, batch(flows=flows, dns=queries, tls=hellos)))
    found = {(a.subject_ip, a.evidence["indicator_value"]): a for a in _anomalies(db, "NDR-TI-001")}
    assert set(found) == {
        (HOST, BAD_IP),
        (HOST, "198.51.100.0/24"),
        (HOST, BAD_DOMAIN),
        ("10.70.0.21", BAD_DOMAIN),
    }
    # La fuente local no es "official"/"trusted": ni el IOC de confianza alta llega a probable.
    local = found[(HOST, BAD_IP)]
    assert local.verdict == "suspicious" and local.evidence["source_trust"] not in (
        "official",
        "trusted",
    )
    assert found[(HOST, "198.51.100.0/24")].verdict == "suspicious"
    assert found[(HOST, BAD_DOMAIN)].evidence["observations"][0]["type"] == "dns_query"
    assert found[("10.70.0.21", BAD_DOMAIN)].evidence["observations"][0]["type"] == "tls_sni"
    assert all(a.verdict != "confirmed" for a in found.values())
    # Mismo tráfico otra vez: se actualiza la misma anomalía.
    _ok(send(sensor, batch(flows=[flow(HOST, BAD_IP, 443)])))
    assert len(_anomalies(db, "NDR-TI-001")) == 4


def test_revoked_or_absent_indicators_do_not_match(
    client: TestClient, sensor: SensorSim, db: Session
) -> None:
    _ok(send(sensor, batch(flows=[flow(HOST, BAD_IP, 443)])))
    assert _anomalies(db, "NDR-TI-001") == []


def test_rule_catalog_exposes_mitre(client: TestClient) -> None:
    rules = {r["id"]: r for r in _ok(client.get(f"{NDR}/rules"))["items"]}
    assert rules["NDR-MITM-001"]["mitre"] == {
        "tactic": "TA0006",
        "technique": "T1557",
        "subtechnique": "T1557.002",
    }
    assert rules["NDR-SCAN-001"]["mitre"]["technique"] == "T1046"
    # Higiene y contexto externo: sin técnica inventada.
    assert rules["NDR-PROTO-001"]["mitre"] is None and rules["NDR-TI-001"]["mitre"] is None


def test_detection_inherits_the_ndr_rule_technique(
    client: TestClient, engine: Engine, sensor: SensorSim, db: Session
) -> None:
    _asset(db, sensor, "10.70.0.99")
    flows = [flow("10.70.0.99", f"10.70.1.{i % 250 + 1}", 445, failed=True) for i in range(60)]
    _ok(send(sensor, batch(flows=flows)))
    anomaly = _anomalies(db, "NDR-SCAN-001")[0]
    listed = _ok(client.get(f"{NDR}/anomalies/{anomaly.public_id}"))
    assert listed["mitre"]["technique"] == "T1046"
    _detect(engine)
    db.expire_all()
    [detection] = db.scalars(select(Detection).where(Detection.rule_id == "NET-NDR-001"))
    assert (detection.mitre_tactic, detection.mitre_technique) == ("TA0007", "T1046")


def test_sigma_dns_rule_runs_on_ndr_queries(
    client: TestClient, engine: Engine, sensor: SensorSim, db: Session
) -> None:
    asset = _asset(db, sensor, HOST)
    preview = _ok(client.post(f"{API}/sigma/preview", json={"yaml": SIGMA_DNS}))
    assert preview["outcome"] == "partial" and preview["sentra_logsource"] == "ndr_dns"
    # Sin reglas activas del logsource no se guarda ninguna señal DNS.
    _ok(send(sensor, batch(dns=[dns(HOST, "www.prohibido.example")])))
    db.expire_all()
    assert db.scalars(select(DetectionSignal).where(DetectionSignal.kind == "ndr_dns")).all() == []

    rule = _ok(client.post(f"{API}/sigma/import", json={"yaml": SIGMA_DNS}))["rule"]
    _enable(client, rule, acknowledge_partial=True)
    runtime.reset_caches()
    _ok(
        send(
            sensor,
            batch(
                dns=[
                    dns(HOST, "www.prohibido.example"),
                    dns(HOST, "www.permitido.example"),
                    # Equipo sin inventariar: no hay activo al que atribuir la señal.
                    dns("10.70.0.77", "x.prohibido.example"),
                ]
            ),
        )
    )
    db.expire_all()
    signals = db.scalars(select(DetectionSignal).where(DetectionSignal.kind == "ndr_dns")).all()
    assert {s.subject for s in signals} == {"www.prohibido.example", "www.permitido.example"}
    assert all(s.asset_id == asset.id for s in signals)
    _detect(engine)
    db.expire_all()
    [found] = db.scalars(select(Detection).where(Detection.rule_source == "sigma"))
    assert found.asset_id == asset.id and found.mitre_technique == "T1071"


def test_scan_flows_helper_still_matches_no_indicator(
    client: TestClient, sensor: SensorSim, db: Session
) -> None:
    # Destinos internos: nunca se consultan contra la inteligencia (no son IOCs externos).
    _import_iocs(client, {"type": "cidr", "value": "10.70.0.0/16", "classification": "malicious"})
    _ok(send(sensor, batch(flows=scan_flows(10))))
    assert _anomalies(db, "NDR-TI-001") == []
