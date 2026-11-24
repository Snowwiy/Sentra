"""Fase 7E.7: plan de respuesta de una anomalía NDR, solicitudes de control de red (solo
registradas) y playbook de investigación de red.

Nada de esto toca la red: los controles quedan pendientes de aprobación en un incidente y el
playbook solo lee evidencia y reevalúa. Las anomalías se generan con el protocolo real del
sensor y los indicadores con la importación local de la Fase 5C.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.models.audit import AuditEvent
from app.models.case_operations import NetworkControlRequest
from app.models.ndr import NdrAnomaly
from app.models.response import ResponseExecution
from app.ndr.response import suggestions
from tests.test_case_operations import _case, _client
from tests.test_ndr_7e1 import NDR, approve, ndr_sensor, send
from tests.test_ndr_7e2 import batch, dns
from tests.test_ndr_7e3 import SCANNER, flow, scan_flows
from tests.test_ndr_7e4 import _asset, _site_id
from tests.test_ndr_7e5 import BAD_IP, HOST, _import_iocs
from tests.test_sites_sensors import SensorSim, _error, _ok

API = "/api/v1"
R = f"{API}/response"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session
    # Los indicadores de la Fase 5C no entran en el TRUNCATE general (ver test_ndr_7e5).
    with engine.begin() as connection:
        connection.execute(
            text("TRUNCATE threat_indicators, threat_intel_changes RESTART IDENTITY CASCADE")
        )


@pytest.fixture
def sensor(client: TestClient) -> SensorSim:
    sim = ndr_sensor(client)
    approve(client, sim)
    return sim


def _anomaly(db: Session, rule_id: str) -> NdrAnomaly:
    db.expire_all()
    row = db.scalar(select(NdrAnomaly).where(NdrAnomaly.rule_id == rule_id))
    assert row is not None
    return row


def _ti_anomaly(client: TestClient, sensor: SensorSim, db: Session) -> NdrAnomaly:
    _import_iocs(
        client,
        {"type": "ipv4", "value": BAD_IP, "classification": "malicious", "confidence": "high"},
    )
    _ok(send(sensor, batch(flows=[flow(HOST, BAD_IP, 443)])))
    return _anomaly(db, "NDR-TI-001")


def _row(rule_id: str, verdict: str, evidence: dict[str, Any], ip: str = HOST) -> NdrAnomaly:
    # Objeto sin guardar: las sugerencias son una función pura de la anomalía.
    return NdrAnomaly(rule_id=rule_id, verdict=verdict, evidence=evidence, subject_ip=ip)


def test_suggestions_follow_fixed_rules_per_ndr_rule() -> None:
    beacon = suggestions(_row("NDR-BEH-003", "suspicious", {"dst_ip": "203.0.113.10"}), False)
    assert [(s.kind, s.target, s.direction) for s in beacon] == [
        ("network_control", {"cidr": "203.0.113.10/32"}, "outbound")
    ]
    # Un destino interno nunca se propone como bloqueo perimetral.
    assert suggestions(_row("NDR-BEH-003", "suspicious", {"dst_ip": "10.70.0.5"}), False) == []
    tunnel = suggestions(_row("NDR-DNS-002", "suspicious", {"parent": "t.example.net"}), True)
    assert [s.suggestion_id for s in tunnel] == [
        "block_domain:t.example.net",
        "playbook:investigate_network_anomaly",
    ]
    # Un hecho observado solo sugiere revisar (más retirar el servicio en claro).
    telnet = suggestions(_row("NDR-PROTO-001", "observed", {"service": "telnet"}), True)
    assert [s.suggestion_id for s in telnet] == ["review", "block_port:tcp/23"]
    assert telnet[1].direction == "inbound" and telnet[1].target == {
        "port": 23,
        "protocol": "tcp",
    }
    l2 = suggestions(_row("NDR-MITM-001", "probable", {}), False)
    assert [(s.kind, s.suggestion_id) for s in l2] == [("manual", "isolate_switch_port")]
    # Un CIDR demasiado amplio no pasa la validación de controles: no se sugiere.
    broad = _row(
        "NDR-TI-001", "suspicious", {"indicator_type": "cidr", "indicator_value": "0.0.0.0/0"}
    )
    assert suggestions(broad, False) == []


def test_response_plan_and_registered_control(
    client: TestClient, engine: Engine, sensor: SensorSim, db: Session
) -> None:
    anomaly = _ti_anomaly(client, sensor, db)
    url = f"{NDR}/anomalies/{anomaly.public_id}"
    plan = _ok(client.get(f"{url}/response-plan"))
    assert plan["applied_by_sentra"] is False
    ids = [s["suggestion_id"] for s in plan["suggestions"]]
    assert ids == [f"block_address:{BAD_IP}/32"]
    block = plan["suggestions"][0]
    assert block["kind"] == "network_control" and block["direction"] == "outbound"
    assert block["instructions"]

    case = _case(client)
    analyst = _client(client, engine, "analyst", "ana-7e7")
    body = {
        "incident_id": case["incident_id"],
        "suggestion_id": block["suggestion_id"],
        "justification": "IOC malicioso contactado desde el equipo de contabilidad.",
    }
    control = _ok(analyst.post(f"{url}/network-controls", json=body), 201)
    # Registrada y pendiente: Sentra no la evalúa ni la aplica.
    assert control["status"] == "pending_approval"
    assert control["enforcement_status"] == "not_evaluated"
    assert control["control_type"] == "block_address"
    assert control["target"] == {"cidr": f"{BAD_IP}/32"}
    assert control["scope"]["type"] == "site"
    assert f"anomalía NDR NDR-TI-001 ({anomaly.public_id})" in control["justification"]
    db.expire_all()
    assert db.scalar(select(NetworkControlRequest.status)) == "pending_approval"

    # Solo sugerencias del plan que sean controles: ni inventadas ni manuales.
    for wrong in ("block_address:198.51.100.1/32", "review"):
        _error(
            analyst.post(f"{url}/network-controls", json={**body, "suggestion_id": wrong}),
            422,
            "ndr_suggestion_invalid",
        )
    # ndr:read no basta: pedir un control es gestionar el caso (incidents:manage).
    viewer = _client(client, engine, "viewer", "vera-7e7")
    _error(viewer.post(f"{url}/network-controls", json=body), 403, "permission_denied")
    assert _ok(viewer.get(f"{url}/response-plan"))["suggestions"]
    db.expire_all()
    assert len(db.scalars(select(NetworkControlRequest)).all()) == 1
    failures = db.scalars(
        select(AuditEvent).where(
            AuditEvent.action == "network_control_requested", AuditEvent.result == "failure"
        )
    ).all()
    assert len(failures) == 2


def test_network_anomaly_playbook_collects_ndr_context(
    client: TestClient, engine: Engine, sensor: SensorSim, db: Session
) -> None:
    asset = _asset(db, _site_id(db, sensor), SCANNER)
    queries = [dns(SCANNER, "intranet.example.org")]
    _ok(send(sensor, batch(flows=scan_flows(60), dns=queries)))
    anomaly = _anomaly(db, "NDR-SCAN-001")
    assert anomaly.asset_id == asset.id
    plan = _ok(client.get(f"{NDR}/anomalies/{anomaly.public_id}/response-plan"))
    assert [s["suggestion_id"] for s in plan["suggestions"]] == [
        "contain_source",
        "playbook:investigate_network_anomaly",
    ]
    playbooks = _ok(client.get(f"{R}/playbooks"))["items"]
    (pb,) = [p for p in playbooks if p["key"] == "investigate_network_anomaly"]
    assert pb["builtin"] and pb["risk_level"] == "low" and pb["required_role"] == "analyst"
    analyst = _client(client, engine, "analyst", "ana-pb-7e7")
    run = _ok(
        analyst.post(
            f"{R}/playbooks/{pb['playbook_id']}/execute",
            json={"target_id": str(asset.public_id)},
        )
    )
    assert run["status"] == "succeeded", run
    db.expire_all()
    execution = db.scalar(
        select(ResponseExecution).where(ResponseExecution.action_id == "collect_ndr_context")
    )
    assert execution is not None and execution.result is not None
    data = execution.result["data"]
    assert [a["rule_id"] for a in data["anomalies"]] == ["NDR-SCAN-001"]
    assert data["flows"]["count"] == 60 and len(data["flows"]["peers"]) == 20
    # Nombres consultados por la IP del activo, con el recuento que informó el sensor.
    assert [(n["kind"], n["name"]) for n in data["names"]] == [("dns", "intranet.example.org")]
    assert data["names"][0]["count"] == queries[0]["count"]
    # Un viewer no tiene ndr:evidence ni response:execute: no puede lanzarlo.
    viewer = _client(client, engine, "viewer", "vera-pb-7e7")
    denied = viewer.post(
        f"{R}/playbooks/{pb['playbook_id']}/execute", json={"target_id": str(asset.public_id)}
    )
    assert denied.status_code == 403
