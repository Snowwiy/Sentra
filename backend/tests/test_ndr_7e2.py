"""Fase 7E.2: reglas NDR de ARP, puerta de enlace, DHCP y DNS, y triaje de anomalías.

Los lotes se construyen con el mismo contrato que envía el sensor (tests/test_ndr_7e1.py usa
la salida real del sensor); aquí se fabrican escenarios concretos con direcciones de
documentación y MACs localmente administradas. Las horas se calculan dentro de cada test.
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.detection.rules import RULES_BY_ID
from app.models.ndr import NdrAnomaly
from app.ndr.detect_dns import entropy, parent_domain
from app.ndr.rules import RULES
from tests.conftest import authenticate
from tests.test_ndr_7e1 import NDR, approve, ndr_sensor, send
from tests.test_sites_sensors import SensorSim, _error, _ok

MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"
MAC_GW = "02:00:00:00:00:01"
MAC_EVIL = "02:00:00:00:00:66"
GATEWAY = "10.70.0.1"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def sensor(client: TestClient) -> SensorSim:
    sim = ndr_sensor(client)
    approve(client, sim)
    return sim


def at(minutes_ago: float) -> str:
    return (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat()


def batch(minutes_ago: float = 1, **records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "batch_id": str(uuid.uuid4()),
        "interface": "lan",
        "config_revision": 1,
        "window_start": at(minutes_ago + 1),
        "window_end": at(minutes_ago),
        "backend": "af_packet",
        "part": 0,
        "parts": 1,
        "flows": [],
        "arp": [],
        "dns": [],
        "dhcp": [],
        "tls": [],
        "stats": None,
        **records,
    }


def arp(
    ip: str,
    mac: str,
    minutes_ago: float = 1,
    unsolicited: int = 0,
    frame_mac: str | None = None,
    target: str = "10.70.0.20",
    count: int = 1,
) -> dict[str, Any]:
    return {
        "operation": "reply",
        "sender_ip": ip,
        "sender_mac": mac,
        "target_ip": target,
        "gratuitous": False,
        "vlan": None,
        "unsolicited": unsolicited,
        "eth_src_mac": frame_mac or mac,
        "count": count,
        "first_seen": at(minutes_ago),
        "last_seen": at(minutes_ago),
    }


def dhcp(
    server: str,
    server_mac: str,
    routers: list[str],
    dns: list[str] | None = None,
    message_type: str = "offer",
    your_ip: str = "10.70.0.50",
    client_mac: str = MAC_B,
    minutes_ago: float = 1,
) -> dict[str, Any]:
    return {
        "message_type": message_type,
        "client_mac": client_mac,
        "server_ip": server,
        "server_mac": server_mac,
        "your_ip": your_ip,
        "routers": routers,
        "dns_servers": dns or [],
        "vlan": None,
        "count": 1,
        "first_seen": at(minutes_ago),
        "last_seen": at(minutes_ago),
    }


def dns(
    client: str,
    qname: str,
    rcode: str = "noerror",
    qtype: str = "A",
    resolver: str = "10.70.0.53",
    queries: int = 1,
) -> dict[str, Any]:
    return {
        "client_ip": client,
        "resolver_ip": resolver,
        "qname": qname,
        "qtype": qtype,
        "queries": queries,
        "responses": 1,
        "rcodes": {rcode: 1},
        "answers": [],
        "min_ttl": None,
        "transport": "udp",
        "vlan": None,
        "count": queries + 1,
        "first_seen": at(1),
        "last_seen": at(1),
    }


def anomalies(db: Session, rule_id: str | None = None) -> list[NdrAnomaly]:
    db.expire_all()
    query = select(NdrAnomaly).order_by(NdrAnomaly.id)
    if rule_id is not None:
        query = query.where(NdrAnomaly.rule_id == rule_id)
    return list(db.scalars(query))


def test_rule_ids_are_stable_unique_and_do_not_collide() -> None:
    ids = [rule.id for rule in RULES]
    assert len(ids) == len(set(ids))
    assert {"NDR-ARP-001", "NDR-ARP-002", "NDR-MITM-001", "NDR-DNS-001", "NDR-DNS-002"} <= set(ids)
    assert not set(ids) & set(RULES_BY_ID)
    for rule in RULES:
        assert rule.id.startswith("NDR-") and rule.verdicts


def test_arp_mac_change_suspicious_then_probable(
    client: TestClient, sensor: SensorSim, db: Session
) -> None:
    _ok(send(sensor, batch(120, arp=[arp("10.70.0.20", MAC_A, 120)])))
    assert anomalies(db) == []
    _ok(send(sensor, batch(arp=[arp("10.70.0.20", MAC_B)])))
    [found] = anomalies(db, "NDR-ARP-001")
    assert found.verdict == "suspicious" and found.subject_mac == MAC_B
    assert found.evidence["previous_macs"][0]["mac"] == MAC_A
    # Las dos MAC alternan en la misma ventana: disputa por la IP.
    _ok(send(sensor, batch(arp=[arp("10.70.0.20", MAC_B), arp("10.70.0.20", MAC_A)])))
    [found] = anomalies(db, "NDR-ARP-001")
    assert found.verdict == "probable" and found.occurrences == 2


def test_dhcp_lease_explains_the_change(sensor: SensorSim, db: Session) -> None:
    _ok(send(sensor, batch(120, arp=[arp("10.70.0.30", MAC_A, 120)])))
    lease = dhcp(GATEWAY, MAC_GW, [GATEWAY], message_type="ack", your_ip="10.70.0.30")
    lease["client_mac"] = MAC_B
    _ok(send(sensor, batch(dhcp=[lease])))
    assert anomalies(db, "NDR-ARP-001") == []


def test_stale_binding_is_not_a_change(sensor: SensorSim, db: Session) -> None:
    _ok(send(sensor, batch(60 * 30, arp=[arp("10.70.0.40", MAC_A, 60 * 30)])))
    _ok(send(sensor, batch(arp=[arp("10.70.0.40", MAC_B)])))
    assert anomalies(db) == []


def _gateway_baseline(sensor: SensorSim) -> None:
    _ok(
        send(
            sensor,
            batch(
                120,
                dhcp=[dhcp(GATEWAY, MAC_GW, [GATEWAY], ["10.70.0.53"], minutes_ago=120)],
                arp=[arp(GATEWAY, MAC_GW, 120)],
            ),
        )
    )


def test_gateway_impersonation_probable_then_confirmed(sensor: SensorSim, db: Session) -> None:
    _gateway_baseline(sensor)
    _ok(send(sensor, batch(arp=[arp(GATEWAY, MAC_EVIL, unsolicited=4)])))
    [mitm] = anomalies(db, "NDR-MITM-001")
    assert mitm.verdict == "probable" and mitm.severity == "high"
    assert anomalies(db, "NDR-ARP-001") == []  # la puerta de enlace la cubre MITM-001
    # Envenenamiento bidireccional: la MAC atacante anuncia también a la víctima y la MAC
    # legítima sigue respondiendo en la misma ventana.
    _ok(
        send(
            sensor,
            batch(
                arp=[
                    arp(GATEWAY, MAC_EVIL, unsolicited=6),
                    arp("10.70.0.20", MAC_EVIL, unsolicited=6, target=GATEWAY),
                    arp(GATEWAY, MAC_GW),
                ]
            ),
        )
    )
    [mitm] = anomalies(db, "NDR-MITM-001")
    assert mitm.verdict == "confirmed" and mitm.severity == "critical"
    assert mitm.evidence["other_ips_claimed"] == ["10.70.0.20"]


def test_one_mac_claiming_many_ips(sensor: SensorSim, db: Session) -> None:
    claims = [arp(f"10.70.0.{i}", MAC_EVIL, unsolicited=4) for i in (21, 22, 23)]
    _ok(send(sensor, batch(arp=claims)))
    [found] = anomalies(db, "NDR-ARP-002")
    assert found.verdict == "probable" and found.evidence["ips"] == [
        "10.70.0.21",
        "10.70.0.22",
        "10.70.0.23",
    ]
    # Un router con proxy ARP (MAC de la puerta de enlace) no cuenta.
    _gateway_baseline(sensor)
    proxy = [arp(f"10.70.1.{i}", MAC_GW, unsolicited=1) for i in (1, 2, 3)]
    _ok(send(sensor, batch(arp=proxy)))
    assert len(anomalies(db, "NDR-ARP-002")) == 1


def test_frame_mac_mismatch(sensor: SensorSim, db: Session) -> None:
    _ok(send(sensor, batch(arp=[arp("10.70.0.25", MAC_A, frame_mac=MAC_EVIL)])))
    [found] = anomalies(db, "NDR-ARP-003")
    assert found.subject_mac == MAC_EVIL and found.verdict == "suspicious"


def test_rogue_dhcp_server(sensor: SensorSim, db: Session) -> None:
    _gateway_baseline(sensor)
    _ok(send(sensor, batch(dhcp=[dhcp("10.70.0.66", MAC_EVIL, ["10.70.0.66"], ["10.70.0.66"])])))
    [found] = anomalies(db, "NDR-DHCP-001")
    assert found.verdict == "probable" and found.subject_ip == "10.70.0.66"
    # El servidor establecido no genera nada.
    _ok(send(sensor, batch(dhcp=[dhcp(GATEWAY, MAC_GW, [GATEWAY], ["10.70.0.53"])])))
    assert len(anomalies(db, "NDR-DHCP-001")) == 1


def test_nxdomain_burst(sensor: SensorSim, db: Session) -> None:
    names = [dns("10.70.0.20", f"q{i}x7k.example{i % 3}.test", "nxdomain") for i in range(25)]
    _ok(send(sensor, batch(dns=names)))
    [found] = anomalies(db, "NDR-DNS-001")
    assert found.verdict == "suspicious" and found.evidence["nxdomain_names"] == 25
    many = [dns("10.70.0.21", f"a{i}b.dom{i % 12}.test", "nxdomain") for i in range(55)]
    _ok(send(sensor, batch(dns=many)))
    probable = [a for a in anomalies(db, "NDR-DNS-001") if a.subject_ip == "10.70.0.21"]
    assert probable[0].verdict == "probable"
    # Pocas respuestas fallidas: nada.
    few = [dns("10.70.0.22", f"n{i}.example.test", "nxdomain") for i in range(5)]
    _ok(send(sensor, batch(dns=few)))
    assert not [a for a in anomalies(db, "NDR-DNS-001") if a.subject_ip == "10.70.0.22"]


def test_dns_tunnel_indicators(sensor: SensorSim, db: Session) -> None:
    encoded = [
        dns("10.70.0.30", f"{uuid.uuid4().hex}{i:04d}.t.exfil.test", qtype="TXT", queries=1)
        for i in range(35)
    ]
    _ok(send(sensor, batch(dns=encoded)))
    [found] = anomalies(db, "NDR-DNS-002")
    assert found.verdict == "probable" and found.evidence["parent"] == "exfil.test"
    normal = [dns("10.70.0.31", f"www{i}.example.com") for i in range(40)]
    _ok(send(sensor, batch(dns=normal)))
    assert len(anomalies(db, "NDR-DNS-002")) == 1


def test_foreign_resolver_is_observed(sensor: SensorSim, db: Session) -> None:
    _gateway_baseline(sensor)
    _ok(send(sensor, batch(dns=[dns("10.70.0.20", "example.com", resolver="8.8.8.8")])))
    [found] = anomalies(db, "NDR-DNS-003")
    assert found.verdict == "observed" and found.severity == "low"
    _ok(send(sensor, batch(dns=[dns("10.70.0.20", "example.com", resolver="10.70.0.53")])))
    assert len(anomalies(db, "NDR-DNS-003")) == 1


def test_helpers() -> None:
    assert parent_domain("a.b.example.co.uk") == "example.co.uk"
    assert parent_domain("x.y.example.com") == "example.com"
    assert entropy("aaaa") == 0 and entropy(uuid.uuid4().hex) > 3


def test_triage_flow_and_permissions(
    client: TestClient, engine: Engine, sensor: SensorSim, db: Session
) -> None:
    _ok(send(sensor, batch(arp=[arp("10.70.0.25", MAC_A, frame_mac=MAC_EVIL)])))
    listed = _ok(client.get(f"{NDR}/anomalies", params={"active": True}))
    assert listed["total"] == 1
    anomaly_id = listed["items"][0]["anomaly_id"]
    url = f"{NDR}/anomalies/{anomaly_id}/status"
    authenticate(client, engine, "viewer")
    assert client.get(f"{NDR}/anomalies/{anomaly_id}").status_code == 200
    _error(client.post(url, json={"status": "acknowledged"}), 403, "permission_denied")
    authenticate(client, engine, "analyst")
    assert _ok(client.post(url, json={"status": "acknowledged"}))["status"] == "acknowledged"
    _error(client.post(url, json={"status": "resolved"}), 409, "ndr_note_required")
    closed = _ok(client.post(url, json={"status": "false_positive", "note": "Puente HA"}))
    assert closed["status"] == "false_positive" and closed["status_by"]
    _error(client.post(url, json={"status": "resolved", "note": "x"}), 409, "ndr_anomaly_closed")
    # Tras cerrarla, una nueva ocurrencia abre otra anomalía (la cerrada es historial).
    _ok(send(sensor, batch(arp=[arp("10.70.0.25", MAC_A, frame_mac=MAC_EVIL)])))
    assert len(anomalies(db, "NDR-ARP-003")) == 2
    rules = _ok(client.get(f"{NDR}/rules"))["items"]
    assert {r["id"] for r in rules} >= {"NDR-MITM-001", "NDR-DNS-002"}


def test_duplicate_batch_does_not_add_occurrences(sensor: SensorSim, db: Session) -> None:
    body = batch(arp=[arp("10.70.0.25", MAC_A, frame_mac=MAC_EVIL)])
    _ok(send(sensor, body))
    assert _ok(send(sensor, body))["duplicate"] is True
    [found] = anomalies(db, "NDR-ARP-003")
    assert found.occurrences == 1


def test_bindings_need_evidence_permission(
    client: TestClient, engine: Engine, sensor: SensorSim, db: Session
) -> None:
    _gateway_baseline(sensor)
    items = _ok(client.get(f"{NDR}/bindings", params={"gateway": True}))["items"]
    assert items[0]["ip"] == GATEWAY and items[0]["mac"] == MAC_GW
    assert db.scalar(select(func.count()).select_from(NdrAnomaly)) == 0
    authenticate(client, engine, "viewer")
    _error(client.get(f"{NDR}/bindings"), 403, "permission_denied")
