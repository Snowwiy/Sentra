"""Fase 7F.4: logs JSON de Zeek (conn, dns, ssl, http, dhcp, ssh) y su correlación con NDR y
Suricata.

Registros SINTÉTICOS con los campos documentados de los logs de Zeek 6/7 (docs.zeek.org,
"Log Files"). No validan un Zeek real.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.models.detection import DetectionSignal
from app.models.siem import SiemEvent, SiemEventLink
from app.siem.catalog import NormalizeContext
from app.siem.contract import RawRecord, RecordRejectedError
from app.siem.normalizers.zeek import normalize
from tests.test_ndr_7e1 import approve, ndr_sensor, send
from tests.test_ndr_7e2 import batch as ndr_batch
from tests.test_ndr_7e3 import flow
from tests.test_ndr_7e4 import _asset, _site_id
from tests.test_siem_7f1 import SIEM
from tests.test_siem_7f3_suricata import eve_alert, import_eve, suricata_source
from tests.test_sites_sensors import _ok, default_site

CTX = NormalizeContext(config={}, raw_store_bytes=2048)
ORIG = "10.70.0.20"
RESP = "198.51.100.23"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def epoch(seconds_ago: float = 90) -> float:
    return (datetime.now(UTC) - timedelta(seconds=seconds_ago)).timestamp()


def conn(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "ts": epoch(),
        "uid": "CHhAvVGS1DHFjwGM9",
        "id.orig_h": ORIG,
        "id.orig_p": 50000,
        "id.resp_h": RESP,
        "id.resp_p": 445,
        "proto": "tcp",
        "service": "smb",
        "duration": 1.5,
        "orig_bytes": 300,
        "resp_bytes": 900,
        "conn_state": "SF",
        "history": "ShADadFf",
        "orig_pkts": 5,
        "resp_pkts": 4,
        "community_id": "1:abcdefghijklmnopqrstuvwxyz0=",
    }
    value.update(overrides)
    return value


def rec(value: dict[str, Any] | str) -> RawRecord:
    text = value if isinstance(value, str) else json.dumps(value)
    return RawRecord(raw=text, transport="file", reference="zeek:file:f@0")


# --- normalizador ----------------------------------------------------------------------------


def test_conn_keeps_uid_and_is_informational() -> None:
    event = normalize(rec(conn()), CTX)
    assert event.event_type == "network.connection" and event.category == "network"
    assert event.flow_ref == event.external_id == "CHhAvVGS1DHFjwGM9"
    assert (event.src_ip, event.src_port, event.dst_ip, event.dst_port) == (ORIG, 50000, RESP, 445)
    assert event.protocol == "tcp" and event.severity == "informational"
    assert event.data["conn_state"] == "SF" and event.data["community_id"].startswith("1:")


def test_iso_timestamps_and_path_are_supported() -> None:
    value = conn(ts="2026-11-24T08:00:00.123456Z", _path="conn")
    assert normalize(rec(value), CTX).observed_at == datetime(
        2026, 11, 24, 8, 0, 0, 123456, tzinfo=UTC
    )


def test_dns_ssl_http_dhcp_ssh_by_fields() -> None:
    dns = normalize(
        rec(
            {
                "ts": epoch(),
                "uid": "C1",
                "id.orig_h": ORIG,
                "id.resp_h": "10.70.0.1",
                "id.orig_p": 5353,
                "id.resp_p": 53,
                "query": "evil.example",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
                "answers": ["203.0.113.9"],
            }
        ),
        CTX,
    )
    assert dns.event_type == "dns.query" and dns.data["query"] == "evil.example"
    assert dns.protocol == "udp" and dns.data["answers"] == ["203.0.113.9"]
    ssl = normalize(
        rec(
            {
                "ts": epoch(),
                "uid": "C2",
                "id.orig_h": ORIG,
                "id.resp_h": RESP,
                "server_name": "login.example",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "version": "TLSv13",
                "established": True,
            }
        ),
        CTX,
    )
    assert ssl.event_type == "tls.handshake" and ssl.hostname == "login.example"
    assert ssl.outcome == "success"
    http = normalize(
        rec(
            {
                "ts": epoch(),
                "uid": "C3",
                "id.orig_h": ORIG,
                "id.resp_h": RESP,
                "method": "POST",
                "host": "api.example",
                "uri": "/login?password=SECRETO",
                "status_code": 302,
                "user_agent": "curl/8",
                "request_body_len": 120,
                "post_body": "user=a&password=SECRETO",
            }
        ),
        CTX,
    )
    assert http.event_type == "http.request" and http.data["uri_path"] == "/login"
    assert "SECRETO" not in json.dumps(http.data) and "SECRETO" not in (http.excerpt or "")
    dhcp = normalize(
        rec(
            {
                "ts": epoch(),
                "uids": ["C4"],
                "client_addr": ORIG,
                "server_addr": "10.70.0.1",
                "mac": "02:00:00:00:00:01",
                "host_name": "laptop-7",
                "assigned_addr": ORIG,
                "msg_types": ["REQUEST", "ACK"],
            }
        ),
        CTX,
    )
    assert dhcp.event_type == "dhcp.message" and dhcp.flow_ref == "C4"
    assert dhcp.hostname == "laptop-7"
    ssh = normalize(
        rec(
            {
                "ts": epoch(),
                "uid": "C5",
                "id.orig_h": RESP,
                "id.resp_h": ORIG,
                "id.resp_p": 22,
                "auth_success": False,
                "auth_attempts": 6,
                "direction": "INBOUND",
                "client": "SSH-2.0-libssh",
            }
        ),
        CTX,
    )
    assert ssh.event_type == "ssh.session" and ssh.outcome == "failure"
    assert ssh.data["auth_attempts"] == 6


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("{nope", "invalid_json"),
        (json.dumps({"ts": 1.0, "_path": "files", "fuid": "F1"}), "unsupported_log"),
        (json.dumps({"ts": 1.0, "something": "else"}), "unsupported_log"),
        (json.dumps({"ts": "ayer", "conn_state": "S0"}), "invalid_timestamp"),
    ],
)
def test_rejections(raw: str, reason: str) -> None:
    with pytest.raises(RecordRejectedError) as info:
        normalize(rec(raw), CTX)
    assert info.value.reason == reason


def test_identity_is_stable_and_specific() -> None:
    base = conn()
    assert (
        normalize(rec(base), CTX).identity
        == normalize(rec(dict(reversed(base.items()))), CTX).identity
    )
    assert (
        normalize(rec({**base, "uid": "Cother"}), CTX).identity
        != normalize(rec(base), CTX).identity
    )


# --- ingesta y correlación -------------------------------------------------------------------


def zeek_source(client: TestClient) -> dict[str, Any]:
    source: dict[str, Any] = _ok(
        client.post(
            f"{SIEM}/sources",
            json={
                "site_id": default_site(client)["site_id"],
                "name": "zeek",
                "source_type": "zeek_json",
                "transport": "upload",
                "enabled": True,
            },
        ),
        201,
    )
    return source


def import_zeek(client: TestClient, source: dict[str, Any], *records: dict[str, Any]) -> Any:
    return _ok(
        client.post(
            f"{SIEM}/sources/{source['source_id']}/import",
            json={"content": "\n".join(json.dumps(r) for r in records), "filename": "conn.log"},
        )
    )


def test_zeek_conn_links_to_ndr_flow_and_never_signals(client: TestClient, db: Session) -> None:
    ndr = ndr_sensor(client)
    approve(client, ndr)
    _asset(db, _site_id(db, ndr), ORIG)
    _ok(send(ndr, ndr_batch(flows=[flow(ORIG, RESP, 445)])))
    result = import_zeek(client, zeek_source(client), conn())
    assert result["accepted"] == 1
    db.expire_all()
    [link] = db.scalars(select(SiemEventLink).where(SiemEventLink.kind == "ndr_flow"))
    assert link.method == "five_tuple_time"
    # Zeek describe tráfico: un conn.log no genera señales de detección.
    assert (
        list(db.scalars(select(DetectionSignal).where(DetectionSignal.kind == "siem_alert"))) == []
    )


def test_zeek_and_suricata_join_by_community_id(client: TestClient, db: Session) -> None:
    import_zeek(client, zeek_source(client), conn())
    alert = eve_alert(src_ip=ORIG, dest_ip=RESP)
    import_eve(client, suricata_source(client), alert)
    db.expire_all()
    [link] = db.scalars(select(SiemEventLink).where(SiemEventLink.kind == "siem_event"))
    assert link.method == "community_id" and link.confidence == "medium"
    events = {e.id: e for e in db.scalars(select(SiemEvent))}
    assert events[link.event_id].source_type == "suricata_eve"
    assert events[link.target_id].source_type == "zeek_json"


def test_asymmetric_or_nat_view_does_not_link(client: TestClient, db: Session) -> None:
    ndr = ndr_sensor(client)
    approve(client, ndr)
    _ok(send(ndr, ndr_batch(flows=[flow(ORIG, RESP, 445)])))
    # Zeek detrás de NAT ve otra IP de origen: no hay enlace (no se adivina la traducción).
    import_zeek(client, zeek_source(client), conn(**{"id.orig_h": "100.64.0.9"}))
    db.expire_all()
    assert list(db.scalars(select(SiemEventLink))) == []


def test_reimport_is_deduplicated(client: TestClient) -> None:
    source = zeek_source(client)
    record = conn()
    assert import_zeek(client, source, record)["accepted"] == 1
    again = import_zeek(client, source, record, conn(uid="C9"))
    assert again["accepted"] == 1 and again["duplicates"] == 1
