"""Fase 7F.3: Suricata EVE JSON, atribución conservadora, enlace con NDR y detección SIEM-EXT-001.

Los registros EVE son SINTÉTICOS, escritos con la estructura documentada de EVE JSON de
Suricata 7 (docs.suricata.io, "Eve JSON Format"). No validan un Suricata real.
"""

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.models.detection import Detection, DetectionSignal
from app.models.siem import SiemEvent, SiemEventLink
from app.risk.calculator import FAMILY_RULES
from app.risk.engine import causal_keys
from app.siem.catalog import NormalizeContext
from app.siem.contract import RawRecord, RecordRejectedError
from app.siem.normalizers.suricata import normalize
from tests.test_ndr_7e1 import approve, ndr_sensor, send
from tests.test_ndr_7e2 import batch as ndr_batch
from tests.test_ndr_7e3 import flow
from tests.test_ndr_7e4 import _asset, _detect, _site_id
from tests.test_siem_7f1 import SIEM
from tests.test_sites_sensors import _ok, default_site

CTX = NormalizeContext(config={}, raw_store_bytes=2048)
ATTACKER = "198.51.100.23"
VICTIM = "10.70.0.20"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def ts(seconds_ago: float = 90) -> str:
    # Formato de Suricata: zona sin dos puntos.
    return (datetime.now(UTC) - timedelta(seconds=seconds_ago)).strftime(
        "%Y-%m-%dT%H:%M:%S.%f+0000"
    )


def eve_alert(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "timestamp": ts(),
        "flow_id": 1234567890123456,
        "in_iface": "eth1",
        "event_type": "alert",
        "src_ip": ATTACKER,
        "src_port": 50000,
        "dest_ip": VICTIM,
        "dest_port": 445,
        "proto": "TCP",
        "community_id": "1:abcdefghijklmnopqrstuvwxyz0=",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024217,
            "rev": 3,
            "signature": "ET EXPLOIT Possible ETERNALBLUE Probe",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1,
            "metadata": {"mitre_tactic_id": ["TA0008"], "mitre_technique_id": ["T1210"]},
        },
        "payload": "AAAAAAAA",
        "payload_printable": "secret-bytes",
        "packet": "deadbeef",
        "app_proto": "smb",
    }
    value.update(overrides)
    return value


def rec(value: dict[str, Any] | str) -> RawRecord:
    text = value if isinstance(value, str) else json.dumps(value)
    return RawRecord(raw=text, transport="file", reference="ids:file:f@0")


# --- normalizador --------------------------------------------------------------------------


def test_alert_is_external_evidence_without_payload() -> None:
    event = normalize(rec(eve_alert()), CTX)
    assert event.event_type == "ids.alert" and event.category == "detection"
    assert event.severity == "high" and event.source_severity == "1"
    assert event.confidence == "low"
    assert event.signature_id == "2024217" and event.rule_id == "1:2024217:3"
    assert event.mitre_techniques == ["T1210"] and event.data["mitre_tactic"] == "TA0008"
    assert event.flow_ref == "1234567890123456" and event.protocol == "tcp"
    assert event.excerpt is not None
    for secret in ("AAAAAAAA", "secret-bytes", "deadbeef"):
        assert secret not in event.excerpt and secret not in json.dumps(event.data)


def test_identity_is_canonical_and_ignores_payload() -> None:
    base = eve_alert()
    first = normalize(rec(base), CTX)
    reordered = dict(reversed(list(base.items())))
    reordered["payload"] = "otro"
    assert normalize(rec(reordered), CTX).identity == first.identity
    assert normalize(rec({**base, "flow_id": 1}), CTX).identity != first.identity


def test_severity_policy_is_explicit_and_overridable() -> None:
    low = eve_alert()
    low["alert"] = {**low["alert"], "severity": 3}
    assert normalize(rec(low), CTX).severity == "low"
    ctx = NormalizeContext(config={"severity_policy": {"1": "critical"}}, raw_store_bytes=0)
    assert normalize(rec(eve_alert()), ctx).severity == "critical"
    weird = eve_alert()
    weird["alert"] = {**weird["alert"], "severity": "muy alta"}
    assert normalize(rec(weird), CTX).severity == "unknown"


def test_http_url_without_query_and_dns_fields() -> None:
    http = normalize(
        rec(
            {
                "timestamp": ts(),
                "event_type": "http",
                "src_ip": VICTIM,
                "src_port": 51000,
                "dest_ip": "203.0.113.5",
                "dest_port": 80,
                "proto": "TCP",
                "http": {
                    "hostname": "updates.example",
                    "url": "/download?token=SECRETO#frag",
                    "http_method": "GET",
                    "status": 200,
                    "http_request_body": "cuerpo",
                },
            }
        ),
        CTX,
    )
    assert http.event_type == "http.request" and http.data["url_path"] == "/download"
    assert "SECRETO" not in json.dumps(http.data) and "SECRETO" not in (http.excerpt or "")
    assert "cuerpo" not in (http.excerpt or "")
    dns = normalize(
        rec(
            {
                "timestamp": ts(),
                "event_type": "dns",
                "src_ip": VICTIM,
                "dest_ip": "10.70.0.1",
                "proto": "UDP",
                "dns": {"type": "query", "rrname": "evil.example", "rrtype": "A"},
            }
        ),
        CTX,
    )
    assert dns.category == "dns" and dns.data["rrname"] == "evil.example"
    assert dns.severity == "informational"


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("no es json", "invalid_json"),
        ("[1,2]", "invalid_json"),
        (
            json.dumps({"timestamp": "2026-11-24T08:00:00+0000", "event_type": "stats"}),
            "unsupported_event_type",
        ),
        (json.dumps({"event_type": "alert", "timestamp": "ayer"}), "invalid_timestamp"),
        (
            json.dumps({"event_type": "alert", "timestamp": "2026-11-24T08:00:00"}),
            "invalid_timestamp",
        ),
    ],
)
def test_rejections(raw: str, reason: str) -> None:
    with pytest.raises(RecordRejectedError) as info:
        normalize(rec(raw), CTX)
    assert info.value.reason == reason


# --- ingesta, atribución y detección ---------------------------------------------------------


def suricata_source(client: TestClient, name: str = "suricata") -> dict[str, Any]:
    source: dict[str, Any] = _ok(
        client.post(
            f"{SIEM}/sources",
            json={
                "site_id": default_site(client)["site_id"],
                "name": name,
                "source_type": "suricata_eve",
                "transport": "upload",
                "enabled": True,
            },
        ),
        201,
    )
    return source


def import_eve(client: TestClient, source: dict[str, Any], *records: dict[str, Any]) -> Any:
    return _ok(
        client.post(
            f"{SIEM}/sources/{source['source_id']}/import",
            json={"content": "\n".join(json.dumps(r) for r in records), "filename": "eve.json"},
        )
    )


def _site(db: Session, client: TestClient) -> int:
    from app.models.site import Site

    site = db.scalar(
        select(Site).where(Site.public_id == uuid.UUID(default_site(client)["site_id"]))
    )
    assert site is not None
    return site.id


def _events(db: Session) -> list[SiemEvent]:
    db.expire_all()
    return list(db.scalars(select(SiemEvent).order_by(SiemEvent.id)))


def _siem_signals(db: Session) -> list[DetectionSignal]:
    db.expire_all()
    return list(db.scalars(select(DetectionSignal).where(DetectionSignal.kind == "siem_alert")))


def test_alert_attributed_to_victim_becomes_low_confidence_detection(
    client: TestClient, engine: Engine, db: Session
) -> None:
    victim = _asset(db, _site(db, client), VICTIM)
    result = import_eve(client, suricata_source(client), eve_alert())
    assert result["accepted"] == 1
    [event] = _events(db)
    assert event.asset_id == victim.id and event.attribution is not None
    assert event.attribution["verdict"] == "attributed"
    assert event.attribution["candidates"][0]["role"] == "destination"
    [signal] = _siem_signals(db)
    assert signal.asset_id == victim.id and signal.source_type == "siem"
    _detect(engine)
    db.expire_all()
    [detection] = db.scalars(select(Detection).where(Detection.rule_id == "SIEM-EXT-001"))
    assert detection.asset_id == victim.id
    assert detection.confidence.value == "low" and detection.severity.value == "high"
    assert detection.details is not None and detection.details["origin"] == "imported"
    assert detection.mitre_technique == "T1210"
    # La API del evento muestra el activo y la procedencia.
    listed = _ok(client.get(f"{SIEM}/events", params={"event_type": "ids.alert"}))
    assert listed["items"][0]["asset"]["asset_id"] == str(victim.public_id)


def test_repeated_alerts_are_one_detection(client: TestClient, engine: Engine, db: Session) -> None:
    _asset(db, _site(db, client), VICTIM)
    source = suricata_source(client)
    import_eve(client, source, *[eve_alert(flow_id=i, timestamp=ts(100 - i)) for i in range(5)])
    assert len(_siem_signals(db)) == 5
    _detect(engine)
    db.expire_all()
    detections = list(db.scalars(select(Detection).where(Detection.rule_id == "SIEM-EXT-001")))
    assert len(detections) == 1


def test_unknown_or_shared_ip_is_kept_without_inventing_an_asset(
    client: TestClient, db: Session
) -> None:
    site_id = _site(db, client)
    # Dos activos con la misma IP (NAT o duplicado): no hay activo único.
    _asset(db, site_id, VICTIM)
    _asset(db, site_id, VICTIM)
    import_eve(client, suricata_source(client), eve_alert(), eve_alert(dest_ip="10.70.0.250"))
    events = _events(db)
    assert [e.asset_id for e in events] == [None, None]
    assert events[0].attribution is not None and events[0].attribution["verdict"] == "ambiguous"
    assert events[1].attribution is not None
    assert events[1].attribution["verdict"] == "insufficient_evidence"
    assert _siem_signals(db) == []


def test_internal_to_internal_alert_signals_both_roles(client: TestClient, db: Session) -> None:
    site_id = _site(db, client)
    source_asset = _asset(db, site_id, "10.70.0.30")
    target = _asset(db, site_id, VICTIM)
    import_eve(client, suricata_source(client), eve_alert(src_ip="10.70.0.30"))
    [event] = _events(db)
    assert event.asset_id is None and event.attribution is not None
    assert event.attribution["verdict"] == "multiple"
    signals = {s.asset_id: s.data for s in _siem_signals(db)}
    assert set(signals) == {source_asset.id, target.id}
    target_data = signals[target.id]
    assert target_data is not None and target_data["role"] == "destination"


def test_informational_records_never_signal(client: TestClient, db: Session) -> None:
    _asset(db, _site(db, client), VICTIM)
    low = eve_alert()
    low["alert"] = {**low["alert"], "severity": 4}
    import_eve(
        client,
        suricata_source(client),
        low,
        {
            "timestamp": ts(),
            "event_type": "flow",
            "src_ip": ATTACKER,
            "dest_ip": VICTIM,
            "proto": "TCP",
            "flow": {},
        },
    )
    assert _siem_signals(db) == []


def test_ndr_flow_corroborates_alert(client: TestClient, engine: Engine, db: Session) -> None:
    ndr = ndr_sensor(client)
    approve(client, ndr)
    victim = _asset(db, _site_id(db, ndr), VICTIM)
    _ok(send(ndr, ndr_batch(flows=[flow(ATTACKER, VICTIM, 445)])))
    import_eve(client, suricata_source(client), eve_alert())
    db.expire_all()
    [link] = db.scalars(select(SiemEventLink).where(SiemEventLink.kind == "ndr_flow"))
    assert link.method == "five_tuple_time" and link.confidence == "high"
    _detect(engine)
    db.expire_all()
    [detection] = db.scalars(select(Detection).where(Detection.rule_id == "SIEM-EXT-001"))
    assert detection.asset_id == victim.id and detection.confidence.value == "medium"
    assert detection.details is not None and detection.details["origin"] == "correlated"
    assert detection.details["ndr_flow_uids"] == [link.target_ref]
    # El detalle del evento explica la relación y la atribución con ids públicos.
    [event] = _events(db)
    detail = _ok(client.get(f"{SIEM}/events/{event.event_id}"))
    assert detail["links"][0]["kind"] == "ndr_flow"
    assert "5-tupla" in detail["links"][0]["explanation"]
    candidate = detail["attribution"]["candidates"][0]
    assert candidate["asset_id"] == str(victim.public_id) and candidate["role"] == "destination"


def test_nat_or_other_ports_do_not_link(client: TestClient, db: Session) -> None:
    ndr = ndr_sensor(client)
    approve(client, ndr)
    _ok(send(ndr, ndr_batch(flows=[flow(ATTACKER, VICTIM, 445)])))
    # Puerto de origen distinto (NAT) y otro destino: sin enlace.
    import_eve(
        client,
        suricata_source(client),
        eve_alert(src_port=61000),
        eve_alert(dest_ip="10.70.0.21", flow_id=2),
    )
    db.expire_all()
    assert list(db.scalars(select(SiemEventLink).where(SiemEventLink.kind == "ndr_flow"))) == []


def test_same_flow_records_are_linked(client: TestClient, db: Session) -> None:
    source = suricata_source(client)
    import_eve(
        client,
        source,
        {
            "timestamp": ts(120),
            "flow_id": 77,
            "event_type": "flow",
            "src_ip": ATTACKER,
            "src_port": 50000,
            "dest_ip": VICTIM,
            "dest_port": 445,
            "proto": "TCP",
            "flow": {"pkts_toserver": 3, "bytes_toserver": 200},
        },
    )
    import_eve(client, source, eve_alert(flow_id=77))
    db.expire_all()
    [link] = db.scalars(select(SiemEventLink).where(SiemEventLink.kind == "siem_event"))
    assert link.method == "flow_ref" and link.confidence == "high"


# --- riesgo: sin doble conteo ----------------------------------------------------------------


def test_risk_does_not_double_count_external_alerts() -> None:
    assert "SIEM-EXT-001" in FAMILY_RULES
    ndr_keys = causal_keys("NET-NDR-001", "ndr:abc", None, None)
    siem_keys = causal_keys("SIEM-EXT-001", "siem:x", None, None, None, ["ndr:abc", "otra"])
    assert ndr_keys == siem_keys == frozenset({"ndr:abc"})
    # Sin enlace con la anomalía no se une nada.
    assert causal_keys("SIEM-EXT-001", "siem:x", None, None, None, []) == frozenset()


def test_alert_with_ndr_anomaly_shares_causal_key(
    client: TestClient, engine: Engine, db: Session
) -> None:
    from tests.test_ndr_7e3 import SCANNER, scan_flows

    ndr = ndr_sensor(client)
    approve(client, ndr)
    scanner = _asset(db, _site_id(db, ndr), SCANNER)
    _ok(send(ndr, ndr_batch(flows=scan_flows(60))))
    scan = eve_alert(src_ip=SCANNER, dest_ip="10.70.0.250", src_port=40000)
    scan["alert"] = {
        **scan["alert"],
        "signature_id": 2010937,
        "signature": "ET SCAN Nmap",
        "severity": 2,
    }
    import_eve(client, suricata_source(client), scan)
    _detect(engine)
    db.expire_all()
    [siem] = db.scalars(select(Detection).where(Detection.rule_id == "SIEM-EXT-001"))
    [ndr_detection] = db.scalars(select(Detection).where(Detection.rule_id == "NET-NDR-001"))
    assert siem.asset_id == ndr_detection.asset_id == scanner.id
    assert siem.details is not None and siem.details["causal_keys"] == [ndr_detection.dedup_key]
