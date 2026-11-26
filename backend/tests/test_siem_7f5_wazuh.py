"""Fase 7F.5: alertas exportadas de Wazuh (alerts.json), solo lectura.

Alertas SINTÉTICAS con la estructura documentada de alerts.json de Wazuh 4.x
(documentation.wazuh.com, "Alerts"). No validan un manager de Wazuh real.
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

from app.models.asset import Asset
from app.models.detection import (
    Detection,
    DetectionConfidence,
    DetectionSeverity,
    DetectionSignal,
    DetectionStatus,
)
from app.models.siem import SiemEvent, SiemEventLink
from app.siem.catalog import NormalizeContext, get_connector
from app.siem.contract import RawRecord, RecordRejectedError
from app.siem.normalizers.wazuh import normalize
from tests.test_ndr_7e4 import _asset, _detect
from tests.test_siem_7f1 import SIEM
from tests.test_siem_7f3_suricata import _site
from tests.test_sites_sensors import _ok, default_site

CTX = NormalizeContext(config={}, raw_store_bytes=2048)
AGENT_IP = "10.80.0.15"
ATTACKER = "203.0.113.77"
POLICY = {"0-3": "informational", "4-7": "low", "8-11": "medium", "12-15": "high"}


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def iso(seconds_ago: float = 60) -> str:
    moment = datetime.now(UTC) - timedelta(seconds=seconds_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"


def alert(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "timestamp": iso(),
        "id": "1732435200.123456",
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "sshd: brute force trying to get access to the system.",
            "groups": ["syslog", "sshd", "authentication_failures"],
            "firedtimes": 3,
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
        },
        "agent": {"id": "003", "name": "web01", "ip": AGENT_IP},
        "manager": {"name": "wazuh-manager"},
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "data": {"srcip": ATTACKER, "srcport": "51022", "dstuser": "root"},
        "full_log": "Nov 24 08:00:00 web01 sshd[123]: Failed password for root",
    }
    value.update(overrides)
    return value


def rec(value: dict[str, Any] | str) -> RawRecord:
    text = value if isinstance(value, str) else json.dumps(value)
    return RawRecord(raw=text, transport="upload", reference="wazuh:upload")


# --- normalizador ----------------------------------------------------------------------------


def test_fields_and_provenance_are_kept() -> None:
    event = normalize(rec(alert()), CTX)
    assert event.event_type == "wazuh.alert" and event.category == "detection"
    assert event.rule_id == event.signature_id == "5712"
    assert event.message is not None and event.message.startswith("sshd: brute force")
    assert event.mitre_techniques == ["T1110"] and event.confidence == "low"
    assert event.src_ip == ATTACKER and event.src_port == 51022 and event.username == "root"
    assert event.source_severity == "level 10" and event.external_id == "1732435200.123456"
    data = event.data
    assert data["origin_product"] == "wazuh" and data["level_bucket"] == "8-11"
    assert data["agent_id"] == "003" and data["agent_name"] == "web01"
    assert data["agent_ip"] == AGENT_IP and data["manager"] == "wazuh-manager"
    assert data["mitre_tactic"] == "TA0006" and data["rule_groups"][-1] == "authentication_failures"


def test_without_explicit_policy_every_level_is_unknown() -> None:
    for level in (0, 3, 7, 11, 15):
        value = alert()
        value["rule"] = {**value["rule"], "level": level}
        assert normalize(rec(value), CTX).severity == "unknown"
    assert set(get_connector("wazuh_alerts").severity_policy.values()) == {"unknown"}  # type: ignore[union-attr]
    ctx = NormalizeContext(config={"severity_policy": POLICY}, raw_store_bytes=0)
    assert normalize(rec(alert()), ctx).severity == "medium"


def test_agent_any_ip_is_not_an_address() -> None:
    value = alert(agent={"id": "000", "name": "wazuh-manager", "ip": "any"})
    assert normalize(rec(value), CTX).data.get("agent_ip") is None


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("{nope", "invalid_json"),
        (json.dumps([1]), "invalid_json"),
        (
            json.dumps({"timestamp": "2026-11-24T08:00:00+0000", "rule": {"id": "1"}}),
            "invalid_schema",
        ),
        (
            json.dumps({"timestamp": "2026-11-24T08:00:00+0000", "rule": {"id": "1", "level": 16}}),
            "invalid_schema",
        ),
        (
            json.dumps(
                {"timestamp": "2026-11-24T08:00:00+0000", "rule": {"id": "1", "level": True}}
            ),
            "invalid_schema",
        ),
        (json.dumps({"timestamp": "ayer", "rule": {"id": "1", "level": 5}}), "invalid_timestamp"),
    ],
)
def test_rejections(raw: str, reason: str) -> None:
    with pytest.raises(RecordRejectedError) as info:
        normalize(rec(raw), CTX)
    assert info.value.reason == reason


def test_identity_dedups_the_same_alert() -> None:
    base = alert()
    assert normalize(rec(base), CTX).identity == normalize(rec(json.dumps(base)), CTX).identity
    other = {**base, "id": "1732435200.999999"}
    assert normalize(rec(other), CTX).identity != normalize(rec(base), CTX).identity


# --- ingesta, atribución y detecciones -------------------------------------------------------


def wazuh_source(client: TestClient, policy: dict[str, str] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "site_id": default_site(client)["site_id"],
        "name": "wazuh",
        "source_type": "wazuh_alerts",
        "transport": "upload",
        "enabled": True,
    }
    if policy is not None:
        body["config"] = {"severity_policy": policy}
    source: dict[str, Any] = _ok(client.post(f"{SIEM}/sources", json=body), 201)
    return source


def import_alerts(client: TestClient, source: dict[str, Any], *records: dict[str, Any]) -> Any:
    return _ok(
        client.post(
            f"{SIEM}/sources/{source['source_id']}/import",
            json={"content": "\n".join(json.dumps(r) for r in records), "filename": "alerts.json"},
        )
    )


def _named_asset(db: Session, site_id: int, ip: str, hostname: str) -> Asset:
    asset = _asset(db, site_id, ip)
    asset.hostname = hostname
    db.commit()
    return asset


def _event(db: Session) -> SiemEvent:
    db.expire_all()
    [event] = db.scalars(select(SiemEvent))
    return event


def _signals(db: Session) -> list[DetectionSignal]:
    db.expire_all()
    return list(db.scalars(select(DetectionSignal).where(DetectionSignal.kind == "siem_alert")))


def _native(db: Session, asset: Asset, *, technique: str | None, category: str) -> Detection:
    now = datetime.now(UTC)
    detection = Detection(
        asset_id=asset.id,
        rule_id="AUTH-001",
        rule_version=1,
        rule_category=category,
        kind="threshold",
        dedup_key=uuid.uuid4().hex,
        severity=DetectionSeverity.MEDIUM,
        confidence=DetectionConfidence.MEDIUM,
        status=DetectionStatus.OPEN,
        title="Fuerza bruta (nativa)",
        summary="Sintética de test",
        mitre_technique=technique,
        first_seen_at=now - timedelta(minutes=5),
        last_seen_at=now - timedelta(minutes=1),
        created_at=now,
        updated_at=now,
    )
    db.add(detection)
    db.commit()
    return detection


def test_no_policy_means_no_signal(client: TestClient, db: Session) -> None:
    _named_asset(db, _site(db, client), AGENT_IP, "web01")
    assert import_alerts(client, wazuh_source(client), alert())["accepted"] == 1
    event = _event(db)
    assert event.severity == "unknown" and event.attribution is not None
    assert event.attribution["verdict"] == "attributed"
    assert _signals(db) == []


def test_with_policy_agent_ip_attributes_and_creates_detection(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _named_asset(db, _site(db, client), AGENT_IP, "web01")
    import_alerts(client, wazuh_source(client, POLICY), alert())
    event = _event(db)
    assert event.asset_id == asset.id and event.attribution is not None
    [candidate] = event.attribution["candidates"]
    # IP y nombre del agente apuntan al mismo activo: confianza media.
    assert (candidate["method"], candidate["confidence"]) == ("agent_ip", "medium")
    assert event.attribution["origin"] == "imported"
    [signal] = _signals(db)
    assert signal.asset_id == asset.id and signal.data is not None
    assert signal.data["origin"] == "imported"
    _detect(engine)
    db.expire_all()
    [detection] = db.scalars(select(Detection).where(Detection.rule_id == "SIEM-EXT-001"))
    assert detection.severity.value == "medium" and detection.confidence.value == "low"
    assert detection.mitre_technique == "T1110"


def test_agent_ip_alone_is_low_confidence(client: TestClient, db: Session) -> None:
    _named_asset(db, _site(db, client), AGENT_IP, "otro-nombre")
    import_alerts(client, wazuh_source(client, POLICY), alert())
    event = _event(db)
    assert event.attribution is not None
    assert event.attribution["candidates"][0]["confidence"] == "low"


def test_hostname_alone_is_a_hint_not_identity(client: TestClient, db: Session) -> None:
    asset = _named_asset(db, _site(db, client), "10.80.0.99", "web01")
    # La IP del agente no está en el inventario: solo coincide el nombre.
    import_alerts(client, wazuh_source(client, POLICY), alert())
    event = _event(db)
    assert event.attribution is not None and event.attribution["verdict"] == "hostname_hint"
    assert event.asset_id is None
    assert event.attribution["candidates"][0]["asset_id"] == asset.id
    assert event.attribution["origin"] == "insufficient_evidence"
    assert _signals(db) == []


def test_unknown_host_is_insufficient_evidence(client: TestClient, db: Session) -> None:
    import_alerts(client, wazuh_source(client, POLICY), alert())
    event = _event(db)
    assert event.attribution is not None
    assert event.attribution["verdict"] == "insufficient_evidence"
    assert event.attribution["origin"] == "insufficient_evidence"
    assert _signals(db) == []


@pytest.mark.parametrize(
    ("technique", "category"),
    [("T1110", "behavior"), (None, "authentication")],
)
def test_native_detection_makes_probable_match_without_duplicate(
    client: TestClient, db: Session, technique: str | None, category: str
) -> None:
    asset = _named_asset(db, _site(db, client), AGENT_IP, "web01")
    native = _native(db, asset, technique=technique, category=category)
    import_alerts(client, wazuh_source(client, POLICY), alert())
    event = _event(db)
    assert event.attribution is not None and event.attribution["origin"] == "probable_match"
    assert _signals(db) == []
    [link] = db.scalars(select(SiemEventLink).where(SiemEventLink.kind == "detection"))
    assert link.target_id == native.id and link.target_ref == str(native.public_id)
    assert link.details is not None and "no se crea otra" in link.details["explanation"]
    detail = _ok(client.get(f"{SIEM}/events/{event.event_id}"))
    assert detail["attribution"]["origin"] == "probable_match"
    assert detail["links"][0]["kind"] == "detection"


def test_time_alone_is_not_a_match(client: TestClient, db: Session) -> None:
    asset = _named_asset(db, _site(db, client), AGENT_IP, "web01")
    # Detección nativa en la misma ventana pero de otro tema y otra técnica.
    _native(db, asset, technique="T1059", category="scripting")
    import_alerts(client, wazuh_source(client, POLICY), alert())
    assert _event(db).attribution["origin"] == "imported"  # type: ignore[index]
    assert len(_signals(db)) == 1


def test_reimport_is_deduplicated(client: TestClient) -> None:
    source = wazuh_source(client)
    record = alert()
    assert import_alerts(client, source, record)["accepted"] == 1
    again = import_alerts(client, source, record, alert(id="1732435200.777777"))
    assert again["accepted"] == 1 and again["duplicates"] == 1


def test_connector_is_read_only_and_documented(client: TestClient) -> None:
    connectors = _ok(client.get(f"{SIEM}/connectors"))["items"]
    [wazuh] = [c for c in connectors if c["source_type"] == "wazuh_alerts"]
    assert "Solo lectura" in wazuh["description"]
    assert "sin validación con un manager de Wazuh real" in wazuh["validation"]
    assert set(wazuh["severity_policy"].values()) == {"unknown"}
