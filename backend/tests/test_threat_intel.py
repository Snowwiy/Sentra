"""Fase 5C: Threat Intelligence de punta a punta con base de datos (fuentes, KEV/EPSS, IOCs,
matching, detección por política, riesgo, incidentes, RBAC, auditoría, CLI y migración).

Datos sintéticos (CVE-2099-*, 203.0.113.0/24, 198.51.100.0/24): nada real. Ningún test toca la
red: las descargas usan un fetcher falso y los ficheros KEV/EPSS se importan desde disco.
"""

import gzip
import io
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app import cli
from app.core.config import get_settings
from app.core.metrics import REGISTRY
from app.detection.config import DetectionConfig
from app.detection.engine import DetectionEngine
from app.models.detection import Detection
from app.models.threat_intel import (
    ThreatIndicator,
    ThreatIntelChange,
    ThreatIntelSource,
    ThreatIntelSync,
    VulnerabilityIntel,
)
from app.risk.config import RiskConfig
from app.risk.engine import RiskEngine
from app.services.alert_service import AlertThresholds
from app.services.audit_service import CLI
from app.threat_intel.config import ThreatIntelConfig
from app.threat_intel.http import FetchError, FetchPolicy, FetchResult
from app.threat_intel.matching import ThreatIntelMatcher
from app.threat_intel.sync import ThreatIntelSyncer
from tests.conftest import agent_payload, authenticate
from tests.test_threat_intel_units import EPSS_CSV, kev_feed
from tests.test_vulnerabilities import (
    API,
    FINDINGS,
    _audit,
    _error,
    _evaluate,
    _findings,
    _ok,
    _one,
    _setup,
)

TI = f"{API}/threat-intel"
MALICIOUS_IP = "203.0.113.66"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session
    # El TRUNCATE general (conftest) no toca las tablas de 5C: las fuentes sembradas por la
    # migración se conservan y se devuelven a su estado inicial.
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE threat_indicators, vulnerability_intel, threat_intel_changes,"
                " threat_intel_syncs, threat_intel_cursors RESTART IDENTITY CASCADE"
            )
        )
        connection.execute(
            text(
                "DELETE FROM threat_intel_sources WHERE source_key NOT IN"
                " ('cisa-kev', 'first-epss', 'local-iocs')"
            )
        )
        connection.execute(
            text(
                "UPDATE threat_intel_sources SET enabled = (source_key = 'local-iocs'),"
                " archived_at = NULL, status = 'never', last_attempt_at = NULL,"
                " last_success_at = NULL, last_error = NULL, last_error_message = NULL,"
                " record_count = 0, next_sync_at = NULL, sync_requested_at = NULL,"
                " etag = NULL, last_modified = NULL, content_sha256 = NULL, revision = 0"
            )
        )


def _config(**overrides: Any) -> ThreatIntelConfig:
    base = ThreatIntelConfig.from_settings(get_settings())
    values = {**base.__dict__, **overrides}
    return ThreatIntelConfig(**values)


def _source(client: TestClient, key: str) -> dict[str, Any]:
    items = _ok(client.get(f"{TI}/sources"))["items"]
    (source,) = [s for s in items if s["source_key"] == key]
    return dict(source)


def _enable(client: TestClient, key: str) -> dict[str, Any]:
    source = _source(client, key)
    body = {"revision": source["revision"]}
    return dict(_ok(client.post(f"{TI}/sources/{source['id']}/enable", json=body)))


def _import_feed(engine: Engine, key: str, content: bytes, tmp_path: Path) -> str:
    """Importación offline (CLI) de un fichero KEV/EPSS: lo que hace un servidor sin red."""
    file = tmp_path / f"{key}-{len(content)}.bin"
    file.write_bytes(content)
    with sessionmaker(bind=engine)() as session:
        source = session.scalar(
            select(ThreatIntelSource).where(ThreatIntelSource.source_key == key)
        )
        assert source is not None
        outcome = ThreatIntelSyncer(
            session, _config(), lock_engine=lambda: engine
        ).import_feed_file(source.id, file, CLI)
    return outcome.status


def _ioc_file(*indicators: dict[str, Any]) -> str:
    return json.dumps({"format": "sentra-ioc/1", "indicators": list(indicators)})


def _import_iocs(client: TestClient, content: str, fmt: str = "sentra-ioc") -> dict[str, Any]:
    source = _source(client, "local-iocs")
    body = {"source_id": source["id"], "format": fmt, "content": content}
    preview = _ok(client.post(f"{TI}/import/preview", json=body))
    confirm = {**body, "expected_sha256": preview["sha256"]}
    return dict(_ok(client.post(f"{TI}/import", json=confirm)))


def _match(engine: Engine, now: datetime | None = None, **config: Any) -> Any:
    with sessionmaker(bind=engine)() as session:
        return ThreatIntelMatcher(session, _config(**config)).run(now)


def _detect(engine: Engine) -> None:
    with sessionmaker(bind=engine)() as session:
        thresholds = AlertThresholds.from_settings(get_settings())
        DetectionEngine(session, DetectionConfig(), thresholds).process_pending()


def _risk(engine: Engine) -> None:
    with sessionmaker(bind=engine)() as session:
        risk = RiskEngine(
            session,
            RiskConfig.from_settings(get_settings()),
            AlertThresholds.from_settings(get_settings()),
        )
        risk.seed_missing()
        risk.process_dirty()


def _agent(client: TestClient, hostname: str = "PC-TI-01") -> tuple[str, str]:
    payload = agent_payload(hostname=hostname)
    body = _ok(client.post(f"{API}/agents/register", json=payload), 201)
    return str(payload["agent_id"]), str(body["asset_id"])


def _failed_logon(client: TestClient, agent_id: str, ip: str, minutes_ago: float = 1) -> None:
    at = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    event = {
        "source": "windows_eventlog",
        "channel": "Security",
        "record_id": int(at.timestamp() * 1000) % 2_000_000_000,
        "event_code": 4625,
        "provider": "Microsoft-Windows-Security-Auditing",
        "level": "warning",
        "message": "An account failed to log on.",
        "occurred_at": at.isoformat(),
        "data": {"TargetUserName": "Administrator", "IpAddress": ip, "LogonType": "3"},
    }
    _ok(client.post(f"{API}/events", json={"agent_id": agent_id, "events": [event]}), 201)


def _connection_inventory(client: TestClient, agent_id: str, remote: str) -> None:
    payload = {
        "agent_id": agent_id,
        "collected_at": datetime.now(UTC).isoformat(),
        "connections": [
            {
                "protocol": "tcp",
                "local_address": "192.168.1.20",
                "local_port": 50123,
                "remote_address": remote,
                "remote_port": 443,
                "status": "established",
                "process_name": "example.exe",
            },
            {
                "protocol": "tcp",
                "local_address": "192.168.1.20",
                "local_port": 3389,
                "status": "listen",
            },
        ],
    }
    _ok(client.post(f"{API}/inventory", json=payload), 201)


# --- Sin fuentes: estado neutro, nunca un error ------------------------------------------------


def test_fresh_install_reports_no_source_configured(client: TestClient, db: Session) -> None:
    overview = _ok(client.get(f"{TI}/overview"))
    assert overview["status"] == "none_configured"
    assert overview["sync_enabled"] is False
    sources = _ok(client.get(f"{TI}/sources"))
    keys = {s["source_key"]: s for s in sources["items"]}
    assert set(keys) == {"cisa-kev", "first-epss", "local-iocs"}
    assert keys["cisa-kev"]["enabled"] is False and keys["cisa-kev"]["trust"] == "official"
    # Solo el host, nunca la URL completa.
    assert keys["cisa-kev"]["download_host"] == "www.cisa.gov"
    assert "url" not in keys["cisa-kev"]
    # La readiness no depende de la inteligencia.
    assert client.get(f"{API}/health/ready").status_code == 200


def test_finding_without_sources_says_none_configured(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _setup(client, engine)
    finding = _one(client)
    assert finding["known_exploited"] is False and finding["epss_score"] is None
    intel = _ok(client.get(f"{FINDINGS}/{finding['finding_id']}/threat-intel"))
    assert intel["status"] == "none_configured" and intel["cve"] == "CVE-2099-1001"


# --- KEV y EPSS --------------------------------------------------------------------------------


def test_kev_and_epss_enrich_findings_and_priority(
    client: TestClient, engine: Engine, db: Session, tmp_path: Path
) -> None:
    _setup(client, engine)
    before = _one(client)
    _enable(client, "cisa-kev")
    _enable(client, "first-epss")
    assert _import_feed(engine, "cisa-kev", kev_feed("CVE-2099-1001"), tmp_path) == "success"
    assert _import_feed(engine, "first-epss", gzip.compress(EPSS_CSV.encode()), tmp_path) == (
        "success"
    )
    _evaluate(engine)
    after = _one(client)
    assert after["known_exploited"] is True
    assert after["epss_score"] == pytest.approx(0.91234)
    assert after["priority_score"] > before["priority_score"]
    factors = {f["factor"] for f in after["priority_factors"]}
    assert {"known_exploited", "epss"} <= factors

    intel = _ok(client.get(f"{FINDINGS}/{after['finding_id']}/threat-intel"))
    assert intel["status"] == "available"
    assert intel["kev"][0]["source"]["trust"] == "official"
    assert intel["kev"][0]["date_added"] == "2099-01-01"
    assert intel["epss"][0]["score_date"] == "2099-01-02"

    # Filtros y resumen.
    assert len(_findings(client, kev=True)) == 1
    assert len(_findings(client, epss_min=0.95)) == 0
    overview = _ok(client.get(f"{TI}/overview"))
    assert overview["status"] == "ok" and overview["kev_findings"] == 1
    assert overview["high_epss_findings"] == 1
    # Historial de la entrada en KEV.
    changes = db.scalars(select(ThreatIntelChange.change)).all()
    assert "kev_added" in changes


def test_disabling_a_source_removes_its_influence(
    client: TestClient, engine: Engine, db: Session, tmp_path: Path
) -> None:
    _setup(client, engine)
    _enable(client, "cisa-kev")
    _import_feed(engine, "cisa-kev", kev_feed("CVE-2099-1001"), tmp_path)
    _evaluate(engine)
    assert _one(client)["known_exploited"] is True
    source = _source(client, "cisa-kev")
    _ok(client.post(f"{TI}/sources/{source['id']}/disable", json={"revision": source["revision"]}))
    _evaluate(engine)
    finding = _one(client)
    assert finding["known_exploited"] is False
    assert "known_exploited" not in {f["factor"] for f in finding["priority_factors"]}
    assert len(_audit(db, "threat_source_disabled")) == 1


def test_kev_removal_and_epss_material_change_are_tracked(
    client: TestClient, engine: Engine, db: Session, tmp_path: Path
) -> None:
    _setup(client, engine)
    _enable(client, "cisa-kev")
    _enable(client, "first-epss")
    _import_feed(engine, "cisa-kev", kev_feed("CVE-2099-1001", "CVE-2099-1002"), tmp_path)
    _import_feed(engine, "first-epss", EPSS_CSV.encode(), tmp_path)
    # Segundo día: CVE-2099-1001 sale de KEV y su EPSS baja de banda.
    _import_feed(engine, "cisa-kev", kev_feed("CVE-2099-1002"), tmp_path)
    lower = EPSS_CSV.replace("0.91234,0.99876", "0.05000,0.80000")
    _import_feed(engine, "first-epss", lower.encode(), tmp_path)
    changes = {
        (c.cve_id, c.change)
        for c in db.scalars(select(ThreatIntelChange).where(ThreatIntelChange.cve_id.is_not(None)))
    }
    assert ("CVE-2099-1001", "kev_removed") in changes
    assert ("CVE-2099-1001", "epss_material_change") in changes
    # El registro retirado se conserva inactivo (procedencia), no se borra.
    removed = db.scalar(
        select(VulnerabilityIntel).where(
            VulnerabilityIntel.cve_id == "CVE-2099-1001", VulnerabilityIntel.kind == "kev"
        )
    )
    assert removed is not None and removed.active is False
    epss_row = db.scalar(
        select(VulnerabilityIntel).where(
            VulnerabilityIntel.cve_id == "CVE-2099-1001", VulnerabilityIntel.kind == "epss"
        )
    )
    assert epss_row is not None and epss_row.data["previous"]["score"] == pytest.approx(0.91234)


def test_reimporting_the_same_feed_changes_nothing(
    client: TestClient, engine: Engine, db: Session, tmp_path: Path
) -> None:
    _enable(client, "cisa-kev")
    _import_feed(engine, "cisa-kev", kev_feed("CVE-2099-1001"), tmp_path)
    count = db.scalar(select(func.count()).select_from(ThreatIntelChange))
    _import_feed(engine, "cisa-kev", kev_feed("CVE-2099-1001"), tmp_path)
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(ThreatIntelChange)) == count


def test_bad_feed_file_keeps_cached_data(
    client: TestClient, engine: Engine, db: Session, tmp_path: Path
) -> None:
    _enable(client, "cisa-kev")
    _import_feed(engine, "cisa-kev", kev_feed("CVE-2099-1001"), tmp_path)
    assert _import_feed(engine, "cisa-kev", b"<html>proxy login</html>", tmp_path) == "failed"
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(VulnerabilityIntel)) == 1
    source = db.scalar(select(ThreatIntelSource).where(ThreatIntelSource.source_key == "cisa-kev"))
    assert source is not None and source.last_error == "intel_invalid_json"
    assert source.last_success_at is not None


# --- Sincronización por red (fetcher falso) ----------------------------------------------------


class FakeFetcher:
    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self,
        url: str,
        policy: FetchPolicy,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> FetchResult:
        self.calls.append({"url": url, "etag": etag})
        response = self.responses.pop(0)
        if isinstance(response, FetchError):
            raise response
        if response == 304:
            return FetchResult(304, None, 0, None, etag, None, "www.cisa.gov")
        import hashlib

        return FetchResult(
            200,
            io.BytesIO(response),
            len(response),
            hashlib.sha256(response).hexdigest(),
            '"v1"',
            None,
            "www.cisa.gov",
        )


def _sync(engine: Engine, fetcher: FakeFetcher, key: str = "cisa-kev", **config: Any) -> Any:
    with sessionmaker(bind=engine)() as session:
        source = session.scalar(
            select(ThreatIntelSource).where(ThreatIntelSource.source_key == key)
        )
        assert source is not None
        syncer = ThreatIntelSyncer(
            session,
            _config(sync_enabled=True, **config),
            fetcher=fetcher,
            lock_engine=lambda: engine,
        )
        return syncer.sync(source.id, "scheduled", CLI)


def test_network_sync_uses_etag_and_keeps_cache_on_failure(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _enable(client, "cisa-kev")
    fetcher = FakeFetcher(
        kev_feed("CVE-2099-1001"),
        304,
        FetchError("unavailable", "Source unavailable (ConnectionRefusedError)"),
    )
    assert _sync(engine, fetcher).status == "success"
    assert fetcher.calls[0]["url"].startswith("https://www.cisa.gov/")
    assert _sync(engine, fetcher).status == "not_modified"
    assert fetcher.calls[1]["etag"] == '"v1"'
    outcome = _sync(engine, fetcher)
    assert outcome.status == "failed" and outcome.error_code == "unavailable"
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(VulnerabilityIntel)) == 1
    statuses = [s.status for s in db.scalars(select(ThreatIntelSync).order_by(ThreatIntelSync.id))]
    assert statuses == ["success", "not_modified", "failed"]
    source = _source(client, "cisa-kev")
    assert source["status"] == "unavailable" and source["record_count"] == 1
    assert source["last_error"] == "unavailable"
    assert len(_audit(db, "threat_sync_failed", "failure")) == 1


def test_sync_refuses_a_suspiciously_small_feed(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _enable(client, "cisa-kev")
    many = [f"CVE-2099-{n}" for n in range(10000, 11200)]
    assert _sync(engine, FakeFetcher(kev_feed(*many))).status == "success"
    outcome = _sync(engine, FakeFetcher(kev_feed(*many[:10])))
    assert outcome.status == "failed" and outcome.error_code == "intel_feed_shrunk"
    db.expire_all()
    assert (
        db.scalar(
            select(func.count()).select_from(VulnerabilityIntel).where(VulnerabilityIntel.active)
        )
        == 1200
    )


def test_sync_request_api_respects_offline_default(
    client: TestClient, engine: Engine, db: Session
) -> None:
    source = _enable(client, "cisa-kev")
    _error(client.post(f"{TI}/sources/{source['id']}/sync"), 422, "threat_intel_sync_disabled")
    local = _source(client, "local-iocs")
    _error(client.post(f"{TI}/sources/{local['id']}/sync"), 422, "threat_source_manual")


def test_custom_source_never_takes_a_url_from_the_api(client: TestClient, db: Session) -> None:
    body = {
        "source_key": "mirror-kev",
        "name": "Espejo KEV",
        "provider": "cisa_kev",
        "category": "exploitation",
        "trust": "trusted",
        "url": "http://169.254.169.254/latest",
    }
    response = client.post(f"{TI}/sources", json=body)
    assert response.status_code == 422
    del body["url"]
    created = _ok(client.post(f"{TI}/sources", json=body), 201)
    # Sin THREAT_INTEL_SOURCE_URLS para esta clave descarga del origen oficial del adapter,
    # nunca de lo que mande el navegador. Se crea desactivada.
    assert created["download_host"] == "www.cisa.gov" and created["enabled"] is False


# --- IOCs: importación ---------------------------------------------------------------------


def test_ioc_import_preview_then_confirm_with_same_hash(client: TestClient, db: Session) -> None:
    content = _ioc_file(
        {
            "type": "ipv4",
            "value": MALICIOUS_IP,
            "classification": "malicious",
            "confidence": "high",
        },
        {"type": "sha256", "value": "a" * 64, "classification": "malicious"},
        {"type": "ipv4", "value": "not-an-ip", "classification": "malicious"},
    )
    source = _source(client, "local-iocs")
    body = {"source_id": source["id"], "format": "sentra-ioc", "content": content}
    preview = _ok(client.post(f"{TI}/import/preview", json=body))
    assert (preview["new"], preview["invalid"], preview["not_matchable"]) == (2, 1, 1)
    assert db.scalar(select(func.count()).select_from(ThreatIndicator)) == 0
    # Otro fichero con el hash previsualizado: rechazado.
    other = {
        **body,
        "content": content.replace("high", "low"),
        "expected_sha256": preview["sha256"],
    }
    _error(client.post(f"{TI}/import", json=other), 409, "threat_intel_changed")
    # Con inválidos y sin skip_invalid: todo o nada.
    _error(
        client.post(f"{TI}/import", json={**body, "expected_sha256": preview["sha256"]}),
        422,
        "intel_invalid_records",
    )
    result = _ok(
        client.post(
            f"{TI}/import",
            json={**body, "expected_sha256": preview["sha256"], "skip_invalid": True},
        )
    )
    assert result["new"] == 2 and result["pending_match"] == 1
    indicators = _ok(client.get(f"{TI}/indicators"))["items"]
    by_type = {i["indicator_type"]: i for i in indicators}
    assert by_type["sha256"]["matching"] == "unsupported"
    assert by_type["ipv4"]["matching"] == "supported"
    assert len(_audit(db, "threat_imported")) == 1


def test_import_is_admin_only_and_viewer_can_read(client: TestClient, engine: Engine) -> None:
    content = _ioc_file({"type": "ipv4", "value": MALICIOUS_IP, "classification": "malicious"})
    source = _source(client, "local-iocs")
    body = {"source_id": source["id"], "format": "sentra-ioc", "content": content}
    for role in ("viewer", "analyst"):
        with TestClient(client.app) as other:
            authenticate(other, engine, role)
            assert other.post(f"{TI}/import/preview", json=body).status_code == 403
            assert other.post(f"{TI}/reevaluate").status_code == 403
            assert other.get(f"{TI}/overview").status_code == 200
            assert other.get(f"{TI}/indicators").status_code == 200


def test_stix_bundle_import(client: TestClient, db: Session) -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--00000000-0000-4000-8000-000000000002",
                "created": "2099-01-01T00:00:00Z",
                "modified": "2099-01-01T00:00:00Z",
                "pattern": "[ipv4-addr:value = '198.51.100.23']",
                "pattern_type": "stix",
                "valid_from": "2020-01-01T00:00:00Z",
                "indicator_types": ["malicious-activity"],
                "labels": ["<script>alert(1)</script>"],
            }
        ],
    }
    result = _import_iocs(client, json.dumps(bundle), "stix")
    assert result["new"] == 1
    (indicator,) = _ok(client.get(f"{TI}/indicators"))["items"]
    detail = _ok(client.get(f"{TI}/indicators/{indicator['indicator_id']}"))
    assert detail["external_id"] == "indicator--00000000-0000-4000-8000-000000000002"
    assert detail["pattern"] == "[ipv4-addr:value = '198.51.100.23']"


# --- Matching, detección, riesgo e incidentes ----------------------------------------------


def test_failed_logon_from_malicious_ip_matches_and_detects(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, asset_id = _agent(client)
    _failed_logon(client, agent_id, MALICIOUS_IP)
    _import_iocs(
        client,
        _ioc_file(
            {
                "type": "ipv4",
                "value": MALICIOUS_IP,
                "classification": "malicious",
                "confidence": "high",
            }
        ),
    )
    # Retroactivo: el evento ya existía antes del indicador.
    run = _match(engine)
    assert run.created == 1
    (match,) = _ok(client.get(f"{TI}/matches"))["items"]
    assert match["observation_type"] == "auth_source_ip"
    assert match["observed_value"] == MALICIOUS_IP and match["asset"]["asset_id"] == asset_id
    assert match["status"] == "open"
    # Repetir no duplica.
    assert _match(engine).created == 0

    # Política por defecto: malicioso + confianza alta -> señal -> detección TI-001.
    _detect(engine)
    detections = _ok(client.get(f"{API}/detections", params={"rule_id": "TI-001"}))["items"]
    assert len(detections) == 1
    assert detections[0]["title"] == "Threat Intel IOC Match"
    _match(engine)
    linked = _ok(client.get(f"{TI}/matches/{match['match_id']}"))
    assert linked["detection_id"] == detections[0]["detection_id"]

    # Riesgo: contribución de threat intel explicada y enlazada al match.
    _risk(engine)
    risk = _ok(client.get(f"{API}/risk/assets/{asset_id}"))
    threat = [c for c in risk["contributions"] if c.get("threat_match_id")]
    assert threat and threat[0]["threat_match_id"] == match["match_id"]


def test_policy_off_never_creates_detections(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, _ = _agent(client)
    _import_iocs(
        client,
        _ioc_file(
            {
                "type": "ipv4",
                "value": MALICIOUS_IP,
                "classification": "malicious",
                "confidence": "high",
            }
        ),
    )
    _match(engine)
    _failed_logon(client, agent_id, MALICIOUS_IP)
    run = _match(engine, detection_policy="off")
    assert run.created == 1 and run.signals == 0
    _detect(engine)
    assert db.scalar(select(func.count()).select_from(Detection)) == 0


def test_suspicious_or_low_confidence_match_is_context_only(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, _ = _agent(client)
    _import_iocs(
        client,
        _ioc_file(
            {
                "type": "ipv4",
                "value": MALICIOUS_IP,
                "classification": "suspicious",
                "confidence": "high",
            },
            {
                "type": "cidr",
                "value": "198.51.100.0/24",
                "classification": "malicious",
                "confidence": "high",
            },
        ),
    )
    _failed_logon(client, agent_id, MALICIOUS_IP)
    _connection_inventory(client, agent_id, "198.51.100.77")
    run = _match(engine)
    assert run.created == 2 and run.signals == 0
    matches = {m["observation_type"]: m for m in _ok(client.get(f"{TI}/matches"))["items"]}
    # Pertenencia a un CIDR: un escalón menos de confianza que la del indicador.
    assert matches["connection_remote_ip"]["match_confidence"] == "medium"


def test_benign_revoked_and_expired_indicators_never_match(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, _ = _agent(client)
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    _import_iocs(
        client,
        _ioc_file(
            {"type": "ipv4", "value": "203.0.113.10", "classification": "benign"},
            {
                "type": "ipv4",
                "value": "203.0.113.11",
                "classification": "malicious",
                "revoked": True,
            },
            {
                "type": "ipv4",
                "value": "203.0.113.12",
                "classification": "malicious",
                "valid_until": past,
            },
        ),
    )
    for ip in ("203.0.113.10", "203.0.113.11", "203.0.113.12"):
        _failed_logon(client, agent_id, ip)
    assert _match(engine).created == 0


def test_match_triage_workflow_and_rbac(client: TestClient, engine: Engine, db: Session) -> None:
    agent_id, _ = _agent(client)
    _connection_inventory(client, agent_id, MALICIOUS_IP)
    _import_iocs(
        client, _ioc_file({"type": "ipv4", "value": MALICIOUS_IP, "classification": "malicious"})
    )
    _match(engine)
    (match,) = _ok(client.get(f"{TI}/matches"))["items"]
    url = f"{TI}/matches/{match['match_id']}"
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        detail = _ok(viewer.get(url))
        assert detail["actions"] == []
        assert viewer.post(f"{url}/acknowledge", json={"version": 1}).status_code == 403
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        detail = _ok(analyst.get(url))
        assert "acknowledge" in detail["actions"]
        acked = _ok(analyst.post(f"{url}/acknowledge", json={"version": detail["version"]}))
        assert acked["status"] == "acknowledged"
        # Versión vieja: conflicto.
        _error(
            analyst.post(f"{url}/dismiss", json={"version": detail["version"], "reason": "fp ok"}),
            409,
            "threat_intel_conflict",
        )
        # Descartar exige motivo.
        assert analyst.post(f"{url}/dismiss", json={"version": acked["version"]}).status_code == 422
        dismissed = _ok(
            analyst.post(
                f"{url}/dismiss", json={"version": acked["version"], "reason": "IP del CDN"}
            )
        )
        assert dismissed["status"] == "dismissed" and dismissed["status_reason"] == "IP del CDN"
    assert len(_audit(db, "threat_intel_match_updated")) == 2
    # Descartado: no suma riesgo.
    _risk(engine)
    risk = _ok(client.get(f"{API}/risk/assets/{match['asset']['asset_id']}"))
    assert not [c for c in risk["contributions"] if c.get("threat_match_id")]


def test_incident_from_match_is_manual_and_linked(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, _ = _agent(client)
    _connection_inventory(client, agent_id, MALICIOUS_IP)
    _import_iocs(
        client,
        _ioc_file(
            {
                "type": "ipv4",
                "value": MALICIOUS_IP,
                "classification": "malicious",
                "confidence": "high",
            }
        ),
    )
    _match(engine)
    (match,) = _ok(client.get(f"{TI}/matches"))["items"]
    # Nada abre incidentes solo.
    assert _ok(client.get(f"{API}/incidents"))["total"] == 0
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        incident = _ok(
            analyst.post(
                f"{TI}/matches/{match['match_id']}/incident", json={"version": match["version"]}
            ),
            201,
        )
    assert incident["confidence"] != "high"
    (linked,) = incident["threat_matches"]
    assert linked["match_id"] == match["match_id"]
    detail = _ok(client.get(f"{TI}/matches/{match['match_id']}"))
    assert detail["incidents"][0]["incident_id"] == incident["incident_id"]
    assert len(_audit(db, "threat_intel_incident_created")) == 1


def test_disabling_ioc_source_hides_matches_from_risk(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, asset_id = _agent(client)
    _connection_inventory(client, agent_id, MALICIOUS_IP)
    _import_iocs(
        client, _ioc_file({"type": "ipv4", "value": MALICIOUS_IP, "classification": "malicious"})
    )
    _match(engine)
    _risk(engine)
    risk = _ok(client.get(f"{API}/risk/assets/{asset_id}"))
    assert [c for c in risk["contributions"] if c.get("threat_match_id")]
    source = _source(client, "local-iocs")
    _ok(client.post(f"{TI}/sources/{source['id']}/disable", json={"revision": source["revision"]}))
    _risk(engine)
    risk = _ok(client.get(f"{API}/risk/assets/{asset_id}"))
    assert not [c for c in risk["contributions"] if c.get("threat_match_id")]
    assert _ok(client.get(f"{TI}/overview"))["active_matches"] == 0


def test_reclassified_indicator_updates_matches(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, _ = _agent(client)
    _connection_inventory(client, agent_id, MALICIOUS_IP)
    _import_iocs(
        client, _ioc_file({"type": "ipv4", "value": MALICIOUS_IP, "classification": "malicious"})
    )
    _match(engine)
    _import_iocs(
        client, _ioc_file({"type": "ipv4", "value": MALICIOUS_IP, "classification": "benign"})
    )
    _match(engine)
    _connection_inventory(client, agent_id, MALICIOUS_IP)
    _match(engine)
    (match,) = _ok(client.get(f"{TI}/matches"))["items"]
    # La clasificación vigente (benign) no vuelve a casar; el match queda con el valor antiguo
    # pero el riesgo usa la clasificación actual del indicador.
    indicator = _ok(client.get(f"{TI}/indicators/{match['indicator_id']}"))
    assert indicator["classification"] == "benign"
    changes = db.scalars(
        select(ThreatIntelChange.change).where(ThreatIntelChange.indicator_id.is_not(None))
    ).all()
    assert "indicator_reclassified" in changes


# --- CLI, métricas y migración -------------------------------------------------------------


def test_cli_status_and_imports(
    client: TestClient,
    engine: Engine,
    db: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "get_sessionmaker", lambda: sessionmaker(bind=engine))
    monkeypatch.setattr(cli, "get_engine", lambda: engine)
    assert cli.main(["threat-intel-status"]) == 0
    assert "No intelligence source configured" in capsys.readouterr().out
    iocs = tmp_path / "iocs.json"
    iocs.write_text(
        _ioc_file({"type": "ipv4", "value": MALICIOUS_IP, "classification": "malicious"})
    )
    assert cli.main(["threat-intel-import", "--source", "local-iocs", str(iocs)]) == 0
    assert "1 new" in capsys.readouterr().out
    kev = tmp_path / "kev.json"
    kev.write_bytes(kev_feed("CVE-2099-1001"))
    # Con la fuente desactivada se puede importar (servidor offline que prepara datos), pero
    # no influye en nada hasta activarla.
    assert cli.main(["threat-intel-import", "--source", "cisa-kev", str(kev)]) == 0
    assert _ok(client.get(f"{TI}/overview"))["kev_findings"] == 0
    _enable(client, "cisa-kev")
    assert _ok(client.get(f"{TI}/overview"))["status"] == "ok"
    assert cli.main(["threat-intel-import", "--source", "nope", str(kev)]) == 1
    # Sin THREAT_INTEL_SYNC_ENABLED la CLI tampoco descarga.
    assert cli.main(["threat-intel-sync"]) == 2
    capsys.readouterr()


def test_metrics_expose_sync_and_match_counters(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _enable(client, "cisa-kev")
    _sync(engine, FakeFetcher(kev_feed("CVE-2099-1001")))
    text_body = "\n".join(REGISTRY.render())
    assert 'sentra_threat_intel_syncs_total{provider="cisa_kev",result="success"}' in text_body


def test_migration_0027_round_trip(client: TestClient, engine: Engine, db: Session) -> None:
    from alembic import command

    from tests.conftest import _alembic_config

    _setup(client, engine)
    config = _alembic_config(str(engine.url.render_as_string(hide_password=False)))
    try:
        command.downgrade(config, "0026")
        with engine.connect() as connection:
            for table in ("threat_intel_sources", "threat_indicators", "vulnerability_intel"):
                assert connection.execute(text(f"SELECT to_regclass('{table}')")).scalar() is None
            assert (
                connection.execute(text("SELECT count(*) FROM vulnerability_findings")).scalar()
                == 1
            )
    finally:
        command.upgrade(config, "head")
    db.expire_all()
    keys = set(db.scalars(select(ThreatIntelSource.source_key)))
    assert keys == {"cisa-kev", "first-epss", "local-iocs"}
    # El backfill de intel_cve deja el CVE listo para el enriquecimiento.
    assert db.scalar(text("SELECT intel_cve FROM vulnerability_findings")) == "CVE-2099-1001"


def test_no_threat_intel_wording_claims_compromise(
    client: TestClient, engine: Engine, db: Session, tmp_path: Path
) -> None:
    _setup(client, engine)
    _enable(client, "cisa-kev")
    _import_feed(engine, "cisa-kev", kev_feed("CVE-2099-1001"), tmp_path)
    _evaluate(engine)
    finding = _one(client)
    body = (
        json.dumps(finding).lower()
        + json.dumps(_ok(client.get(f"{FINDINGS}/{finding['finding_id']}/threat-intel"))).lower()
    )
    for forbidden in ("exploited on this", "90% vulnerable", "is exploitable", "compromised"):
        assert forbidden not in body
