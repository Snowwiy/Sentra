"""Vulnerability & Exposure Management (Fase 5B) de extremo a extremo.

Ingesta real del agente -> cola -> motor -> findings -> API, flujo de trabajo, Risk 4I,
incidentes 4K, alertas y migración. Catálogos sintéticos (identificadores CVE-2099-*,
productos de ejemplo): nada de esto describe una vulnerabilidad real.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.alert import Alert, AlertRule, AlertStatus
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.exposure import AssetPort, PortStateValue
from app.models.vulnerability import (
    AssetVulnerabilityState,
    Vulnerability,
    VulnerabilityFinding,
)
from app.risk.config import FORMULA_VERSION
from app.services.alert_service import AlertThresholds
from app.vulnerabilities import queue
from app.vulnerabilities.catalog import FORMAT
from app.vulnerabilities.engine import VulnerabilityConfig, VulnerabilityEngine, VulnerabilityRun
from tests.conftest import agent_payload, authenticate
from tests.test_risk import _risk

API = "/api/v1"
VULNS = f"{API}/vulnerabilities"
FINDINGS = f"{VULNS}/findings"
WINDOWS_VERSION = "11 (build 10.0.26200)"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


# --- Ayudantes ---------------------------------------------------------------------------------


def _ok(response: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return response.json()


def _error(response: Any, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()["error"]
    assert body["code"] == code, body
    return body


def _record(
    vuln_id: str = "CVE-2099-1001",
    *,
    severity: str = "high",
    ranges: list[dict[str, str]] | None = None,
    ports: list[int] | None = None,
    publishers: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "id": vuln_id,
        "title": f"Example issue {vuln_id} in ExampleApp",
        "description": "Synthetic record used by the Sentra test suite.",
        "severity": severity,
        "cvss": {"version": "3.1", "score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"},
        "references": ["https://example.org/advisories/" + vuln_id],
        "remediation": "Update ExampleApp to 2.5.0 or later.",
        "affected": [
            {
                "product": "ExampleApp",
                "vendor": "Example Corp",
                "names": ["ExampleApp"],
                "publishers": ["Example Corp"] if publishers is None else publishers,
                "ranges": ranges or [{"lt": "2.5.0"}],
                "fixed_version": "2.5.0",
                "service_ports": ports or [],
                "platforms": ["windows"],
            }
        ],
        **extra,
    }


def _catalog(*records: dict[str, Any], source: str = "test-catalog") -> str:
    return json.dumps(
        {
            "format": FORMAT,
            "source": {"id": source, "name": "Test catalog", "version": "2099.1"},
            "vulnerabilities": list(records),
        }
    )


def _import(client: TestClient, content: str, *, skip_invalid: bool = False) -> dict[str, Any]:
    preview = _ok(client.post(f"{VULNS}/catalog/preview", json={"content": content}))
    body = {"content": content, "expected_sha256": preview["sha256"], "skip_invalid": skip_invalid}
    result: dict[str, Any] = _ok(client.post(f"{VULNS}/catalog/import", json=body))
    return result


def _agent(
    client: TestClient, hostname: str = "PC-VULN-01", os_version: str = WINDOWS_VERSION
) -> tuple[str, str]:
    payload = agent_payload(hostname=hostname, os_name="Windows", os_version=os_version)
    body = _ok(client.post(f"{API}/agents/register", json=payload), 201)
    return str(payload["agent_id"]), str(body["asset_id"])


def _app(version: str | None = "2.4.1", publisher: str | None = "Example Corp") -> dict[str, Any]:
    return {"name": "ExampleApp (64-bit)", "version": version, "publisher": publisher}


def _inventory(
    client: TestClient,
    agent_id: str,
    software: list[dict[str, Any]],
    *,
    minutes_ago: float = 0,
    **extra: Any,
) -> None:
    payload: dict[str, Any] = {
        "agent_id": agent_id,
        "collected_at": (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat(),
        "software": software,
        "software_source": "windows_registry",
        "incomplete_sections": [],
        **extra,
    }
    _ok(client.post(f"{API}/inventory", json=payload), 201)


def _evaluate(engine: Engine, now: datetime | None = None) -> VulnerabilityRun:
    settings = get_settings()
    with sessionmaker(bind=engine)() as session:
        vuln_engine = VulnerabilityEngine(
            session,
            VulnerabilityConfig.from_settings(settings),
            AlertThresholds.from_settings(settings),
        )
        vuln_engine.seed_missing()
        return vuln_engine.process_dirty(now)


def _findings(client: TestClient, **params: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = _ok(client.get(FINDINGS, params={"limit": 200, **params}))[
        "items"
    ]
    return items


def _one(client: TestClient, **params: Any) -> dict[str, Any]:
    (finding,) = _findings(client, **params)
    detail: dict[str, Any] = _ok(client.get(f"{FINDINGS}/{finding['finding_id']}"))
    return detail


def _act(client: TestClient, finding: dict[str, Any], action: str, **body: Any) -> Any:
    return client.post(
        f"{FINDINGS}/{finding['finding_id']}/{action}",
        json={"version": finding["version"], **body},
    )


def _audit(db: Session, action: str, result: str = "success") -> list[AuditEvent]:
    db.expire_all()
    return list(
        db.scalars(
            select(AuditEvent).where(AuditEvent.action == action, AuditEvent.result == result)
        )
    )


def _vuln_alerts(db: Session) -> list[Alert]:
    db.expire_all()
    return list(
        db.scalars(
            select(Alert).where(
                Alert.rule == AlertRule.VULNERABILITY, Alert.status != AlertStatus.RESOLVED
            )
        )
    )


def _open_port(db: Session, asset_public_id: str, port: int) -> None:
    asset = db.scalar(select(Asset).where(Asset.public_id == asset_public_id))
    assert asset is not None
    now = datetime.now(UTC)
    db.add(
        AssetPort(
            asset_id=asset.id,
            protocol="tcp",
            port=port,
            state=PortStateValue.OPEN,
            first_seen_at=now,
            opened_at=now,
            last_seen_at=now,
            misses=0,
        )
    )
    db.commit()


def _setup(client: TestClient, engine: Engine, **record: Any) -> tuple[str, str]:
    """Activo Windows con ExampleApp 2.4.1, catálogo importado y evaluación hecha."""
    agent_id, asset_id = _agent(client)
    _inventory(client, agent_id, [_app()])
    _import(client, _catalog(_record(**record)))
    _evaluate(engine)
    return agent_id, asset_id


# --- Catálogo: previsualización, importación y auditoría ---------------------------------------


def test_preview_changes_nothing_and_import_is_audited(
    client: TestClient, engine: Engine, db: Session
) -> None:
    bad = _record("CVE-2099-1003", references=["javascript:alert(1)"])
    content = _catalog(_record(), _record("CVE-2099-1002", severity="critical"), bad)
    preview = _ok(client.post(f"{VULNS}/catalog/preview", json={"content": content}))
    assert (preview["total"], preview["valid"], preview["new"], preview["invalid"]) == (3, 2, 2, 1)
    assert preview["invalid_records"][0]["code"] == "invalid_reference"
    assert preview["existing_source"] is False
    # La previsualización no escribe nada.
    assert db.scalar(select(func.count()).select_from(Vulnerability)) == 0

    body = {"content": content, "expected_sha256": preview["sha256"]}
    _error(client.post(f"{VULNS}/catalog/import", json=body), 422, "catalog_invalid_records")
    other = {"content": _catalog(_record()), "expected_sha256": preview["sha256"]}
    _error(client.post(f"{VULNS}/catalog/import", json=other), 409, "catalog_changed")

    # Los intentos rechazados quedan auditados como fallo.
    assert len(_audit(db, "vulnerability_catalog_imported", "failure")) == 2
    result = _import(client, content, skip_invalid=True)
    assert (result["new"], result["updated"], result["invalid"]) == (2, 0, 1)
    (event,) = _audit(db, "vulnerability_catalog_imported")
    assert event.details is not None and event.details["new"] == 2
    assert event.details["sha256"] == preview["sha256"]

    again = _import(client, content, skip_invalid=True)
    assert (again["new"], again["updated"], again["unchanged"]) == (0, 0, 2)
    assert len(_audit(db, "vulnerability_catalog_updated")) == 1
    catalog = _ok(client.get(f"{VULNS}/catalog", params={"q": "CVE-2099-100"}))
    assert catalog["total"] == 2 and catalog["sources"][0]["source"] == "test-catalog"


def test_catalog_import_requires_admin(client: TestClient, engine: Engine) -> None:
    content = _catalog(_record())
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        response = analyst.post(f"{VULNS}/catalog/preview", json={"content": content})
        _error(response, 403, "permission_denied")
        assert analyst.get(f"{VULNS}/catalog").status_code == 200


def test_oversized_or_hostile_catalogs_are_rejected(client: TestClient) -> None:
    deep = '{"a":' * 40 + "1" + "}" * 40
    response = client.post(f"{VULNS}/catalog/preview", json={"content": deep})
    _error(response, 422, "catalog_too_deep")
    response = client.post(f"{VULNS}/catalog/preview", json={"content": "[1, 2"})
    _error(response, 422, "catalog_invalid_json")


# --- Inventario -> finding ---------------------------------------------------------------------


def test_inventory_to_finding_with_evidence_and_rationale(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _, asset_id = _setup(client, engine)
    finding = _one(client)
    assert finding["vulnerability_id"] == "CVE-2099-1001"
    assert finding["asset"]["asset_id"] == asset_id
    assert (finding["match_state"], finding["confidence"], finding["status"]) == (
        "confirmed",
        "high",
        "open",
    )
    assert finding["installed_version"] == "2.4.1" and finding["fixed_version"] == "2.5.0"
    assert "2.4.1" in finding["rationale"] and "< 2.5.0" in finding["rationale"]
    evidence = finding["evidence"]
    assert evidence["source"] == "agent_inventory"
    assert evidence["component"]["publisher"] == "Example Corp"
    # Nunca el inventario completo: solo el componente afectado.
    assert "software" not in evidence
    assert finding["catalog"]["references"] == ["https://example.org/advisories/CVE-2099-1001"]
    assert finding["actions"] == ["acknowledge", "mitigating", "resolve", "accept-risk",
                                  "false-positive", "incident"]  # fmt: skip
    history = _ok(client.get(f"{FINDINGS}/{finding['finding_id']}/history"))["items"]
    assert [h["action"] for h in history] == ["created"]

    asset = _ok(client.get(f"{API}/assets/{asset_id}/vulnerabilities"))
    assert asset["total"] == 1 and asset["by_severity"]["high"] == 1
    assert asset["status"]["inventory_complete"] is True
    assert "windows_build_without_patch_revision" in asset["status"]["limitations"]

    overview = _ok(client.get(f"{VULNS}/overview"))
    assert overview["confirmed"] == 1 and overview["assets_affected"] == 1
    assert overview["catalog_records"] == 1


def test_potential_findings_are_never_counted_as_confirmed(
    client: TestClient, engine: Engine
) -> None:
    agent_id, _ = _agent(client)
    _inventory(client, agent_id, [_app("2.5.0-custom")])
    _import(client, _catalog(_record(severity="critical")))
    _evaluate(engine)
    finding = _one(client)
    assert finding["match_state"] == "potential" and finding["confidence"] == "low"
    overview = _ok(client.get(f"{VULNS}/overview"))
    assert overview["confirmed"] == overview["probable"] == 0
    assert overview["potential"] == 1 and overview["by_severity"]["critical"] == 0
    assert overview["assets_affected"] == 0
    dashboard = _ok(client.get(f"{API}/dashboard/summary"))
    assert dashboard["vulnerabilities"]["potential"] == 1
    assert dashboard["vulnerabilities"]["by_severity"]["critical"] == 0


def test_other_publisher_or_fixed_version_produces_no_finding(
    client: TestClient, engine: Engine
) -> None:
    agent_id, _ = _agent(client)
    _inventory(client, agent_id, [_app("2.4.1", "Someone Else Ltd"), _app("2.6.0")])
    _import(client, _catalog(_record()))
    _evaluate(engine)
    assert _findings(client) == []


def test_open_port_alone_is_exposure_not_vulnerability(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, asset_id = _agent(client)
    _inventory(client, agent_id, [])
    _open_port(db, asset_id, 3389)
    _import(client, _catalog(_record(ports=[3389])))
    _evaluate(engine)
    assert _findings(client) == []
    exposure = _ok(client.get(f"{VULNS}/exposure", params={"asset_id": asset_id}))
    (item,) = exposure["items"]
    assert item["port"] == 3389 and item["vulnerabilities"] == []


# --- Exposición, prioridad y alertas -----------------------------------------------------------


def test_observed_service_raises_priority_and_alerts_once(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, asset_id = _agent(client)
    _inventory(client, agent_id, [_app()])
    _open_port(db, asset_id, 8443)
    _import(client, _catalog(_record(ports=[8443])))
    _evaluate(engine)
    finding = _one(client)
    assert finding["exposure_state"] == "observed"
    assert "observed_from_sentra_sensor" in finding["exposure"]["labels"]
    assert "internet_exposure_unknown" in finding["exposure"]["labels"]
    factors = {f["factor"] for f in finding["priority_factors"]}
    assert {"severity", "exposure"} <= factors
    (alert,) = _vuln_alerts(db)
    assert "CVE-2099-1001" in alert.message
    assert alert.details is not None and alert.details["finding_id"] == finding["finding_id"]

    # Misma evidencia otra vez: sin alerta nueva (cooldown y una alerta por activo).
    _inventory(client, agent_id, [_app(), {"name": "Other", "version": "1.0"}])
    _evaluate(engine)
    assert len(_vuln_alerts(db)) == 1

    exposure = _ok(client.get(f"{VULNS}/exposure", params={"with_vulnerabilities": True}))
    (item,) = exposure["items"]
    assert item["vulnerabilities"][0]["vulnerability_id"] == "CVE-2099-1001"


def test_high_without_exposure_and_potential_never_alert(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, _ = _agent(client)
    _inventory(client, agent_id, [_app(), {"name": "Tool", "version": "9.0-custom"}])
    tool = _record("CVE-2099-2002", severity="critical", ranges=[{"lt": "9.0"}], publishers=[])
    tool["affected"][0].update(product="Tool", names=["Tool"], vendor=None)
    _import(client, _catalog(_record(), tool))
    _evaluate(engine)
    states = {f["vulnerability_id"]: f["match_state"] for f in _findings(client)}
    assert states == {"CVE-2099-1001": "confirmed", "CVE-2099-2002": "potential"}
    assert _vuln_alerts(db) == []


def test_critical_confirmed_alert_resolves_when_fixed(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, _ = _setup(client, engine, severity="critical")
    assert len(_vuln_alerts(db)) == 1
    _inventory(client, agent_id, [_app("2.5.0")])
    _evaluate(engine)
    assert _vuln_alerts(db) == []


# --- Ciclo de vida: corrección, reaparición, inventario parcial --------------------------------


def test_upgrade_resolves_and_downgrade_reopens(client: TestClient, engine: Engine) -> None:
    agent_id, _ = _setup(client, engine)
    _inventory(client, agent_id, [_app("2.5.0")])
    run = _evaluate(engine)
    assert run.resolved == 1
    finding = _one(client)
    assert finding["status"] == "resolved"
    assert finding["resolution"] == "resolved_by_inventory_change"
    assert finding["match_state"] == "not_affected"

    _inventory(client, agent_id, [_app("2.4.0")])
    run = _evaluate(engine)
    assert run.reopened == 1
    finding = _one(client)
    assert (finding["status"], finding["reopen_count"]) == ("open", 1)
    assert finding["installed_version"] == "2.4.0"
    actions = [h["action"] for h in _ok(client.get(
        f"{FINDINGS}/{finding['finding_id']}/history"))["items"]]  # fmt: skip
    assert {"created", "resolved", "reopened", "version_changed"} <= set(actions)


def test_partial_or_old_agent_inventory_never_resolves(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, _ = _setup(client, engine)
    # Sección de software fallida: lista vacía pero marcada incompleta.
    _inventory(client, agent_id, [], incomplete_sections=["software"])
    _evaluate(engine)
    assert _one(client)["status"] == "open"
    # Agente anterior a 5B: no declara completitud; una lista vacía no prueba nada.
    payload = {"agent_id": agent_id, "collected_at": datetime.now(UTC).isoformat(), "software": []}
    _ok(client.post(f"{API}/inventory", json=payload), 201)
    _evaluate(engine)
    finding = _one(client)
    assert finding["status"] == "open" and finding["missing_count"] == 0


def test_removal_needs_consecutive_complete_inventories(client: TestClient, engine: Engine) -> None:
    agent_id, _ = _setup(client, engine)
    _inventory(client, agent_id, [{"name": "Other", "version": "1.0"}])
    _evaluate(engine)
    finding = _one(client)
    assert finding["status"] == "open" and finding["missing_count"] == 1
    _inventory(client, agent_id, [{"name": "Other", "version": "1.1"}])
    _evaluate(engine)
    finding = _one(client)
    assert finding["status"] == "resolved"
    assert finding["resolution"] == "resolved_by_component_removal"


def test_offline_asset_is_stale_not_resolved(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _setup(client, engine)
    db.execute(
        update(VulnerabilityFinding).values(
            inventory_observed_at=datetime.now(UTC) - timedelta(days=10)
        )
    )
    db.commit()
    (item,) = _findings(client, stale=True)
    assert item["stale"] is True and item["status"] == "open"
    assert _findings(client, stale=False) == []
    assert _ok(client.get(f"{VULNS}/overview"))["stale"] == 1


def test_heartbeat_does_not_queue_and_identical_inventory_is_cheap(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, _ = _setup(client, engine)
    response = client.post(f"{API}/agents/heartbeat", json={"agent_id": agent_id})
    assert response.status_code == 200, response.text
    db.expire_all()
    assert db.scalar(select(func.count()).where(AssetVulnerabilityState.dirty_at.is_not(None))) == 0
    _inventory(client, agent_id, [_app()])
    run = _evaluate(engine)
    assert (run.assets, run.unchanged, run.updated) == (1, 1, 0)


def test_catalog_update_is_incremental_and_resolves_by_catalog(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _setup(client, engine)
    other_agent, _ = _agent(client, "PC-OTHER")
    _inventory(client, other_agent, [{"name": "Unrelated", "version": "1.0"}])
    _evaluate(engine)
    corrected = _import(client, _catalog(_record(ranges=[{"lt": "2.4.0"}])))
    assert corrected["updated"] == 1
    # Solo se encola el activo que tiene el producto, no toda la flota.
    assert corrected["assets_queued"] == 1
    run = _evaluate(engine)
    assert run.assets == 1
    finding = _one(client)
    assert finding["status"] == "resolved"
    assert finding["resolution"] == "resolved_by_catalog_update"


# --- Flujo de trabajo, RBAC y concurrencia -----------------------------------------------------


def test_workflow_rbac_and_optimistic_concurrency(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _setup(client, engine)
    finding = _one(client)
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        assert viewer.get(f"{FINDINGS}/{finding['finding_id']}").json()["actions"] == []
        _error(_act(viewer, finding, "acknowledge"), 403, "permission_denied")
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        acked = _ok(_act(analyst, finding, "acknowledge", reason="Ticket CHG-1"))
        assert acked["status"] == "acknowledged" and acked["version"] == finding["version"] + 1
        # Versión vieja: 409 con la versión actual para refrescar.
        conflict = _error(_act(analyst, finding, "mitigating"), 409, "vulnerability_conflict")
        assert conflict["details"][0]["version"] == acked["version"]
        _error(
            _act(analyst, acked, "accept-risk", reason="compensating control"),
            403,
            "permission_denied",
        )
        # Resolver a mano con la evidencia diciendo "vulnerable" exige confirmarlo.
        response = _act(analyst, acked, "resolve", reason="patched by hand")
        _error(response, 422, "vulnerability_evidence_vulnerable")
        resolved = _ok(_act(analyst, acked, "resolve", reason="patched", override_evidence=True))
        assert resolved["status"] == "resolved" and resolved["resolution"] == "manual"
    assert len(_audit(db, "vulnerability_finding_acknowledged")) == 1
    (event,) = _audit(db, "vulnerability_finding_resolved")
    assert event.details is not None and event.details["override_evidence"] is True

    # La misma evidencia no reabre una resolución manual.
    _evaluate(engine)
    assert _one(client)["status"] == "resolved"


def test_accepted_risk_expires_back_to_open(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _setup(client, engine)
    finding = _one(client)
    _error(_act(client, finding, "accept-risk"), 422, "validation_error")
    until = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    accepted = _ok(_act(client, finding, "accept-risk", reason="WAF rule", accepted_until=until))
    assert accepted["status"] == "accepted_risk"
    assert len(_audit(db, "vulnerability_risk_accepted")) == 1
    # Mientras dura, la evaluación respeta la decisión.
    _evaluate(engine)
    assert _one(client)["status"] == "accepted_risk"

    settings = get_settings()
    with sessionmaker(bind=engine)() as session:
        expired = VulnerabilityEngine(
            session, VulnerabilityConfig.from_settings(settings)
        ).expire_accepted_audited(datetime.now(UTC) + timedelta(days=31))
    assert expired == 1
    assert _one(client)["status"] == "open"
    (event,) = _audit(db, "vulnerability_risk_acceptance_expired")
    assert event.actor == "sentra"


def test_false_positive_is_reevaluated_on_material_change(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent_id, _ = _setup(client, engine)
    finding = _one(client)
    marked = _ok(_act(client, finding, "false-positive", reason="vendor backport confirmed"))
    assert marked["status"] == "false_positive"
    assert marked["review_basis"]["installed_version"] == "2.4.1"
    _inventory(client, agent_id, [_app(), {"name": "Other", "version": "1.0"}])
    _evaluate(engine)
    assert _one(client)["status"] == "false_positive"
    # Otra versión, todavía afectada: la decisión ya no describe lo instalado.
    _inventory(client, agent_id, [_app("2.4.2")])
    _evaluate(engine)
    reopened = _one(client)
    assert reopened["status"] == "open" and reopened["installed_version"] == "2.4.2"
    assert len(_audit(db, "vulnerability_false_positive")) == 1


# --- Integraciones: Risk 4I e incidentes 4K ----------------------------------------------------


def test_risk_engine_counts_findings_without_double_counting(
    client: TestClient, engine: Engine
) -> None:
    _, asset_id = _setup(client, engine)
    _risk(engine)
    detail = _ok(client.get(f"{API}/risk/assets/{asset_id}"))
    assert detail["formula_version"] == FORMULA_VERSION
    (contribution,) = [c for c in detail["contributions"] if c["factor"] == "vulnerability"]
    finding = _one(client)
    assert contribution["finding_id"] == finding["finding_id"]
    assert contribution["points"] > 0
    before = contribution["points"]

    _ok(_act(client, finding, "acknowledge"))
    _risk(engine)
    detail = _ok(client.get(f"{API}/risk/assets/{asset_id}"))
    (contribution,) = [c for c in detail["contributions"] if c["factor"] == "vulnerability"]
    assert contribution["points"] < before


def test_incident_from_finding_is_linked_and_audited(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _setup(client, engine)
    finding = _one(client)
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        incident = _ok(_act(analyst, finding, "incident"), 201)
        assert incident["title"].startswith("CVE-2099-1001")
        assert incident["severity"] == "high" and incident["confidence"] == "high"
        (linked,) = incident["vulnerabilities"]
        assert linked["finding_id"] == finding["finding_id"]
        refreshed = _ok(analyst.get(f"{FINDINGS}/{finding['finding_id']}"))
        assert refreshed["incidents"][0]["incident_id"] == incident["incident_id"]
        # Ya está en un caso activo: no se abre otro.
        response = _act(analyst, refreshed, "incident")
        assert response.status_code == 409, response.text
    assert len(_audit(db, "vulnerability_incident_created")) == 1
    assert len(_audit(db, "incident_created")) == 1


# --- Listado: filtros, búsqueda, orden y paginación --------------------------------------------


def test_list_filters_search_sort_and_pagination(client: TestClient, engine: Engine) -> None:
    agent_id, asset_id = _agent(client, "SRV-FILES-01")
    _inventory(client, agent_id, [_app()])
    records = [
        _record(f"CVE-2099-30{i:02d}", severity=s)
        for i, s in enumerate(["low", "medium", "high", "critical"])
    ]
    _import(client, _catalog(*records))
    _evaluate(engine)
    assert len(_findings(client)) == 4
    by_priority = _findings(client, sort="priority", order="desc")
    assert by_priority[0]["severity"] == "critical" and by_priority[-1]["severity"] == "low"
    assert _findings(client, sort="severity", order="asc")[0]["severity"] == "low"
    assert [f["severity"] for f in _findings(client, severity="high")] == ["high"]
    assert len(_findings(client, q="CVE-2099-3002")) == 1
    assert len(_findings(client, q="SRV-FILES")) == 4
    assert len(_findings(client, q="exampleapp")) == 4
    assert len(_findings(client, asset_id=asset_id, active=True)) == 4
    page = _ok(client.get(FINDINGS, params={"limit": 2, "offset": 2}))
    assert page["total"] == 4 and len(page["items"]) == 2
    assert client.get(FINDINGS, params={"sort": "title; DROP TABLE"}).status_code == 422
    assert client.get(FINDINGS, params={"q": "x" * 300}).status_code == 422


def test_admin_can_evaluate_one_asset_now(client: TestClient, engine: Engine, db: Session) -> None:
    agent_id, asset_id = _agent(client)
    _inventory(client, agent_id, [_app()])
    _import(client, _catalog(_record()))
    result = _ok(client.post(f"{VULNS}/evaluate", json={"asset_id": asset_id}))
    assert result["mode"] == "immediate" and result["created"] == 1
    assert len(_audit(db, "vulnerability_evaluation_started")) == 1
    queued = _ok(client.post(f"{VULNS}/evaluate", json={}))
    assert queued["mode"] == "queued" and queued["assets"] == 1
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        response = analyst.post(f"{VULNS}/evaluate", json={"asset_id": asset_id})
        _error(response, 403, "permission_denied")


def test_evaluate_all_queues_in_chunks(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "Reevaluar todo" con miles de activos: un único INSERT superaría el máximo de
    # parámetros de PostgreSQL y no encolaría nada (fallo silencioso del SAVEPOINT).
    monkeypatch.setattr(queue, "MARK_CHUNK", 2)
    for n in range(5):
        _agent(client, hostname=f"PC-CHUNK-{n}")
    _evaluate(engine)  # cola vacía: lo que quede pendiente lo ha encolado "Reevaluar todo"
    queued = _ok(client.post(f"{VULNS}/evaluate", json={}))
    assert queued["assets"] == 5
    dirty = db.scalar(
        select(func.count())
        .select_from(AssetVulnerabilityState)
        .where(AssetVulnerabilityState.dirty_at.is_not(None))
    )
    assert dirty == 5


# --- Migración ---------------------------------------------------------------------------------


def test_migration_0026_round_trip(client: TestClient, engine: Engine, db: Session) -> None:
    from alembic import command

    from tests.conftest import _alembic_config

    _setup(client, engine)
    config = _alembic_config(str(engine.url.render_as_string(hide_password=False)))
    try:
        command.downgrade(config, "0025")
        with engine.connect() as connection:
            for table in ("vulnerability_findings", "vulnerabilities", "vulnerability_sources"):
                regclass = connection.execute(text(f"SELECT to_regclass('{table}')")).scalar()
                assert regclass is None
            # Lo anterior a 5B sigue ahí (activos e inventario).
            assert connection.execute(text("SELECT count(*) FROM assets")).scalar() == 1
    finally:
        command.upgrade(config, "head")
    # Esquema operativo de nuevo (los findings y el catálogo se pierden al bajar).
    assert db.scalar(select(func.count()).select_from(VulnerabilityFinding)) == 0
    _import(client, _catalog(_record()))
    _evaluate(engine)
    assert len(_findings(client)) == 1
