"""Fase 7B-Fix1: servicios por usuario, CORR-002 v5 causal y PER-001 v3.

Caso real (ravenslg): WpnUserService_6df11 apareció en el inventario ANTES que 200 bloques
4104 y CORR-002 v4 lo presentó como persistencia. Aquí se comprueba que:
- una instancia por usuario verificable no es una instalación ni dispara PER-001/CORR-002;
- la proximidad temporal sin relación causal queda como contexto de SCR-001;
- la suplantación (svchost.exe fuera de System32, firma inválida, tipo sin el bit de
  instancia) y las instalaciones posteriores al script siguen detectándose;
- los 200 bloques forman una sola detección SCR-001 sin borrar los eventos.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from itertools import count
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.detection import service_identity as si
from app.detection.config import DetectionConfig
from app.detection.engine import DetectionEngine
from app.detection.rules import causal_links
from app.detection.signals import SignalKind
from app.models.asset import Asset
from app.models.change import ChangeKind
from app.models.detection import (
    Detection,
    DetectionConfidence,
    DetectionEvidence,
    DetectionSeverity,
    DetectionSignal,
)
from app.models.event import SystemEvent
from app.models.risk import AssetRisk
from app.services.alert_service import AlertThresholds
from app.services.change_detection import diff_inventory
from tests.conftest import agent_payload

API = "/api/v1"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
CONFIG = DetectionConfig()
SVCHOST = r"C:\WINDOWS\system32\svchost.exe"
MS_SIGNATURE = {
    "status": "Valid",
    "signer": "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
}
_records = count(50_000)


def _svc(name: str, **fields: Any) -> dict[str, Any]:
    return {"name": name, "status": "running", "start_type": "manual", **fields}


def _instance(name: str, **overrides: Any) -> dict[str, Any]:
    """Instancia por usuario tal como la envía el agente 0.6.2 en un Windows sano."""
    fields: dict[str, Any] = {
        "binpath": f"{SVCHOST} -k UnistackSvcGroup",
        "image": SVCHOST,
        "service_type": 0xE0,
        "image_signature": MS_SIGNATURE,
    }
    fields.update(overrides)
    return _svc(name, **{k: v for k, v in fields.items() if v is not None})


def _templates() -> list[dict[str, Any]]:
    return [
        _svc("WpnUserService", binpath=f"{SVCHOST} -k UnistackSvcGroup", service_type=0x60),
        _svc("OneSyncSvc", binpath=f"{SVCHOST} -k UnistackSvcGroup", service_type=0x60),
        _svc("Spooler", binpath=r"C:\WINDOWS\System32\spoolsv.exe", service_type=0x10),
    ]


def _inventory_map(services: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {s["name"].lower(): s for s in services}


# --- Clasificación pura ---------------------------------------------------------------------


def test_verified_user_service_instance() -> None:
    services = [*_templates(), _instance("WpnUserService_6df11"), _instance("OneSyncSvc_6df11")]
    found = si.classify_inventory_service(
        "WpnUserService_6df11", services[3], _inventory_map(services)
    )
    assert (found.kind, found.verification) == (si.USER_INSTANCE, si.VERIFIED)
    assert found.template == "WpnUserService" and found.session_suffix == "6df11"
    assert found.legitimate_user_instance and not found.suspicious
    checks = {c.code: c.result for c in found.checks}
    assert checks == {
        "template": "pass",
        "session_peers": "pass",
        "service_type": "pass",
        "host_image": "pass",
        "host_group": "pass",
        "signature": "pass",
    }


def test_old_agent_can_only_reach_probable() -> None:
    services = [*_templates(), _svc("WpnUserService_6df11")]
    found = si.classify_inventory_service(
        "WpnUserService_6df11", services[-1], _inventory_map(services)
    )
    assert found.verification == si.PROBABLE
    assert "0.6.2" in found.explanation


@pytest.mark.parametrize(
    ("overrides", "failed"),
    [
        # svchost.exe fuera de System32: el disfraz clásico.
        ({"image": r"C:\Users\Public\svchost.exe"}, "host_image"),
        ({"image": r"C:\Windows\Temp\System32\svchost.exe"}, "host_image"),
        ({"image_signature": {"status": "HashMismatch", "signer": None}}, "signature"),
        ({"image_signature": {"status": "Valid", "signer": "CN=Evil, O=Evil Corp"}}, "signature"),
        ({"service_type": 0x10}, "service_type"),
        ({"binpath": f"{SVCHOST} -k netsvcs"}, "host_group"),
    ],
)
def test_impersonated_instance_is_suspicious(overrides: dict[str, Any], failed: str) -> None:
    candidate = _instance("WpnUserService_6df11", **overrides)
    services = [*_templates(), candidate]
    found = si.classify_inventory_service(
        "WpnUserService_6df11", candidate, _inventory_map(services)
    )
    assert found.verification == si.SUSPICIOUS and found.suspicious
    assert not found.legitimate_user_instance
    assert {c.code: c.result for c in found.checks}[failed] == "fail"


def test_instance_name_without_template_is_not_trusted() -> None:
    candidate = _instance("Updater_abcd1")
    found = si.classify_inventory_service(
        "Updater_abcd1", candidate, _inventory_map([*_templates(), candidate])
    )
    assert found.verification == si.UNVERIFIED and not found.legitimate_user_instance


def test_plain_new_service_is_discovered_not_installed() -> None:
    found = si.classify_inventory_service("Foo", _svc("Foo"), {})
    assert (found.kind, found.verification) == (si.DISCOVERED, si.UNVERIFIED)


def test_diff_reports_image_change_and_classification() -> None:
    before = {"services": [*_templates(), _svc("Svc", binpath=r"C:\A\svc.exe")]}
    after = {
        "services": [
            *_templates(),
            _svc("Svc", binpath=r"C:\Users\Public\svc.exe"),
            _instance("WpnUserService_6df11"),
        ]
    }
    changes = {(c.kind, c.item): c for c in diff_inventory(before, after)}
    image = changes[(ChangeKind.IMAGE_CHANGED, "Svc")]
    assert image.details is not None
    assert image.details["before"] == r"C:\A\svc.exe"
    assert image.details["after"] == r"C:\Users\Public\svc.exe"
    added = changes[(ChangeKind.ADDED, "WpnUserService_6df11")]
    assert added.details is not None
    assert added.details["classification"]["verification"] == "verified"


def test_diff_without_binpath_reports_no_image_change() -> None:
    # Un agente antiguo no envía binpath: "no lo sé" nunca es "cambió".
    before = {"services": [_svc("Svc")]}
    after = {"services": [_svc("Svc", binpath=r"C:\A\svc.exe")]}
    assert [c for c in diff_inventory(before, after) if c.kind is ChangeKind.IMAGE_CHANGED] == []


def _signal(kind: SignalKind, at: datetime, **data: Any) -> DetectionSignal:
    return DetectionSignal(asset_id=1, kind=kind.value, occurred_at=at, subject="x", data=data)


def test_process_lineage_links_script_and_service_binary() -> None:
    now = datetime.now(UTC)
    script = _signal(SignalKind.POWERSHELL_SUSPICIOUS, now - timedelta(minutes=9), pid=4242)
    service = _signal(
        SignalKind.SERVICE_ADDED,
        now - timedelta(minutes=12),
        service="Updater",
        image_path=r"C:\ProgramData\u\updater.exe",
    )
    child = _signal(
        SignalKind.PROCESS_NEW,
        now - timedelta(minutes=8),
        pid=5000,
        ppid=4242,
        exe=r"c:\programdata\U\updater.exe",
    )
    stranger = _signal(
        SignalKind.PROCESS_NEW, now, pid=5001, ppid=1, exe=r"C:\ProgramData\u\updater.exe"
    )
    assert causal_links([script], service, [stranger]) == []
    codes = [link["code"] for link in causal_links([script], service, [stranger, child])]
    assert codes == ["script_started_service_binary"]


# --- Motor completo ---------------------------------------------------------------------------


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _run(engine: Engine) -> None:
    with sessionmaker(bind=engine)() as session:
        DetectionEngine(
            session, CONFIG, AlertThresholds.from_settings(get_settings())
        ).process_pending()


def _agent(client: TestClient, db: Session) -> tuple[str, int]:
    payload = agent_payload(hostname=f"PC-{uuid4().hex[:6]}", os_name="Windows")
    assert client.post(f"{API}/agents/register", json=payload).status_code == 201
    asset_id = db.scalar(select(Asset.id).where(Asset.agent_id == payload["agent_id"]))
    assert asset_id is not None
    return str(payload["agent_id"]), asset_id


def _ago(minutes: float) -> datetime:
    return datetime.now(UTC) - timedelta(minutes=minutes)


def _inventory(client: TestClient, agent: str, at: datetime, services: list[Any]) -> None:
    body = {"agent_id": agent, "collected_at": at.isoformat(), "services": services}
    response = client.post(f"{API}/inventory", json=body)
    assert response.status_code == 201, response.text


def _block(at: datetime, sha: str = "c" * 64, path: str = r"C:\Users\x\run.ps1") -> Any:
    return {
        "source": "windows_eventlog",
        "channel": POWERSHELL,
        "record_id": next(_records),
        "event_code": 4104,
        "provider": "Microsoft-Windows-PowerShell",
        "level": "warning",
        "message": "Microsoft-Windows-PowerShell event 4104 (content not collected)",
        "occurred_at": at.isoformat(),
        "data": {
            "ScriptBlockId": str(uuid4()),
            "MessageNumber": "1",
            "MessageTotal": "1",
            "ProcessID": "4242",
            "UserID": "S-1-5-21-1-2-3-1001",
            "SuspiciousKeywords": "InteropServices,Marshal",
            "Path": path,
            "ScriptSha256": sha,
        },
    }


def _install(at: datetime, name: str, image: str) -> Any:
    return {
        "source": "windows_eventlog",
        "channel": "System",
        "record_id": next(_records),
        "event_code": 7045,
        "provider": "Service Control Manager",
        "level": "warning",
        "message": "event 7045",
        "occurred_at": at.isoformat(),
        "data": {"ServiceName": name, "ImagePath": image, "AccountName": "LocalSystem"},
    }


def _send(client: TestClient, agent: str, events: list[Any]) -> None:
    for start in range(0, len(events), 100):
        body = {"agent_id": agent, "events": events[start : start + 100]}
        response = client.post(f"{API}/events", json=body)
        assert response.status_code == 201, response.text


def _detections(client: TestClient, rule_id: str) -> list[dict[str, Any]]:
    response = client.get(f"{API}/detections", params={"rule_id": rule_id, "limit": 100})
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


def _details(client: TestClient, detection: dict[str, Any]) -> dict[str, Any]:
    details: dict[str, Any] = client.get(f"{API}/detections/{detection['detection_id']}").json()[
        "details"
    ]
    return details


def test_ravenslg_user_instance_before_200_blocks_is_only_context(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    _inventory(client, agent, _ago(40), _templates())
    session = [_instance("WpnUserService_6df11"), _instance("OneSyncSvc_6df11")]
    _inventory(client, agent, _ago(20), [*_templates(), *session])
    blocks = [_block(_ago(15 - i * 0.05)) for i in range(200)]
    _send(client, agent, blocks)
    _run(engine)

    assert _detections(client, "CORR-002") == []
    assert _detections(client, "PER-001") == []
    # Los 200 bloques del mismo script son una detección, con todos los eventos guardados.
    (scr,) = _detections(client, "SCR-001")
    evidence = db.scalar(
        select(func.count())
        .select_from(DetectionEvidence)
        .join(Detection, Detection.id == DetectionEvidence.detection_id)
        .where(Detection.asset_id == asset_id, Detection.rule_id == "SCR-001")
    )
    assert evidence is not None and evidence > 1
    stored = db.scalar(
        select(func.count()).select_from(SystemEvent).where(SystemEvent.asset_id == asset_id)
    )
    assert stored == 200
    context = _details(client, scr)["temporal_context"]
    assert {c["service"] for c in context} == {"WpnUserService_6df11", "OneSyncSvc_6df11"}
    assert {c["position"] for c in context} == {"before_script"}
    assert {c["verification"] for c in context} == {"verified"}


def test_old_agent_instance_is_low_noise_not_correlated(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, _ = _agent(client, db)
    old = [_svc("WpnUserService"), _svc("OneSyncSvc")]
    _inventory(client, agent, _ago(40), old)
    _send(client, agent, [_block(_ago(30))])
    _inventory(client, agent, _ago(20), [*old, _svc("WpnUserService_6df11")])
    _run(engine)

    assert _detections(client, "CORR-002") == []
    (per,) = _detections(client, "PER-001")
    assert per["severity"] == "low"
    details = _details(client, per)
    assert details["classification"]["verification"] == "probable"


def test_spoofed_instance_after_script_is_still_correlated(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, _ = _agent(client, db)
    _inventory(client, agent, _ago(40), _templates())
    _send(client, agent, [_block(_ago(30))])
    fake = _instance(
        "WpnUserService_6df11",
        image=r"C:\Users\Public\svchost.exe",
        binpath=r"C:\Users\Public\svchost.exe -k UnistackSvcGroup",
        image_signature={"status": "NotSigned", "signer": None},
    )
    _inventory(client, agent, _ago(20), [*_templates(), fake])
    _run(engine)

    (per,) = _detections(client, "PER-001")
    assert per["severity"] == "high"
    (corr,) = _detections(client, "CORR-002")
    details = _details(client, corr)
    assert details["relation"] == "causal"
    assert "suspicious_service_after_script" in [c["code"] for c in details["causal_links"]]
    assert details["persistence"]["classification"]["verification"] == "suspicious"


def test_install_before_script_is_context_and_after_is_causal(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, _ = _agent(client, db)
    _send(client, agent, [_install(_ago(30), "EarlySvc", r"C:\Tools\early.exe")])
    _send(client, agent, [_block(_ago(25), sha="d" * 64)])
    _run(engine)
    assert _detections(client, "CORR-002") == []
    (scr,) = _detections(client, "SCR-001")
    (context,) = _details(client, scr)["temporal_context"]
    assert context["position"] == "before_script" and context["source"] == "event_7045"

    _send(client, agent, [_install(_ago(20), "LateSvc", r"C:\Tools\late.exe")])
    _run(engine)
    (corr,) = _detections(client, "CORR-002")
    details = _details(client, corr)
    assert details["service"] == "LateSvc"
    assert corr["confidence"] == "high"
    assert details["script_keys"] == ["script:" + "d" * 64]


def test_modified_service_after_script_is_correlated(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, _ = _agent(client, db)
    original = _svc("Updater", binpath=r'"C:\Program Files\U\updater.exe"', service_type=0x10)
    _inventory(client, agent, _ago(40), [*_templates(), original])
    _send(client, agent, [_block(_ago(30))])
    hijacked = {**original, "binpath": r"C:\Users\Public\u.exe", "image": r"C:\Users\Public\u.exe"}
    _inventory(client, agent, _ago(20), [*_templates(), hijacked])
    _run(engine)

    (per,) = _detections(client, "PER-001")
    per_details = _details(client, per)
    assert per_details["previous_binpath"] == r'"C:\Program Files\U\updater.exe"'
    (corr,) = _detections(client, "CORR-002")
    codes = [c["code"] for c in _details(client, corr)["causal_links"]]
    assert "service_modified_after_script" in codes


# --- Revisión de CORR-002 v4 ya creadas --------------------------------------------------------


def _v4_correlation(db: Session, asset_id: int, service_kind: str, service_at: datetime) -> Any:
    """Una CORR-002 v4 como la de ravenslg, con su evidencia guardada."""
    now = datetime.now(UTC)
    detection = Detection(
        asset_id=asset_id,
        rule_id="CORR-002",
        rule_version=4,
        rule_category="correlation",
        kind="correlation",
        dedup_key=f"wpnuserservice_6df11:{service_kind}",
        severity=DetectionSeverity.HIGH,
        confidence=DetectionConfidence.MEDIUM,
        title="PowerShell sospechoso seguido de persistencia",
        summary="v4",
        details={"service": "WpnUserService_6df11"},
        first_seen_at=service_at,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(detection)
    db.flush()
    rows = [
        (SignalKind.POWERSHELL_SUSPICIOUS.value, "powershell", _ago(15), {"pid": 4242}),
        (service_kind, "persistence", service_at, {"service": "WpnUserService_6df11"}),
    ]
    for kind, role, at, data in rows:
        db.add(
            DetectionEvidence(
                detection_id=detection.id,
                signal_kind=kind,
                role=role,
                source_type="inventory",
                occurred_at=at,
                summary=kind,
                data=data,
                created_at=now,
            )
        )
    db.commit()
    return detection.public_id


def test_review_resolves_only_temporal_v4_correlations(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _, asset_id = _agent(client, db)
    temporal = _v4_correlation(db, asset_id, SignalKind.SERVICE_ADDED.value, _ago(20))
    causal = _v4_correlation(db, asset_id, SignalKind.SERVICE_INSTALLED.value, _ago(10))
    asset = str(db.scalar(select(Asset.public_id).where(Asset.id == asset_id)))

    preview = client.post(
        f"{API}/detections/correlation-review/preview", json={"asset_id": asset}
    ).json()
    verdicts = {item["detection_id"]: item for item in preview["items"]}
    assert verdicts[str(temporal)]["verdict"] == "temporal_only"
    assert verdicts[str(temporal)]["would_resolve"] is True
    assert verdicts[str(temporal)]["temporal_context"]["order"] == "service_first"
    assert verdicts[str(causal)]["verdict"] == "causal"
    assert verdicts[str(causal)]["would_resolve"] is False

    body: dict[str, Any] = {"detection_ids": [str(temporal), str(causal)], "confirm": True}
    assert (
        client.post(
            f"{API}/detections/correlation-review/apply", json={**body, "confirm": False}
        ).status_code
        == 422
    )
    result = client.post(f"{API}/detections/correlation-review/apply", json=body).json()
    assert result == {"reviewed": 2, "resolved": 1, "kept": 1}

    resolved = client.get(f"{API}/detections/{temporal}").json()
    assert resolved["status"] == "resolved"
    assert resolved["details"]["correlation_review"]["verdict"] == "temporal_only"
    kept = client.get(f"{API}/detections/{causal}").json()
    assert kept["status"] == "open"
    assert kept["details"]["correlation_review"]["verdict"] == "causal"
    # Nada se borra: la evidencia sigue ahí y queda auditado.
    evidence = db.scalar(select(func.count()).select_from(DetectionEvidence))
    assert evidence is not None and evidence >= 4
    audit = client.get(f"{API}/audit", params={"action": "correlation_review_applied"}).json()
    assert audit["items"]
    db.expire_all()
    assert db.scalar(select(AssetRisk.dirty_at).where(AssetRisk.asset_id == asset_id)) is not None
    # Una segunda vista previa ya no la propone.
    again = client.post(f"{API}/detections/correlation-review/preview", json={"asset_id": asset})
    assert [i["detection_id"] for i in again.json()["items"]] == [str(causal)]
