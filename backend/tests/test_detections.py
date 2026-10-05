"""Motor de detección (Fase 4H) de extremo a extremo: ingesta real -> señales -> motor -> API.

Los datos son eventos sintéticos con la forma que envía el agente (fixtures de test, nunca
datos en producción). El motor se ejecuta a mano (`_run`), como haría el job interno.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from itertools import count
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.detection import rules as rules_module
from app.detection import signals as signals_module
from app.detection.config import DetectionConfig
from app.detection.engine import MAX_EVIDENCE, DetectionEngine, EngineRun
from app.detection.recorder import SignalRecorder
from app.models.alert import Alert, AlertRule, AlertStatus
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.change import ChangeKind
from app.models.detection import Detection, DetectionEvidence, DetectionSignal, DetectionStatus
from app.services.alert_service import AlertThresholds
from app.services.retention_service import RetentionPolicy, RetentionService
from tests.conftest import agent_payload, authenticate

API = "/api/v1"
SECURITY = "Microsoft-Windows-Security-Auditing"
CONFIG = DetectionConfig()
_records = count(1)


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _run(engine: Engine, config: DetectionConfig = CONFIG) -> EngineRun:
    with sessionmaker(bind=engine)() as session:
        thresholds = AlertThresholds.from_settings(get_settings())
        return DetectionEngine(session, config, thresholds).process_pending()


def _agent(client: TestClient, hostname: str = "PC-ADMIN-01", os_name: str = "Windows") -> str:
    payload = agent_payload(hostname=hostname, os_name=os_name)
    assert client.post(f"{API}/agents/register", json=payload).status_code == 201
    return str(payload["agent_id"])


def _ago(minutes: float) -> datetime:
    return datetime.now(UTC) - timedelta(minutes=minutes)


def ev(
    code: int,
    at: datetime,
    *,
    channel: str = "Security",
    provider: str = SECURITY,
    level: str = "warning",
    record: int | None = None,
    # Para nombres que no son identificadores Python ("Threat Name") o dicts ya montados.
    fields: dict[str, str] | None = None,
    **data: str,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "source": "windows_eventlog",
        "channel": channel,
        "record_id": record if record is not None else next(_records),
        "event_code": code,
        "provider": provider,
        "level": level,
        "message": f"event {code}",
        "occurred_at": at.isoformat(),
    }
    if fields or data:
        event["data"] = {**(fields or {}), **data}
    return event


def fail(user: str, at: datetime, ip: str = "10.0.0.66") -> dict[str, Any]:
    return ev(4625, at, TargetUserName=user, IpAddress=ip, LogonType="3")


def success(
    user: str, at: datetime, sid: str = "S-1-5-21-1-2-3-1001", **extra: str
) -> dict[str, Any]:
    data = {"TargetUserName": user, "TargetUserSid": sid, "LogonType": "10", **extra}
    return ev(4624, at, level="info", fields=data)


def admin_add(
    at: datetime, member_sid: str = "S-1-5-21-1-2-3-1001", **extra: str
) -> dict[str, Any]:
    data = {"MemberSid": member_sid, "TargetSid": "S-1-5-32-544",
            "TargetUserName": "Administradores", **extra}  # fmt: skip
    return ev(4732, at, fields=data)


def _send(client: TestClient, agent_id: str, events: list[dict[str, Any]]) -> Any:
    response = client.post(f"{API}/events", json={"agent_id": agent_id, "events": events})
    assert response.status_code == 201, response.text
    return response.json()


def _detections(client: TestClient, **params: Any) -> list[dict[str, Any]]:
    response = client.get(f"{API}/detections", params={"limit": 500, **params})
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


def _by_rule(client: TestClient, **params: Any) -> dict[str, dict[str, Any]]:
    return {d["rule_id"]: d for d in _detections(client, **params)}


def _detail(client: TestClient, detection_id: str) -> dict[str, Any]:
    response = client.get(f"{API}/detections/{detection_id}")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


# --- Autenticación y correlación principal ----------------------------------------------------


def test_single_failed_logon_is_not_an_attack(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    _send(client, agent, [fail("ana", _ago(1))])

    _run(engine)

    assert _detections(client) == []


def test_repeated_failures_success_and_admin_change_correlate(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _agent(client)
    failures = [fail("ana", _ago(4 - i * 0.5)) for i in range(5)]
    _send(client, agent, [*failures, success("ana", _ago(1)), admin_add(_ago(0.5))])

    run = _run(engine)

    assert run.rule_errors == 0
    found = _by_rule(client)
    assert {"AUTH-001", "CORR-001", "ACCT-002"} <= found.keys()
    corr = found["CORR-001"]
    # Fallos + éxito + cambio de administradores: crítica con confianza alta.
    assert (corr["severity"], corr["confidence"]) == ("critical", "high")
    assert corr["kind"] == "correlation" and corr["mitre_technique"] == "T1110"
    detail = _detail(client, corr["detection_id"])
    roles = [e["role"] for e in detail["evidence"]]
    assert roles == ["failure"] * 5 + ["success", "admin_change"]
    times = [e["occurred_at"] for e in detail["evidence"]]
    assert times == sorted(times)  # timeline cronológico
    assert detail["recommendations"] and detail["why"]
    assert all("explot" not in r.lower() for r in detail["recommendations"])
    assert detail["evidence"][5]["source_id"]  # enlaza con el evento de /events
    # AUTH-001 sola es media: un patrón, no una confirmación.
    assert (found["AUTH-001"]["severity"], found["AUTH-001"]["confidence"]) == ("medium", "medium")
    # Las detecciones graves abren una alerta security_detection enlazada.
    alert = db.scalars(select(Alert).where(Alert.rule == AlertRule.SECURITY_DETECTION)).one()
    assert alert.status == AlertStatus.OPEN and alert.details is not None
    assert corr["alert_id"] == str(alert.public_id) or found["ACCT-002"]["alert_id"]


def test_success_without_admin_change_is_high_not_critical(
    client: TestClient, engine: Engine
) -> None:
    agent = _agent(client)
    _send(client, agent, [*(fail("ana", _ago(5 - i)) for i in range(5)), success("ana", _ago(0))])

    _run(engine)

    corr = _by_rule(client)["CORR-001"]
    assert corr["severity"] == "high"


def test_admin_change_arriving_later_escalates_the_same_correlation(
    client: TestClient, engine: Engine
) -> None:
    agent = _agent(client)
    _send(client, agent, [*(fail("ana", _ago(6 - i)) for i in range(5)), success("ana", _ago(1))])
    _run(engine)
    first = _by_rule(client)["CORR-001"]

    _send(client, agent, [admin_add(_ago(0.2))])
    _run(engine)

    corr = [d for d in _detections(client) if d["rule_id"] == "CORR-001"]
    assert len(corr) == 1 and corr[0]["detection_id"] == first["detection_id"]
    assert corr[0]["severity"] == "critical"  # severidad solo sube


def test_correlation_does_not_happen_outside_the_window(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    # Fallos hace 40 min (ventana de 15 min): el acceso de ahora no se correlaciona.
    _send(client, agent, [*(fail("ana", _ago(40 + i * 0.1)) for i in range(5))])
    _send(client, agent, [success("ana", _ago(0))])

    _run(engine)

    found = _by_rule(client)
    assert "CORR-001" not in found
    assert "AUTH-001" in found


def test_failures_spread_beyond_the_window_do_not_count(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    _send(client, agent, [*(fail("ana", _ago(20 + i)) for i in range(3))])
    _send(client, agent, [*(fail("ana", _ago(i)) for i in range(2))])

    _run(engine)

    assert _detections(client) == []


def test_evidence_of_different_assets_and_accounts_is_never_mixed(
    client: TestClient, engine: Engine
) -> None:
    first, second = _agent(client, "PC-A"), _agent(client, "PC-B")
    # 3 fallos en cada activo: ninguno llega al umbral por separado.
    _send(client, first, [fail("ana", _ago(3 - i * 0.1)) for i in range(3)])
    _send(client, second, [fail("ana", _ago(3 - i * 0.1)) for i in range(3)])
    # 5 fallos de "ana" y acceso de "bob": cuentas distintas, no hay correlación.
    _send(
        client,
        first,
        [*(fail("ana", _ago(2 - i * 0.1)) for i in range(2)), success("bob", _ago(0))],
    )
    _send(client, second, [success("ana", _ago(0), sid="S-1-5-21-9-9-9-1001")])

    _run(engine)

    found = _detections(client)
    assert [(d["rule_id"], d["hostname"]) for d in found] == [("AUTH-001", "PC-A")]


def test_new_account_elevated_and_used_is_corr_004(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    sid = "S-1-5-21-5-5-5-1010"
    created = ev(4720, _ago(10), TargetUserName="soporte2", TargetSid=sid, SubjectUserName="admin")
    _send(client, agent, [created, admin_add(_ago(8), sid), success("soporte2", _ago(2), sid)])

    _run(engine)

    found = _by_rule(client)
    corr = found["CORR-004"]
    assert (corr["severity"], corr["confidence"]) == ("critical", "high")
    roles = [e["role"] for e in _detail(client, corr["detection_id"])["evidence"]]
    assert roles == ["account_created", "admin_change", "logon"]
    assert found["ACCT-001"]["severity"] == "medium"


def test_new_account_without_logon_is_not_corr_004(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    sid = "S-1-5-21-5-5-5-1011"
    _send(
        client,
        agent,
        [ev(4720, _ago(10), TargetUserName="x", TargetSid=sid), admin_add(_ago(8), sid)],
    )

    _run(engine)

    assert "CORR-004" not in _by_rule(client)


# --- Deduplicación, cooldown y baseline ---------------------------------------------------------


def test_duplicate_events_and_repetition_do_not_flood(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _agent(client)
    batch = [fail("ana", _ago(4 - i * 0.2), ip="10.0.0.5") for i in range(8)]
    _send(client, agent, batch)
    _run(engine)
    # Reenvío idéntico (respuesta perdida): los eventos no se insertan, no hay señales nuevas.
    assert _send(client, agent, batch)["stored"] == 0
    _run(engine)

    (auth,) = [d for d in _detections(client) if d["rule_id"] == "AUTH-001"]
    # Dentro del cooldown (la ventana de 5 min) es una sola oleada.
    assert auth["occurrence_count"] == 1
    assert db.scalar(select(func.count()).select_from(Detection)) == 1
    evidence = db.scalar(
        select(func.count())
        .select_from(DetectionEvidence)
        .where(DetectionEvidence.detection_id == db.scalar(select(Detection.id)))
    )
    assert evidence == 8


def test_new_wave_after_cooldown_counts_a_new_occurrence(
    client: TestClient, engine: Engine
) -> None:
    agent = _agent(client)
    _send(client, agent, [fail("ana", _ago(30 - i * 0.1)) for i in range(5)])
    _run(engine)
    _send(client, agent, [fail("ana", _ago(5 - i * 0.1)) for i in range(5)])
    _run(engine)

    (auth,) = _detections(client)
    assert auth["occurrence_count"] == 2
    assert auth["first_seen_at"] < auth["last_seen_at"]


def test_rule_without_cooldown_counts_each_material_repetition(
    client: TestClient, engine: Engine
) -> None:
    agent = _agent(client)
    _send(client, agent, [ev(1102, _ago(10), level="critical")])
    _run(engine)
    _send(client, agent, [ev(1102, _ago(1), level="critical")])
    _run(engine)

    (cleared,) = _detections(client, rule_id="DEF-001")
    assert cleared["occurrence_count"] == 2


def _inventory(client: TestClient, agent: str, at: datetime, **sections: Any) -> None:
    body = {"agent_id": agent, "collected_at": at.isoformat(), **sections}
    assert client.post(f"{API}/inventory", json=body).status_code == 201


def _processes(client: TestClient, agent: str, at: datetime, exes: list[str]) -> None:
    processes = [
        {"pid": 100 + i, "name": exe.replace("\\", "/").rsplit("/", 1)[-1], "exe": exe,
         "memory_bytes": 1}
        for i, exe in enumerate(exes)
    ]  # fmt: skip
    body = {"agent_id": agent, "collected_at": at.isoformat(), "processes": processes}
    assert client.post(f"{API}/processes", json=body).status_code == 201


def _svc(name: str, status: str = "running", start_type: str = "automatic") -> dict[str, Any]:
    return {"name": name, "status": status, "start_type": start_type}


def _listen(port: int, process: str) -> dict[str, Any]:
    return {"protocol": "tcp", "status": "listen", "local_address": "0.0.0.0",  # noqa: S104
            "local_port": port, "process_name": process, "pid": 4242}  # fmt: skip


def test_first_inventory_and_process_snapshot_are_baseline_not_a_flood(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _agent(client)
    temp = "C:\\Users\\ana\\AppData\\Local\\Temp\\setup.exe"
    services = [_svc(f"svc{i}") for i in range(150)]
    accounts = [{"name": f"user{i}", "enabled": True, "is_admin": i == 0} for i in range(20)]
    _inventory(client, agent, _ago(10), services=services, accounts=accounts,
               connections=[_listen(3389, "svchost.exe")])  # fmt: skip
    _processes(client, agent, _ago(10), [f"C:\\App\\p{i}.exe" for i in range(200)] + [temp])

    _run(engine)

    assert db.scalar(select(func.count()).select_from(DetectionSignal)) == 0
    assert _detections(client) == []

    # Después de la línea base, un ejecutable nuevo desde Temp sí es señal (confianza baja).
    newer = "C:\\Users\\ana\\AppData\\Local\\Temp\\x7.exe"
    _processes(client, agent, _ago(5), [f"C:\\App\\p{i}.exe" for i in range(200)] + [newer])
    _run(engine)
    (proc,) = _detections(client)
    assert proc["rule_id"] == "PROC-001"
    assert (proc["severity"], proc["confidence"]) == ("medium", "low")


def test_exposure_with_new_software_correlates(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    _inventory(
        client, agent, _ago(30), services=[_svc("Spooler")], connections=[_listen(80, "web")]
    )
    _inventory(
        client,
        agent,
        _ago(5),
        services=[_svc("Spooler"), _svc("RemoteHelper")],
        connections=[_listen(80, "web"), _listen(3389, "helper.exe")],
    )

    _run(engine)

    found = _by_rule(client)
    assert {"NET-002", "PER-001", "CORR-003"} <= found.keys()
    corr = found["CORR-003"]
    assert corr["severity"] == "high" and corr["confidence"] == "medium"
    assert "helper.exe" in corr["summary"] and "3389" in corr["summary"]
    # Servicio solo visto en inventario: severidad baja (sin el evento 7045).
    assert found["PER-001"]["severity"] == "low"


def test_powershell_and_new_service_correlate(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    ps = ev(4104, _ago(6), channel="Microsoft-Windows-PowerShell/Operational",
            provider="Microsoft-Windows-PowerShell")  # fmt: skip
    svc = ev(7045, _ago(3), channel="System", provider="Service Control Manager",
             ServiceName="UpdaterSvc", ImagePath="C:\\Windows\\Temp\\upd.exe")  # fmt: skip
    _send(client, agent, [ps, svc])

    _run(engine)

    found = _by_rule(client)
    assert found["CORR-002"]["severity"] == "high"
    assert found["SCR-001"]["severity"] == "medium"
    # Servicio desde una carpeta temporal: PER-001 alta, con MITRE de servicio de Windows.
    assert found["PER-001"]["severity"] == "high"
    assert found["PER-001"]["mitre_subtechnique"] == "T1543.003"


def test_normal_powershell_is_never_critical(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    errors = [
        ev(4100, _ago(2 - i * 0.1), channel="Microsoft-Windows-PowerShell/Operational",
           provider="Microsoft-Windows-PowerShell", level="error")
        for i in range(10)
    ]  # fmt: skip
    _send(client, agent, errors)
    _run(engine)
    assert _detections(client) == []

    flagged = ev(4104, _ago(1), channel="Microsoft-Windows-PowerShell/Operational",
                 provider="Microsoft-Windows-PowerShell")  # fmt: skip
    _send(client, agent, [flagged])
    _run(engine)
    (scr,) = _detections(client)
    assert scr["severity"] != "critical" and scr["rule_id"] == "SCR-001"


# --- Reglas simples -------------------------------------------------------------------------------


def test_defense_rules(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    defender = "Microsoft-Windows-Windows Defender/Operational"
    _send(
        client,
        agent,
        [
            ev(1102, _ago(9), level="critical", SubjectUserName="eve"),
            ev(4719, _ago(8), AuditPolicyChanges="%%8448"),
            ev(5001, _ago(7), channel=defender, provider="Microsoft-Windows-Windows Defender"),
            ev(1116, _ago(6), channel=defender, provider="Microsoft-Windows-Windows Defender",
               fields={"Threat Name": "Trojan:Win32/Test", "Path": "C:\\x.exe"}),
        ],
    )  # fmt: skip
    _run(engine)
    found = _by_rule(client)
    assert (found["DEF-001"]["severity"], found["DEF-001"]["mitre_subtechnique"]) == (
        "high",
        "T1070.001",
    )
    assert found["DEF-002"]["severity"] == "high"
    assert found["DEF-004"]["severity"] == "high"
    assert found["DEF-005"]["severity"] == "high"

    # La misma amenaza sin neutralizar escala la misma detección a crítica.
    _send(client, agent, [ev(1119, _ago(5), channel=defender, level="critical",
                             provider="Microsoft-Windows-Windows Defender",
                             fields={"Threat Name": "Trojan:Win32/Test"})])  # fmt: skip
    _run(engine)
    malware = [d for d in _detections(client) if d["rule_id"] == "DEF-005"]
    assert len(malware) == 1 and malware[0]["severity"] == "critical"


def test_audit_policy_widened_is_informational(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    _send(client, agent, [ev(4719, _ago(1), AuditPolicyChanges="%%8449")])
    _run(engine)
    (audit,) = _detections(client)
    assert audit["severity"] == "informational"


def test_security_service_stopped_from_inventory(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    _inventory(client, agent, _ago(20), services=[_svc("WinDefend"), _svc("Spooler")])
    _inventory(client, agent, _ago(5), services=[_svc("WinDefend", "stopped"), _svc("Spooler")])

    _run(engine)

    (svc,) = _detections(client)
    assert (svc["rule_id"], svc["severity"], svc["confidence"]) == ("DEF-003", "high", "medium")


def test_repetitive_system_patterns(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)

    def crash(at: datetime) -> dict[str, Any]:
        return ev(7034, at, channel="System", provider="Service Control Manager", level="error",
                  param1="Spooler")  # fmt: skip

    _send(client, agent, [crash(_ago(50))])
    _send(client, agent, [ev(41, _ago(200), channel="System", level="critical",
                             provider="Microsoft-Windows-Kernel-Power")])  # fmt: skip
    _run(engine)
    found = _by_rule(client)
    # Un fallo aislado de servicio no es detección; un apagado inesperado sí (baja).
    assert "SYS-002" not in found
    assert found["SYS-001"]["severity"] == "low"

    _send(client, agent, [crash(_ago(40 - i * 10)) for i in range(2)])
    _send(client, agent, [ev(6008, _ago(100 - i * 30), channel="System", level="error",
                             provider="EventLog") for i in range(2)])  # fmt: skip
    _run(engine)
    found = _by_rule(client)
    assert found["SYS-002"]["severity"] == "medium"
    assert found["SYS-001"]["severity"] == "medium"


def test_discovery_exposure_reuses_discovery_baseline(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _agent(client)
    asset_id = db.scalar(select(Asset.id).where(Asset.agent_id == agent))
    assert asset_id is not None
    recorder = SignalRecorder(db, CONFIG)
    recorder.record_discovery_change(
        asset_id, ChangeKind.PORT_OPENED, "3389/tcp (rdp)", _ago(1), {}
    )
    recorder.record_discovery_change(asset_id, ChangeKind.PORT_OPENED, "8080/tcp", _ago(1), {})
    # PORT_CLOSED no es una señal (no aporta riesgo nuevo).
    recorder.record_discovery_change(asset_id, ChangeKind.PORT_CLOSED, "22/tcp", _ago(1), {})
    db.commit()

    _run(engine)

    exposed = {d["summary"].split()[2]: d for d in _detections(client, rule_id="NET-001")}
    assert exposed["3389/tcp"]["severity"] == "high"
    assert exposed["8080/tcp"]["severity"] == "low"


def test_old_backlog_events_do_not_become_detections(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    _send(client, agent, [ev(1102, datetime.now(UTC) - timedelta(days=5), level="critical")])

    _run(engine)

    assert _detections(client) == []


# --- Flujo del analista, RBAC y auditoría -----------------------------------------------------


def _one_detection(client: TestClient, engine: Engine) -> dict[str, Any]:
    agent = _agent(client)
    _send(client, agent, [ev(1102, _ago(2), level="critical")])
    _run(engine)
    (found,) = _detections(client)
    return found


def test_viewer_reads_but_cannot_acknowledge_or_resolve(
    client: TestClient, engine: Engine, db: Session
) -> None:
    detection = _one_detection(client, engine)
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        assert viewer.get(f"{API}/detections").status_code == 200
        assert viewer.get(f"{API}/detections/{detection['detection_id']}").status_code == 200
        assert viewer.get(f"{API}/detection-rules").status_code == 200
        for action in ("acknowledge", "resolve"):
            response = viewer.post(f"{API}/detections/{detection['detection_id']}/{action}")
            assert response.status_code == 403
    assert _detail(client, detection["detection_id"])["status"] == "open"


def test_analyst_acknowledges_and_resolves_with_audit(
    client: TestClient, engine: Engine, db: Session
) -> None:
    detection = _one_detection(client, engine)
    path = f"{API}/detections/{detection['detection_id']}"
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst", "ana-analyst")
        acked = analyst.post(f"{path}/acknowledge")
        assert acked.status_code == 200
        assert acked.json()["status"] == "acknowledged"
        assert acked.json()["acknowledged_by"] == "ana-analyst"
        resolved = analyst.post(f"{path}/resolve", json={"note": "Mantenimiento planificado"})
        assert resolved.status_code == 200
        body = resolved.json()
        assert (
            body["status"] == "resolved" and body["resolution_note"] == "Mantenimiento planificado"
        )
        # Resuelta no se puede reconocer (409, auditado como fallo).
        assert analyst.post(f"{path}/acknowledge").status_code == 409
    actions = db.execute(
        select(AuditEvent.action, AuditEvent.result, AuditEvent.actor)
        .where(AuditEvent.target_type == "detection")
        .order_by(AuditEvent.id)
    ).all()
    assert [tuple(a) for a in actions] == [
        ("detection_acknowledged", "success", "ana-analyst"),
        ("detection_resolved", "success", "ana-analyst"),
        ("detection_acknowledged", "failure", "ana-analyst"),
    ]
    # Resolver cierra también la alerta asociada (ninguna otra detección la mantiene).
    alert = db.scalars(select(Alert).where(Alert.rule == AlertRule.SECURITY_DETECTION)).one()
    assert alert.status == AlertStatus.RESOLVED


def test_resolved_detections_are_kept_and_recurrence_opens_a_new_one(
    client: TestClient, engine: Engine, db: Session
) -> None:
    detection = _one_detection(client, engine)
    client.post(f"{API}/detections/{detection['detection_id']}/resolve")
    agent = db.scalar(select(Asset.agent_id).where(Asset.public_id == detection["asset_id"]))
    _send(client, str(agent), [ev(1102, _ago(1), level="critical")])

    _run(engine)

    found = _detections(client, rule_id="DEF-001")
    assert sorted(d["status"] for d in found) == ["open", "resolved"]
    assert len(_detections(client, active="true")) == 1


def test_unknown_detection_returns_404(client: TestClient) -> None:
    assert client.get(f"{API}/detections/{uuid4()}").status_code == 404
    assert client.post(f"{API}/detections/{uuid4()}/resolve").status_code == 404


# --- Filtros ---------------------------------------------------------------------------------


def test_filters(client: TestClient, engine: Engine) -> None:
    first, second = _agent(client, "PC-A"), _agent(client, "SRV-B")
    _send(client, first, [ev(1102, _ago(30), level="critical")])
    _send(client, second, [ev(4719, _ago(2))])  # sin detalle: medium / low
    _run(engine)
    second_id = client.get(f"{API}/assets").json()["items"]
    asset_b = next(a["asset_id"] for a in second_id if a["hostname"] == "SRV-B")

    assert [d["rule_id"] for d in _detections(client, severity="high")] == ["DEF-001"]
    assert [d["rule_id"] for d in _detections(client, min_severity="medium")] == [
        "DEF-002",
        "DEF-001",
    ]
    assert [d["rule_id"] for d in _detections(client, confidence="low")] == ["DEF-002"]
    assert [d["rule_id"] for d in _detections(client, rule_id="DEF-001")] == ["DEF-001"]
    assert [d["hostname"] for d in _detections(client, asset_id=asset_b)] == ["SRV-B"]
    assert [d["rule_id"] for d in _detections(client, since=_ago(10).isoformat())] == ["DEF-002"]
    assert [d["rule_id"] for d in _detections(client, until=_ago(10).isoformat())] == ["DEF-001"]
    assert [d["hostname"] for d in _detections(client, q="srv-")] == ["SRV-B"]
    assert [d["rule_id"] for d in _detections(client, status="open")] == ["DEF-002", "DEF-001"]
    assert client.get(f"{API}/detections", params={"rule_id": "DROP TABLE"}).status_code == 422
    assert client.get(f"{API}/detections", params={"severity": "extreme"}).status_code == 422
    rules = client.get(f"{API}/detection-rules").json()
    assert {"AUTH-001", "CORR-001", "CORR-004"} <= {r["rule_id"] for r in rules["items"]}
    assert rules["windows"]["correlation_window"] == 15


# --- Resiliencia y datos no confiables ---------------------------------------------------------


def test_a_failing_rule_does_not_stop_the_others(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: object, ctx: object, signal: object) -> list[object]:
        raise RuntimeError("regla rota")

    monkeypatch.setattr(rules_module.FailedLogonBurst, "evaluate", broken)
    agent = _agent(client)
    _send(client, agent, [*(fail("ana", _ago(5 - i * 0.5)) for i in range(6)), ev(1102, _ago(1))])

    run = _run(engine)

    assert run.rule_errors == 6 and run.failed_rules == {"AUTH-001": 6}
    assert "DEF-001" in _by_rule(client)
    # Las señales quedan evaluadas: una regla rota no bloquea la cola en bucle.
    pending = db.scalar(
        select(func.count())
        .select_from(DetectionSignal)
        .where(DetectionSignal.evaluated_at.is_(None))
    )
    assert pending == 0


def test_signal_extraction_failure_never_rejects_ingest(
    client: TestClient, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: object, **kwargs: object) -> list[object]:
        raise RuntimeError("extracción rota")

    monkeypatch.setattr("app.detection.recorder.signals_from_events", broken)
    agent = _agent(client)

    response = _send(client, agent, [ev(1102, _ago(1)), fail("ana", _ago(1))])

    assert response["stored"] == 2
    assert client.get(f"{API}/events").json()["total"] == 2
    # El heartbeat sigue funcionando con normalidad.
    heartbeat = client.post(f"{API}/agents/heartbeat", json={"agent_id": agent})
    assert heartbeat.status_code == 200


def test_untrusted_event_data_is_sanitized(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    hostile = "<img src=x onerror=alert(1)>\x1b[2J\r\nadmin"
    _send(client, agent, [*(fail(hostile + "x" * 450, _ago(3 - i * 0.1)) for i in range(5))])

    _run(engine)

    (auth,) = _detections(client)
    assert "\x1b" not in auth["summary"] and "\n" not in auth["summary"]
    assert len(auth["summary"]) <= 1000
    # El sujeto (clave de deduplicación) queda acotado a 255 y sin controles.
    assert "\x1b" not in auth["summary"] and "<img" in auth["summary"]  # texto, no HTML
    detail = _detail(client, auth["detection_id"])
    assert all(len(str(v)) <= 512 for e in detail["evidence"] for v in (e["data"] or {}).values())


@pytest.mark.parametrize(
    "data",
    [
        {"Bad Key!": "x"},
        {"TargetUserName": "a\x00b"},
        {"TargetUserName": "x" * 513},
        {f"Field{i}": "x" for i in range(17)},
    ],
)
def test_invalid_event_data_is_rejected(client: TestClient, data: dict[str, str]) -> None:
    agent = _agent(client)
    event = ev(4625, _ago(1))
    event["data"] = data
    response = client.post(f"{API}/events", json={"agent_id": agent, "events": [event]})
    assert response.status_code == 422


def test_engine_disabled_records_nothing(client: TestClient, engine: Engine, db: Session) -> None:
    from app.api import deps

    app = client.app
    app.dependency_overrides[deps.get_detection_config] = lambda: DetectionConfig(  # type: ignore[attr-defined]
        enabled=False
    )
    try:
        agent = _agent(client)
        _send(client, agent, [ev(1102, _ago(1))])
    finally:
        app.dependency_overrides.pop(deps.get_detection_config)  # type: ignore[attr-defined]
    assert db.scalar(select(func.count()).select_from(DetectionSignal)) == 0


def test_disabled_rule_is_not_evaluated(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    _send(client, agent, [ev(1102, _ago(1))])

    _run(engine, DetectionConfig(disabled_rules=frozenset({"DEF-001"})))

    assert _detections(client) == []


# --- Evidencia, reevaluación y retención --------------------------------------------------------


def test_evidence_is_capped(client: TestClient, engine: Engine, db: Session) -> None:
    agent = _agent(client)
    for chunk in range(3):
        _send(client, agent, [fail("ana", _ago(4.9 - chunk * 1.5 - i * 0.01)) for i in range(50)])
    _run(engine)

    (auth,) = _detections(client)
    detail = _detail(client, auth["detection_id"])
    assert detail["evidence_total"] == MAX_EVIDENCE == len(detail["evidence"])


def test_reevaluation_is_idempotent(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    _send(client, agent, [*(fail("ana", _ago(5 - i)) for i in range(5)), success("ana", _ago(0))])
    _run(engine)
    before = {d["rule_id"]: (d["occurrence_count"], d["severity"]) for d in _detections(client)}

    with sessionmaker(bind=engine)() as session:
        queued = DetectionEngine(session, CONFIG).reevaluate(_ago(60))
    _run(engine)

    assert queued == 6
    after = {d["rule_id"]: (d["occurrence_count"], d["severity"]) for d in _detections(client)}
    assert after == before


def test_retention_keeps_open_detections_and_purges_old_resolved(
    client: TestClient, engine: Engine, db: Session
) -> None:
    detection = _one_detection(client, engine)
    agent = _agent(client, "PC-OTHER")
    _send(client, agent, [ev(1102, _ago(1))])
    _run(engine)
    client.post(f"{API}/detections/{detection['detection_id']}/resolve")
    db.execute(
        text(
            "UPDATE detections SET resolved_at = now() - interval '40 days'"
            " WHERE status = 'resolved'"
        )
    )
    db.commit()

    result = RetentionService(db, RetentionPolicy(None, None, detection_days=30)).purge()

    assert result.detections == 1
    remaining = db.scalars(select(Detection)).all()
    assert [d.status for d in remaining] == [DetectionStatus.OPEN]
    # La evidencia de la purgada se fue en cascada; la de la abierta sigue.
    owners = set(db.scalars(select(DetectionEvidence.detection_id)))
    assert owners == {remaining[0].id}


def test_expired_signals_are_purged_but_evidence_survives(
    client: TestClient, engine: Engine, db: Session
) -> None:
    detection = _one_detection(client, engine)
    db.execute(text("UPDATE detection_signals SET created_at = now() - interval '3 days'"))
    db.commit()

    purged = DetectionEngine(db, CONFIG).purge_signals()

    assert purged == 1
    assert len(_detail(client, detection["detection_id"])["evidence"]) == 1


def test_signals_module_exposes_every_kind_used_by_rules() -> None:
    used = {kind for rule in rules_module.RULES for kind in rule.meta.triggers}
    assert used <= set(signals_module.SignalKind)
    ids = [rule.meta.id for rule in rules_module.RULES]
    assert len(ids) == len(set(ids))
    for rule in rules_module.RULES:
        meta = rule.meta
        assert meta.recommendations and meta.why and meta.required_data, meta.id
        # Una sola señal débil nunca es crítica por defecto.
        if meta.kind == "single":
            assert meta.severity != "critical", meta.id


# --- Migración 0018 con datos existentes ---------------------------------------------------------


def test_migration_0018_round_trip_keeps_existing_data(client: TestClient, engine: Engine) -> None:
    from alembic import command

    from tests.conftest import _alembic_config

    agent = _agent(client)
    _send(
        client,
        agent,
        [ev(1102, _ago(2), level="critical", SubjectUserName="eve"), fail("a", _ago(1))],
    )
    _run(engine)
    assert _detections(client)  # hay detección y alerta security_detection

    def counts() -> dict[str, int]:
        with engine.connect() as connection:
            return {
                table: connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()  # noqa: S608
                for table in ("assets", "system_events", "alerts", "users", "audit_events")
            }

    before = counts()
    config = _alembic_config(str(engine.url.render_as_string(hide_password=False)))
    try:
        command.downgrade(config, "0017")
        after_down = counts()
        # Solo desaparecen las alertas security_detection (no existen antes de la 0018).
        assert after_down == {**before, "alerts": before["alerts"] - 1}
        with engine.connect() as connection:
            assert connection.execute(text("SELECT to_regclass('detections')")).scalar() is None
    finally:
        command.upgrade(config, "head")
    assert counts() == {**before, "alerts": before["alerts"] - 1}
    # El esquema vuelve a funcionar entero: se puede ingerir y detectar de nuevo.
    _send(client, agent, [ev(1102, _ago(1), level="critical")])
    _run(engine)
    assert [d["rule_id"] for d in _detections(client)] == ["DEF-001"]
