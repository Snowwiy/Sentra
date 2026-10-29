"""Fase 7A.8: contexto de PowerShell, NET-001 con proceso y excepciones exactas.

Eventos sintéticos con la forma del agente 0.6.0 (ruta, hash, PID, palabras clave; nunca el
contenido del script). El motor se ejecuta a mano, como el job interno.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from itertools import count
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.detection.config import DetectionConfig
from app.detection.engine import DetectionEngine
from app.detection.recorder import SignalRecorder
from app.detection.script_context import powershell_values, sentra_module
from app.models.asset import Asset
from app.models.change import ChangeKind
from app.models.endpoint import DetectionExclusion, ProcessInstance
from app.services.alert_service import AlertThresholds
from tests.conftest import agent_payload

API = "/api/v1"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
CONFIG = DetectionConfig()
SHA = "a" * 64
OTHER_SHA = "b" * 64
SCRIPT = "C:\\Sentra\\agent\\packaging\\windows\\install-sentra-agent.ps1"
_records = count(10_000)


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


def _block(
    at: datetime, path: str | None = SCRIPT, sha: str | None = SHA, **extra: str
) -> dict[str, Any]:
    data = {
        "ScriptBlockId": str(uuid4()),
        "MessageNumber": "1",
        "MessageTotal": "1",
        "ProcessID": "4242",
        "UserID": "S-1-5-21-1-2-3-500",
        "SuspiciousKeywords": "InteropServices,Marshal",
        **extra,
    }
    if path:
        data["Path"] = path
    if sha:
        data["ScriptSha256"] = sha
    return {
        "source": "windows_eventlog",
        "channel": POWERSHELL,
        "record_id": next(_records),
        "event_code": 4104,
        "provider": "Microsoft-Windows-PowerShell",
        "level": "warning",
        "message": "Microsoft-Windows-PowerShell event 4104 (content not collected)",
        "occurred_at": at.isoformat(),
        "data": data,
    }


def _service(at: datetime, name: str = "SentraAgent") -> dict[str, Any]:
    return {
        "source": "windows_eventlog",
        "channel": "System",
        "record_id": next(_records),
        "event_code": 7045,
        "provider": "Service Control Manager",
        "level": "warning",
        "message": "event 7045",
        "occurred_at": at.isoformat(),
        "data": {
            "ServiceName": name,
            "ImagePath": (
                '"C:\\Program Files\\Sentra Agent\\runtime\\python.exe" -I -m sentra_agent'
            ),
            "AccountName": "LocalSystem",
        },
    }


def _send(client: TestClient, agent: str, events: list[dict[str, Any]]) -> None:
    response = client.post(f"{API}/events", json={"agent_id": agent, "events": events})
    assert response.status_code == 201, response.text


def _process(db: Session, asset_id: int, pid: int, **fields: Any) -> ProcessInstance:
    now = datetime.now(UTC)
    row = ProcessInstance(
        asset_id=asset_id,
        instance_key=uuid4().hex,
        boot_id="boot-1",
        pid=pid,
        source="etw",
        started_at=now - timedelta(hours=1),
        first_seen_at=now - timedelta(hours=1),
        last_seen_at=now,
        **fields,
    )
    db.add(row)
    db.commit()
    return row


def _detections(client: TestClient, rule_id: str) -> list[dict[str, Any]]:
    response = client.get(f"{API}/detections", params={"rule_id": rule_id, "limit": 100})
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


def _details(client: TestClient, detection: dict[str, Any]) -> dict[str, Any]:
    body = client.get(f"{API}/detections/{detection['detection_id']}").json()
    details: dict[str, Any] = body["details"]
    return details


def _exclusion(client: TestClient, **body: Any) -> Any:
    payload = {
        "reason": "Instalador del agente revisado",
        "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        **body,
    }
    return client.post(f"{API}/detection-exclusions", json=payload)


# --- Valores del 4104 ---------------------------------------------------------------------------


def test_untrusted_values_are_validated() -> None:
    values = powershell_values(
        {
            "Path": "C:\\x\\Script.ps1",
            "ScriptSha256": "not-a-hash",
            "ScriptBlockId": "<script>",
            "ProcessID": "-1",
            "UserID": "nobody",
            "SuspiciousKeywords": "Marshal, marshal ,rm -rf /,Add-Type",
        }
    )
    assert values["script_name"] == "script.ps1"
    assert values["script_sha256"] is None and values["script_block_id"] is None
    assert values["pid"] is None and values["user_sid"] is None
    # Solo palabras del vocabulario cerrado, sin duplicados: nunca texto libre del host.
    assert values["keywords"] == ["Marshal", "Add-Type"]
    assert values["script_origin"] == "file"
    assert powershell_values({})["script_origin"] is None


def test_sentra_component_is_recognised_by_command_line() -> None:
    assert (
        sentra_module('"C:\\Program Files\\Sentra\\python.exe" -I -m sentra_agent --service')
        == "sentra_agent"
    )
    assert sentra_module("python.exe -m uvicorn app.main:app --port 8000") == "sentra_api"
    assert sentra_module("powershell.exe -File x.ps1") is None


# --- SCR-001 v2 ---------------------------------------------------------------------------------


def test_scr_001_explains_script_process_and_cause(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    parent = _process(db, asset_id, 900, name="explorer.exe", exe="C:\\Windows\\explorer.exe")
    _process(
        db,
        asset_id,
        4242,
        name="powershell.exe",
        exe="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmdline="powershell.exe -File install-sentra-agent.ps1 [redacted]",
        username="PC\\admin",
        signer="Microsoft Windows",
        parent_instance_key=parent.instance_key,
    )
    _send(client, agent, [_block(_ago(2))])
    _run(engine)

    (detection,) = _detections(client, "SCR-001")
    assert "install-sentra-agent.ps1" in detection["summary"]
    assert "InteropServices, Marshal" in detection["summary"]
    assert "desde explorer.exe" in detection["summary"]
    details = _details(client, detection)
    assert details["script"]["script_sha256"] == SHA
    assert details["process"]["process_signer"] == "Microsoft Windows"
    assert details["process"]["parent_name"] == "explorer.exe"
    assert details["user_sid"] == "S-1-5-21-1-2-3-500"
    assert details["trigger"]["keywords"] == ["InteropServices", "Marshal"]
    assert details["sentra"]["script_name_match"] is True
    assert details["missing_context"] == []
    text = " ".join(details["explanation"])
    # El nombre de un script de Sentra se avisa, pero nunca rebaja la detección.
    assert "no prueba el origen" in text and "SecureString" in text
    assert detection["severity"] == "medium"


def test_powershell_7_channel_is_detected_too(
    client: TestClient, engine: Engine, db: Session
) -> None:
    """Fase 7B.0: un 4104 de pwsh (PowerShellCore/Operational, agente 0.6.1) da SCR-001."""
    agent, _ = _agent(client, db)
    block = _block(_ago(2))
    block["channel"] = "PowerShellCore/Operational"
    block["provider"] = "PowerShellCore"
    _send(client, agent, [block])
    _run(engine)
    (detection,) = _detections(client, "SCR-001")
    assert _details(client, detection)["script"]["powershell"] == "core"


def test_missing_context_is_reported_not_invented(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, _ = _agent(client, db)
    old_agent = _block(_ago(3), path=None, sha=None)
    old_agent["data"] = {}
    _send(client, agent, [old_agent, _block(_ago(2), path=None, sha=None)])
    _run(engine)

    by_key = {
        tuple(_details(client, d)["missing_context"]): d for d in _detections(client, "SCR-001")
    }
    assert ("agent_without_script_context",) in by_key
    inline = by_key[("process_not_in_telemetry",)]
    assert "en línea" in inline["summary"]


# --- Excepciones exactas ------------------------------------------------------------------------


def test_script_exclusions_must_be_exact_and_expire(client: TestClient, db: Session) -> None:
    _, asset_id = _agent(client, db)
    asset = str(db.scalar(select(Asset.public_id).where(Asset.id == asset_id)))
    too_broad: list[dict[str, Any]] = [
        {"rule_id": "SCR-001", "field": "name", "value": "powershell.exe"},
        {"rule_id": "SCR-001", "field": "script_path", "value": SCRIPT},  # sin hash
        {"rule_id": "SCR-001", "field": "script_sha256", "value": SHA, "expires_at": None},
        {
            "rule_id": "SCR-001",
            "field": "script_sha256",
            "value": SHA,
            "expires_at": (datetime.now(UTC) + timedelta(days=200)).isoformat(),
        },
        {"rule_id": "NET-001", "field": "exe", "value": "C:\\Py\\python.exe", "asset_id": asset},
        {"rule_id": "NET-001", "field": "exe", "value": "C:\\Py\\python.exe", "port": 8000},
        {"rule_id": "AUTH-001", "field": "script_path", "value": SCRIPT},
        # Un intérprete del sistema oculta todo lo que se ejecute con él, en cualquier regla.
        {
            "rule_id": "BEH-002",
            "field": "exe",
            "value": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        },
    ]
    for body in too_broad:
        response = _exclusion(client, **body)
        assert response.status_code == 422, body
        assert response.json()["error"]["code"] == "exclusion_too_broad", body
    created = _exclusion(
        client, rule_id="SCR-001", field="script_path", value=SCRIPT, require_sha256=SHA.upper()
    )
    assert created.status_code == 201, created.text
    assert created.json()["require_sha256"] == SHA
    port = _exclusion(
        client,
        rule_id="NET-001",
        field="exe",
        value="C:\\Sentra\\backend\\.venv\\Scripts\\python.exe",
        port=8000,
        asset_id=asset,
    )
    assert port.status_code == 201, port.text


def test_exclusion_by_path_and_hash_stops_matching_when_the_script_changes(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, _ = _agent(client, db)
    created = _exclusion(
        client, rule_id="SCR-001", field="script_path", value=SCRIPT.upper(), require_sha256=SHA
    )
    assert created.status_code == 201, created.text
    _send(client, agent, [_block(_ago(5))])
    _run(engine)
    assert _detections(client, "SCR-001") == []
    hits = db.scalars(select(DetectionExclusion.hits)).one()
    assert hits == 1

    # Mismo fichero, otro contenido: la excepción ya no cubre el script.
    _send(client, agent, [_block(_ago(1), sha=OTHER_SHA)])
    _run(engine)
    (detection,) = _detections(client, "SCR-001")
    assert _details(client, detection)["script"]["script_sha256"] == OTHER_SHA


def test_corr_002_ignores_excepted_scripts_but_keeps_the_rest(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, _ = _agent(client, db)
    assert (
        _exclusion(client, rule_id="CORR-002", field="script_sha256", value=SHA).status_code == 201
    )
    _send(client, agent, [_block(_ago(8)), _service(_ago(4))])
    _run(engine)
    # El instalador revisado más su servicio no correlacionan.
    assert _detections(client, "CORR-002") == []

    other = "C:\\Users\\Public\\x.ps1"
    # Fase 7B-Fix1 (CORR-002 v5): solo un script ANTERIOR a la instalación puede causarla.
    _send(client, agent, [_block(_ago(6), path=other, sha=OTHER_SHA)])
    _run(engine)
    (corr,) = _detections(client, "CORR-002")
    details = _details(client, corr)
    assert details["excluded_powershell_events"] == 1
    assert [s["script"]["script_path"] for s in details["scripts"]] == [other]
    assert details["persistence"]["source"] == "event_7045"
    assert details["persistence"]["sentra_service_name"] is True
    assert details["persistence"]["account"] == "LocalSystem"
    assert "servicio de Sentra" in " ".join(details["explanation"])
    assert corr["severity"] == "high"
    assert [link["code"] for link in details["causal_links"]] == ["install_event_after_script"]


# --- NET-001 con el proceso que escucha ---------------------------------------------------------


def test_exposed_port_names_its_process_and_can_be_excepted_exactly(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    exe = "C:\\Sentra\\backend\\.venv\\Scripts\\python.exe"
    _process(
        db,
        asset_id,
        5151,
        name="python.exe",
        exe=exe,
        cmdline=f"{exe} -m uvicorn app.main:app --host 0.0.0.0 --port 8000",
    )
    listener = {"protocol": "tcp", "status": "listen", "local_address": "0.0.0.0",  # noqa: S104
                "local_port": 8000, "process_name": "python.exe", "pid": 5151}  # fmt: skip
    body = {"agent_id": agent, "collected_at": _ago(1).isoformat(), "connections": [listener]}
    assert client.post(f"{API}/inventory", json=body).status_code == 201
    recorder = SignalRecorder(db, CONFIG)
    recorder.record_discovery_change(asset_id, ChangeKind.PORT_OPENED, "8000/tcp", _ago(1), {})
    db.commit()
    _run(engine)

    (detection,) = _detections(client, "NET-001")
    assert "python.exe (la API de Sentra)" in detection["summary"]
    details = _details(client, detection)
    assert details["owner"]["exe"] == exe and details["owner"]["pid"] == 5151
    assert "start_backend.ps1" in " ".join(details["explanation"])

    asset = str(db.scalar(select(Asset.public_id).where(Asset.id == asset_id)))
    created = _exclusion(
        client, rule_id="NET-001", field="exe", value=exe, port=8000, asset_id=asset
    )
    assert created.status_code == 201, created.text
    # La excepción se limita a 8000: el mismo ejecutable en otro puerto sigue detectándose.
    listener9 = {**listener, "local_port": 9000}
    body = {
        "agent_id": agent,
        "collected_at": _ago(0).isoformat(),
        "connections": [listener, listener9],
    }
    assert client.post(f"{API}/inventory", json=body).status_code == 201
    recorder.record_discovery_change(asset_id, ChangeKind.PORT_OPENED, "8000/tcp", _ago(0), {})
    recorder.record_discovery_change(asset_id, ChangeKind.PORT_OPENED, "9000/tcp", _ago(0), {})
    db.commit()
    _run(engine)
    ports = sorted(d["details"]["port"] if "details" in d else _details(client, d)["port"]
                   for d in _detections(client, "NET-001"))  # fmt: skip
    assert ports == [8000, 9000]
    hits = db.scalars(select(DetectionExclusion.hits).where(DetectionExclusion.port == 8000)).one()
    assert hits == 1
