"""Investigación forense (6E.6) y aislamiento seguro (6E.7) sobre el Response Engine.

Ningún test toca un firewall real: el "agente" es el TestClient y el resultado del helper se
simula con el JSON del contrato (docs/fase-6e-contracts.md).
"""

import hashlib
import io
import json
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.isolation.state import sweep_isolation
from app.models.alert import Alert, AlertRule, AlertStatus
from app.models.audit import AuditEvent
from app.models.forensics import EvidencePackage, ForensicArtifact
from app.models.isolation import IsolationSession
from app.models.response import AgentCommand
from app.response.playbooks import PlaybookError, validate_steps
from app.services.forensics_service import canonical
from tests.conftest import authenticate
from tests.test_response import ALL_CAPS, HEARTBEAT, R, _agent, _error, _execute, _ok, _result
from tests.test_risk import _discovered

API = "/api/v1"
INV = f"{API}/investigations"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _investigation(client: TestClient, asset_id: str, title: str = "Caso de prueba") -> str:
    body = _ok(client.post(INV, json={"asset_id": asset_id, "title": title}), 201)
    return str(body["id"])


def _poll(client: TestClient, agent_id: str) -> list[dict[str, Any]]:
    body = _ok(client.post(f"{API}/agents/commands/poll", json={"agent_id": agent_id}))
    commands: list[dict[str, Any]] = body["commands"]
    return commands


def _artifact(kind: str, content: dict[str, Any], sha: str | None = None) -> dict[str, Any]:
    return {
        "artifact": {
            "schema": "sentra-forensic/1",
            "kind": kind,
            "collected_at": datetime.now(UTC).isoformat(),
            "agent_version": "0.5.0",
            "platform": "windows",
            "content": content,
            "sha256": sha or hashlib.sha256(canonical(content)).hexdigest(),
            "truncated": False,
        },
        "limitations": [{"code": "permission_denied", "detail": "2 procesos sin acceso"}],
    }


def _collect(
    client: TestClient,
    agent: dict[str, str],
    investigation: str,
    content: dict[str, Any],
    *,
    action: str = "forensic_processes",
    sha: str | None = None,
) -> dict[str, Any]:
    out = _ok(
        _execute(client, action, agent["asset_id"], investigation_id=investigation, confirm=True)
    )
    assert out["status"] == "queued"
    commands = _poll(client, agent["agent_id"])
    assert [c["type"] for c in commands] == [action]
    _ok(
        _result(
            client,
            agent["agent_id"],
            commands[0]["request_id"],
            data=_artifact(action, content, sha),
        )
    )
    execution = _ok(client.get(f"{R}/executions/{out['execution_id']}"))
    return execution


# --- 6E.6 forense --------------------------------------------------------------------------


def test_forensic_collection_stores_verified_artifact(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    investigation = _investigation(client, agent["asset_id"])
    content = {"items": [{"pid": 4, "name": "System", "ratio": 0.1}], "total": 1}
    execution = _collect(client, agent, investigation, content)
    assert execution["status"] == "succeeded"
    reference = execution["result"]["data"]
    assert reference["integrity"] == "verified"
    assert reference["sha256"] == hashlib.sha256(canonical(content)).hexdigest()

    detail = _ok(client.get(f"{INV}/{investigation}"))
    assert detail["investigation"]["artifact_count"] == 1
    assert [c["status"] for c in detail["collections"]] == ["succeeded"]
    artifact = detail["artifacts"][0]
    assert artifact["operator"] == "admin"
    assert artifact["limitations"][0]["code"] == "permission_denied"
    full = _ok(client.get(f"{INV}/{investigation}/artifacts/{artifact['id']}"))
    assert full["content"] == content
    row = db.scalar(select(ForensicArtifact))
    assert row is not None
    # Lo guardado es el JSON canónico exacto: su hash se puede volver a comprobar.
    assert hashlib.sha256(row.content.encode()).hexdigest() == row.sha256


def test_forensic_action_requires_an_open_investigation(client: TestClient) -> None:
    agent = _agent(client)
    error = _error(
        _execute(client, "forensic_processes", agent["asset_id"]), 409, "response_blocked"
    )
    assert "investigation_required" in {d.get("code") for d in error["details"]}
    other = _agent(client, hostname="PC-OTHER")
    foreign = _investigation(client, other["asset_id"])
    mismatch = _execute(client, "forensic_processes", agent["asset_id"], investigation_id=foreign)
    assert "investigation_mismatch" in {
        d.get("code") for d in _error(mismatch, 409, "response_blocked")["details"]
    }
    not_forensic = _execute(
        client, "collect_inventory", agent["asset_id"], investigation_id=foreign
    )
    _error(not_forensic, 422, "investigation_not_applicable")
    with pytest.raises(PlaybookError):
        validate_steps([{"action_id": "forensic_processes"}])


def test_hash_mismatch_is_flagged_and_package_needs_acknowledgement(
    client: TestClient, db: Session
) -> None:
    agent = _agent(client)
    investigation = _investigation(client, agent["asset_id"])
    _collect(client, agent, investigation, {"items": [], "total": 0})
    _collect(
        client,
        agent,
        investigation,
        {"items": [{"name": "svc"}], "total": 1},
        action="forensic_services",
        sha="0" * 64,
    )
    detail = _ok(client.get(f"{INV}/{investigation}"))
    assert detail["investigation"]["mismatch_count"] == 1
    note = {"kind": "ai_summary", "body": "Posible persistencia; revisar servicio svc."}
    _ok(client.post(f"{INV}/{investigation}/notes", json=note), 201)

    refused = client.post(f"{INV}/{investigation}/package", json={})
    _error(refused, 409, "evidence_integrity_mismatch")
    response = client.post(f"{INV}/{investigation}/package", json={"acknowledge_mismatch": True})
    assert response.status_code == 200, response.text
    digest = response.headers["x-sentra-sha256"]
    assert hashlib.sha256(response.content).hexdigest() == digest
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        names = archive.namelist()
        interpretations = json.loads(archive.read("interpretations/notes.json"))
        for entry in manifest["artifacts"]:
            data = archive.read(entry["file"])
            assert hashlib.sha256(data).hexdigest() == entry["sha256"]
            assert entry["stored_hash_verified"] is True
    assert manifest["includes_mismatch"] is True
    assert {a["integrity"] for a in manifest["artifacts"]} == {"verified", "mismatch"}
    assert sum(n.startswith("evidence/") for n in names) == 2
    assert interpretations["items"][0]["kind"] == "ai_summary"
    custody = {e["action"] for e in manifest["chain_of_custody"]}
    assert {"investigation_created", "forensic_artifact_received", "response_completed"} <= custody
    package = db.scalar(select(EvidencePackage))
    assert package is not None
    assert package.sha256 == digest
    assert package.includes_mismatch is True
    audit = db.scalar(select(AuditEvent).where(AuditEvent.action == "evidence_package_downloaded"))
    assert audit is not None


def test_invalid_artifact_fails_the_collection(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    investigation = _investigation(client, agent["asset_id"])
    out = _ok(
        _execute(client, "forensic_sessions", agent["asset_id"], investigation_id=investigation)
    )
    command = _poll(client, agent["agent_id"])[0]
    wrong = _artifact("forensic_processes", {"items": []})
    _ok(_result(client, agent["agent_id"], command["request_id"], data=wrong))
    execution = _ok(client.get(f"{R}/executions/{out['execution_id']}"))
    assert execution["status"] == "failed"
    assert execution["error_code"] == "artifact_invalid"
    assert db.scalar(select(ForensicArtifact)) is None
    _error(client.post(f"{INV}/{investigation}/package", json={}), 409, "evidence_empty")


def test_file_metadata_params_are_validated_and_delivered(
    client: TestClient, engine: Engine
) -> None:
    agent = _agent(client)
    investigation = _investigation(client, agent["asset_id"])
    for bad in (
        "relative\\file.txt",
        "C:\\Windows\\..\\secret",
        "\\\\server\\share\\x",
        "C:\\a:ads",
    ):
        response = _execute(
            client,
            "forensic_file_metadata",
            agent["asset_id"],
            investigation_id=investigation,
            parameters={"path": bad},
            confirm=True,
        )
        _error(response, 422, "response_invalid_parameters")
    posix = _execute(
        client,
        "forensic_file_metadata",
        agent["asset_id"],
        investigation_id=investigation,
        parameters={"path": "/etc/passwd"},
        confirm=True,
    )
    assert "path_platform_mismatch" in {
        d.get("code") for d in _error(posix, 409, "response_blocked")["details"]
    }
    params = {"path": "C:\\Windows\\System32\\drivers\\etc\\hosts", "hash": True}
    _ok(
        _execute(
            client,
            "forensic_file_metadata",
            agent["asset_id"],
            investigation_id=investigation,
            parameters=params,
            confirm=True,
        )
    )
    assert _poll(client, agent["agent_id"])[0]["params"] == params
    # MEDIUM: un analista recoge procesos pero no metadatos de ficheros.
    authenticate(client, engine, "analyst")
    denied = _execute(
        client,
        "forensic_file_metadata",
        agent["asset_id"],
        investigation_id=investigation,
        parameters=params,
        confirm=True,
    )
    assert denied.status_code == 403


def test_two_investigations_do_not_deduplicate_each_other(client: TestClient) -> None:
    agent = _agent(client)
    first = _investigation(client, agent["asset_id"])
    second = _investigation(client, agent["asset_id"], "Otro caso")
    a = _ok(_execute(client, "forensic_processes", agent["asset_id"], investigation_id=first))
    b = _ok(_execute(client, "forensic_processes", agent["asset_id"], investigation_id=second))
    assert a["execution_id"] != b["execution_id"]
    again = _ok(_execute(client, "forensic_processes", agent["asset_id"], investigation_id=first))
    assert again["execution_id"] == a["execution_id"]


def test_closed_investigation_and_permissions(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    investigation = _investigation(client, agent["asset_id"])
    authenticate(client, engine, "analyst")
    _ok(client.post(f"{INV}/{investigation}/notes", json={"body": "Nota del analista"}), 201)
    assert client.post(f"{INV}/{investigation}/close", json={"version": 1}).status_code == 403
    authenticate(client, engine, "viewer")
    assert client.get(INV).status_code == 403
    authenticate(client, engine, "admin")
    _ok(client.post(f"{INV}/{investigation}/legal-hold", json={"version": 1, "legal_hold": True}))
    _error(
        client.post(f"{INV}/{investigation}/close", json={"version": 1}),
        409,
        "investigation_version_conflict",
    )
    closed = _ok(client.post(f"{INV}/{investigation}/close", json={"version": 2}))
    assert closed["status"] == "closed"
    assert closed["legal_hold"] is True
    _error(
        client.post(f"{INV}/{investigation}/notes", json={"body": "x"}), 409, "investigation_closed"
    )
    blocked = _execute(
        client, "forensic_processes", agent["asset_id"], investigation_id=investigation
    )
    assert "investigation_closed" in {
        d.get("code") for d in _error(blocked, 409, "response_blocked")["details"]
    }
    listed = _ok(client.get(INV, params={"asset_id": agent["asset_id"], "status": "closed"}))
    assert listed["total"] == 1


# --- 6E.7 aislamiento ------------------------------------------------------------------------


@pytest.fixture
def isolation_on(client: TestClient) -> Iterator[None]:
    settings = get_settings().model_copy(update={"isolation_enabled": True})
    client.app.dependency_overrides[get_settings] = lambda: settings  # type: ignore[attr-defined]
    yield
    client.app.dependency_overrides.pop(get_settings, None)  # type: ignore[attr-defined]


def _iso(client: TestClient, asset_id: str, **extra: Any) -> Any:
    body = {
        "duration_minutes": 30,
        "reason": "Equipo con beacon sospechoso, contener",
        "confirm_name": "PC-ADMIN-01",
        **extra,
    }
    return client.post(f"{API}/assets/{asset_id}/isolation", json=body)


def _helper_report(state: str, session_id: str | None, verified: bool = True) -> dict[str, Any]:
    return {
        "helper": "ready",
        "state": state,
        "session_id": session_id,
        "applied_at": datetime.now(UTC).isoformat() if state == "isolated" else None,
        "expires_at": None,
        "method": "windows_firewall" if state == "isolated" else None,
        "verified": verified,
        "error_code": None,
    }


def _isolation_result(session_id: str, state: str = "isolated") -> dict[str, Any]:
    return {
        "isolation": {
            "state": state,
            "session_id": session_id,
            "applied_at": datetime.now(UTC).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(minutes=30)).isoformat(),
            "method": "windows_firewall",
            "allowed": ["203.0.113.10", "127.0.0.0/8"],
            "rules": [{"name": "Sentra Isolation out", "direction": "outbound", "action": "block"}],
            "verified": True,
            "error_code": None,
        }
    }


def _alert(db: Session) -> Alert | None:
    db.expire_all()
    return db.scalar(select(Alert).where(Alert.rule == AlertRule.ISOLATION_STATE))


def test_devices_without_agent_cannot_be_isolated(client: TestClient, db: Session) -> None:
    asset = _discovered(db, name="impresora")
    overview = _ok(client.get(f"{API}/assets/{asset.public_id}/isolation"))
    assert overview["available"] is False
    assert overview["unavailable_message"] == "Aislamiento no disponible para este dispositivo"
    assert overview["manual_recommendations"]
    mac = _agent(client, os_name="macOS", hostname="MAC-01")
    overview = _ok(client.get(f"{API}/assets/{mac['asset_id']}/isolation"))
    assert "unsupported_platform" in {r["code"] for r in overview["reasons"]}
    assert overview["unavailable_message"] == "Aislamiento no disponible para este dispositivo"


def test_isolation_is_disabled_by_default(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    overview = _ok(client.get(f"{API}/assets/{agent['asset_id']}/isolation"))
    assert overview["server_enabled"] is False
    assert "isolation_disabled" in {r["code"] for r in overview["reasons"]}
    _error(_iso(client, agent["asset_id"]), 409, "isolation_disabled")
    assert db.scalar(select(IsolationSession)) is None


def test_isolation_requires_confirmation_duration_and_helper(
    client: TestClient, db: Session, isolation_on: None
) -> None:
    agent = _agent(client)
    _error(
        _iso(client, agent["asset_id"], confirm_name="otro"), 422, "isolation_confirmation_mismatch"
    )
    _error(
        _iso(client, agent["asset_id"], duration_minutes=600),
        422,
        "isolation_duration_exceeds_policy",
    )
    no_helper = _agent(client, caps=[c for c in ALL_CAPS if c != "isolate_host"], hostname="PC-2")
    overview = _ok(client.get(f"{API}/assets/{no_helper['asset_id']}/isolation"))
    assert "helper_unavailable" in {r["code"] for r in overview["reasons"]}
    error = _error(
        _iso(client, no_helper["asset_id"], confirm_name="PC-2"), 409, "response_blocked"
    )
    assert "unsupported_capability" in {d.get("code") for d in error["details"]}
    row = db.scalar(select(IsolationSession))
    assert row is not None
    assert row.status == "failed"
    assert row.error_code == "unsupported_capability"
    assert db.scalar(select(AgentCommand)) is None


def test_isolation_lifecycle_with_verified_helper(
    client: TestClient, db: Session, engine: Engine, isolation_on: None
) -> None:
    agent = _agent(client)
    session = _ok(_iso(client, agent["asset_id"]))
    assert session["status"] == "applying"
    assert session["approved_by"] == "admin"
    _error(_iso(client, agent["asset_id"]), 409, "isolation_unavailable")
    command = _poll(client, agent["agent_id"])[0]
    assert command["type"] == "isolate_host"
    assert command["params"]["session_id"] == session["id"]
    # El servidor solo manda sesión y caducidad: nunca direcciones permitidas.
    assert set(command["params"]) == {"session_id", "expires_at"}
    _ok(
        _result(
            client, agent["agent_id"], command["request_id"], data=_isolation_result(session["id"])
        )
    )
    current = _ok(client.get(f"{API}/assets/{agent['asset_id']}/isolation"))["current"]
    assert current["status"] == "isolated"
    assert current["verified"] is True
    assert current["method"] == "windows_firewall"

    # El equipo dice que no está aislado antes de caducar: discrepancia → unknown + alerta.
    beat = {"agent_id": agent["agent_id"], "isolation": _helper_report("none", None)}
    _ok(client.post(HEARTBEAT, json=beat))
    current = _ok(client.get(f"{API}/assets/{agent['asset_id']}/isolation"))["current"]
    assert current["status"] == "unknown"
    assert current["error_code"] == "rules_lost"
    alert = _alert(db)
    assert alert is not None
    assert alert.status == AlertStatus.OPEN
    # Vuelve a informar aislado y verificado: coincide otra vez y la alerta se resuelve.
    beat["isolation"] = _helper_report("isolated", session["id"])
    _ok(client.post(HEARTBEAT, json=beat))
    current = _ok(client.get(f"{API}/assets/{agent['asset_id']}/isolation"))["current"]
    assert current["status"] == "isolated"
    alert = _alert(db)
    assert alert is not None
    assert alert.status == AlertStatus.RESOLVED

    authenticate(client, engine, "analyst")
    denied = client.post(
        f"{API}/assets/{agent['asset_id']}/isolation/release",
        json={"version": current["version"], "reason": "falso positivo"},
    )
    assert denied.status_code == 403
    authenticate(client, engine, "admin")
    released = _ok(
        client.post(
            f"{API}/assets/{agent['asset_id']}/isolation/release",
            json={"version": current["version"], "reason": "Analizado: falso positivo"},
        )
    )
    assert released["status"] == "reverting"
    command = _poll(client, agent["agent_id"])[0]
    assert command["type"] == "release_isolation"
    assert command["params"] == {"session_id": session["id"]}
    _ok(
        _result(
            client,
            agent["agent_id"],
            command["request_id"],
            data=_isolation_result(session["id"], "restored"),
        )
    )
    history = _ok(client.get(f"{API}/assets/{agent['asset_id']}/isolation/sessions"))
    assert history["items"][0]["status"] == "restored"
    actions = set(
        db.scalars(select(AuditEvent.action).where(AuditEvent.target_type == "isolation_session"))
    )
    assert {
        "isolation_requested",
        "isolation_approved",
        "isolation_dispatched",
        "isolation_applied",
        "isolation_state_unknown",
        "isolation_release_requested",
        "isolation_restored",
    } <= actions


def test_failed_helper_result_and_expiry(
    client: TestClient, db: Session, isolation_on: None
) -> None:
    agent = _agent(client)
    session = _ok(_iso(client, agent["asset_id"]))
    command = _poll(client, agent["agent_id"])[0]
    data = _isolation_result(session["id"], "failed")
    _ok(
        _result(
            client,
            agent["agent_id"],
            command["request_id"],
            status="failed",
            error_code="firewall_disabled",
            data=data,
        )
    )
    failed = _ok(client.get(f"{API}/assets/{agent['asset_id']}/isolation/sessions"))["items"][0]
    assert failed["status"] == "failed"
    assert failed["error_code"] == "firewall_disabled"

    session = _ok(_iso(client, agent["asset_id"]))
    command = _poll(client, agent["agent_id"])[0]
    _ok(
        _result(
            client, agent["agent_id"], command["request_id"], data=_isolation_result(session["id"])
        )
    )
    db.execute(
        update(IsolationSession)
        .where(IsolationSession.public_id == UUID(session["id"]))
        .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
    )
    db.commit()
    beat = {"agent_id": agent["agent_id"], "isolation": _helper_report("none", None)}
    _ok(client.post(HEARTBEAT, json=beat))
    current = _ok(client.get(f"{API}/assets/{agent['asset_id']}/isolation/sessions"))["items"][0]
    assert current["status"] == "expired"
    assert _alert(db) is None


def test_undelivered_isolation_fails_on_sweep(
    client: TestClient, db: Session, isolation_on: None
) -> None:
    agent = _agent(client)
    session = _ok(_iso(client, agent["asset_id"]))
    # El comando caduca sin entregarse (agente que no vuelve a sondear).
    db.execute(update(AgentCommand).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    db.commit()
    from app.services.response_service import ResponseService

    ResponseService(db, get_settings()).sweep()
    sweep_isolation(db)
    db.expire_all()
    row = db.scalar(
        select(IsolationSession).where(IsolationSession.public_id == UUID(session["id"]))
    )
    assert row is not None
    assert row.status == "failed"


def test_host_isolated_without_session_raises_alert(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    beat = {"agent_id": agent["agent_id"], "isolation": _helper_report("isolated", str(uuid4()))}
    _ok(client.post(HEARTBEAT, json=beat))
    alert = _alert(db)
    assert alert is not None
    assert alert.status == AlertStatus.OPEN
    # Un agente anterior (sin el campo) sigue funcionando igual.
    _ok(client.post(HEARTBEAT, json={"agent_id": agent["agent_id"]}))


def test_isolate_host_is_never_a_loose_response_action(client: TestClient) -> None:
    agent = _agent(client)
    response = _execute(
        client,
        "release_isolation",
        agent["asset_id"],
        confirm=True,
        parameters={"session_id": str(uuid4())},
    )
    error = _error(response, 409, "response_blocked")
    assert "isolation_session_required" in {d.get("code") for d in error["details"]}
