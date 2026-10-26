"""Response Engine y Playbooks (Fase 5D): API de extremo a extremo con PostgreSQL real.

Datos sintéticos (agentes y activos de test). Los casos A-X del enunciado de la fase llevan
su letra en el nombre del test. El agente se simula con llamadas HTTP reales al protocolo
(heartbeat, poll, result) con su propio token, como hace sentra_agent.
"""

import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.permissions import ROLE_PERMISSIONS, Permission, Role
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.incident import Incident, IncidentActivity
from app.models.response import AgentCommand, PlaybookRun, ResponseExecution
from app.response import catalog
from app.response.catalog import ACTIONS, AGENT_COMMAND_TYPES
from app.response.playbooks import PlaybookError, validate_steps
from app.response.results import bounded_result
from app.schemas.response import CommandResultRequest, ExecutionRequest
from app.services import agent_service
from app.services.response_service import ResponseService
from tests.conftest import agent_payload, authenticate
from tests.test_risk import _detection, _discovered
from tests.test_telemetry import telemetry_payload

API = "/api/v1"
R = f"{API}/response"
HEARTBEAT = f"{API}/agents/heartbeat"
ALL_CAPS = sorted(AGENT_COMMAND_TYPES)


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _ok(response: Any, status: int = 200) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


def _error(response: Any, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()["error"]
    assert body["code"] == code, body
    return body


def _agent(client: TestClient, caps: list[str] | None = ALL_CAPS, **host: Any) -> dict[str, str]:
    """Agente registrado (con capacidades) y en línea."""
    payload = agent_payload(**host)
    if caps is not None:
        payload["capabilities"] = caps
    response = client.post(f"{API}/agents/register", json=payload)
    assert response.status_code == 201, response.text
    beat = client.post(HEARTBEAT, json={"agent_id": payload["agent_id"]})
    assert beat.status_code == 200, beat.text
    return {"agent_id": payload["agent_id"], "asset_id": response.json()["asset_id"]}


def _offline(db: Session, asset_id: str, minutes: float = 30) -> None:
    db.execute(
        update(Asset)
        .where(Asset.public_id == UUID(asset_id))
        .values(last_seen_at=datetime.now(UTC) - timedelta(minutes=minutes))
    )
    db.commit()


def _execute(client: TestClient, action: str, target: str, **extra: Any) -> Any:
    return client.post(f"{R}/executions", json={"action_id": action, "target_id": target, **extra})


def _poll(client: TestClient, agent_id: str, **headers: str) -> Any:
    return client.post(
        f"{API}/agents/commands/poll", json={"agent_id": agent_id}, headers=headers or None
    )


def _result(
    client: TestClient, agent_id: str, request_id: str, status: str = "succeeded", **extra: Any
) -> Any:
    body = {"agent_id": agent_id, "status": status, "summary": "ok", **extra}
    return client.post(f"{API}/agents/commands/{request_id}/result", json=body)


def _execution(db: Session, public_id: str) -> ResponseExecution:
    db.expire_all()
    row = db.scalar(select(ResponseExecution).where(ResponseExecution.public_id == UUID(public_id)))
    assert row is not None
    return row


def _audits(db: Session, action: str) -> list[AuditEvent]:
    db.expire_all()
    return list(
        db.scalars(select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id))
    )


def _service(db: Session, **overrides: Any) -> ResponseService:
    settings = get_settings().model_copy(update=overrides) if overrides else get_settings()
    return ResponseService(db, settings)


def _playbook(client: TestClient, key: str) -> dict[str, Any]:
    items = _ok(client.get(f"{R}/playbooks"))["items"]
    found: dict[str, Any] = next(p for p in items if p["key"] == key)
    return found


# --- A/B/C. RBAC ---------------------------------------------------------------------------


def test_a_viewer_reads_but_cannot_execute(client: TestClient, engine: Engine) -> None:
    agent = _agent(client)
    authenticate(client, engine, "viewer")
    listing = _ok(client.get(f"{R}/actions", params={"asset_id": agent["asset_id"]}))
    assert all(item["permitted"] is False for item in listing["items"])
    _error(_execute(client, "recalculate_risk", agent["asset_id"]), 403, "permission_denied")
    preview = client.post(
        f"{R}/preview", json={"action_id": "recalculate_risk", "target_id": agent["asset_id"]}
    )
    _error(preview, 403, "permission_denied")
    pb = _playbook(client, "refresh_asset_analysis")
    run = client.post(
        f"{R}/playbooks/{pb['playbook_id']}/execute", json={"target_id": agent["asset_id"]}
    )
    _error(run, 403, "permission_denied")


def test_b_analyst_runs_an_allowed_low_action(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _agent(client)
    authenticate(client, engine, "analyst")
    body = _ok(_execute(client, "recalculate_risk", agent["asset_id"]))
    assert body["status"] == "succeeded" and body["risk_level"] == "low"
    assert body["result_summary"]
    assert len(_audits(db, "response_completed")) == 1


def test_c_analyst_cannot_run_admin_only_actions(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _agent(client)
    authenticate(client, engine, "analyst")
    for action, extra in (
        ("open_incident", {"confirm": True}),
        ("archive_asset", {"confirm": True, "parameters": {"reason": "fuera de servicio"}}),
        ("reevaluate_vulnerabilities", {}),
    ):
        _error(_execute(client, action, agent["asset_id"], **extra), 403, "permission_denied")
    assert db.scalar(select(func.count()).select_from(ResponseExecution)) == 0
    assert db.scalar(select(func.count()).select_from(Incident)) == 0
    denied = _audits(db, "permission_denied")
    assert {(a.details or {}).get("action") for a in denied} >= {"open_incident", "archive_asset"}


def test_role_mapping_for_response() -> None:
    assert Permission.RESPONSE_READ in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.RESPONSE_EXECUTE not in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.RESPONSE_EXECUTE in ROLE_PERMISSIONS[Role.ANALYST]
    assert Permission.RESPONSE_MANAGE not in ROLE_PERMISSIONS[Role.ANALYST]
    for action in ACTIONS.values():
        if action.risk_level != "low":
            # MEDIUM o superior exige response:manage (admin).
            assert Permission.RESPONSE_MANAGE in action.required_permissions, action.id


# --- D/E. Preview y misma política ---------------------------------------------------------


def test_d_preview_has_no_side_effects(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    request = {"action_id": "open_incident", "target_id": agent["asset_id"]}
    preview = _ok(client.post(f"{R}/preview", json=request))
    assert preview["allowed"] is True and preview["requires_confirmation"] is True
    assert preview["risk_level"] == "medium" and preview["required_role"] == "admin"
    assert "confirmation_required" in {w["code"] for w in preview["warnings"]}
    assert preview["expected_effect"] and "action_allowlisted" in preview["preconditions"]
    assert db.scalar(select(func.count()).select_from(Incident)) == 0
    assert db.scalar(select(func.count()).select_from(ResponseExecution)) == 0
    # Solo se audita el preview de acciones mutativas.
    assert len(_audits(db, "response_preview_generated")) == 1
    # Sin confirmar no se ejecuta.
    _error(_execute(client, "open_incident", agent["asset_id"]), 422, "confirmation_required")
    assert db.scalar(select(func.count()).select_from(Incident)) == 0


def test_e_execution_uses_the_same_policy_as_preview(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    _offline(db, agent["asset_id"])
    request = {"action_id": "collect_inventory", "target_id": agent["asset_id"]}
    preview = _ok(client.post(f"{R}/preview", json=request))
    assert preview["allowed"] is False
    error = _error(client.post(f"{R}/executions", json=request), 409, "response_blocked")
    execution_id = error["details"][0]["execution_id"]
    blocked = _execution(db, execution_id)
    assert blocked.status == "blocked"
    assert {b["code"] for b in blocked.blockers or []} == {b["code"] for b in preview["blockers"]}
    assert db.scalar(select(func.count()).select_from(AgentCommand)) == 0


def test_not_implemented_actions_are_listed_but_never_run(client: TestClient) -> None:
    agent = _agent(client)
    listing = _ok(client.get(f"{R}/actions"))["items"]
    future = {a["id"]: a for a in listing if a["availability"] == "not_implemented"}
    assert {"kill_process", "block_network_address"} <= set(future)
    assert all(ACTIONS[a].handler is None for a in future)
    response = _execute(client, "kill_process", agent["asset_id"], confirm=True)
    _error(response, 409, "response_blocked")
    # Fase 6E.7: aislar existe, pero nunca como ejecución suelta de Response.
    isolate = _execute(
        client,
        "isolate_host",
        agent["asset_id"],
        confirm=True,
        parameters={"session_id": str(uuid4()), "expires_at": "2099-01-01T00:00:00Z"},
    )
    error = _error(isolate, 409, "response_blocked")
    assert "isolation_session_required" in {d.get("code") for d in error["details"]}


# --- F. Agente offline ---------------------------------------------------------------------


def test_f_offline_agent_never_fakes_success(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    _offline(db, agent["asset_id"])
    error = _error(_execute(client, "collect_events", agent["asset_id"]), 409, "response_blocked")
    assert "agent_offline" in {d.get("code") for d in error["details"]}
    # Con la política "queue" se encola con TTL (aviso), nunca se marca como hecha.
    service = _service(db, response_offline_agent_policy="queue")
    admin = _admin_operator(db)
    out = service.execute(
        admin,
        ExecutionRequest(action_id="collect_events", target_id=UUID(agent["asset_id"])),
    )
    assert out.status == "queued" and out.finished_at is None
    command = db.scalar(select(AgentCommand))
    assert command is not None and command.expires_at > datetime.now(UTC)


def _admin_operator(db: Session) -> Any:
    from app.models.user import User
    from app.services.response_service import Operator

    user = db.scalar(select(User).where(User.username == "admin"))
    assert user is not None
    return Operator.for_user(user, "127.0.0.1")


# --- G/H. Cola de comandos -----------------------------------------------------------------


def test_g_agent_receives_an_allowlisted_typed_command(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    queued = _ok(_execute(client, "collect_inventory", agent["asset_id"]))
    assert queued["status"] == "queued" and queued["requires_agent"] is True
    beat = _ok(client.post(HEARTBEAT, json={"agent_id": agent["agent_id"]}))
    assert beat["pending_commands"] == 1
    [command] = _ok(_poll(client, agent["agent_id"]))["commands"]
    assert command["type"] == "collect_inventory" and command["params"] == {}
    assert set(command) == {"request_id", "type", "params", "deadline_at"}
    assert _execution(db, queued["execution_id"]).status == "running"
    # Nada más que entregar: una segunda consulta no lo repite.
    assert _ok(_poll(client, agent["agent_id"]))["commands"] == []
    done = _ok(_result(client, agent["agent_id"], command["request_id"], data={"sections": {}}))
    assert done == {"accepted": True, "duplicate": False, "status": "completed"}
    final = _ok(client.get(f"{R}/executions/{queued['execution_id']}"))
    assert final["status"] == "succeeded" and final["result"]["data"] == {"sections": {}}


def test_h_agent_rejection_fails_the_execution(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    queued = _ok(_execute(client, "collect_processes", agent["asset_id"]))
    [command] = _ok(_poll(client, agent["agent_id"]))["commands"]
    _ok(_result(client, agent["agent_id"], command["request_id"], "rejected",
                error_code="unknown_command"))  # fmt: skip
    final = _execution(db, queued["execution_id"])
    assert final.status == "failed" and final.error_code == "unknown_command"
    # Un action_id fuera del catálogo no llega a crear nada.
    _error(_execute(client, "run_shell", agent["asset_id"]), 404, "not_found")


def test_i_there_is_no_field_for_arbitrary_commands(client: TestClient) -> None:
    agent = _agent(client)
    for extra in ({"command": "whoami"}, {"script": "x"}, {"shell": "cmd"}):
        response = _execute(client, "collect_inventory", agent["asset_id"], **extra)
        assert response.status_code == 422, response.text
    bad_params = _execute(
        client, "recalculate_risk", agent["asset_id"], parameters={"cmd": "whoami"}
    )
    _error(bad_params, 422, "response_invalid_parameters")
    forbidden = {"command", "cmd", "script", "shell", "powershell", "bash", "exec", "path", "url"}
    for action in ACTIONS.values():
        properties = set(action.params_model.model_json_schema().get("properties", {}))
        if action.id == "forensic_file_metadata":
            # Fase 6E.6: la única ruta del catálogo; solo metadatos, validada dos veces.
            assert properties == {"path", "hash"}
            continue
        assert not properties & forbidden, action.id
    # El servidor y el agente comparten la misma allowlist cerrada.
    assert agent_service.AGENT_COMMAND_TYPES == catalog.AGENT_COMMAND_TYPES
    with pytest.raises(PlaybookError):
        validate_steps([{"action_id": "collect_inventory", "script": "rm -rf /"}])
    with pytest.raises(PlaybookError):
        validate_steps([{"action_id": "isolate_host"}])


# --- J/K/L. Duplicados, timeout y reentrega ------------------------------------------------


def test_j_duplicate_agent_result_and_requests_do_not_duplicate_effects(
    client: TestClient, db: Session
) -> None:
    agent = _agent(client)
    first = _ok(_execute(client, "collect_telemetry", agent["asset_id"]))
    again = _ok(_execute(client, "collect_telemetry", agent["asset_id"]))
    assert again["execution_id"] == first["execution_id"] and again["deduplicated"] is True
    [command] = _ok(_poll(client, agent["agent_id"]))["commands"]
    _ok(_result(client, agent["agent_id"], command["request_id"]))
    version = _execution(db, first["execution_id"]).version
    replay = _ok(_result(client, agent["agent_id"], command["request_id"], "failed"))
    assert replay == {"accepted": False, "duplicate": True, "status": "completed"}
    final = _execution(db, first["execution_id"])
    assert final.status == "succeeded" and final.version == version
    assert len(_audits(db, "response_completed")) == 1
    # Idempotencia de una mutación: la misma clave devuelve el mismo incidente.
    key = {"confirm": True, "idempotency_key": "dialog-0001"}
    one = _ok(_execute(client, "open_incident", agent["asset_id"], **key))
    two = _ok(_execute(client, "open_incident", agent["asset_id"], **key))
    assert one["execution_id"] == two["execution_id"] and two["deduplicated"] is True
    assert db.scalar(select(func.count()).select_from(Incident)) == 1
    # La clave no sirve para otra petición.
    other = _execute(client, "recalculate_risk", agent["asset_id"], **key)
    _error(other, 409, "response_conflict")


def test_forged_or_foreign_results_are_refused(client: TestClient, db: Session) -> None:
    owner = _agent(client)
    intruder = _agent(client, hostname="PC-OTRO", primary_ip="192.168.1.77")
    queued = _ok(_execute(client, "collect_inventory", owner["asset_id"]))
    # Resultado antes de entregarse: falsificación o replay.
    command = _command(db, queued["execution_id"])
    _error(
        _result(client, owner["agent_id"], str(command.request_id)), 409, "command_not_delivered"
    )
    [delivered] = _ok(_poll(client, owner["agent_id"]))["commands"]
    # Otro agente (con su token válido) no puede completar el comando ajeno.
    forged = _result(client, intruder["agent_id"], delivered["request_id"])
    _error(forged, 404, "command_not_found")
    # Sin token: 401.
    no_token = client.post(
        f"{API}/agents/commands/{delivered['request_id']}/result",
        json={"agent_id": owner["agent_id"], "status": "succeeded"},
        headers={},
    )
    assert no_token.status_code == 401
    assert _execution(db, queued["execution_id"]).status == "running"
    # El intruso tampoco recibe los comandos del otro activo.
    assert _ok(_poll(client, intruder["agent_id"]))["commands"] == []


def _command(db: Session, execution_public_id: str) -> AgentCommand:
    execution = _execution(db, execution_public_id)
    command = db.scalar(select(AgentCommand).where(AgentCommand.execution_id == execution.id))
    assert command is not None
    return command


def test_k_timeout_marks_the_execution(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    queued = _ok(_execute(client, "collect_inventory", agent["asset_id"]))
    later = datetime.now(UTC) + timedelta(minutes=16)  # TTL de 15 min sin recoger
    counts = _service(db).sweep(now=later)
    assert counts["expired"] == 1
    final = _execution(db, queued["execution_id"])
    assert final.status == "timed_out" and final.error_code == "command_expired"
    # Ya no se entrega y un resultado tardío no reabre nada.
    assert (
        _ok(client.post(HEARTBEAT, json={"agent_id": agent["agent_id"]}))["pending_commands"] == 0
    )
    assert _ok(_poll(client, agent["agent_id"]))["commands"] == []
    request_id = str(_command(db, queued["execution_id"]).request_id)
    late = _ok(_result(client, agent["agent_id"], request_id))
    assert late == {"accepted": False, "duplicate": False, "status": "expired"}


def test_l_lost_delivery_is_redelivered_once_then_times_out(
    client: TestClient, db: Session
) -> None:
    agent = _agent(client)
    queued = _ok(_execute(client, "collect_processes", agent["asset_id"]))
    [first] = _ok(_poll(client, agent["agent_id"]))["commands"]
    lease = _command(db, queued["execution_id"]).lease_expires_at
    assert lease is not None
    counts = _service(db).sweep(now=lease + timedelta(seconds=1))
    assert counts["redelivered"] == 1
    assert _execution(db, queued["execution_id"]).status == "queued"
    [second] = _ok(_poll(client, agent["agent_id"]))["commands"]
    # Mismo request_id: el agente reutiliza su resultado (no recolecta dos veces).
    assert second["request_id"] == first["request_id"]
    command = _command(db, queued["execution_id"])
    assert command.delivery_count == 2 == command.max_deliveries
    assert command.lease_expires_at is not None
    counts = _service(db).sweep(now=command.lease_expires_at + timedelta(seconds=1))
    assert counts["timed_out"] == 1
    final = _execution(db, queued["execution_id"])
    assert final.status == "timed_out" and final.error_code == "agent_timeout"


def test_server_execution_interrupted_is_closed_by_deadline(
    client: TestClient, db: Session
) -> None:
    agent = _agent(client)
    asset = db.scalar(select(Asset).where(Asset.public_id == UUID(agent["asset_id"])))
    assert asset is not None
    now = datetime.now(UTC)
    # Simula una caída del proceso a mitad de un handler: queda "running" con plazo.
    stuck = ResponseExecution(
        action_id="recalculate_risk", status="running", risk_level="low", requires_agent=False,
        target_type="asset", target_public_id=asset.public_id, target_label="x",
        asset_id=asset.id, parameters={}, actor="admin", confirmed=False, created_at=now,
        started_at=now, deadline_at=now + timedelta(seconds=60), version=1,
    )  # fmt: skip
    db.add(stuck)
    db.commit()
    _service(db).sweep(now=now + timedelta(seconds=61))
    db.refresh(stuck)
    assert stuck.status == "timed_out" and stuck.error_code == "deadline_exceeded"


# --- M/N. Playbooks ------------------------------------------------------------------------


def test_m_playbook_is_fail_stop(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    created = _ok(
        client.post(
            f"{R}/playbooks",
            json={
                "name": "Inventario y riesgo",
                "steps": [
                    {"action_id": "recalculate_risk"},
                    {"action_id": "collect_inventory"},
                    {"action_id": "collect_timeline"},
                ],
            },
        )
    )
    run = _ok(
        client.post(
            f"{R}/playbooks/{created['playbook_id']}/execute",
            json={"target_id": agent["asset_id"]},
        )
    )
    assert run["status"] == "running" and run["current_step"] == 1
    [command] = _ok(_poll(client, agent["agent_id"]))["commands"]
    _ok(_result(client, agent["agent_id"], command["request_id"], "failed",
                error_code="collector_failed"))  # fmt: skip
    final = _ok(client.get(f"{R}/runs/{run['run_id']}"))
    assert final["status"] == "failed" and final["error_code"] == "step_failed"
    assert [s["status"] for s in final["steps"]] == ["succeeded", "failed", "skipped"]
    # El paso 3 nunca se ejecutó.
    assert not db.scalar(
        select(ResponseExecution).where(ResponseExecution.action_id == "collect_timeline")
    )
    assert len(_audits(db, "playbook_run_finished")) == 1


def test_unsafe_continue_after_failure_is_refused(client: TestClient) -> None:
    response = client.post(
        f"{R}/playbooks",
        json={
            "name": "Mutación sin freno",
            "steps": [{"action_id": "open_incident", "on_failure": "continue"}],
        },
    )
    _error(response, 422, "playbook_unsafe_continue")


def test_n_playbook_history_keeps_the_version_used(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    created = _ok(
        client.post(
            f"{R}/playbooks",
            json={"name": "Riesgo", "steps": [{"action_id": "recalculate_risk"}]},
        )
    )
    url = f"{R}/playbooks/{created['playbook_id']}"
    first = _ok(client.post(f"{url}/execute", json={"target_id": agent["asset_id"]}))
    assert first["status"] == "succeeded" and first["playbook_version"] == 1
    updated = _ok(
        client.patch(
            url,
            json={
                "revision": created["revision"],
                "name": "Riesgo y timeline",
                "steps": [{"action_id": "recalculate_risk"}, {"action_id": "collect_timeline"}],
            },
        )
    )
    assert updated["version"] == 2
    old = _ok(client.get(f"{R}/runs/{first['run_id']}"))
    assert old["playbook_version"] == 1 and len(old["steps"]) == 1
    assert old["playbook_name"] == "Riesgo"
    second = _ok(client.post(f"{url}/execute", json={"target_id": agent["asset_id"]}))
    assert second["playbook_version"] == 2 and len(second["steps"]) == 2
    # Una revisión vieja no pisa la edición de otro admin.
    stale = client.patch(
        url,
        json={
            "revision": created["revision"],
            "name": "Edición vieja",
            "steps": [{"action_id": "recalculate_risk"}],
        },
    )
    _error(stale, 409, "response_conflict")


def test_builtin_playbooks_are_low_risk_and_runnable_by_analyst(
    client: TestClient, engine: Engine
) -> None:
    agent = _agent(client)
    items = _ok(client.get(f"{R}/playbooks"))["items"]
    builtins = {p["key"]: p for p in items if p["builtin"]}
    assert set(builtins) == {"investigate_endpoint", "refresh_asset_analysis",
                             "investigate_detection"}  # fmt: skip
    assert all(p["risk_level"] == "low" and p["required_role"] == "analyst"
               for p in builtins.values())  # fmt: skip
    authenticate(client, engine, "analyst")
    run = _ok(
        client.post(
            f"{R}/playbooks/{builtins['refresh_asset_analysis']['playbook_id']}/execute",
            json={"target_id": agent["asset_id"]},
        )
    )
    assert run["status"] == "succeeded", run
    # Un analyst no edita playbooks (response:manage).
    edit = client.patch(
        f"{R}/playbooks/{builtins['refresh_asset_analysis']['playbook_id']}",
        json={"revision": 1, "name": "abc", "steps": [{"action_id": "recalculate_risk"}]},
    )
    _error(edit, 403, "permission_denied")


def test_playbook_preview_blocks_without_agent(client: TestClient, db: Session) -> None:
    asset = _discovered(db)
    pb = _playbook(client, "investigate_endpoint")
    preview = _ok(
        client.post(
            f"{R}/playbooks/{pb['playbook_id']}/preview", json={"target_id": str(asset.public_id)}
        )
    )
    assert preview["allowed"] is False
    assert "no_agent" in {b["code"] for s in preview["steps"] for b in s["blockers"]}
    run = client.post(
        f"{R}/playbooks/{pb['playbook_id']}/execute", json={"target_id": str(asset.public_id)}
    )
    _error(run, 409, "response_blocked")
    assert db.scalar(select(PlaybookRun.status)) == "blocked"
    assert db.scalar(select(func.count()).select_from(ResponseExecution)) == 0


# --- O. Cancelación ------------------------------------------------------------------------


def test_o_cancel_is_safe(client: TestClient, engine: Engine, db: Session) -> None:
    agent = _agent(client)
    queued = _ok(_execute(client, "collect_inventory", agent["asset_id"]))
    url = f"{R}/executions/{queued['execution_id']}/cancel"
    _error(client.post(url, json={"version": queued["version"] + 5}), 409, "response_conflict")
    analyst_client_state = dict(client.headers), dict(client.cookies)
    authenticate(client, engine, "analyst")
    _error(client.post(url, json={"version": queued["version"]}), 403, "permission_denied")
    client.headers.update(analyst_client_state[0])
    authenticate(client, engine, "admin", f"admin2-{uuid4().hex[:6]}")
    cancelled = _ok(client.post(url, json={"version": queued["version"], "reason": "error"}))
    assert cancelled["status"] == "cancelled"
    assert _command(db, queued["execution_id"]).status == "cancelled"
    assert _ok(_poll(client, agent["agent_id"]))["commands"] == []
    request_id = str(_command(db, queued["execution_id"]).request_id)
    late = _ok(_result(client, agent["agent_id"], request_id))
    assert late["accepted"] is False
    _error(client.post(url, json={"version": cancelled["version"]}), 409, "response_invalid_state")
    assert len(_audits(db, "response_cancelled")) == 1


def test_cancel_run_stops_the_playbook(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    pb = _playbook(client, "investigate_endpoint")
    run = _ok(
        client.post(
            f"{R}/playbooks/{pb['playbook_id']}/execute", json={"target_id": agent["asset_id"]}
        )
    )
    assert run["status"] == "running"
    cancelled = _ok(client.post(f"{R}/runs/{run['run_id']}/cancel",
                                json={"version": run["version"]}))  # fmt: skip
    assert cancelled["status"] == "cancelled"
    assert _ok(_poll(client, agent["agent_id"]))["commands"] == []


# --- P/Q. Linaje 5C.2 ----------------------------------------------------------------------


def _reconcile(client: TestClient, source: str, target: str) -> None:
    def version(asset_id: str) -> int:
        value: int = _ok(client.get(f"{API}/assets/{asset_id}"))["lifecycle_version"]
        return value

    response = client.post(
        f"{API}/assets/{source}/reconcile",
        json={
            "target_asset_id": target,
            "version": version(source),
            "target_version": version(target),
            "acknowledge_weak_evidence": True,
        },
    )
    assert response.status_code == 200, response.text


def test_pq_after_reconciliation_only_the_current_agent_gets_commands(
    client: TestClient, db: Session
) -> None:
    ip = "192.168.50.201"
    historical = _agent(client, hostname="DESKTOP-03IJGBE", primary_ip=ip,
                        machine_id_hash="d" * 64)  # fmt: skip
    old_token = client.tokens[historical["agent_id"]]  # type: ignore[attr-defined]
    assert client.post(f"{API}/telemetry", json=telemetry_payload(historical["agent_id"]))
    _offline(db, historical["asset_id"], 60 * 24 * 3)
    current = _agent(client, hostname="ravenslg", primary_ip=ip, machine_id_hash="e" * 64)
    # Comando pendiente en el activo duplicado justo antes de reconciliar.
    pending = _ok(_execute(client, "collect_events", current["asset_id"]))
    _reconcile(client, current["asset_id"], historical["asset_id"])
    _service(db).sweep()
    stale = _execution(db, pending["execution_id"])
    assert stale.status == "cancelled" and stale.error_code in {"asset_archived",
                                                                "agent_reassigned"}  # fmt: skip

    # P. Acción nueva sobre el activo canónico: va al agente actual.
    queued = _ok(_execute(client, "collect_inventory", historical["asset_id"]))
    assert _command(db, queued["execution_id"]).agent_id == UUID(current["agent_id"])
    [command] = _ok(_poll(client, current["agent_id"]))["commands"]
    _ok(_result(client, current["agent_id"], command["request_id"]))
    assert _execution(db, queued["execution_id"]).status == "succeeded"
    # Q. El agente histórico no autentica (credencial descartada) y no recibe nada.
    old = _poll(client, historical["agent_id"], Authorization=f"Bearer {old_token}")
    assert old.status_code == 401
    # Sobre el activo origen (archivado) no se puede lanzar nada que necesite agente.
    blocked = _execute(client, "collect_inventory", current["asset_id"])
    _error(blocked, 409, "response_blocked")


def test_q_revoked_agent_never_receives_commands(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    revoke = client.post(f"{API}/console/agents/{agent['asset_id']}/revoke")
    assert revoke.status_code == 200, revoke.text
    error = _error(_execute(client, "collect_inventory", agent["asset_id"]), 409,
                   "response_blocked")  # fmt: skip
    assert "agent_credential_inactive" in {d.get("code") for d in error["details"]}
    assert _poll(client, agent["agent_id"]).status_code == 401


# --- R. Archivado durante la ejecución -----------------------------------------------------


def test_r_archiving_cancels_open_commands(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    queued = _ok(_execute(client, "collect_inventory", agent["asset_id"]))
    db.execute(
        update(Asset)
        .where(Asset.public_id == UUID(agent["asset_id"]))
        .values(archived_at=datetime.now(UTC), archived_by="admin", archive_reason="test")
    )
    db.commit()
    counts = _service(db).sweep()
    assert counts["cancelled"] == 1
    final = _execution(db, queued["execution_id"])
    assert final.status == "cancelled" and final.error_code == "asset_archived"
    # Lecturas de evidencia siguen permitidas sobre un activo archivado.
    timeline = _ok(_execute(client, "collect_timeline", agent["asset_id"]))
    assert timeline["status"] == "succeeded"


# --- S. Concurrencia -----------------------------------------------------------------------


def test_s_concurrent_identical_requests_create_one_execution(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _agent(client)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    results: list[Any] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(4)

    def worker() -> None:
        try:
            with factory() as session:
                from app.models.user import User
                from app.services.response_service import Operator

                user = session.scalar(select(User).where(User.username == "admin"))
                assert user is not None
                op = Operator.for_user(user, "127.0.0.1")
                barrier.wait()
                out = ResponseService(session, get_settings()).execute(
                    op,
                    ExecutionRequest(
                        action_id="collect_inventory", target_id=UUID(agent["asset_id"])
                    ),
                )
                results.append(out)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    # Ninguna se pierde ni se duplica: o devuelve la ejecución viva o un 409 limpio.
    assert all(getattr(e, "status_code", None) == 409 for e in errors), errors
    assert len({r.execution_id for r in results}) == 1
    assert db.scalar(select(func.count()).select_from(ResponseExecution)) == 1
    assert db.scalar(select(func.count()).select_from(AgentCommand)) == 1


# --- T/U. Auditoría y tamaño ---------------------------------------------------------------


def test_t_audit_carries_no_secrets(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    token = client.tokens[agent["agent_id"]]  # type: ignore[attr-defined]
    queued = _ok(_execute(client, "collect_diagnostics", agent["asset_id"], reason="revisión"))
    [command] = _ok(_poll(client, agent["agent_id"]))["commands"]
    _ok(_result(client, agent["agent_id"], command["request_id"],
                data={"note": "x"}))  # fmt: skip
    note = "contraseña de prueba: hunter2"
    _ok(_execute(client, "open_incident", agent["asset_id"], confirm=True))
    incident = db.scalar(select(Incident))
    assert incident is not None
    _ok(
        client.post(
            f"{R}/executions",
            json={
                "action_id": "add_incident_note",
                "target_type": "incident",
                "target_id": str(incident.public_id),
                "parameters": {"body": note},
                "confirm": True,
            },
        )
    )
    rows = [a for a in _audits_all(db) if a.action.startswith(("response_", "playbook_"))]
    assert rows
    text = repr([(a.action, a.details) for a in rows])
    assert token not in text and "hunter2" not in text
    assert queued["execution_id"] in text  # trazabilidad por id


def _audits_all(db: Session) -> list[AuditEvent]:
    db.expire_all()
    return list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))


def test_u_result_size_is_bounded(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    queued = _ok(_execute(client, "collect_processes", agent["asset_id"]))
    [command] = _ok(_poll(client, agent["agent_id"]))["commands"]
    huge = {"rows": ["<script>alert(1)</script>" + "x" * 1900] * 500}
    _ok(_result(client, agent["agent_id"], command["request_id"], data=huge))
    stored = _execution(db, queued["execution_id"]).result
    assert stored is not None and stored["data"]["truncated"] is True
    bounded = bounded_result("s\x00\u2028ok", {"k\x07": [1, 2**60, float("nan")]}, 1024)
    assert bounded == {"summary": "sok", "data": {"k": [1, str(2**60), None]}}
    # El esquema de entrada limita el resumen.
    with pytest.raises(ValueError):
        CommandResultRequest(agent_id=uuid4(), status="succeeded", summary="x" * 501)


# --- V/W. Plataforma y capacidades ---------------------------------------------------------


def test_v_unsupported_platform_is_blocked(client: TestClient) -> None:
    agent = _agent(client, os_name="FreeBSD", os_version="14")
    error = _error(_execute(client, "collect_inventory", agent["asset_id"]), 409,
                   "response_blocked")  # fmt: skip
    assert "unsupported_platform" in {d.get("code") for d in error["details"]}


@pytest.mark.parametrize("os_name", ["macOS", "Darwin"])
def test_v_macos_agent_receives_read_only_commands(client: TestClient, os_name: str) -> None:
    # Fase 6C.5: el agente de macOS informa "macOS"; uno anterior en un Mac, "Darwin".
    agent = _agent(client, os_name=os_name, os_version="15.1 (24B83)", architecture="arm64")
    _ok(_execute(client, "collect_events", agent["asset_id"]))
    [command] = _ok(_poll(client, agent["agent_id"]))["commands"]
    assert command["type"] == "collect_events"
    action = next(
        a for a in client.get(f"{R}/actions").json()["items"] if a["id"] == "collect_events"
    )
    assert action["supported_platforms"] == ["linux", "macos", "windows"]


def test_w_unsupported_or_unknown_capability_is_blocked(client: TestClient) -> None:
    partial = _agent(client, caps=["collect_inventory"])
    error = _error(_execute(client, "collect_events", partial["asset_id"]), 409,
                   "response_blocked")  # fmt: skip
    assert "unsupported_capability" in {d.get("code") for d in error["details"]}
    # Un agente anterior a 5D (sin capacidades) no recibe comandos.
    legacy = _agent(client, caps=None, hostname="PC-VIEJO", primary_ip="192.168.1.30")
    error = _error(_execute(client, "collect_inventory", legacy["asset_id"]), 409,
                   "response_blocked")  # fmt: skip
    assert "agent_capabilities_unknown" in {d.get("code") for d in error["details"]}
    # Capacidades fuera de la allowlist del servidor se descartan al guardarlas.
    beat = client.post(
        HEARTBEAT,
        json={
            "agent_id": partial["agent_id"],
            "host": {
                **agent_payload(),
                "agent_id": None,
                "capabilities": ["run_shell", "collect_events"],
            },
        },
    )
    assert beat.status_code in (200, 422)


# --- X. Integración con incidentes ---------------------------------------------------------


def test_x_incident_integration_keeps_traceability(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    asset = db.scalar(select(Asset).where(Asset.public_id == UUID(agent["asset_id"])))
    assert asset is not None
    detection = _detection(db, asset)
    opened = _ok(
        _execute(
            client,
            "open_incident",
            agent["asset_id"],
            detection_id=str(detection.public_id),
            confirm=True,
            parameters={"title": "Investigación de la detección"},
        )
    )
    assert opened["status"] == "succeeded" and opened["incident_id"]
    incident_id = opened["incident_id"]
    # Lanzar el playbook de investigación desde el caso deja rastro en su timeline.
    pb = _playbook(client, "investigate_detection")
    run = _ok(
        client.post(
            f"{R}/playbooks/{pb['playbook_id']}/execute",
            json={
                "target_id": agent["asset_id"],
                "incident_id": incident_id,
                "detection_id": str(detection.public_id),
            },
        )
    )
    assert run["status"] == "succeeded" and run["incident_id"] == incident_id
    incident = db.scalar(select(Incident).where(Incident.public_id == UUID(incident_id)))
    assert incident is not None
    db.expire_all()
    actions = {
        a.action
        for a in db.scalars(
            select(IncidentActivity).where(IncidentActivity.incident_id == incident.id)
        )
    }
    assert {"playbook_started", "playbook_succeeded", "response_completed"} <= actions
    listed = _ok(client.get(f"{R}/executions", params={"incident_id": incident_id}))
    assert listed["total"] >= len(run["steps"])
    # Repetir la apertura desde la misma detección no crea otro caso.
    again = _ok(_execute(client, "open_incident", agent["asset_id"],
                         detection_id=str(detection.public_id), confirm=True))  # fmt: skip
    assert again["incident_id"] == incident_id
    assert db.scalar(select(func.count()).select_from(Incident)) == 1


def test_detection_from_another_asset_is_refused(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    other = _discovered(db)
    detection = _detection(db, other)
    response = _execute(client, "collect_timeline", agent["asset_id"],
                        detection_id=str(detection.public_id))  # fmt: skip
    error = _error(response, 409, "response_blocked")
    assert "detection_mismatch" in {d.get("code") for d in error["details"]}


def test_response_disabled_refuses_everything(client: TestClient, db: Session) -> None:
    agent = _agent(client)
    service = _service(db, response_enabled=False)
    with pytest.raises(Exception) as caught:
        service.execute(
            _admin_operator(db),
            ExecutionRequest(action_id="recalculate_risk", target_id=UUID(agent["asset_id"])),
        )
    assert getattr(caught.value, "code", None) == "response_disabled"
    asset = db.scalar(select(Asset).where(Asset.public_id == UUID(agent["asset_id"])))
    assert asset is not None and service.pending_count(asset) == 0
