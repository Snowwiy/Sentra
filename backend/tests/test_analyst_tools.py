"""Analyst Tool Engine (Fase 7A.1-7A.3): registro, ejecutor y API con PostgreSQL real.

Cubre las garantías del motor: registro cerrado sin campos de código, validación estricta,
RBAC en el backend (con fila rejected y auditoría), alcance de site, lecturas en transacción
READ ONLY con plazo y cancelación real, idempotencia, anti-duplicado, concurrencia, vista
previa y confirmación de acciones y visibilidad del historial.
"""

import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.exceptions import RateLimitedError
from app.core.permissions import ROLE_PERMISSIONS, Permission, Role
from app.core.rate_limit import make_limiter
from app.models.audit import AuditEvent
from app.models.incident import Incident
from app.models.response import ResponseExecution
from app.models.site import Site
from app.models.tool import ToolExecution
from app.models.user import User
from app.schemas.common import RequestModel, ResponseModel
from app.schemas.tools import ToolRunRequest
from app.services.audit_service import Actor
from app.services.tool_service import (
    ToolEngine,
    ToolOperator,
    _cancellation_failure,
    _query_cancelled,
    canonical_json,
    sha256_of,
)
from app.tools import catalog
from app.tools.registry import (
    FORBIDDEN_INPUT_FIELDS,
    ToolContext,
    ToolDefinition,
    ToolOutput,
    validate_registry,
)
from tests.conftest import authenticate
from tests.test_risk import _detection, _discovered

API = "/api/v1"
T = f"{API}/tools"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def analyst(client: TestClient, engine: Engine) -> Iterator[TestClient]:
    with TestClient(client.app) as other:
        authenticate(other, engine, "analyst")
        yield other


def _ok(response: Any, status: int = 200) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


def _error(response: Any, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()["error"]
    assert body["code"] == code, body
    return body


def _run(client: TestClient, tool_id: str, payload: dict[str, Any], **extra: Any) -> Any:
    return client.post(f"{T}/{tool_id}/execute", json={"input": payload, **extra})


# --- Herramientas de prueba (registradas solo durante un test) --------------------------------


class _EmptyIn(RequestModel):
    seconds: float = 0


class _EmptyOut(ResponseModel):
    value: int


def _sleep(ctx: ToolContext, params: _EmptyIn) -> ToolOutput:
    ctx.session.execute(text("SELECT pg_sleep(:s)"), {"s": params.seconds})
    return ToolOutput("ok", _EmptyOut(value=1))


def _write(ctx: ToolContext, params: _EmptyIn) -> ToolOutput:
    # Una lectura que intentara escribir: la transacción READ ONLY lo impide.
    ctx.session.execute(text("UPDATE users SET is_active = is_active"))
    return ToolOutput("escrito", _EmptyOut(value=1))


def _big(ctx: ToolContext, params: _EmptyIn) -> ToolOutput:
    return ToolOutput("grande", _BigOut(items=["x" * 1000] * 400))


class _BigOut(ResponseModel):
    items: list[str]


def _test_tool(tool_id: str, handler: Any, **overrides: Any) -> ToolDefinition:
    values: dict[str, Any] = {
        "id": tool_id,
        "version": 1,
        "name": tool_id,
        "description": "Herramienta de test",
        "category": "read",
        "scope": "global",
        "risk_level": "none",
        "permissions": (Permission.MONITORING_READ,),
        "input_model": _EmptyIn,
        "output_model": _BigOut if handler is _big else _EmptyOut,
        "handler": handler,
    }
    values.update(overrides)
    return ToolDefinition(**values)


@pytest.fixture
def register(monkeypatch: pytest.MonkeyPatch) -> Any:
    def add(tool: ToolDefinition) -> ToolDefinition:
        monkeypatch.setitem(catalog.TOOLS, tool.id, tool)
        return tool

    return add


# --- Registro ----------------------------------------------------------------------------------


def test_registry_is_closed_and_has_no_code_inputs() -> None:
    assert len(catalog.TOOLS) >= 16
    validate_registry(catalog.TOOLS)
    for tool in catalog.TOOLS.values():
        schema = tool.input_model.model_json_schema()
        assert schema.get("additionalProperties") is False, tool.id
        assert not set(schema.get("properties", {})) & FORBIDDEN_INPUT_FIELDS, tool.id
        if tool.category == "action":
            assert tool.policy == "preview_confirm" and tool.preview is not None
        if tool.category == "read":
            assert tool.risk_level == "none" and tool.id not in catalog.WRITING_TOOLS
    # Ninguna herramienta genérica de ejecución.
    for forbidden in ("shell", "run", "sql", "http", "command", "script"):
        assert not any(forbidden in tool_id.split(".") for tool_id in catalog.TOOLS)
    # La contención nunca se delega desde las herramientas (su flujo tiene doble confirmación).
    assert "isolate_host" not in catalog.DELEGABLE_ACTIONS
    assert "release_isolation" not in catalog.DELEGABLE_ACTIONS


def test_registry_rejects_code_fields_and_unsafe_policies() -> None:
    class Nested(BaseModel):
        model_config = {"extra": "forbid"}
        script: str

    class WithCode(RequestModel):
        options: Nested

    class Loose(BaseModel):
        value: int = 1

    with pytest.raises(ValueError, match="forbidden input fields"):
        validate_registry({"x.code": _test_tool("x.code", _sleep, input_model=WithCode)})
    with pytest.raises(ValueError, match="forbid extra"):
        validate_registry({"x.loose": _test_tool("x.loose", _sleep, input_model=Loose)})
    with pytest.raises(ValueError, match="preview_confirm"):
        validate_registry(
            {"x.act": _test_tool("x.act", _sleep, category="action", risk_level="low")}
        )
    with pytest.raises(ValueError, match="no risk"):
        validate_registry({"x.read": _test_tool("x.read", _sleep, risk_level="low")})


def test_roles_and_tool_permissions() -> None:
    assert Permission.TOOLS_READ in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.TOOLS_EXECUTE not in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.TOOLS_EXECUTE in ROLE_PERMISSIONS[Role.ANALYST]
    assert Permission.TOOLS_MANAGE not in ROLE_PERMISSIONS[Role.ANALYST]
    for tool in catalog.TOOLS.values():
        assert Permission.TOOLS_EXECUTE in tool.required_permissions


# --- Catálogo ----------------------------------------------------------------------------------


def test_catalog_lists_contracts_and_permissions(client: TestClient, engine: Engine) -> None:
    body = _ok(client.get(T))
    assert body["enabled"] is True
    ids = {item["id"] for item in body["items"]}
    assert ids == set(catalog.TOOLS)
    profile = next(item for item in body["items"] if item["id"] == "asset.profile")
    assert profile["input_schema"]["required"] == ["asset_id"]
    assert profile["output_schema"]["type"] == "object"
    assert profile["permitted"] is True and profile["availability"] == "available"
    one = _ok(client.get(f"{T}/case.open"))
    assert one["policy"] == "preview_confirm" and one["category"] == "action"
    _error(client.get(f"{T}/nope.tool"), 404, "not_found")

    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        items = _ok(viewer.get(T))["items"]
        assert not any(item["permitted"] for item in items)
        _error(_run(viewer, "asset.lookup", {"text": "abc"}), 403, "permission_denied")


# --- Ejecución de lecturas --------------------------------------------------------------------


def test_read_tool_succeeds_with_hash_evidence_and_audit(analyst: TestClient, db: Session) -> None:
    asset = _discovered(db, name="impresora-planta")
    _detection(db, asset)
    body = _ok(_run(analyst, "asset.profile", {"asset_id": str(asset.public_id)}))
    assert body["status"] == "succeeded"
    assert body["target_type"] == "asset" and body["target_id"] == str(asset.public_id)
    assert body["asset_id"] == str(asset.public_id)
    assert body["output_sha256"] == sha256_of(body["output"])
    assert body["output_bytes"] == len(canonical_json(body["output"]))
    assert body["input"] == {"asset_id": str(asset.public_id)}
    assert any(ref["type"] == "asset" for ref in body["evidence"])
    assert body["provenance"]["tool_version"] == 1
    assert body["duration_ms"] is not None and body["finished_at"]
    audit = db.scalars(
        select(AuditEvent).where(
            AuditEvent.action == "tool_executed", AuditEvent.target_id == "asset.profile"
        )
    ).all()
    assert len(audit) == 1 and audit[0].result == "success"
    # Historial y detalle.
    listed = _ok(analyst.get(f"{T}/executions"))
    assert listed["total"] == 1 and listed["items"][0]["execution_id"] == body["execution_id"]
    _ok(analyst.get(f"{T}/executions/{body['execution_id']}"))


READ_INPUTS: dict[str, dict[str, Any]] = {
    "asset.lookup": {"text": "10.20"},
    "asset.history": {},
    "telemetry.recent": {},
    "process.tree": {},
    "events.search": {"hours": 48},
    "detections.search": {"active": False},
    "vulnerabilities.assess": {},
    "exposure.ports": {},
    "risk.explain": {},
    "timeline.build": {"hours": 12},
    "topology.changes": {"days": 3},
    "identity.evidence": {},
    "operations.history": {},
}
ASSET_SCOPED = {
    "asset.history", "telemetry.recent", "process.tree", "events.search",
    "vulnerabilities.assess", "exposure.ports", "risk.explain", "timeline.build",
    "identity.evidence",
}  # fmt: skip


@pytest.mark.parametrize("tool_id", sorted(READ_INPUTS))
def test_every_read_tool_runs(tool_id: str, analyst: TestClient, db: Session) -> None:
    asset = _discovered(db, name="equipo-lab")
    _detection(db, asset)
    payload = dict(READ_INPUTS[tool_id])
    if tool_id in ASSET_SCOPED:
        payload["asset_id"] = str(asset.public_id)
    body = _ok(_run(analyst, tool_id, payload))
    assert body["status"] == "succeeded", body
    assert body["summary"]
    assert body["output_sha256"] == sha256_of(body["output"])


def test_detection_get_and_missing_targets(analyst: TestClient, db: Session) -> None:
    asset = _discovered(db)
    detection = _detection(db, asset)
    body = _ok(_run(analyst, "detections.get", {"detection_id": str(detection.public_id)}))
    assert body["status"] == "succeeded"
    assert any(ref["type"] == "detection" for ref in body["evidence"])
    _error(_run(analyst, "asset.profile", {"asset_id": str(uuid4())}), 404, "not_found")
    missing = _run(
        analyst, "process.instance", {"asset_id": str(asset.public_id), "instance_key": "a" * 32}
    )
    assert missing.status_code == 404


def test_strict_input_validation(analyst: TestClient, db: Session) -> None:
    asset = _discovered(db)
    target = str(asset.public_id)
    for payload in (
        {"asset_id": target, "command": "whoami"},
        {"asset_id": target, "unexpected": 1},
        {"asset_id": "not-a-uuid"},
        {},
    ):
        _error(_run(analyst, "asset.profile", payload), 422, "tool_invalid_input")
    # Un campo fuera de `input` también es 422 (el sobre es RequestModel).
    response = analyst.post(f"{T}/asset.profile/execute", json={"input": {}, "shell": "x"})
    assert response.status_code == 422
    _error(
        _run(analyst, "events.search", {"asset_id": target, "hours": 100000}),
        422,
        "tool_invalid_input",
    )
    _error(_run(analyst, "no.such", {}), 404, "not_found")
    assert not _ok(analyst.get(f"{T}/executions"))["total"]


def test_site_scope_hides_assets_of_other_sites(analyst: TestClient, db: Session) -> None:
    asset = _discovered(db)
    suffix = uuid4().hex[:6]
    other = Site(name=f"Sede {suffix}", slug=f"sede-{suffix}")
    db.add(other)
    db.commit()
    body = {"input": {"asset_id": str(asset.public_id)}, "site_id": str(other.public_id)}
    _error(analyst.post(f"{T}/asset.profile/execute", json=body), 404, "not_found")
    body["site_id"] = str(uuid4())
    _error(analyst.post(f"{T}/asset.profile/execute", json=body), 404, "not_found")


def test_missing_domain_permission_is_rejected_and_audited(
    analyst: TestClient, db: Session, register: Any
) -> None:
    register(_test_tool("test.admin_only", _sleep, permissions=(Permission.TOOLS_MANAGE,)))
    _error(_run(analyst, "test.admin_only", {}), 403, "permission_denied")
    row = db.scalars(select(ToolExecution).where(ToolExecution.tool_id == "test.admin_only")).one()
    assert row.status == "rejected" and row.error_code == "permission_denied"
    assert row.input == {}  # La entrada sin validar no se guarda.
    denied = db.scalars(
        select(AuditEvent).where(
            AuditEvent.action == "permission_denied", AuditEvent.target_id == "test.admin_only"
        )
    ).all()
    assert len(denied) == 1 and denied[0].result == "denied"


# --- Solo lectura, plazos y cancelación --------------------------------------------------------


def test_read_tools_cannot_write(analyst: TestClient, register: Any) -> None:
    register(_test_tool("test.write", _write))
    body = _ok(_run(analyst, "test.write", {}))
    assert body["status"] == "failed"
    assert body["error_code"] == "tool_database_error"
    assert body["output"] is None


def test_timeout_cancels_the_query(analyst: TestClient, register: Any) -> None:
    register(_test_tool("test.sleep", _sleep, timeout_seconds=1))
    started = time.monotonic()
    body = _ok(_run(analyst, "test.sleep", {"seconds": 5}))
    assert time.monotonic() - started < 4
    assert body["status"] == "timed_out" and body["error_code"] == "tool_timeout"


def test_cancel_interrupts_a_running_read(analyst: TestClient, db: Session, register: Any) -> None:
    register(_test_tool("test.sleep", _sleep, timeout_seconds=30))
    result: dict[str, Any] = {}

    def run() -> None:
        result["response"] = _run(analyst, "test.sleep", {"seconds": 20})

    worker = threading.Thread(target=run)
    worker.start()
    deadline = time.monotonic() + 10
    row = None
    while time.monotonic() < deadline:
        db.expire_all()
        row = db.scalar(
            select(ToolExecution).where(
                ToolExecution.tool_id == "test.sleep", ToolExecution.backend_pid.is_not(None)
            )
        )
        if row is not None:
            break
        time.sleep(0.05)
    assert row is not None
    started = time.monotonic()
    cancelled = _ok(
        analyst.post(f"{T}/executions/{row.public_id}/cancel", json={"version": row.version})
    )
    assert cancelled["status"] == "cancelled" and cancelled["cancelled_by"]
    worker.join(15)
    assert time.monotonic() - started < 10
    final = _ok(result["response"])
    assert final["status"] == "cancelled" and final["output"] is None


class _PgError(Exception):
    """Error de psycopg simulado: solo importan el SQLSTATE y un mensaje localizado."""

    def __init__(self, sqlstate: str, message: str) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


@pytest.mark.parametrize(
    "message",
    [
        "canceling statement due to statement timeout",
        # lc_messages en español (PostgreSQL de Jesus en Windows) y en alemán.
        "cancelando la sentencia debido a que se agotó el tiempo de espera de sentencias",
        "storniere Anfrage wegen Zeitüberschreitung der Anweisung",
        "cancelando la sentencia debido a una petición del usuario",
    ],
)
def test_cancellation_is_classified_without_reading_the_message(message: str) -> None:
    from sqlalchemy.exc import DBAPIError

    exc = DBAPIError("SELECT pg_sleep(5)", {}, _PgError("57014", message))
    assert _query_cancelled(exc) is True
    # Mismo mensaje, causa distinta: decide el estado guardado y el tiempo, no el idioma.
    assert _cancellation_failure("running", 1.0, 1)[:2] == ("timed_out", "tool_timeout")
    assert _cancellation_failure("cancelled", 1.5, 1)[:2] == ("cancelled", "tool_cancelled")
    assert _cancellation_failure("running", 0.2, 30)[:2] == ("failed", "tool_query_cancelled")


def test_other_database_errors_are_not_cancellations() -> None:
    from sqlalchemy.exc import DBAPIError

    exc = DBAPIError("SELECT 1", {}, _PgError("25006", "read-only transaction"))
    assert _query_cancelled(exc) is False


def test_cancel_after_timeout_window_is_still_a_human_cancel(
    analyst: TestClient, db: Session, register: Any
) -> None:
    # Una cancelación por API que llega cuando ya ha pasado casi todo el plazo sigue siendo
    # humana: el estado se confirma antes de pg_cancel_backend.
    register(_test_tool("test.sleep", _sleep, timeout_seconds=3))
    result: dict[str, Any] = {}

    def run() -> None:
        result["response"] = _run(analyst, "test.sleep", {"seconds": 20})

    worker = threading.Thread(target=run)
    worker.start()
    row = _wait_running(db, "test.sleep")
    time.sleep(2.95 - 0.5)
    _ok(analyst.post(f"{T}/executions/{row.public_id}/cancel", json={"version": row.version}))
    worker.join(15)
    final = _ok(result["response"])
    assert final["status"] == "cancelled" and final["error_code"] == "tool_cancelled"


def test_query_cancelled_outside_sentra_is_a_failure(
    analyst: TestClient, db: Session, register: Any
) -> None:
    # pg_cancel_backend de un DBA: ni timeout de la herramienta ni cancelación de un usuario.
    register(_test_tool("test.sleep", _sleep, timeout_seconds=30))
    result: dict[str, Any] = {}

    def run() -> None:
        result["response"] = _run(analyst, "test.sleep", {"seconds": 20})

    worker = threading.Thread(target=run)
    worker.start()
    row = _wait_running(db, "test.sleep")
    db.execute(text("SELECT pg_cancel_backend(:pid)"), {"pid": row.backend_pid})
    db.commit()
    worker.join(15)
    final = _ok(result["response"])
    assert final["status"] == "failed" and final["error_code"] == "tool_query_cancelled"
    assert final["cancelled_by"] is None


def _wait_running(db: Session, tool_id: str) -> ToolExecution:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        db.expire_all()
        row = db.scalar(
            select(ToolExecution).where(
                ToolExecution.tool_id == tool_id, ToolExecution.backend_pid.is_not(None)
            )
        )
        if row is not None:
            return row
        time.sleep(0.05)
    raise AssertionError("the tool never started")


def test_large_output_is_replaced_by_a_marker(analyst: TestClient, register: Any) -> None:
    register(_test_tool("test.big", _big))
    body = _ok(_run(analyst, "test.big", {}))
    assert body["status"] == "succeeded" and body["truncated"] is True
    assert body["output"]["truncated"] is True
    assert body["output_bytes"] > 256 * 1024
    assert body["output"]["original_bytes"] == body["output_bytes"]


# --- Idempotencia, duplicados, límites ---------------------------------------------------------


def test_idempotency_key_returns_the_same_execution(analyst: TestClient, db: Session) -> None:
    asset = _discovered(db)
    payload = {"asset_id": str(asset.public_id)}
    first = _ok(_run(analyst, "asset.profile", payload, idempotency_key="key-0001"))
    again = _ok(_run(analyst, "asset.profile", payload, idempotency_key="key-0001"))
    assert again["execution_id"] == first["execution_id"] and again["deduplicated"] is True
    _error(
        _run(analyst, "asset.history", payload, idempotency_key="key-0001"),
        409,
        "tool_invalid_state",
    )
    assert _ok(analyst.get(f"{T}/executions"))["total"] == 1


def _running_rows(db: Session, user: User, count: int, tool_id: str = "asset.lookup") -> None:
    now = datetime.now(UTC)
    model = catalog.TOOLS[tool_id].input_model
    for index in range(count):
        # Entrada normalizada como la guarda el motor (con los valores por defecto).
        payload = model.model_validate({"text": f"busqueda-{index}"}).model_dump(mode="json")
        db.add(
            ToolExecution(
                tool_id=tool_id,
                tool_version=1,
                category="read",
                risk_level="none",
                status="running",
                invoker="user",
                actor=user.username,
                actor_user_id=user.id,
                input=payload,
                input_sha256=sha256_of(payload),
                created_at=now,
                started_at=now,
                deadline_at=now + timedelta(seconds=30),
            )
        )
    db.commit()


def test_concurrency_limit_per_user(client: TestClient, engine: Engine, db: Session) -> None:
    with TestClient(client.app) as other:
        user = authenticate(other, engine, "analyst")
        _running_rows(db, user, 3)
        _error(_run(other, "asset.lookup", {"text": "abc"}), 429, "tool_concurrency_limit")
        # Una petición idéntica a una en curso devuelve esa (anti doble clic).
        db.execute(
            update(ToolExecution).values(deadline_at=datetime.now(UTC) + timedelta(seconds=30))
        )
        db.execute(
            update(ToolExecution)
            .where(ToolExecution.input["text"].astext != "busqueda-0")
            .values(status="failed")
        )
        db.commit()
        same = _ok(_run(other, "asset.lookup", {"text": "busqueda-0"}))
        assert same["deduplicated"] is True and same["status"] == "running"


def test_stale_running_rows_are_closed_as_interrupted(
    client: TestClient, engine: Engine, db: Session
) -> None:
    with TestClient(client.app) as other:
        user = authenticate(other, engine, "analyst")
        _running_rows(db, user, 3)
        old = datetime.now(UTC) - timedelta(minutes=10)
        db.execute(update(ToolExecution).values(deadline_at=old))
        db.commit()
        body = _ok(_run(other, "asset.lookup", {"text": "abc"}))
        assert body["status"] == "succeeded"
        db.expire_all()
        statuses = db.scalars(
            select(ToolExecution.error_code).where(ToolExecution.input["text"].astext != "abc")
        ).all()
        assert statuses == ["interrupted"] * 3


def test_rate_limit_per_user(db: Session) -> None:
    settings = get_settings()
    user = db.scalars(select(User).where(User.role == "admin")).first()
    assert user is not None
    limiter = make_limiter("memory", "analyst_tools", 1, 60, lambda: db.get_bind())  # type: ignore[arg-type,return-value]
    tools = ToolEngine(db, settings, limiter)
    op = ToolOperator(user, Actor(user.username, user.id), frozenset(ROLE_PERMISSIONS[Role.ADMIN]))
    tools.execute(op, "asset.lookup", ToolRunRequest(input={"text": "abc"}))
    with pytest.raises(RateLimitedError):
        tools.execute(op, "asset.lookup", ToolRunRequest(input={"text": "abc"}))


def test_disabled_engine_refuses_execution(db: Session) -> None:
    settings = get_settings().model_copy(update={"analyst_tools_enabled": False})
    user = db.scalars(select(User).where(User.role == "admin")).first()
    assert user is not None
    op = ToolOperator(user, Actor(user.username, user.id), frozenset(ROLE_PERMISSIONS[Role.ADMIN]))
    tools = ToolEngine(db, settings)
    from app.services.tool_service import ToolsDisabledError

    with pytest.raises(ToolsDisabledError):
        tools.execute(op, "asset.lookup", ToolRunRequest(input={"text": "abc"}))
    assert tools.catalog(op).enabled is False


# --- Acciones: vista previa y confirmación -----------------------------------------------------


def test_action_requires_preview_and_explicit_confirmation(
    analyst: TestClient, db: Session
) -> None:
    asset = _discovered(db, name="servidor-ficheros")
    detection = _detection(db, asset)
    payload = {"source": "detection", "source_id": str(detection.public_id)}
    _error(_run(analyst, "case.open", payload), 422, "tool_preview_required")

    preview = _ok(analyst.post(f"{T}/case.open/preview", json={"input": payload}))
    assert preview["status"] == "previewed"
    assert preview["output"]["preview"]["allowed"] is True
    assert preview["deadline_at"]
    assert db.scalar(select(Incident.id)) is None  # La vista previa no crea nada.

    url = f"{T}/executions/{preview['execution_id']}/confirm"
    _error(
        analyst.post(url, json={"version": preview["version"], "confirm": False}),
        422,
        "confirmation_required",
    )
    _error(analyst.post(url, json={"version": 99, "confirm": True}), 409, "tool_invalid_state")
    done = _ok(
        analyst.post(url, json={"version": preview["version"], "confirm": True, "note": "Revisado"})
    )
    assert done["status"] == "succeeded", done
    assert done["approved_by"] and done["approved_at"] and done["approval_note"] == "Revisado"
    assert done["incident_id"] is not None
    incident = db.scalars(select(Incident)).one()
    assert str(incident.public_id) == done["incident_id"]
    assert incident.owner_user_id is not None  # Quien lo abre lo asume.
    # No se puede confirmar dos veces.
    _error(
        analyst.post(url, json={"version": done["version"], "confirm": True}),
        409,
        "tool_invalid_state",
    )
    # Otra vista previa del mismo origen reutiliza el caso (sin duplicados).
    again = _ok(analyst.post(f"{T}/case.open/preview", json={"input": payload}))
    assert "ya está" in again["summary"]


def test_expired_preview_cannot_be_confirmed(analyst: TestClient, db: Session) -> None:
    asset = _discovered(db)
    payload = {"source": "asset", "source_id": str(asset.public_id), "title": "Revisión"}
    preview = _ok(analyst.post(f"{T}/case.open/preview", json={"input": payload}))
    db.execute(
        update(ToolExecution)
        .where(ToolExecution.public_id == UUID(preview["execution_id"]))
        .values(deadline_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    db.commit()
    url = f"{T}/executions/{preview['execution_id']}/confirm"
    _error(
        analyst.post(url, json={"version": preview["version"], "confirm": True}),
        409,
        "tool_invalid_state",
    )
    row = db.scalars(select(ToolExecution)).one()
    db.refresh(row)
    assert row.status == "expired"
    assert db.scalar(select(Incident.id)) is None


def test_preview_can_be_cancelled(analyst: TestClient, db: Session) -> None:
    asset = _discovered(db)
    payload = {"source": "asset", "source_id": str(asset.public_id), "title": "Revisión"}
    preview = _ok(analyst.post(f"{T}/case.open/preview", json={"input": payload}))
    url = f"{T}/executions/{preview['execution_id']}"
    cancelled = _ok(analyst.post(f"{url}/cancel", json={"version": preview["version"]}))
    assert cancelled["status"] == "cancelled"
    _error(
        analyst.post(f"{url}/confirm", json={"version": cancelled["version"], "confirm": True}),
        409,
        "tool_invalid_state",
    )


def test_direct_tools_have_no_preview(analyst: TestClient, db: Session) -> None:
    asset = _discovered(db)
    response = analyst.post(
        f"{T}/asset.profile/preview", json={"input": {"asset_id": str(asset.public_id)}}
    )
    _error(response, 422, "tool_preview_not_applicable")


def test_containment_is_not_delegable(analyst: TestClient, db: Session) -> None:
    asset = _discovered(db)
    payload = {"action_id": "isolate_host", "target_id": str(asset.public_id)}
    _error(analyst.post(f"{T}/response.execute/preview", json={"input": payload}), 404, "not_found")
    _error(_run(analyst, "response.prepare", payload), 404, "not_found")


def test_response_prepare_delegates_to_the_response_policy(
    analyst: TestClient, db: Session
) -> None:
    asset = _discovered(db)
    action = "recalculate_risk"  # LOW: el analista puede previsualizarla
    body = _ok(
        _run(analyst, "response.prepare", {"action_id": action, "target_id": str(asset.public_id)})
    )
    # La decisión (permitida o bloqueada) es de la política de Response, no de la herramienta.
    assert body["status"] == "succeeded", body
    assert body["output"]["preview"]["action"] == action
    # Una acción MEDIUM exige response:manage: el 403 de Response llega igual y queda en la fila.
    payload = {"action_id": "archive_asset", "target_id": str(asset.public_id)}
    _error(_run(analyst, "response.prepare", payload), 403, "permission_denied")
    failed = db.scalars(select(ToolExecution).where(ToolExecution.status == "failed")).one()
    assert failed.error_code == "permission_denied"


def test_response_execute_delegates_after_confirmation(client: TestClient, db: Session) -> None:
    asset = _discovered(db)
    payload = {
        "action_id": "recalculate_risk",
        "target_id": str(asset.public_id),
        "reason": "Revisión tras cambio",
    }
    preview = _ok(client.post(f"{T}/response.execute/preview", json={"input": payload}))
    assert preview["status"] == "previewed"
    assert preview["output"]["preview"]["allowed"] is True, preview
    assert db.scalar(select(ResponseExecution.id)) is None
    done = _ok(
        client.post(
            f"{T}/executions/{preview['execution_id']}/confirm",
            json={"version": preview["version"], "confirm": True},
        )
    )
    assert done["status"] == "succeeded", done
    delegated = done["response_execution"]
    assert delegated and delegated["action_id"] == "recalculate_risk"
    row = db.scalars(select(ResponseExecution)).one()
    assert str(row.public_id) == delegated["execution_id"]


# --- Visibilidad del historial ------------------------------------------------------------------


def test_history_is_private_unless_tools_manage(
    client: TestClient, analyst: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    mine = _ok(_run(analyst, "asset.profile", {"asset_id": str(asset.public_id)}))
    with TestClient(client.app) as other:
        authenticate(other, engine, "analyst")
        _error(other.get(f"{T}/executions/{mine['execution_id']}"), 404, "not_found")
        assert _ok(other.get(f"{T}/executions", params={"mine": False}))["total"] == 0
        _error(
            other.post(f"{T}/executions/{mine['execution_id']}/cancel", json={"version": 1}),
            404,
            "not_found",
        )
    # Un admin (tools:manage) ve las de todos.
    _ok(client.get(f"{T}/executions/{mine['execution_id']}"))
    assert _ok(client.get(f"{T}/executions", params={"mine": False}))["total"] == 1


def test_purge_is_opt_in_and_keeps_case_evidence(db: Session, analyst: TestClient) -> None:
    asset = _discovered(db)
    _ok(_run(analyst, "asset.profile", {"asset_id": str(asset.public_id)}))
    old = datetime.now(UTC) - timedelta(days=400)
    db.execute(update(ToolExecution).values(created_at=old))
    db.commit()
    settings = get_settings()
    assert ToolEngine(db, settings).purge() == 0  # Sin retención configurada no se borra nada.
    retained = settings.model_copy(update={"analyst_tools_retention_days": 30})
    assert ToolEngine(db, retained).purge() == 1
    assert db.scalar(select(ToolExecution.id)) is None
