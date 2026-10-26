"""Analyst Tool Engine (Fase 7A): el único ejecutor de las herramientas del registro.

Cada petición pasa, en este orden, por:

1. Activación (ANALYST_TOOLS_ENABLED) y herramienta del registro cerrado (404 si no existe).
2. Rate limit por usuario (ANALYST_TOOLS_PER_USER_PER_MINUTE, 429).
3. RBAC en el backend: tools:execute + permisos de dominio de la herramienta. Un rechazo
   queda como ejecución `rejected` y en la auditoría (permission_denied), sin la entrada.
4. Validación estricta de la entrada con el modelo de la herramienta (extra=forbid, 422).
5. Objetivo y alcance: el activo o incidente debe existir y estar en el site pedido (404).
6. Idempotencia (clave del cliente) y anti-duplicado (misma entrada en curso del mismo
   usuario): se devuelve la ejecución existente.
7. Concurrencia por usuario y global, contada bajo un advisory lock (429).
8. Ejecución con plazo:
   - lecturas: en una conexión propia, transacción READ ONLY y statement_timeout; su PID
     se guarda para que `cancel` la interrumpa de verdad (pg_cancel_backend);
   - investigaciones y acciones: en la sesión de la petición, delegando en el Response
     Engine o en el servicio de casos (con su propia política, idempotencia y auditoría).
9. Salida validada con el modelo de salida, acotada (ANALYST_TOOLS_RESULT_MAX_KB) y con el
   SHA-256 de su JSON canónico; evidencia y procedencia; auditoría `tool_*`.

Las herramientas de acción no se ejecutan en un paso: `preview` guarda una vista previa sin
efectos (estado previewed, caduca en ANALYST_TOOLS_PREVIEW_TTL_MINUTES) y `confirm` la
ejecuta con la MISMA entrada (no se puede cambiar entre la vista previa y la confirmación),
registrando quién aprobó y cuándo.

Nada aquí acepta comandos, scripts ni SQL, y nada se ejecuta por iniciativa propia: siempre
hay un usuario con su rol (invoker=user).
"""

import hashlib
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ValidationError
from sqlalchemy import Engine, delete, func, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
    SentraError,
)
from app.core.permissions import Permission
from app.core.rate_limit import Limiter
from app.db.locks import TOOL_CONCURRENCY_LOCK_KEY
from app.models.asset import Asset
from app.models.incident import Incident
from app.models.response import ResponseExecution
from app.models.site import Site
from app.models.tool import ToolExecution
from app.models.user import User
from app.response.results import clean_text
from app.schemas.tools import (
    DelegatedExecution,
    ToolCatalog,
    ToolExecutionList,
    ToolExecutionOut,
    ToolOut,
    ToolRunRequest,
)
from app.services import audit_service
from app.services.audit_service import Actor
from app.tools.catalog import TOOLS, WRITING_TOOLS, get_tool
from app.tools.registry import ToolContext, ToolDefinition, ToolOutput, ToolPreview

logger = logging.getLogger(__name__)

# Margen tras el plazo antes de dar por interrumpida una ejecución running (el proceso que la
# llevaba murió): el statement_timeout ya la habría cortado mucho antes.
INTERRUPTED_GRACE = timedelta(seconds=120)
SUMMARY_MAX = 500
EVIDENCE_MAX = 50
SWEEP_BATCH = 500


class ToolsDisabledError(ConflictError):
    code = "tools_disabled"


class ToolUnavailableError(ConflictError):
    code = "tool_unavailable"


class ToolValidationError(SentraError):
    status_code = 422
    code = "tool_invalid_input"


class ToolPolicyError(SentraError):
    status_code = 422

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ToolStateError(ConflictError):
    code = "tool_invalid_state"


class ToolConcurrencyError(RateLimitedError):
    code = "tool_concurrency_limit"


@dataclass(frozen=True)
class ToolOperator:
    """Quién pide la herramienta: siempre un usuario del dashboard con sus permisos."""

    user: User
    actor: Actor
    permissions: frozenset[Permission]


@dataclass
class _Target:
    type: str | None = None
    public_id: UUID | None = None
    label: str | None = None
    asset: Asset | None = None
    incident: Incident | None = None
    site_id: int | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def canonical_json(value: Any) -> bytes:
    """JSON canónico (claves ordenadas, sin espacios, UTF-8): base de los SHA-256."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_of(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


# Margen para el reloj al comparar lo que tardó con el statement_timeout (en Windows la
# resolución del reloj ronda los 15 ms).
TIMEOUT_SLACK_SECONDS = 0.1


def _query_cancelled(exc: BaseException) -> bool:
    """True si PostgreSQL canceló la consulta (SQLSTATE 57014, query_canceled).

    El SQLSTATE es el mismo para un statement_timeout y para pg_cancel_backend, y el texto
    del mensaje depende de lc_messages del servidor (en un PostgreSQL en español no dice
    "statement timeout"): la causa se decide con el estado guardado y el tiempo transcurrido
    (ver `_cancellation_failure`), nunca con el mensaje.
    """
    orig = getattr(exc, "orig", None)
    return getattr(orig, "sqlstate", None) == "57014"


def _cancellation_failure(
    persisted_status: str | None, elapsed_seconds: float, timeout_seconds: int
) -> tuple[str, str, str]:
    """Causa de una consulta cancelada por PostgreSQL.

    - La cancelación por API guarda `cancelled` (con quién) y lo confirma ANTES de llamar a
      pg_cancel_backend, así que si la fila dice `cancelled` fue una persona.
    - Si no, la única cancelación que pide Sentra es su statement_timeout: solo se acepta
      como timeout si de verdad pasó ese tiempo.
    - Cualquier otra (un DBA con pg_cancel_backend, un reinicio) es un fallo, no se atribuye
      ni a una persona de Sentra ni al límite de la herramienta.
    """
    if persisted_status == "cancelled":
        return ("cancelled", "tool_cancelled", "Cancelled by a user")
    if elapsed_seconds + TIMEOUT_SLACK_SECONDS >= timeout_seconds:
        return ("timed_out", "tool_timeout", f"Exceeded {timeout_seconds} s")
    return ("failed", "tool_query_cancelled", "The database cancelled the query")


class ToolEngine:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        limiter: Limiter | None = None,
        discovery_runner: Callable[[], Any] | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._limiter = limiter
        self._discovery_runner = discovery_runner

    # --- Catálogo ------------------------------------------------------------------------------

    def _tool_out(self, tool: ToolDefinition, op: ToolOperator) -> ToolOut:
        reason = tool.unavailable_reason(self._settings)
        return ToolOut(
            id=tool.id,
            version=tool.version,
            name=tool.name,
            description=tool.description,
            category=tool.category,
            scope=tool.scope,
            risk_level=tool.risk_level,
            policy=tool.policy,
            required_permissions=sorted(p.value for p in tool.required_permissions),
            required_role=tool.required_role,
            timeout_seconds=tool.timeout_seconds,
            max_rows=tool.max_rows,
            required_capabilities=list(tool.required_capabilities),
            sources=list(tool.sources),
            availability="unavailable" if reason else "available",
            unavailable_reason=reason,
            permitted=tool.required_permissions <= op.permissions,
            input_schema=tool.input_model.model_json_schema(),
            output_schema=tool.output_model.model_json_schema(),
        )

    def catalog(self, op: ToolOperator) -> ToolCatalog:
        return ToolCatalog(
            items=[self._tool_out(tool, op) for tool in TOOLS.values()],
            enabled=self._settings.analyst_tools_enabled,
        )

    def definition(self, op: ToolOperator, tool_id: str) -> ToolOut:
        return self._tool_out(self._tool(tool_id), op)

    def _tool(self, tool_id: str) -> ToolDefinition:
        tool = get_tool(tool_id)
        if tool is None:
            raise NotFoundError("Unknown tool")
        return tool

    # --- Comprobaciones comunes ---------------------------------------------------------------

    def _require_enabled(self) -> None:
        if not self._settings.analyst_tools_enabled:
            raise ToolsDisabledError("The Analyst Tool Engine is disabled on this server")

    def _rate_limit(self, op: ToolOperator) -> None:
        if self._limiter is None:
            return
        wait = self._limiter.acquire(f"user:{op.user.id}")
        if wait > 0:
            raise RateLimitedError("Too many tool requests", wait, scope="analyst_tools")

    def _authorize(self, op: ToolOperator, tool: ToolDefinition, raw: dict[str, Any]) -> None:
        missing = tool.required_permissions - op.permissions
        if not missing:
            return
        # Se guarda el intento (sin la entrada: no está validada) y se audita como el resto de
        # denegaciones de escritura. El 403 sale después del commit.
        now = _now()
        row = ToolExecution(
            tool_id=tool.id,
            tool_version=tool.version,
            category=tool.category,
            risk_level=tool.risk_level,
            status="rejected",
            invoker="user",
            actor=op.actor.name[:64],
            actor_user_id=op.user.id,
            input={},
            input_sha256=sha256_of(raw),
            error_code="permission_denied",
            error_message="Missing: " + ", ".join(sorted(p.value for p in missing)),
            created_at=now,
            finished_at=now,
            duration_ms=0,
        )
        self._session.add(row)
        self._session.flush()
        audit_service.record(
            self._session,
            op.actor,
            "permission_denied",
            audit_service.DENIED,
            target_type="tool",
            target_id=tool.id,
            details={
                "execution": str(row.public_id),
                "permission": sorted(p.value for p in missing),
            },
        )
        raise PermissionDeniedError(f"Your role does not allow this tool ({tool.id})")

    def _validate(self, tool: ToolDefinition, raw: dict[str, Any]) -> BaseModel:
        try:
            return tool.input_model.model_validate(raw)
        except ValidationError as exc:
            details = [
                {"loc": list(err.get("loc", ())), "type": err.get("type")} for err in exc.errors()
            ]
            raise ToolValidationError("Invalid tool input", details) from exc

    def _site(self, site_public_id: UUID | None) -> int | None:
        if site_public_id is None:
            return None
        site_id = self._session.scalar(select(Site.id).where(Site.public_id == site_public_id))
        if site_id is None:
            raise NotFoundError("Site not found")
        return site_id

    def _target(self, params: BaseModel, site_id: int | None) -> _Target:
        """Objetivo principal de la entrada (activo o incidente) dentro del alcance pedido."""
        target = _Target(site_id=site_id)
        asset_id = getattr(params, "asset_id", None)
        if asset_id is None and getattr(params, "target_type", None) == "asset":
            asset_id = getattr(params, "target_id", None)
        if asset_id is None and getattr(params, "source", None) == "asset":
            asset_id = getattr(params, "source_id", None)
        if isinstance(asset_id, UUID):
            asset = self._session.scalar(select(Asset).where(Asset.public_id == asset_id))
            if asset is None or (site_id is not None and asset.site_id != site_id):
                raise NotFoundError("Asset not found")
            target.type, target.public_id, target.asset = "asset", asset.public_id, asset
            target.label = asset.display_name[:255]
            target.site_id = asset.site_id
            return target
        incident_id = getattr(params, "incident_id", None)
        if incident_id is None and getattr(params, "target_type", None) == "incident":
            incident_id = getattr(params, "target_id", None)
        if isinstance(incident_id, UUID):
            incident = self._session.scalar(
                select(Incident).where(Incident.public_id == incident_id)
            )
            if incident is None:
                raise NotFoundError("Incident not found")
            from app.incidents.workflow import incident_key

            target.type, target.public_id, target.incident = (
                "incident",
                incident.public_id,
                incident,
            )
            target.label = f"{incident_key(incident.number)} {incident.title}"[:255]
        return target

    def _context_incident(self, public_id: UUID | None) -> Incident | None:
        if public_id is None:
            return None
        incident = self._session.scalar(select(Incident).where(Incident.public_id == public_id))
        if incident is None:
            raise NotFoundError("Incident not found")
        return incident

    def _by_idempotency(
        self, op: ToolOperator, key: str | None, tool: ToolDefinition, input_hash: str
    ) -> ToolExecution | None:
        if key is None:
            return None
        row = self._session.scalar(
            select(ToolExecution).where(
                ToolExecution.actor_user_id == op.user.id, ToolExecution.idempotency_key == key
            )
        )
        if row is not None and (row.tool_id != tool.id or row.input_sha256 != input_hash):
            raise ToolStateError("This idempotency key was used for another request")
        return row

    def _expire_stale(self, now: datetime) -> None:
        """Cierra filas vivas cuyo plazo venció (proceso muerto o vista previa olvidada)."""
        self._session.execute(
            update(ToolExecution)
            .where(
                ToolExecution.status == "running",
                ToolExecution.deadline_at < now - INTERRUPTED_GRACE,
            )
            .values(
                status="failed",
                error_code="interrupted",
                error_message="The process running this tool stopped before finishing",
                finished_at=now,
                backend_pid=None,
            )
        )
        self._session.execute(
            update(ToolExecution)
            .where(ToolExecution.status == "previewed", ToolExecution.deadline_at < now)
            .values(status="expired", finished_at=now)
        )

    def _check_concurrency(self, op: ToolOperator, now: datetime) -> None:
        # El advisory lock de transacción serializa el conteo y la inserción: dos peticiones
        # simultáneas no pueden ver ambas "hay hueco" y superar el límite.
        self._session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": TOOL_CONCURRENCY_LOCK_KEY}
        )
        self._expire_stale(now)
        mine, total = self._session.execute(
            select(
                func.count().filter(ToolExecution.actor_user_id == op.user.id),
                func.count(),
            ).where(ToolExecution.status == "running")
        ).one()
        if mine >= self._settings.analyst_tools_max_concurrent_per_user:
            raise ToolConcurrencyError("Too many tools running for this user", 2, "analyst_tools")
        if total >= self._settings.analyst_tools_max_concurrent:
            raise ToolConcurrencyError("Too many tools running on this server", 2, "analyst_tools")

    def _new_row(
        self,
        op: ToolOperator,
        tool: ToolDefinition,
        params: BaseModel,
        target: _Target,
        context_incident: Incident | None,
        status: str,
        key: str | None,
        now: datetime,
        deadline: datetime,
    ) -> ToolExecution:
        payload = params.model_dump(mode="json")
        return ToolExecution(
            tool_id=tool.id,
            tool_version=tool.version,
            category=tool.category,
            risk_level=tool.risk_level,
            status=status,
            invoker="user",
            actor=op.actor.name[:64],
            actor_user_id=op.user.id,
            input=payload,
            input_sha256=sha256_of(payload),
            target_type=target.type,
            target_public_id=target.public_id,
            target_label=target.label,
            site_id=target.site_id,
            asset_id=target.asset.id if target.asset else None,
            incident_id=(
                context_incident.id
                if context_incident
                else (target.incident.id if target.incident else None)
            ),
            idempotency_key=key,
            created_at=now,
            started_at=now if status == "running" else None,
            deadline_at=deadline,
        )

    def _context(
        self,
        op: ToolOperator,
        session: Session,
        site_id: int | None,
        incident: Incident | None,
        key: str | None,
    ) -> ToolContext:
        return ToolContext(
            session=session,
            settings=self._settings,
            user=op.user,
            actor=op.actor,
            permissions=op.permissions,
            now=_now(),
            site_id=site_id,
            incident_public_id=incident.public_id if incident else None,
            discovery_runner=self._discovery_runner,
            idempotency_key=key,
        )

    def _prepare(
        self, op: ToolOperator, tool_id: str, body: ToolRunRequest
    ) -> tuple[ToolDefinition, BaseModel, _Target, Incident | None, int | None]:
        self._require_enabled()
        tool = self._tool(tool_id)
        self._rate_limit(op)
        self._authorize(op, tool, body.input)
        params = self._validate(tool, body.input)
        reason = tool.unavailable_reason(self._settings)
        if reason:
            raise ToolUnavailableError(f"Tool unavailable: {reason}")
        site_id = self._site(body.site_id)
        target = self._target(params, site_id)
        incident = self._context_incident(body.incident_id)
        return tool, params, target, incident, site_id

    # --- Ejecución directa ---------------------------------------------------------------------

    def execute(self, op: ToolOperator, tool_id: str, body: ToolRunRequest) -> ToolExecutionOut:
        tool, params, target, incident, site_id = self._prepare(op, tool_id, body)
        if tool.policy == "preview_confirm":
            raise ToolPolicyError(
                "tool_preview_required", "This tool changes data: request a preview first"
            )
        input_hash = sha256_of(params.model_dump(mode="json"))
        existing = self._by_idempotency(op, body.idempotency_key, tool, input_hash)
        if existing is not None:
            return self.execution_out(existing, deduplicated=True)
        now = _now()
        self._check_concurrency(op, now)
        running = self._session.scalar(
            select(ToolExecution).where(
                ToolExecution.actor_user_id == op.user.id,
                ToolExecution.tool_id == tool.id,
                ToolExecution.input_sha256 == input_hash,
                ToolExecution.status == "running",
            )
        )
        if running is not None:
            self._session.commit()
            return self.execution_out(running, deduplicated=True)
        row = self._new_row(
            op,
            tool,
            params,
            target,
            incident,
            "running",
            body.idempotency_key,
            now,
            now + timedelta(seconds=tool.timeout_seconds),
        )
        self._session.add(row)
        try:
            self._session.commit()
        except IntegrityError:
            # Carrera con otra petición idéntica en otro worker: se devuelve la suya.
            self._session.rollback()
            other = self._session.scalar(
                select(ToolExecution).where(
                    ToolExecution.actor_user_id == op.user.id,
                    ToolExecution.tool_id == tool.id,
                    ToolExecution.input_sha256 == input_hash,
                    ToolExecution.status == "running",
                )
            ) or self._by_idempotency(op, body.idempotency_key, tool, input_hash)
            if other is None:
                raise
            return self.execution_out(other, deduplicated=True)
        self._run(op, tool, params, row, site_id, incident, body.idempotency_key)
        return self.execution_out(row)

    def _run(
        self,
        op: ToolOperator,
        tool: ToolDefinition,
        params: BaseModel,
        row: ToolExecution,
        site_id: int | None,
        incident: Incident | None,
        key: str | None,
    ) -> None:
        started = _now()
        clock = time.monotonic()
        output: ToolOutput | None = None
        failure: tuple[str, str, str] | None = None  # (status, code, message)
        try:
            if tool.id in WRITING_TOOLS:
                output = self._run_writing(op, tool, params, site_id, incident, key)
            else:
                output = self._run_read_only(op, tool, params, row, site_id, incident, key)
        except SentraError as exc:
            self._session.rollback()
            failure = ("failed", exc.code, exc.message)
            if isinstance(exc, PermissionDeniedError | NotFoundError | RateLimitedError):
                # El servicio delegado negó algo que la herramienta no podía saber antes (p. ej.
                # una acción de Response que exige response:manage): misma respuesta HTTP.
                self._finish(row, failure, None, started)
                raise
        except DBAPIError as exc:
            self._session.rollback()
            if _query_cancelled(exc):
                persisted = self._session.scalar(
                    select(ToolExecution.status).where(ToolExecution.id == row.id)
                )
                failure = _cancellation_failure(
                    persisted, time.monotonic() - clock, tool.timeout_seconds
                )
            else:
                logger.exception("tool failed", extra={"tool": tool.id})
                failure = ("failed", "tool_database_error", "Database error while running")
        except Exception:
            self._session.rollback()
            logger.exception("tool failed", extra={"tool": tool.id})
            failure = ("failed", "tool_error", "Unexpected error while running the tool")
        # Los errores de la política delegada (response_blocked...) quedan en la fila con el
        # código de Response: la petición responde 200 con la ejecución en estado failed.
        self._finish(row, failure, output, started)

    def _run_read_only(
        self,
        op: ToolOperator,
        tool: ToolDefinition,
        params: BaseModel,
        row: ToolExecution,
        site_id: int | None,
        incident: Incident | None,
        key: str | None,
    ) -> ToolOutput:
        """Lectura en una conexión propia: READ ONLY, statement_timeout y PID cancelable."""
        bind = self._session.get_bind()
        engine: Engine = bind if isinstance(bind, Engine) else bind.engine
        timeout_ms = tool.timeout_seconds * 1000
        with engine.connect() as conn:
            conn.execute(text("SET TRANSACTION READ ONLY"))
            conn.execute(
                text("SELECT set_config('statement_timeout', :ms, true)"), {"ms": str(timeout_ms)}
            )
            pid = conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
            self._session.execute(
                update(ToolExecution).where(ToolExecution.id == row.id).values(backend_pid=pid)
            )
            self._session.commit()
            with Session(bind=conn, expire_on_commit=False) as work:
                ctx = self._context(op, work, site_id, incident, key)
                output = tool.handler(ctx, params)
                # Se serializa dentro de la transacción: los atributos perezosos se leen aquí.
                self._serialize(tool, output)
            conn.rollback()
        return output

    def _run_writing(
        self,
        op: ToolOperator,
        tool: ToolDefinition,
        params: BaseModel,
        site_id: int | None,
        incident: Incident | None,
        key: str | None,
    ) -> ToolOutput:
        """Investigaciones y acciones: delegan en servicios que confirman su propio trabajo."""
        self._session.execute(
            text("SELECT set_config('statement_timeout', :ms, true)"),
            {"ms": str(tool.timeout_seconds * 1000)},
        )
        ctx = self._context(op, self._session, site_id, incident, key)
        output = tool.handler(ctx, params)
        self._serialize(tool, output)
        return output

    def _serialize(self, tool: ToolDefinition, output: ToolOutput) -> None:
        # Valida contra el modelo de salida declarado (un handler no puede devolver otra
        # cosa) y deja el JSON preparado en el propio objeto.
        data = tool.output_model.model_validate(output.data).model_dump(mode="json")
        output.provenance = {**output.provenance, "_payload": data}

    def _finish(
        self,
        row: ToolExecution,
        failure: tuple[str, str, str] | None,
        output: ToolOutput | None,
        started: datetime,
    ) -> None:
        current = self._session.get(ToolExecution, row.id, populate_existing=True)
        assert current is not None  # noqa: S101  (fila de esta petición)
        now = _now()
        if current.status == "cancelled":
            # Cancelada desde otra petición mientras corría: se respeta (sin salida).
            failure = ("cancelled", current.error_code or "tool_cancelled", "Cancelled by a user")
        if failure is None and current.deadline_at and now > current.deadline_at:
            failure = ("timed_out", "tool_timeout", "The tool exceeded its time limit")
        if failure is not None:
            current.status, current.error_code, current.error_message = (
                failure[0],
                failure[1][:64],
                clean_text(failure[2], 500),
            )
        elif output is not None:
            self._store_output(current, output)
            current.status = "succeeded"
            current.response_execution_id = output.response_execution_id
            if output.incident_id is not None:
                current.incident_id = output.incident_id
        current.finished_at = now
        current.duration_ms = max(0, int((now - started).total_seconds() * 1000))
        current.backend_pid = None
        current.version += 1
        audit_service.record(
            self._session,
            Actor(current.actor, current.actor_user_id),
            "tool_executed",
            audit_service.SUCCESS if current.status == "succeeded" else audit_service.FAILURE,
            target_type="tool",
            target_id=current.tool_id,
            details={
                "execution": str(current.public_id),
                "status": current.status,
                "target": str(current.target_public_id) if current.target_public_id else None,
                "error": current.error_code,
                "output_sha256": current.output_sha256,
            },
            commit=False,
        )
        self._session.commit()
        row.status = current.status

    def _store_output(self, row: ToolExecution, output: ToolOutput) -> None:
        provenance = dict(output.provenance)
        payload = provenance.pop("_payload")
        limit = self._settings.analyst_tools_result_max_kb * 1024
        encoded = canonical_json(payload)
        row.output_bytes = len(encoded)
        if len(encoded) > limit:
            # Un JSON cortado no es evidencia fiable: se guarda un marcador con el tamaño y el
            # hash de lo que se obtuvo, y la evidencia (referencias) se conserva entera.
            row.output = {"truncated": True, "original_bytes": len(encoded), "max_bytes": limit}
            row.truncated = True
        else:
            row.output = payload
            row.truncated = False
        row.output_sha256 = hashlib.sha256(encoded).hexdigest()
        row.summary = clean_text(output.summary, SUMMARY_MAX)
        row.evidence = [ref.as_dict() for ref in output.evidence[:EVIDENCE_MAX]]
        provenance["generated_at"] = _now().isoformat()
        provenance["tool_version"] = row.tool_version
        row.provenance = provenance

    # --- Vista previa y confirmación de acciones -----------------------------------------------

    def preview(self, op: ToolOperator, tool_id: str, body: ToolRunRequest) -> ToolExecutionOut:
        tool, params, target, incident, site_id = self._prepare(op, tool_id, body)
        if tool.policy != "preview_confirm" or tool.preview is None:
            raise ToolPolicyError("tool_preview_not_applicable", "This tool runs directly")
        input_hash = sha256_of(params.model_dump(mode="json"))
        existing = self._by_idempotency(op, body.idempotency_key, tool, input_hash)
        if existing is not None:
            return self.execution_out(existing, deduplicated=True)
        ctx = self._context(op, self._session, site_id, incident, body.idempotency_key)
        result: ToolPreview = tool.preview(ctx, params)
        now = _now()
        row = self._new_row(
            op,
            tool,
            params,
            target,
            incident,
            "previewed",
            body.idempotency_key,
            now,
            now + timedelta(minutes=self._settings.analyst_tools_preview_ttl_minutes),
        )
        preview = {
            "allowed": result.allowed,
            "effects": [clean_text(e, 300) for e in result.effects][:20],
            "blockers": result.blockers[:20],
            "warnings": result.warnings[:20],
            "data": result.data,
        }
        row.output = {"preview": preview}
        row.output_sha256 = sha256_of(row.output)
        row.summary = clean_text(result.summary, SUMMARY_MAX)
        self._session.add(row)
        self._session.flush()
        audit_service.record(
            self._session,
            op.actor,
            "tool_preview_generated",
            target_type="tool",
            target_id=tool.id,
            details={
                "execution": str(row.public_id),
                "allowed": result.allowed,
                "blockers": [b.get("code") for b in result.blockers],
            },
            commit=False,
        )
        self._session.commit()
        return self.execution_out(row)

    def _lock(self, public_id: UUID) -> ToolExecution:
        row = self._session.scalar(
            select(ToolExecution).where(ToolExecution.public_id == public_id).with_for_update()
        )
        if row is None:
            raise NotFoundError("Tool execution not found")
        return row

    def _visible(self, op: ToolOperator, row: ToolExecution) -> None:
        # Sin tools:manage solo las propias; las ajenas responden 404 (sin revelar que existen).
        if row.actor_user_id != op.user.id and Permission.TOOLS_MANAGE not in op.permissions:
            raise NotFoundError("Tool execution not found")

    def confirm(
        self,
        op: ToolOperator,
        public_id: UUID,
        version: int,
        confirmed: bool,
        note: str | None,
    ) -> ToolExecutionOut:
        """Ejecuta una vista previa vigente con su MISMA entrada y registra la aprobación."""
        self._require_enabled()
        self._rate_limit(op)
        row = self._lock(public_id)
        self._visible(op, row)
        tool = self._tool(row.tool_id)
        if not confirmed:
            raise ToolPolicyError("confirmation_required", "Confirm the action explicitly")
        now = _now()
        if row.status == "previewed" and row.deadline_at and row.deadline_at < now:
            row.status, row.finished_at = "expired", now
            self._session.commit()
        if row.status != "previewed":
            raise ToolStateError(f"The execution is {row.status}, not previewed")
        if row.version != version:
            raise ToolStateError("The execution changed; reload it")
        if row.tool_version != tool.version:
            raise ToolStateError("The tool changed after the preview; preview it again")
        missing = tool.required_permissions - op.permissions
        if missing:
            audit_service.record(
                self._session,
                op.actor,
                "permission_denied",
                audit_service.DENIED,
                target_type="tool",
                target_id=tool.id,
                details={"execution": str(row.public_id)},
            )
            raise PermissionDeniedError(f"Your role does not allow this tool ({tool.id})")
        params = self._validate(tool, row.input)
        site_id = row.site_id
        incident = self._session.get(Incident, row.incident_id) if row.incident_id else None
        self._check_concurrency(op, now)
        row.status = "running"
        row.started_at = now
        row.deadline_at = now + timedelta(seconds=tool.timeout_seconds)
        row.approved_by = op.actor.name[:64]
        row.approved_by_user_id = op.user.id
        row.approved_at = now
        row.approval_note = clean_text(note, 500) if note else None
        row.output = None
        row.output_sha256 = None
        row.version += 1
        audit_service.record(
            self._session,
            op.actor,
            "tool_action_approved",
            target_type="tool",
            target_id=tool.id,
            details={
                "execution": str(row.public_id),
                "requested_by": row.actor,
                "target": str(row.target_public_id) if row.target_public_id else None,
            },
            commit=False,
        )
        self._session.commit()
        self._run(op, tool, params, row, site_id, incident, row.idempotency_key)
        return self.execution_out(row)

    # --- Cancelación -----------------------------------------------------------------------------

    def cancel(self, op: ToolOperator, public_id: UUID, version: int) -> ToolExecutionOut:
        row = self._lock(public_id)
        self._visible(op, row)
        if row.version != version:
            raise ToolStateError("The execution changed; reload it")
        now = _now()
        pid: int | None = None
        if row.status == "previewed":
            row.status, row.finished_at = "cancelled", now
        elif row.status == "running":
            pid = row.backend_pid
            row.status, row.finished_at = "cancelled", now
            row.error_code = "tool_cancelled"
        elif row.response_execution_id is not None:
            # Acción delegada: se cancela en el Response Engine (con su permiso response:manage
            # y su propia auditoría); la ejecución de la herramienta ya terminó (la delegación).
            from app.services.response_service import Operator as ResponseOperator
            from app.services.response_service import ResponseService

            delegated = self._session.get(ResponseExecution, row.response_execution_id)
            if delegated is None:
                raise ToolStateError("The delegated execution no longer exists")
            ResponseService(self._session, self._settings, self._discovery_runner).cancel(
                ResponseOperator(op.user, op.actor, op.permissions),
                delegated.public_id,
                delegated.version,
                "Cancelled from the Analyst Tool Engine",
            )
            return self.execution_out(row)
        else:
            raise ToolStateError(f"The execution is {row.status} and cannot be cancelled")
        row.cancelled_by = op.actor.name[:64]
        row.version += 1
        audit_service.record(
            self._session,
            op.actor,
            "tool_execution_cancelled",
            target_type="tool",
            target_id=row.tool_id,
            details={"execution": str(row.public_id)},
            commit=False,
        )
        # Primero se confirma el estado y después se cancela la consulta: así el ejecutor, al
        # recibir query_canceled, ya lee `cancelled` y no lo confunde con un timeout.
        self._session.commit()
        if pid is not None:
            # Solo el PID guardado de ESTA ejecución (nunca uno arbitrario), y solo si sigue
            # siendo de esta ejecución en curso.
            still_running = self._session.scalar(
                select(ToolExecution.backend_pid).where(ToolExecution.id == row.id)
            )
            if still_running == pid:
                self._session.execute(text("SELECT pg_cancel_backend(:pid)"), {"pid": pid})
                self._session.commit()
        return self.execution_out(row)

    # --- Lecturas del historial ----------------------------------------------------------------

    def get(self, op: ToolOperator, public_id: UUID) -> ToolExecutionOut:
        row = self._session.scalar(
            select(ToolExecution).where(ToolExecution.public_id == public_id)
        )
        if row is None:
            raise NotFoundError("Tool execution not found")
        self._visible(op, row)
        return self.execution_out(row)

    def list(
        self,
        op: ToolOperator,
        *,
        tool_id: str | None = None,
        status: str | None = None,
        asset_public_id: UUID | None = None,
        incident_public_id: UUID | None = None,
        mine: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> ToolExecutionList:
        where: list[Any] = []
        if mine or Permission.TOOLS_MANAGE not in op.permissions:
            where.append(ToolExecution.actor_user_id == op.user.id)
        if tool_id:
            where.append(ToolExecution.tool_id == tool_id)
        if status:
            where.append(ToolExecution.status == status)
        if asset_public_id is not None:
            where.append(
                ToolExecution.asset_id.in_(
                    select(Asset.id).where(Asset.public_id == asset_public_id)
                )
            )
        if incident_public_id is not None:
            where.append(
                ToolExecution.incident_id.in_(
                    select(Incident.id).where(Incident.public_id == incident_public_id)
                )
            )
        total = self._session.scalar(select(func.count()).select_from(ToolExecution).where(*where))
        rows = self._session.scalars(
            select(ToolExecution)
            .where(*where)
            .order_by(ToolExecution.created_at.desc(), ToolExecution.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return ToolExecutionList(items=[self.execution_out(r) for r in rows], total=int(total or 0))

    def execution_out(self, row: ToolExecution, *, deduplicated: bool = False) -> ToolExecutionOut:
        tool = get_tool(row.tool_id)
        site = self._session.get(Site, row.site_id) if row.site_id else None
        asset = self._session.get(Asset, row.asset_id) if row.asset_id else None
        incident = self._session.get(Incident, row.incident_id) if row.incident_id else None
        delegated = (
            self._session.get(ResponseExecution, row.response_execution_id)
            if row.response_execution_id
            else None
        )
        return ToolExecutionOut(
            execution_id=row.public_id,
            correlation_id=row.correlation_id,
            tool_id=row.tool_id,
            tool_version=row.tool_version,
            tool_name=tool.name if tool else row.tool_id,
            category=row.category,
            risk_level=row.risk_level,
            status=row.status,
            invoker=row.invoker,
            actor=row.actor,
            input=row.input or {},
            input_sha256=row.input_sha256,
            output=row.output,
            output_sha256=row.output_sha256,
            output_bytes=row.output_bytes,
            truncated=row.truncated,
            summary=row.summary,
            evidence=list(row.evidence or []),
            provenance=row.provenance,
            error_code=row.error_code,
            error_message=row.error_message,
            target_type=row.target_type,
            target_id=row.target_public_id,
            target_label=row.target_label,
            site_id=site.public_id if site else None,
            asset_id=asset.public_id if asset else None,
            incident_id=incident.public_id if incident else None,
            response_execution=(
                DelegatedExecution(
                    execution_id=delegated.public_id,
                    action_id=delegated.action_id,
                    status=delegated.status,
                )
                if delegated
                else None
            ),
            approved_by=row.approved_by,
            approved_at=row.approved_at,
            approval_note=row.approval_note,
            cancelled_by=row.cancelled_by,
            created_at=row.created_at,
            started_at=row.started_at,
            finished_at=row.finished_at,
            deadline_at=row.deadline_at,
            duration_ms=row.duration_ms,
            version=row.version,
            deduplicated=deduplicated,
        )

    # --- Mantenimiento ---------------------------------------------------------------------------

    def sweep(self, now: datetime | None = None) -> None:
        """Vistas previas caducadas y ejecuciones interrumpidas (job response-engine)."""
        self._expire_stale(now or _now())
        self._session.commit()

    def purge(self, now: datetime | None = None) -> int:
        """Retención opt-in (ANALYST_TOOLS_RETENTION_DAYS): nunca lo vinculado a un caso."""
        days = self._settings.analyst_tools_retention_days
        if days is None:
            return 0
        cutoff = (now or _now()) - timedelta(days=days)
        ids = self._session.scalars(
            select(ToolExecution.id)
            .where(
                ToolExecution.created_at < cutoff,
                ToolExecution.incident_id.is_(None),
                ToolExecution.status.not_in(("previewed", "running")),
            )
            .limit(SWEEP_BATCH)
        ).all()
        if ids:
            self._session.execute(delete(ToolExecution).where(ToolExecution.id.in_(ids)))
        self._session.commit()
        return len(ids)
