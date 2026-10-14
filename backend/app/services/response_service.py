"""Response Engine y Playbooks (Fase 5D): la única capa que valida, ejecuta y sigue acciones.

La API del dashboard, la UI, los playbooks, el job de barrido y el protocolo del agente
pasan todos por aquí, así no hay reglas distintas en ningún sitio:

1. RBAC: el rol debe tener TODOS los permisos de la acción (403 si no), igual en preview,
   ejecución y cada paso de playbook (con los permisos del actor en ese momento).
2. Política (app/response/policy.py): bloqueos y avisos sobre el objetivo, el agente, sus
   capacidades, la plataforma y los límites. Preview y ejecución llaman a la misma función.
3. Idempotencia: clave del cliente (una por diálogo) e índice único de ejecuciones vivas por
   acción+objetivo; la segunda petición igual recibe la primera ejecución.
4. Ejecución: acciones de servidor, en la petición con su handler; acciones de agente, como
   comando en cola con TTL que solo el agente actual del activo puede recoger y completar.
5. Seguimiento: el barrido caduca comandos y plazos (timed_out), reentrega una vez lo que es
   idempotente y avanza los playbooks (fail-stop por defecto).

Nunca se finge éxito: un agente offline, sin capacidad o revocado bloquea (o deja en cola
con TTL si RESPONSE_OFFLINE_AGENT_POLICY=queue); un comando sin respuesta acaba en
timed_out. Toda transición queda en audit_events sin secretos.
"""

import logging
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    SentraError,
)
from app.core.permissions import Permission, permissions_for
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.incident import Incident, IncidentActivity
from app.models.response import (
    ACTIVE_EXECUTION_STATUSES,
    AgentCommand,
    Playbook,
    PlaybookRun,
    PlaybookVersion,
    ResponseExecution,
)
from app.models.user import User
from app.repositories.asset_repository import AssetRepository
from app.response.catalog import (
    ACTIONS,
    RISK_RANK,
    ActionDefinition,
    get_action,
)
from app.response.handlers import ActionContext, ActionFailedError, ActionResult, Issue
from app.response.playbooks import (
    BUILTIN_PLAYBOOKS,
    PlaybookError,
    PlaybookStepIn,
    ValidatedSteps,
    validate_steps,
)
from app.response.policy import Decision, evaluate
from app.response.results import bounded_result, clean_text
from app.schemas.response import (
    ActionList,
    ActionOut,
    AgentCommandOut,
    CommandResultRequest,
    CommandResultResponse,
    ExecutionList,
    ExecutionOut,
    ExecutionRequest,
    IssueOut,
    PlaybookCreate,
    PlaybookList,
    PlaybookOut,
    PlaybookPreviewOut,
    PlaybookRunList,
    PlaybookRunOut,
    PlaybookRunRequest,
    PlaybookRunStepOut,
    PlaybookStepOut,
    PlaybookStepPreview,
    PlaybookUpdate,
    PreviewOut,
)
from app.services import audit_service
from app.services.agent_service import authenticate_agent, record_contact
from app.services.audit_service import Actor

logger = logging.getLogger(__name__)
SYSTEM = Actor("system")
# Lotes del barrido: acotan el trabajo por vuelta (lo que no cabe queda para la siguiente).
SWEEP_BATCH = 200
RUNS_PER_SWEEP = 100


class ResponseDisabledError(ConflictError):
    code = "response_disabled"


class ResponseBlockedError(ConflictError):
    # La política bloquea la ejecución: `details` lleva los bloqueos y, si quedó registrada,
    # la ejecución blocked (evidencia del intento).
    code = "response_blocked"


class ResponseValidationError(SentraError):
    status_code = 422
    code = "response_invalid"

    def __init__(self, code: str, message: str, details: list[dict[str, Any]] | None = None):
        super().__init__(message, details)
        self.code = code


class ResponseConflictError(ConflictError):
    code = "response_conflict"


class ResponseStateError(ConflictError):
    code = "response_invalid_state"


class CommandNotFoundError(NotFoundError):
    code = "command_not_found"


class CommandNotDeliveredError(ConflictError):
    code = "command_not_delivered"


@dataclass(frozen=True)
class Operator:
    """Quién pide la acción: usuario del dashboard (o None para el sistema) y sus permisos."""

    user: User | None
    actor: Actor
    permissions: frozenset[Permission]

    @classmethod
    def for_user(cls, user: User, client_ip: str | None) -> "Operator":
        return cls(user, Actor.for_user(user, client_ip), permissions_for(user.role))


@dataclass
class Target:
    asset: Asset | None = None
    incident: Incident | None = None
    detection: Detection | None = None
    # Incidente de contexto (ejecución lanzada desde un caso), distinto del objetivo.
    context_incident: Incident | None = None

    @property
    def label(self) -> str:
        if self.asset is not None:
            return self.asset.display_name[:255]
        if self.incident is not None:
            from app.incidents.workflow import incident_key

            return f"{incident_key(self.incident.number)} {self.incident.title}"[:255]
        return "-"


@dataclass
class _Created:
    execution: ResponseExecution
    deduplicated: bool = False


def _now() -> datetime:
    return datetime.now(UTC)


def _issues(issues: Sequence[Issue]) -> list[IssueOut]:
    return [IssueOut(code=i.code, message=i.message) for i in issues]


def _duration(start: datetime | None, end: datetime | None) -> int | None:
    if start is None or end is None:
        return None
    return max(0, int((end - start).total_seconds() * 1000))


def _retry_policy(action: ActionDefinition) -> str:
    if action.requires_agent and action.max_deliveries > 1:
        return f"redeliver_up_to_{action.max_deliveries}"
    return "none"


class ResponseService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        discovery_runner: Callable[[], Any] | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._discovery_runner = discovery_runner

    # --- Utilidades --------------------------------------------------------------------------

    def _require_enabled(self) -> None:
        if not self._settings.response_enabled:
            raise ResponseDisabledError("Response is disabled on this server")

    def _require_playbooks(self) -> None:
        self._require_enabled()
        if not self._settings.playbooks_enabled:
            raise ResponseDisabledError("Playbooks are disabled on this server")

    def _deny(self, op: Operator, what: str, target: object, missing: set[Permission]) -> None:
        # Auditado como el resto de denegaciones de escritura (require_permission).
        audit_service.record(
            self._session,
            op.actor,
            "permission_denied",
            audit_service.DENIED,
            target_type="response",
            target_id=target,
            details={"action": what, "permission": sorted(p.value for p in missing)},
        )
        raise PermissionDeniedError(f"Your role does not allow this action ({what})")

    def _check_permissions(
        self, op: Operator, needed: frozenset[Permission], what: str, target: object
    ) -> None:
        missing = set(needed - op.permissions)
        if missing:
            self._deny(op, what, target, missing)

    def _resolve(
        self,
        op: Operator,
        target_type: str,
        target_id: UUID,
        incident_id: UUID | None,
        detection_id: UUID | None,
    ) -> Target:
        target = Target()
        if target_type == "asset":
            target.asset = AssetRepository(self._session).get_by_public_id(target_id)
            if target.asset is None:
                raise NotFoundError("Asset not found")
        else:
            target.incident = self._session.scalar(
                select(Incident).where(Incident.public_id == target_id)
            )
            if target.incident is None:
                raise NotFoundError("Incident not found")
        if incident_id is not None:
            # Lanzar desde un caso escribe en su timeline: hace falta poder trabajar casos.
            self._check_permissions(
                op,
                frozenset({Permission.INCIDENTS_READ, Permission.INCIDENTS_MANAGE}),
                "incident_context",
                incident_id,
            )
            target.context_incident = self._session.scalar(
                select(Incident).where(Incident.public_id == incident_id)
            )
            if target.context_incident is None:
                raise NotFoundError("Incident not found")
            if target.incident is None:
                target.incident = target.context_incident
        if detection_id is not None:
            target.detection = self._session.scalar(
                select(Detection).where(Detection.public_id == detection_id)
            )
            if target.detection is None:
                raise NotFoundError("Detection not found")
        return target

    def _params(self, action: ActionDefinition, raw: dict[str, Any]) -> Any:
        try:
            return action.params_model.model_validate(raw)
        except ValidationError as exc:
            details = [
                {"loc": list(err.get("loc", ())), "type": err.get("type")} for err in exc.errors()
            ]
            raise ResponseValidationError(
                "response_invalid_parameters", "Invalid action parameters", details
            ) from exc

    def _context(self, op: Operator, target: Target, params: Any, now: datetime) -> ActionContext:
        return ActionContext(
            session=self._session,
            settings=self._settings,
            actor=op.actor,
            user=op.user,
            permissions=op.permissions,
            params=params,
            now=now,
            asset=target.asset,
            incident=target.incident,
            detection=target.detection,
            discovery_runner=self._discovery_runner,
        )

    def _action(self, action_id: str) -> ActionDefinition:
        action = get_action(action_id)
        if action is None:
            raise NotFoundError("Unknown response action")
        return action

    def _prepare(
        self, op: Operator, request: ExecutionRequest
    ) -> tuple[ActionDefinition, Target, Any, ActionContext, Decision]:
        action = self._action(request.action_id)
        # 403 antes de mirar el objetivo: sin permiso no se revela nada de él.
        self._check_permissions(op, action.required_permissions, action.id, request.target_id)
        if request.target_type != action.target_type:
            raise ResponseValidationError(
                "response_target_mismatch", f"This action targets an {action.target_type}"
            )
        target = self._resolve(
            op, request.target_type, request.target_id, request.incident_id, request.detection_id
        )
        params = self._params(action, request.parameters)
        ctx = self._context(op, target, params, _now())
        return action, target, params, ctx, evaluate(action, ctx)

    # --- Catálogo ----------------------------------------------------------------------------

    def list_actions(self, op: Operator, asset_public_id: UUID | None = None) -> ActionList:
        asset = None
        if asset_public_id is not None:
            asset = AssetRepository(self._session).get_by_public_id(asset_public_id)
            if asset is None:
                raise NotFoundError("Asset not found")
        items = []
        for action in ACTIONS.values():
            blockers: list[Issue] = []
            if asset is not None and action.target_type == "asset":
                ctx = self._context(
                    op, Target(asset=asset), action.params_model.model_construct(), _now()
                )
                blockers = evaluate(action, ctx, count_active=False).blockers
            items.append(self._action_out(action, op, blockers))
        return ActionList(
            items=items,
            response_enabled=self._settings.response_enabled,
            playbooks_enabled=self._settings.playbooks_enabled,
        )

    def _action_out(
        self, action: ActionDefinition, op: Operator, blockers: Sequence[Issue] = ()
    ) -> ActionOut:
        return ActionOut(
            id=action.id,
            name=action.name,
            description=action.description,
            category=action.category,
            scope=action.scope,
            target_type=action.target_type,
            risk_level=action.risk_level,
            destructive=action.destructive,
            requires_confirmation=action.requires_confirmation,
            requires_agent=action.requires_agent,
            supported_platforms=sorted(action.supported_platforms),
            required_role=action.required_role,
            required_permissions=sorted(p.value for p in action.required_permissions),
            timeout_seconds=action.timeout_seconds,
            retry_policy=_retry_policy(action),
            availability=action.availability if action.available else "not_implemented",
            expected_effect=action.expected_effect,
            parameters_schema=action.params_model.model_json_schema(),
            permitted=action.required_permissions <= op.permissions,
            blockers=_issues(blockers),
        )

    # --- Preview -----------------------------------------------------------------------------

    def preview(self, op: Operator, request: ExecutionRequest) -> PreviewOut:
        """Sin efectos: misma política que execute (solo la auditoría de previews mutativos)."""
        self._require_enabled()
        action, target, params, _, decision = self._prepare(op, request)
        if action.requires_confirmation:
            # Solo se audita el preview de acciones que cambian datos: es la antesala de una
            # mutación. Los de lectura no llenan la auditoría.
            audit_service.record(
                self._session,
                op.actor,
                "response_preview_generated",
                target_type=request.target_type,
                target_id=request.target_id,
                details={"action": action.id, "blockers": [b.code for b in decision.blockers]},
            )
        return PreviewOut(
            action=action.id,
            action_name=action.name,
            target_type=action.target_type,
            target_id=request.target_id,
            target_label=target.label,
            parameters=params.model_dump(mode="json"),
            risk_level=action.risk_level,
            required_role=action.required_role,
            requires_confirmation=action.requires_confirmation,
            requires_agent=action.requires_agent,
            expected_effect=action.expected_effect,
            preconditions=decision.preconditions,
            blockers=_issues(decision.blockers),
            warnings=_issues(decision.warnings),
            allowed=decision.allowed,
        )

    # --- Ejecución manual --------------------------------------------------------------------

    def execute(self, op: Operator, request: ExecutionRequest) -> ExecutionOut:
        self._require_enabled()
        action, target, params, ctx, decision = self._prepare(op, request)
        existing = self._by_idempotency(op, request.idempotency_key, action.id, request.target_id)
        if existing is not None:
            return self.execution_out(existing, deduplicated=True)
        if decision.allowed and action.requires_confirmation and not request.confirm:
            raise ResponseValidationError(
                "confirmation_required", "This action changes data: confirm it explicitly"
            )
        dedupe = f"{action.id}:{action.target_type}:{request.target_id}"
        if decision.allowed:
            active = self._session.scalar(
                select(ResponseExecution).where(
                    ResponseExecution.dedupe_key == dedupe,
                    ResponseExecution.status.in_(ACTIVE_EXECUTION_STATUSES),
                )
            )
            if active is not None:
                return self.execution_out(active, deduplicated=True)
        created = self._create(
            op,
            action,
            target,
            params,
            decision,
            reason=request.reason,
            confirmed=request.confirm,
            idempotency_key=request.idempotency_key,
            dedupe_key=dedupe if decision.allowed else None,
        )
        if created.deduplicated:
            return self.execution_out(created.execution, deduplicated=True)
        execution = created.execution
        if not decision.allowed:
            raise ResponseBlockedError(
                "The response policy blocks this action",
                details=[
                    {"execution_id": str(execution.public_id)},
                    *[b.as_dict() for b in decision.blockers],
                ],
            )
        self._dispatch(action, ctx, execution)
        return self.execution_out(self._reload(execution.id))

    def _by_idempotency(
        self, op: Operator, key: str | None, action_id: str, target_id: UUID
    ) -> ResponseExecution | None:
        if key is None or op.user is None:
            return None
        existing = self._session.scalar(
            select(ResponseExecution).where(
                ResponseExecution.actor_user_id == op.user.id,
                ResponseExecution.idempotency_key == key,
            )
        )
        if existing is not None and (
            existing.action_id != action_id or existing.target_public_id != target_id
        ):
            raise ResponseConflictError("This idempotency key was used for another request")
        return existing

    def _create(
        self,
        op: Operator,
        action: ActionDefinition,
        target: Target,
        params: Any,
        decision: Decision,
        *,
        reason: str | None,
        confirmed: bool,
        idempotency_key: str | None = None,
        dedupe_key: str | None = None,
        run: PlaybookRun | None = None,
        step_index: int | None = None,
        timeout_seconds: int | None = None,
    ) -> _Created:
        now = _now()
        asset = target.asset
        context_incident = target.context_incident or (
            target.incident if action.target_type == "incident" else None
        )
        execution = ResponseExecution(
            action_id=action.id,
            status="blocked" if not decision.allowed else "pending",
            risk_level=action.risk_level,
            requires_agent=action.requires_agent,
            target_type=action.target_type,
            target_public_id=(
                asset.public_id
                if asset is not None and action.target_type == "asset"
                else target.incident.public_id
                if target.incident is not None
                else None
            ),
            target_label=target.label,
            asset_id=asset.id if asset is not None else None,
            incident_id=context_incident.id if context_incident is not None else None,
            detection_public_id=target.detection.public_id if target.detection else None,
            agent_id=asset.agent_id if asset is not None and action.requires_agent else None,
            parameters=params.model_dump(mode="json"),
            blockers=[b.as_dict() for b in decision.blockers] or None,
            actor=op.actor.name[:64],
            actor_user_id=op.user.id if op.user is not None else None,
            reason=clean_text(reason, 500) if reason else None,
            confirmed=confirmed,
            idempotency_key=idempotency_key,
            dedupe_key=dedupe_key,
            playbook_run_id=run.id if run is not None else None,
            step_index=step_index,
            created_at=now,
            finished_at=now if not decision.allowed else None,
            error_code=decision.blockers[0].code if decision.blockers else None,
            error_message=decision.blockers[0].message if decision.blockers else None,
            version=1,
        )
        if timeout_seconds is not None:
            execution.deadline_at = now + timedelta(seconds=timeout_seconds)
        try:
            with self._session.begin_nested():
                self._session.add(execution)
                self._session.flush()
        except IntegrityError:
            # Otra petición igual ganó la carrera (índice de vivas o clave de idempotencia):
            # se devuelve la suya, nunca se crea una segunda.
            other = self._session.scalar(
                select(ResponseExecution).where(
                    (ResponseExecution.dedupe_key == dedupe_key)
                    & ResponseExecution.status.in_(ACTIVE_EXECUTION_STATUSES)
                    if dedupe_key
                    else (ResponseExecution.actor_user_id == execution.actor_user_id)
                    & (ResponseExecution.idempotency_key == idempotency_key)
                )
            )
            if other is None:
                raise ResponseConflictError(
                    "A concurrent identical request is in progress"
                ) from None
            return _Created(other, deduplicated=True)
        self._audit(
            op.actor,
            "response_execution_created",
            execution,
            result=audit_service.DENIED if not decision.allowed else audit_service.SUCCESS,
            extra={"blockers": [b.code for b in decision.blockers]} if decision.blockers else None,
        )
        if context_incident is not None:
            self._incident_activity(
                execution,
                "response_blocked" if not decision.allowed else "response_requested",
                f"Response {action.id} {'bloqueada' if not decision.allowed else 'solicitada'}"
                f" por {op.actor.name}",
            )
        self._session.commit()
        return _Created(execution)

    def _dispatch(
        self, action: ActionDefinition, ctx: ActionContext, execution: ResponseExecution
    ) -> None:
        now = _now()
        if action.requires_agent:
            asset = ctx.asset
            assert asset is not None and asset.agent_id is not None  # noqa: S101 (la política)
            ttl = timedelta(minutes=self._settings.response_command_ttl_minutes)
            command = AgentCommand(
                execution_id=execution.id,
                asset_id=asset.id,
                agent_id=asset.agent_id,
                command_type=action.agent_command,
                params={},
                status="queued",
                created_at=now,
                expires_at=now + ttl,
                delivery_count=0,
                max_deliveries=action.max_deliveries,
            )
            self._session.add(command)
            execution.status = "queued"
            execution.queued_at = now
            # Plazo total: TTL de la cola + un lease por cada entrega posible.
            execution.deadline_at = (
                now + ttl + timedelta(seconds=self._lease(action) * action.max_deliveries)
            )
            self._session.commit()
            return
        execution.status = "running"
        execution.started_at = now
        if execution.deadline_at is None:
            execution.deadline_at = now + timedelta(seconds=action.timeout_seconds)
        self._audit(ctx.actor, "response_started", execution)
        # Commit antes del handler: si el proceso muere a mitad, la ejecución queda como
        # running con plazo y el barrido la cierra como timed_out (nunca desaparece).
        self._session.commit()
        execution_id = execution.id
        try:
            assert action.handler is not None  # noqa: S101 (action.available)
            result = action.handler(ctx)
        except Exception as exc:
            self._session.rollback()
            execution = self._reload(execution_id)
            code, message = self._error_of(exc)
            if not isinstance(exc, ActionFailedError | SentraError):
                logger.exception("response handler failed", extra={"action": action.id})
            self._finish(execution, "failed", ctx.actor, error_code=code, error_message=message)
            self._session.commit()
            return
        execution = self._reload(execution_id)
        if result.incident_id is not None and execution.incident_id is None:
            execution.incident_id = result.incident_id
        self._finish(execution, "succeeded", ctx.actor, result=result)
        self._session.commit()

    @staticmethod
    def _error_of(exc: Exception) -> tuple[str, str]:
        if isinstance(exc, ActionFailedError):
            return exc.code, clean_text(exc.message, 500)
        if isinstance(exc, SentraError):
            return exc.code, clean_text(exc.message, 500)
        # Nunca se expone el texto de una excepción inesperada (puede llevar datos internos).
        return "internal_error", "The action failed unexpectedly; see the server log"

    def _lease(self, action: ActionDefinition) -> int:
        return min(action.timeout_seconds, self._settings.response_command_lease_seconds)

    def _reload(self, execution_id: int) -> ResponseExecution:
        execution = self._session.get(ResponseExecution, execution_id, populate_existing=True)
        if execution is None:  # pragma: no cover - las ejecuciones nunca se borran
            raise NotFoundError("Execution not found")
        return execution

    def _finish(
        self,
        execution: ResponseExecution,
        status: str,
        actor: Actor,
        *,
        result: ActionResult | None = None,
        data: dict[str, Any] | None = None,
        summary: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> bool:
        """Transición a un estado final; False si ya era final (resultado tardío o duplicado)."""
        if execution.status not in ACTIVE_EXECUTION_STATUSES:
            return False
        now = _now()
        execution.status = status
        execution.finished_at = now
        execution.version += 1
        if result is not None:
            summary, data = result.summary, result.data
        if summary is not None or data is not None:
            bounded = bounded_result(
                summary or "", data or {}, self._settings.response_result_max_kb * 1024
            )
            execution.result = bounded
            execution.result_summary = bounded["summary"] or None
        execution.error_code = error_code
        execution.error_message = clean_text(error_message, 500) if error_message else None
        action = {
            "succeeded": "response_completed",
            "cancelled": "response_cancelled",
        }.get(status, "response_failed")
        self._audit(
            actor,
            action,
            execution,
            result=audit_service.SUCCESS if status == "succeeded" else audit_service.FAILURE,
        )
        if execution.incident_id is not None:
            text = execution.result_summary or execution.error_code or status
            self._incident_activity(
                execution, action, f"Response {execution.action_id}: {status} ({text})"
            )
        return True

    def _audit(
        self,
        actor: Actor,
        action: str,
        execution: ResponseExecution,
        *,
        result: str = audit_service.SUCCESS,
        extra: dict[str, Any] | None = None,
    ) -> None:
        # Nunca los parámetros completos (una nota puede llevar texto sensible): solo sus
        # nombres. Sin tokens ni identidades de máquina: no existen en estas filas.
        details: dict[str, Any] = {
            "execution": str(execution.public_id),
            "correlation": str(execution.correlation_id),
            "action": execution.action_id,
            "status": execution.status,
            "target": str(execution.target_public_id),
            "parameters": sorted(execution.parameters or {}),
        }
        if execution.error_code:
            details["error"] = execution.error_code
        if execution.playbook_run_id is not None:
            details["playbook_step"] = execution.step_index
        details.update(extra or {})
        audit_service.record(
            self._session,
            actor,
            action,
            result,
            target_type=execution.target_type,
            target_id=execution.target_public_id,
            details=details,
            commit=False,
        )

    def _incident_activity(self, execution: ResponseExecution, action: str, summary: str) -> None:
        incident = self._session.get(Incident, execution.incident_id)
        if incident is None:
            return
        now = _now()
        self._session.add(
            IncidentActivity(
                incident_id=incident.id,
                occurred_at=now,
                action=action[:32],
                actor_user_id=execution.actor_user_id,
                actor=execution.actor,
                entity_type="response",
                entity_id=str(execution.public_id),
                summary=clean_text(summary, 300),
                details={"action": execution.action_id, "status": execution.status},
            )
        )
        incident.last_activity_at = now

    # --- Lectura -----------------------------------------------------------------------------

    def get_execution(self, public_id: UUID) -> ExecutionOut:
        execution = self._session.scalar(
            select(ResponseExecution).where(ResponseExecution.public_id == public_id)
        )
        if execution is None:
            raise NotFoundError("Execution not found")
        return self.execution_out(execution)

    def list_executions(
        self,
        *,
        status: str | None = None,
        action_id: str | None = None,
        asset_public_id: UUID | None = None,
        incident_public_id: UUID | None = None,
        run_public_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ExecutionList:
        where: list[Any] = []
        if status:
            where.append(ResponseExecution.status == status)
        if action_id:
            where.append(ResponseExecution.action_id == action_id)
        if asset_public_id is not None:
            where.append(
                ResponseExecution.asset_id.in_(
                    select(Asset.id).where(Asset.public_id == asset_public_id)
                )
            )
        if incident_public_id is not None:
            where.append(
                ResponseExecution.incident_id.in_(
                    select(Incident.id).where(Incident.public_id == incident_public_id)
                )
            )
        if run_public_id is not None:
            where.append(
                ResponseExecution.playbook_run_id.in_(
                    select(PlaybookRun.id).where(PlaybookRun.public_id == run_public_id)
                )
            )
        total = self._session.scalar(
            select(func.count()).select_from(ResponseExecution).where(*where)
        )
        rows = self._session.scalars(
            select(ResponseExecution)
            .where(*where)
            .order_by(ResponseExecution.created_at.desc(), ResponseExecution.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return ExecutionList(items=self._outs(rows), total=int(total or 0))

    def _outs(self, rows: Sequence[ResponseExecution]) -> list[ExecutionOut]:
        # Ids públicos relacionados en tres consultas por página (sin N+1).
        asset_ids = {r.asset_id for r in rows if r.asset_id is not None}
        incident_ids = {r.incident_id for r in rows if r.incident_id is not None}
        run_ids = {r.playbook_run_id for r in rows if r.playbook_run_id is not None}
        assets = (
            dict(
                self._session.execute(
                    select(Asset.id, Asset.public_id).where(Asset.id.in_(asset_ids))
                ).all()
            )
            if asset_ids
            else {}
        )
        incidents = (
            dict(
                self._session.execute(
                    select(Incident.id, Incident.public_id).where(Incident.id.in_(incident_ids))
                ).all()
            )
            if incident_ids
            else {}
        )
        runs = (
            dict(
                self._session.execute(
                    select(PlaybookRun.id, PlaybookRun.public_id).where(PlaybookRun.id.in_(run_ids))
                ).all()
            )
            if run_ids
            else {}
        )
        return [self.execution_out(r, refs=(assets, incidents, runs)) for r in rows]

    def execution_out(
        self,
        execution: ResponseExecution,
        *,
        deduplicated: bool = False,
        refs: tuple[dict[int, UUID], dict[int, UUID], dict[int, UUID]] | None = None,
    ) -> ExecutionOut:
        if refs is None:
            refs = self._refs(execution)
        assets, incidents, runs = refs
        action = get_action(execution.action_id)
        return ExecutionOut(
            execution_id=execution.public_id,
            correlation_id=execution.correlation_id,
            action_id=execution.action_id,
            action_name=action.name if action else execution.action_id,
            status=execution.status,
            risk_level=execution.risk_level,
            requires_agent=execution.requires_agent,
            target_type=execution.target_type,
            target_id=execution.target_public_id,
            target_label=execution.target_label,
            asset_id=assets.get(execution.asset_id) if execution.asset_id else None,
            incident_id=incidents.get(execution.incident_id) if execution.incident_id else None,
            detection_id=execution.detection_public_id,
            parameters=execution.parameters or {},
            result=execution.result,
            result_summary=execution.result_summary,
            error_code=execution.error_code,
            error_message=execution.error_message,
            blockers=[IssueOut(**b) for b in execution.blockers or []],
            actor=execution.actor,
            reason=execution.reason,
            playbook_run_id=runs.get(execution.playbook_run_id)
            if execution.playbook_run_id
            else None,
            step_index=execution.step_index,
            created_at=execution.created_at,
            queued_at=execution.queued_at,
            started_at=execution.started_at,
            finished_at=execution.finished_at,
            deadline_at=execution.deadline_at,
            duration_ms=_duration(
                execution.started_at or execution.queued_at, execution.finished_at
            ),
            version=execution.version,
            deduplicated=deduplicated,
        )

    def _refs(
        self, execution: ResponseExecution
    ) -> tuple[dict[int, UUID], dict[int, UUID], dict[int, UUID]]:
        assets: dict[int, UUID] = {}
        incidents: dict[int, UUID] = {}
        runs: dict[int, UUID] = {}
        if execution.asset_id is not None:
            value = self._session.scalar(
                select(Asset.public_id).where(Asset.id == execution.asset_id)
            )
            if value is not None:
                assets[execution.asset_id] = value
        if execution.incident_id is not None:
            value = self._session.scalar(
                select(Incident.public_id).where(Incident.id == execution.incident_id)
            )
            if value is not None:
                incidents[execution.incident_id] = value
        if execution.playbook_run_id is not None:
            value = self._session.scalar(
                select(PlaybookRun.public_id).where(PlaybookRun.id == execution.playbook_run_id)
            )
            if value is not None:
                runs[execution.playbook_run_id] = value
        return assets, incidents, runs

    # --- Cancelar ----------------------------------------------------------------------------

    def cancel(
        self, op: Operator, public_id: UUID, version: int, reason: str | None
    ) -> ExecutionOut:
        self._check_permissions(op, frozenset({Permission.RESPONSE_MANAGE}), "cancel", public_id)
        execution = self._session.scalar(
            select(ResponseExecution)
            .where(ResponseExecution.public_id == public_id)
            .with_for_update()
        )
        if execution is None:
            raise NotFoundError("Execution not found")
        if execution.version != version:
            raise ResponseConflictError(
                "The execution changed; reload it",
                details=[{"current_version": execution.version, "status": execution.status}],
            )
        if execution.status not in ACTIVE_EXECUTION_STATUSES:
            raise ResponseStateError("Only pending, queued or running executions can be cancelled")
        self._cancel_commands([execution.id])
        if reason:
            execution.reason = clean_text(reason, 500)
        self._finish(execution, "cancelled", op.actor, error_code="cancelled_by_operator")
        self._session.commit()
        if execution.playbook_run_id is not None:
            self.advance_run(execution.playbook_run_id)
        return self.execution_out(self._reload(execution.id))

    def _cancel_commands(self, execution_ids: Sequence[int]) -> None:
        """Cancela los comandos abiertos: un resultado posterior del agente se ignora."""
        self._session.execute(
            update(AgentCommand)
            .where(
                AgentCommand.execution_id.in_(list(execution_ids)),
                AgentCommand.status.in_(("queued", "delivered")),
            )
            .values(status="cancelled", completed_at=_now())
        )

    # --- Protocolo del agente ----------------------------------------------------------------

    def pending_count(self, asset: Asset) -> int:
        """Comandos en cola para el agente actual (lo devuelve el heartbeat)."""
        if not self._settings.response_enabled or asset.agent_id is None:
            return 0
        return int(
            self._session.scalar(
                select(func.count())
                .select_from(AgentCommand)
                .where(
                    AgentCommand.asset_id == asset.id,
                    AgentCommand.agent_id == asset.agent_id,
                    AgentCommand.status == "queued",
                    AgentCommand.expires_at > _now(),
                )
            )
            or 0
        )

    def poll(self, agent_id: UUID, token: str | None, max_commands: int) -> list[AgentCommandOut]:
        # Mismo 401 que el resto de llamadas del agente: sin token válido no se sabe nada.
        asset = authenticate_agent(AssetRepository(self._session), agent_id, token)
        now = _now()
        record_contact(self._session, asset, now)
        if not self._settings.response_enabled:
            self._session.commit()
            return []
        if asset.is_archived:
            self._cancel_for_assets([asset.id], "asset_archived")
            self._session.commit()
            return []
        # Solo los comandos de ESTE agente en ESTE activo: tras una reconciliación (5C.2) el
        # agente actual del activo canónico recibe los suyos y nunca los del activo origen.
        commands = self._session.scalars(
            select(AgentCommand)
            .where(
                AgentCommand.asset_id == asset.id,
                AgentCommand.agent_id == asset.agent_id,
                AgentCommand.status == "queued",
                AgentCommand.expires_at > now,
            )
            .order_by(AgentCommand.created_at, AgentCommand.id)
            .limit(max_commands)
            .with_for_update(skip_locked=True)
        ).all()
        out = []
        for command in commands:
            execution = self._session.get(ResponseExecution, command.execution_id)
            action = get_action(command.command_type)
            if (
                execution is None
                or action is None
                or execution.status not in ACTIVE_EXECUTION_STATUSES
            ):
                command.status = "cancelled"
                command.completed_at = now
                continue
            command.status = "delivered"
            command.delivered_at = now
            command.delivery_count += 1
            command.lease_expires_at = min(
                now + timedelta(seconds=self._lease(action)),
                max(command.expires_at, now) + timedelta(seconds=self._lease(action)),
            )
            if execution.status != "running":
                execution.status = "running"
                execution.started_at = execution.started_at or now
                self._audit(
                    Actor(f"agent:{str(asset.agent_id)[:8]}"),
                    "response_started",
                    execution,
                    extra={"delivery": command.delivery_count},
                )
            out.append(
                AgentCommandOut(
                    request_id=command.request_id,
                    type=command.command_type,
                    params=command.params or {},
                    deadline_at=command.lease_expires_at,
                )
            )
        self._session.commit()
        return out

    def complete(
        self, request_id: UUID, token: str | None, body: CommandResultRequest
    ) -> CommandResultResponse:
        asset = authenticate_agent(AssetRepository(self._session), body.agent_id, token)
        record_contact(self._session, asset, _now())
        command = self._session.scalar(
            select(AgentCommand).where(AgentCommand.request_id == request_id).with_for_update()
        )
        # Comando de otro agente u otro activo: mismo 404 que uno inexistente (no se revela
        # que existe). Un agente nunca puede completar comandos ajenos.
        if command is None or command.agent_id != body.agent_id or command.asset_id != asset.id:
            self._session.commit()
            raise CommandNotFoundError("Command not found")
        if command.status in ("completed", "failed"):
            # Respuesta repetida (reintento del agente tras perder la respuesta): idempotente.
            self._session.commit()
            return CommandResultResponse(accepted=False, duplicate=True, status=command.status)
        if command.status in ("expired", "cancelled"):
            # Llega tarde: la ejecución ya terminó (timed_out o cancelada) y no se reabre.
            self._session.commit()
            return CommandResultResponse(accepted=False, duplicate=False, status=command.status)
        if command.status != "delivered":
            # Un resultado de un comando que nunca se entregó es una falsificación o replay.
            self._session.commit()
            raise CommandNotDeliveredError("This command was not delivered to the agent")
        now = _now()
        succeeded = body.status == "succeeded"
        command.status = "completed" if succeeded else "failed"
        command.completed_at = now
        execution = self._reload(command.execution_id)
        agent_actor = Actor(f"agent:{str(body.agent_id)[:8]}")
        if succeeded:
            self._finish(execution, "succeeded", agent_actor, summary=body.summary, data=body.data)
        else:
            self._finish(
                execution,
                "failed",
                agent_actor,
                summary=body.summary,
                data=body.data,
                error_code=body.error_code or f"agent_{body.status}",
                error_message=body.summary or None,
            )
        self._session.commit()
        if execution.playbook_run_id is not None:
            try:
                self.advance_run(execution.playbook_run_id)
            except Exception:
                # El resultado del agente ya está guardado; el barrido seguirá con el playbook.
                self._session.rollback()
                logger.exception("playbook advance failed after agent result")
        return CommandResultResponse(accepted=True, duplicate=False, status=command.status)

    def _cancel_for_assets(self, asset_ids: Sequence[int], code: str) -> int:
        rows = self._session.scalars(
            select(AgentCommand)
            .where(
                AgentCommand.asset_id.in_(list(asset_ids)),
                AgentCommand.status.in_(("queued", "delivered")),
            )
            .with_for_update(skip_locked=True)
        ).all()
        return self._close_commands(rows, "cancelled", "cancelled", code)

    def _close_commands(
        self, commands: Sequence[AgentCommand], command_status: str, status: str, code: str
    ) -> int:
        now = _now()
        closed = 0
        for command in commands:
            command.status = command_status
            command.completed_at = now
            execution = self._session.get(ResponseExecution, command.execution_id)
            if execution is not None and self._finish(
                execution, status, SYSTEM, error_code=code, error_message=_MESSAGES.get(code)
            ):
                closed += 1
        return closed

    # --- Barrido periódico -------------------------------------------------------------------

    def sweep(self, now: datetime | None = None) -> dict[str, int]:
        """Caduca comandos, cierra plazos vencidos, reentrega y avanza playbooks (acotado)."""
        now = now or _now()
        counts = {"expired": 0, "redelivered": 0, "timed_out": 0, "cancelled": 0, "runs": 0}
        # 1. Comandos de un agente que ya no es el actual del activo (reconciliado, revocado
        #    y reenrolado con otro agent_id...) o de un activo archivado: se cancelan.
        stale = self._session.scalars(
            select(AgentCommand)
            .join(Asset, Asset.id == AgentCommand.asset_id)
            .where(
                AgentCommand.status.in_(("queued", "delivered")),
                (Asset.agent_id.is_distinct_from(AgentCommand.agent_id))
                | Asset.archived_at.is_not(None),
            )
            .limit(SWEEP_BATCH)
            .with_for_update(of=AgentCommand, skip_locked=True)
        ).all()
        archived = (
            {
                asset_id
                for (asset_id,) in self._session.execute(
                    select(Asset.id).where(
                        Asset.id.in_({c.asset_id for c in stale}), Asset.archived_at.is_not(None)
                    )
                ).all()
            }
            if stale
            else set()
        )
        for command in stale:
            counts["cancelled"] += self._close_commands(
                [command],
                "cancelled",
                "cancelled",
                "asset_archived" if command.asset_id in archived else "agent_reassigned",
            )
        # 2. En cola sin recoger tras el TTL.
        expired = self._session.scalars(
            select(AgentCommand)
            .where(AgentCommand.status == "queued", AgentCommand.expires_at <= now)
            .limit(SWEEP_BATCH)
            .with_for_update(skip_locked=True)
        ).all()
        counts["expired"] += self._close_commands(
            expired, "expired", "timed_out", "command_expired"
        )
        # 3. Entregados sin resultado dentro del lease: una reentrega si la acción es
        #    idempotente y queda TTL; si no, timed_out.
        overdue = self._session.scalars(
            select(AgentCommand)
            .where(AgentCommand.status == "delivered", AgentCommand.lease_expires_at <= now)
            .limit(SWEEP_BATCH)
            .with_for_update(skip_locked=True)
        ).all()
        for command in overdue:
            if command.delivery_count < command.max_deliveries and command.expires_at > now:
                command.status = "queued"
                command.lease_expires_at = None
                execution = self._session.get(ResponseExecution, command.execution_id)
                if execution is not None and execution.status == "running":
                    execution.status = "queued"
                counts["redelivered"] += 1
            else:
                counts["timed_out"] += self._close_commands(
                    [command], "expired", "timed_out", "agent_timeout"
                )
        # 4. Cualquier ejecución viva con el plazo vencido (handler interrumpido por una caída
        #    del proceso, comando perdido): nunca se queda "running" para siempre.
        late = self._session.scalars(
            select(ResponseExecution)
            .where(
                ResponseExecution.status.in_(ACTIVE_EXECUTION_STATUSES),
                ResponseExecution.deadline_at <= now,
            )
            .limit(SWEEP_BATCH)
            .with_for_update(skip_locked=True)
        ).all()
        for execution in late:
            self._cancel_commands([execution.id])
            if self._finish(
                execution,
                "timed_out",
                SYSTEM,
                error_code="deadline_exceeded",
                error_message=_MESSAGES["deadline_exceeded"],
            ):
                counts["timed_out"] += 1
        self._session.commit()
        # 5. Playbooks en curso (también los que esperaban a un paso que acaba de cerrarse).
        run_ids = list(
            self._session.scalars(
                select(PlaybookRun.id)
                .where(PlaybookRun.status == "running")
                .order_by(PlaybookRun.created_at)
                .limit(RUNS_PER_SWEEP)
            )
        )
        for run_id in run_ids:
            try:
                self.advance_run(run_id)
                counts["runs"] += 1
            except Exception:
                self._session.rollback()
                logger.exception("playbook advance failed", extra={"run": run_id})
        return counts

    # --- Playbooks: definiciones -------------------------------------------------------------

    def ensure_builtins(self) -> None:
        """Crea o actualiza (nueva versión) los playbooks built-in definidos en código."""
        now = _now()
        changed = False
        for builtin in BUILTIN_PLAYBOOKS:
            validated = validate_steps(list(builtin.steps))
            playbook = self._session.scalar(select(Playbook).where(Playbook.key == builtin.key))
            if playbook is None:
                playbook = Playbook(
                    key=builtin.key,
                    name=builtin.name,
                    description=builtin.description,
                    builtin=True,
                    enabled=True,
                    current_version=builtin.version,
                    risk_level=validated.risk_level,
                    created_by="system",
                    created_at=now,
                    updated_at=now,
                    revision=1,
                )
            elif playbook.current_version >= builtin.version:
                continue
            else:
                playbook.current_version = builtin.version
                playbook.name = builtin.name
                playbook.description = builtin.description
                playbook.risk_level = validated.risk_level
                playbook.updated_at = now
                playbook.revision += 1
            try:
                with self._session.begin_nested():
                    self._session.add(playbook)
                    self._session.flush()
                    self._session.add(
                        PlaybookVersion(
                            playbook_id=playbook.id,
                            version=builtin.version,
                            name=builtin.name,
                            description=builtin.description,
                            steps=validated.steps,
                            risk_level=validated.risk_level,
                            created_by="system",
                            created_at=now,
                        )
                    )
                    self._session.flush()
                changed = True
            except IntegrityError:
                # Otro proceso lo sembró a la vez: el suyo vale igual.
                continue
        if changed:
            self._session.commit()

    def _playbook(self, public_id: UUID, lock: bool = False) -> Playbook:
        query = select(Playbook).where(Playbook.public_id == public_id)
        if lock:
            query = query.with_for_update()
        playbook = self._session.scalar(query)
        if playbook is None:
            raise NotFoundError("Playbook not found")
        return playbook

    def _version(self, playbook: Playbook, version: int | None = None) -> PlaybookVersion:
        row = self._session.scalar(
            select(PlaybookVersion).where(
                PlaybookVersion.playbook_id == playbook.id,
                PlaybookVersion.version == (version or playbook.current_version),
            )
        )
        if row is None:  # pragma: no cover - toda versión actual tiene su fila
            raise NotFoundError("Playbook version not found")
        return row

    def _validated(self, steps: list[dict[str, Any]] | list[PlaybookStepIn]) -> ValidatedSteps:
        try:
            return validate_steps(steps)
        except PlaybookError as exc:
            raise ResponseValidationError(exc.code, exc.message) from exc

    def list_playbooks(self, op: Operator, asset_public_id: UUID | None = None) -> PlaybookList:
        self.ensure_builtins()
        asset = None
        if asset_public_id is not None:
            asset = AssetRepository(self._session).get_by_public_id(asset_public_id)
            if asset is None:
                raise NotFoundError("Asset not found")
        playbooks = self._session.scalars(
            select(Playbook).order_by(Playbook.builtin.desc(), Playbook.name)
        ).all()
        versions = {
            (v.playbook_id, v.version): v
            for v in self._session.scalars(
                select(PlaybookVersion).where(
                    PlaybookVersion.playbook_id.in_([p.id for p in playbooks] or [0])
                )
            )
        }
        items = []
        for playbook in playbooks:
            version = versions.get((playbook.id, playbook.current_version))
            if version is None:
                continue
            blockers: list[Issue] = []
            if asset is not None:
                blockers = self._preflight(op, playbook, version, Target(asset=asset))[1]
            items.append(self._playbook_out(playbook, version, op, blockers))
        return PlaybookList(items=items)

    def get_playbook(self, op: Operator, public_id: UUID) -> PlaybookOut:
        self.ensure_builtins()
        playbook = self._playbook(public_id)
        return self._playbook_out(playbook, self._version(playbook), op)

    def _playbook_out(
        self,
        playbook: Playbook,
        version: PlaybookVersion,
        op: Operator,
        blockers: Sequence[Issue] = (),
    ) -> PlaybookOut:
        validated = self._safe_validate(version.steps)
        steps = []
        for step in version.steps:
            action = get_action(str(step.get("action_id")))
            steps.append(
                PlaybookStepOut(
                    order=int(step.get("order", 0)),
                    action_id=str(step.get("action_id")),
                    action_name=action.name if action else str(step.get("action_id")),
                    parameters=dict(step.get("parameters") or {}),
                    on_success=str(step.get("on_success", "continue")),
                    on_failure=str(step.get("on_failure", "stop")),
                    timeout_seconds=int(step.get("timeout_seconds", 60)),
                    risk_level=action.risk_level if action else "unknown",
                )
            )
        permissions = (
            validated.permissions if validated else frozenset({Permission.RESPONSE_MANAGE})
        )
        return PlaybookOut(
            playbook_id=playbook.public_id,
            key=playbook.key,
            name=version.name,
            description=version.description,
            builtin=playbook.builtin,
            enabled=playbook.enabled,
            version=version.version,
            risk_level=version.risk_level,
            required_role=validated.required_role if validated else "admin",
            requires_confirmation=validated.requires_confirmation if validated else True,
            requires_agent=any(
                (a := get_action(str(s.get("action_id")))) is not None and a.requires_agent
                for s in version.steps
            ),
            steps=steps,
            created_by=playbook.created_by,
            created_at=playbook.created_at,
            updated_at=playbook.updated_at,
            revision=playbook.revision,
            permitted=validated is not None and permissions <= op.permissions and playbook.enabled,
            blockers=_issues(blockers),
        )

    @staticmethod
    def _safe_validate(steps: list[dict[str, Any]]) -> ValidatedSteps | None:
        try:
            return validate_steps(steps)
        except PlaybookError:
            # Un playbook guardado que ya no valida (acción retirada en una versión nueva de
            # Sentra) se muestra, pero no se puede ejecutar.
            return None

    def create_playbook(self, op: Operator, body: PlaybookCreate) -> PlaybookOut:
        self._require_playbooks()
        validated = self._validated(body.steps)
        now = _now()
        playbook = Playbook(
            key=f"custom_{func_uuid()}",
            name=clean_text(body.name, 120),
            description=clean_text(body.description, 1000),
            builtin=False,
            enabled=True,
            current_version=1,
            risk_level=validated.risk_level,
            created_by=op.actor.name[:64],
            created_by_user_id=op.user.id if op.user else None,
            created_at=now,
            updated_at=now,
            revision=1,
        )
        self._session.add(playbook)
        self._session.flush()
        version = self._add_version(playbook, 1, validated, op, now)
        self._playbook_audit(op, "playbook_created", playbook, {"steps": len(validated.steps)})
        self._session.commit()
        return self._playbook_out(playbook, version, op)

    def _add_version(
        self,
        playbook: Playbook,
        number: int,
        validated: ValidatedSteps,
        op: Operator,
        now: datetime,
    ) -> PlaybookVersion:
        version = PlaybookVersion(
            playbook_id=playbook.id,
            version=number,
            name=playbook.name,
            description=playbook.description,
            steps=validated.steps,
            risk_level=validated.risk_level,
            created_by=op.actor.name[:64],
            created_at=now,
        )
        self._session.add(version)
        self._session.flush()
        return version

    def update_playbook(self, op: Operator, public_id: UUID, body: PlaybookUpdate) -> PlaybookOut:
        self._require_playbooks()
        playbook = self._playbook(public_id, lock=True)
        self._check_revision(playbook, body.revision)
        if playbook.builtin:
            raise ResponseStateError("Built-in playbooks cannot be edited; create a custom one")
        validated = self._validated(body.steps)
        now = _now()
        playbook.current_version += 1
        playbook.name = clean_text(body.name, 120)
        playbook.description = clean_text(body.description, 1000)
        playbook.risk_level = validated.risk_level
        playbook.updated_at = now
        playbook.revision += 1
        version = self._add_version(playbook, playbook.current_version, validated, op, now)
        self._playbook_audit(
            op, "playbook_updated", playbook, {"version": playbook.current_version}
        )
        self._session.commit()
        return self._playbook_out(playbook, version, op)

    def set_enabled(
        self, op: Operator, public_id: UUID, revision: int, enabled: bool
    ) -> PlaybookOut:
        self._require_playbooks()
        playbook = self._playbook(public_id, lock=True)
        self._check_revision(playbook, revision)
        if playbook.enabled != enabled:
            playbook.enabled = enabled
            playbook.revision += 1
            playbook.updated_at = _now()
            self._playbook_audit(
                op, "playbook_enabled" if enabled else "playbook_disabled", playbook
            )
        self._session.commit()
        return self._playbook_out(playbook, self._version(playbook), op)

    @staticmethod
    def _check_revision(playbook: Playbook, revision: int) -> None:
        if playbook.revision != revision:
            raise ResponseConflictError(
                "The playbook changed; reload it",
                details=[{"current_revision": playbook.revision}],
            )

    def _playbook_audit(
        self, op: Operator, action: str, playbook: Playbook, extra: dict[str, Any] | None = None
    ) -> None:
        audit_service.record(
            self._session,
            op.actor,
            action,
            target_type="playbook",
            target_id=playbook.public_id,
            details={
                "playbook": playbook.key,
                "version": playbook.current_version,
                "risk": playbook.risk_level,
                **(extra or {}),
            },
            commit=False,
        )

    # --- Playbooks: preview y ejecución ------------------------------------------------------

    def _preflight(
        self, op: Operator, playbook: Playbook, version: PlaybookVersion, target: Target
    ) -> tuple[list[PlaybookStepPreview], list[Issue], ValidatedSteps | None]:
        """Política de cada paso sobre el objetivo, con el estado actual (sin efectos)."""
        validated = self._safe_validate(version.steps)
        blockers: list[Issue] = []
        previews: list[PlaybookStepPreview] = []
        if not self._settings.playbooks_enabled:
            blockers.append(Issue("playbooks_disabled", "Playbooks are disabled on this server"))
        if not playbook.enabled:
            blockers.append(Issue("playbook_disabled", "The playbook is disabled"))
        if validated is None:
            blockers.append(Issue("playbook_invalid", "The playbook uses actions not available"))
            return previews, blockers, None
        now = _now()
        for step in validated.steps:
            action = ACTIONS[step["action_id"]]
            params = action.params_model.model_validate(step["parameters"])
            decision = evaluate(action, self._context(op, target, params, now), count_active=False)
            previews.append(
                PlaybookStepPreview(
                    order=step["order"],
                    action_id=action.id,
                    action_name=action.name,
                    risk_level=action.risk_level,
                    requires_agent=action.requires_agent,
                    blockers=_issues(decision.blockers),
                    warnings=_issues(
                        [w for w in decision.warnings if w.code != "confirmation_required"]
                    ),
                )
            )
            for issue in decision.blockers:
                blockers.append(
                    Issue(issue.code, f"Step {step['order']} ({action.id}): {issue.message}")
                )
        return previews, blockers, validated

    def preview_playbook(
        self, op: Operator, public_id: UUID, body: PlaybookRunRequest
    ) -> PlaybookPreviewOut:
        self._require_playbooks()
        self.ensure_builtins()
        playbook = self._playbook(public_id)
        version = self._version(playbook)
        validated = self._safe_validate(version.steps)
        if validated is not None:
            self._check_permissions(
                op, validated.permissions, f"playbook:{playbook.key}", public_id
            )
        target = self._resolve(op, "asset", body.target_id, body.incident_id, body.detection_id)
        steps, blockers, validated = self._preflight(op, playbook, version, target)
        return PlaybookPreviewOut(
            playbook_id=playbook.public_id,
            name=version.name,
            version=version.version,
            target_id=body.target_id,
            target_label=target.label,
            risk_level=version.risk_level,
            required_role=validated.required_role if validated else "admin",
            requires_confirmation=validated.requires_confirmation if validated else True,
            steps=steps,
            blockers=_issues(blockers),
            allowed=not blockers,
        )

    def execute_playbook(
        self, op: Operator, public_id: UUID, body: PlaybookRunRequest
    ) -> PlaybookRunOut:
        self._require_playbooks()
        self.ensure_builtins()
        playbook = self._playbook(public_id)
        version = self._version(playbook)
        validated = self._safe_validate(version.steps)
        if validated is not None:
            self._check_permissions(
                op, validated.permissions, f"playbook:{playbook.key}", public_id
            )
        target = self._resolve(op, "asset", body.target_id, body.incident_id, body.detection_id)
        if body.idempotency_key and op.user is not None:
            existing = self._session.scalar(
                select(PlaybookRun).where(
                    PlaybookRun.actor_user_id == op.user.id,
                    PlaybookRun.idempotency_key == body.idempotency_key,
                )
            )
            if existing is not None:
                if (
                    existing.playbook_id != playbook.id
                    or existing.target_public_id != body.target_id
                ):
                    raise ResponseConflictError("This idempotency key was used for another request")
                return self.run_out(existing, deduplicated=True)
        _, blockers, validated = self._preflight(op, playbook, version, target)
        if (
            not blockers
            and validated is not None
            and validated.requires_confirmation
            and not body.confirm
        ):
            raise ResponseValidationError(
                "confirmation_required", "This playbook changes data: confirm it explicitly"
            )
        dedupe = f"playbook:{playbook.key}:{body.target_id}"
        if not blockers:
            active = self._session.scalar(
                select(PlaybookRun).where(
                    PlaybookRun.dedupe_key == dedupe, PlaybookRun.status == "running"
                )
            )
            if active is not None:
                return self.run_out(active, deduplicated=True)
        asset = target.asset
        assert asset is not None  # noqa: S101 (_resolve con "asset")
        now = _now()
        run = PlaybookRun(
            playbook_id=playbook.id,
            playbook_key=playbook.key,
            playbook_name=version.name,
            playbook_version=version.version,
            # Copia inmutable de los pasos: editar el playbook después no cambia este run.
            steps=list(version.steps),
            risk_level=version.risk_level,
            status="blocked" if blockers else "running",
            current_step=0,
            target_public_id=asset.public_id,
            target_label=target.label,
            asset_id=asset.id,
            incident_id=target.context_incident.id if target.context_incident else None,
            detection_public_id=target.detection.public_id if target.detection else None,
            actor=op.actor.name[:64],
            actor_user_id=op.user.id if op.user else None,
            reason=clean_text(body.reason, 500) if body.reason else None,
            idempotency_key=body.idempotency_key,
            dedupe_key=None if blockers else dedupe,
            error_code=blockers[0].code if blockers else None,
            error_message=blockers[0].message[:500] if blockers else None,
            created_at=now,
            finished_at=now if blockers else None,
            version=1,
        )
        try:
            with self._session.begin_nested():
                self._session.add(run)
                self._session.flush()
        except IntegrityError:
            other = self._session.scalar(
                select(PlaybookRun).where(
                    PlaybookRun.dedupe_key == dedupe, PlaybookRun.status == "running"
                )
            )
            if other is None:
                raise ResponseConflictError(
                    "A concurrent identical request is in progress"
                ) from None
            return self.run_out(other, deduplicated=True)
        audit_service.record(
            self._session,
            op.actor,
            "playbook_executed",
            audit_service.DENIED if blockers else audit_service.SUCCESS,
            target_type="asset",
            target_id=asset.public_id,
            details={
                "run": str(run.public_id),
                "playbook": playbook.key,
                "version": version.version,
                "status": run.status,
                **({"blockers": [b.code for b in blockers]} if blockers else {}),
            },
            commit=False,
        )
        if run.incident_id is not None:
            self._run_activity(run, "playbook_started" if not blockers else "playbook_blocked")
        self._session.commit()
        if blockers:
            raise ResponseBlockedError(
                "The response policy blocks this playbook",
                details=[{"run_id": str(run.public_id)}, *[b.as_dict() for b in blockers]],
            )
        self.advance_run(run.id)
        return self.run_out(self._session.get(PlaybookRun, run.id, populate_existing=True) or run)

    def _run_activity(self, run: PlaybookRun, action: str) -> None:
        incident = self._session.get(Incident, run.incident_id)
        if incident is None:
            return
        now = _now()
        self._session.add(
            IncidentActivity(
                incident_id=incident.id,
                occurred_at=now,
                action=action[:32],
                actor_user_id=run.actor_user_id,
                actor=run.actor,
                entity_type="playbook_run",
                entity_id=str(run.public_id),
                summary=clean_text(
                    f"Playbook {run.playbook_name} v{run.playbook_version}: {run.status}", 300
                ),
                details={"playbook": run.playbook_key, "status": run.status},
            )
        )
        incident.last_activity_at = now

    def _run_operator(self, run: PlaybookRun) -> Operator | None:
        """Permisos ACTUALES del actor: si se le quitó el rol o la cuenta, el run se detiene."""
        if run.actor_user_id is None:
            return None
        user = self._session.get(User, run.actor_user_id)
        if user is None or not user.is_active:
            return None
        return Operator(user, Actor(run.actor), permissions_for(user.role))

    def advance_run(self, run_id: int) -> None:
        """Avanza el run hasta un paso que espera (agente) o hasta terminar. Seguro en paralelo:
        cada paso tiene a lo sumo una ejecución (índice único) y el avance usa `version`."""
        for _ in range(64):
            run = self._session.get(PlaybookRun, run_id, populate_existing=True)
            if run is None or run.status != "running":
                return
            if run.current_step >= len(run.steps):
                self._finish_run(run, "succeeded")
                return
            step = run.steps[run.current_step]
            execution = self._session.scalar(
                select(ResponseExecution).where(
                    ResponseExecution.playbook_run_id == run.id,
                    ResponseExecution.step_index == run.current_step,
                )
            )
            if execution is None:
                if not self._start_step(run, step):
                    return
                continue
            if execution.status in ACTIVE_EXECUTION_STATUSES:
                return
            if execution.status == "succeeded":
                nxt = len(run.steps) if step.get("on_success") == "stop" else run.current_step + 1
                if not self._move(run, nxt):
                    return
                continue
            if execution.status == "cancelled":
                self._finish_run(
                    run, "cancelled", "step_cancelled", f"Step {step.get('order')} cancelled"
                )
                return
            action = get_action(str(step.get("action_id")))
            safe_continue = (
                step.get("on_failure") == "continue"
                and action is not None
                and RISK_RANK[action.risk_level] == RISK_RANK["low"]
            )
            if safe_continue:
                if not self._move(run, run.current_step + 1):
                    return
                continue
            # Fail-stop: un paso fallido detiene el playbook y el motivo queda visible.
            self._finish_run(
                run,
                "failed",
                f"step_{execution.status}",
                f"Step {step.get('order')} ({step.get('action_id')}): "
                f"{execution.error_code or execution.status}",
            )
            return

    def _move(self, run: PlaybookRun, nxt: int) -> bool:
        result = self._session.execute(
            update(PlaybookRun)
            .where(
                PlaybookRun.id == run.id,
                PlaybookRun.version == run.version,
                PlaybookRun.status == "running",
            )
            .values(current_step=nxt, version=PlaybookRun.version + 1)
        )
        self._session.commit()
        return bool(result.rowcount)  # type: ignore[attr-defined]

    def _finish_run(
        self, run: PlaybookRun, status: str, code: str | None = None, message: str | None = None
    ) -> None:
        result = self._session.execute(
            update(PlaybookRun)
            .where(PlaybookRun.id == run.id, PlaybookRun.status == "running")
            .values(
                status=status,
                finished_at=_now(),
                error_code=code,
                error_message=clean_text(message, 500) if message else None,
                version=PlaybookRun.version + 1,
                dedupe_key=None,
            )
        )
        if result.rowcount:  # type: ignore[attr-defined]
            run = self._session.get(PlaybookRun, run.id, populate_existing=True) or run
            audit_service.record(
                self._session,
                Actor(run.actor),
                "playbook_run_finished",
                audit_service.SUCCESS if status == "succeeded" else audit_service.FAILURE,
                target_type="asset",
                target_id=run.target_public_id,
                details={
                    "run": str(run.public_id),
                    "playbook": run.playbook_key,
                    "status": status,
                    **({"error": code} if code else {}),
                },
                commit=False,
            )
            if run.incident_id is not None:
                self._run_activity(run, f"playbook_{status}")
        self._session.commit()

    def _start_step(self, run: PlaybookRun, step: dict[str, Any]) -> bool:
        """Crea y lanza la ejecución del paso actual. False si otro proceso se adelantó."""
        action = get_action(str(step.get("action_id")))
        op = self._run_operator(run)
        if op is None:
            self._finish_run(
                run, "failed", "actor_inactive", "The user who started it is no longer active"
            )
            return False
        if action is None or not action.available:
            self._finish_run(
                run, "failed", "action_unavailable", "A step action is no longer available"
            )
            return False
        if not action.required_permissions <= op.permissions:
            self._finish_run(
                run, "failed", "permission_revoked", "The user no longer has the permissions"
            )
            return False
        asset = self._session.get(Asset, run.asset_id) if run.asset_id is not None else None
        if asset is None:
            self._finish_run(run, "failed", "target_missing", "The asset no longer exists")
            return False
        target = Target(
            asset=asset,
            incident=self._session.get(Incident, run.incident_id) if run.incident_id else None,
            context_incident=self._session.get(Incident, run.incident_id)
            if run.incident_id
            else None,
        )
        if run.detection_public_id is not None:
            target.detection = self._session.scalar(
                select(Detection).where(Detection.public_id == run.detection_public_id)
            )
        params = action.params_model.model_validate(step.get("parameters") or {})
        ctx = self._context(op, target, params, _now())
        # Misma política que una ejecución manual, evaluada AHORA (el estado pudo cambiar
        # desde el preview: agente offline, activo archivado...).
        decision = evaluate(action, ctx)
        try:
            created = self._create(
                op,
                action,
                target,
                params,
                decision,
                reason=run.reason,
                confirmed=True,
                run=run,
                step_index=run.current_step,
                timeout_seconds=None
                if action.requires_agent
                else int(step.get("timeout_seconds") or action.timeout_seconds),
            )
        except ResponseConflictError:
            self._session.rollback()
            return False
        if created.deduplicated:
            return True
        if decision.allowed:
            self._dispatch(action, ctx, created.execution)
        return True

    # --- Playbooks: lectura y cancelación ----------------------------------------------------

    def _run(self, public_id: UUID, lock: bool = False) -> PlaybookRun:
        query = select(PlaybookRun).where(PlaybookRun.public_id == public_id)
        if lock:
            query = query.with_for_update()
        run = self._session.scalar(query)
        if run is None:
            raise NotFoundError("Playbook run not found")
        return run

    def get_run(self, public_id: UUID) -> PlaybookRunOut:
        return self.run_out(self._run(public_id))

    def list_runs(
        self,
        *,
        status: str | None = None,
        asset_public_id: UUID | None = None,
        incident_public_id: UUID | None = None,
        playbook_public_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> PlaybookRunList:
        where: list[Any] = []
        if status:
            where.append(PlaybookRun.status == status)
        if asset_public_id is not None:
            where.append(PlaybookRun.target_public_id == asset_public_id)
        if incident_public_id is not None:
            where.append(
                PlaybookRun.incident_id.in_(
                    select(Incident.id).where(Incident.public_id == incident_public_id)
                )
            )
        if playbook_public_id is not None:
            where.append(
                PlaybookRun.playbook_id.in_(
                    select(Playbook.id).where(Playbook.public_id == playbook_public_id)
                )
            )
        total = self._session.scalar(select(func.count()).select_from(PlaybookRun).where(*where))
        runs = self._session.scalars(
            select(PlaybookRun)
            .where(*where)
            .order_by(PlaybookRun.created_at.desc(), PlaybookRun.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return PlaybookRunList(items=self._run_outs(runs), total=int(total or 0))

    def _run_outs(self, runs: Sequence[PlaybookRun]) -> list[PlaybookRunOut]:
        ids = [r.id for r in runs]
        executions: dict[int, dict[int, ResponseExecution]] = {}
        if ids:
            for execution in self._session.scalars(
                select(ResponseExecution).where(ResponseExecution.playbook_run_id.in_(ids))
            ):
                executions.setdefault(execution.playbook_run_id or 0, {})[
                    execution.step_index or 0
                ] = execution
        playbooks = (
            dict(
                self._session.execute(
                    select(Playbook.id, Playbook.public_id).where(
                        Playbook.id.in_({r.playbook_id for r in runs if r.playbook_id})
                    )
                ).all()
            )
            if runs
            else {}
        )
        incidents = (
            dict(
                self._session.execute(
                    select(Incident.id, Incident.public_id).where(
                        Incident.id.in_({r.incident_id for r in runs if r.incident_id})
                    )
                ).all()
            )
            if runs
            else {}
        )
        return [self._run_out(r, executions.get(r.id, {}), playbooks, incidents) for r in runs]

    def run_out(self, run: PlaybookRun, *, deduplicated: bool = False) -> PlaybookRunOut:
        out = self._run_outs([run])[0]
        out.deduplicated = deduplicated
        return out

    def _run_out(
        self,
        run: PlaybookRun,
        executions: dict[int, ResponseExecution],
        playbooks: dict[int, UUID],
        incidents: dict[int, UUID],
    ) -> PlaybookRunOut:
        steps = []
        for index, step in enumerate(run.steps):
            action = get_action(str(step.get("action_id")))
            execution = executions.get(index)
            if execution is not None:
                status = execution.status
            elif run.status == "running" and index >= run.current_step:
                status = "pending"
            else:
                # Pasos no alcanzados por fail-stop, cancelación o bloqueo.
                status = "skipped"
            steps.append(
                PlaybookRunStepOut(
                    order=int(step.get("order", index + 1)),
                    action_id=str(step.get("action_id")),
                    action_name=action.name if action else str(step.get("action_id")),
                    on_failure=str(step.get("on_failure", "stop")),
                    status=status,
                    execution_id=execution.public_id if execution else None,
                    result_summary=execution.result_summary if execution else None,
                    error_code=execution.error_code if execution else None,
                    error_message=execution.error_message if execution else None,
                    started_at=(execution.started_at or execution.queued_at) if execution else None,
                    finished_at=execution.finished_at if execution else None,
                    duration_ms=_duration(
                        execution.started_at or execution.queued_at, execution.finished_at
                    )
                    if execution
                    else None,
                )
            )
        return PlaybookRunOut(
            run_id=run.public_id,
            playbook_id=playbooks.get(run.playbook_id) if run.playbook_id else None,
            playbook_key=run.playbook_key,
            playbook_name=run.playbook_name,
            playbook_version=run.playbook_version,
            status=run.status,
            current_step=run.current_step,
            risk_level=run.risk_level,
            target_id=run.target_public_id,
            target_label=run.target_label,
            incident_id=incidents.get(run.incident_id) if run.incident_id else None,
            detection_id=run.detection_public_id,
            actor=run.actor,
            reason=run.reason,
            error_code=run.error_code,
            error_message=run.error_message,
            created_at=run.created_at,
            finished_at=run.finished_at,
            version=run.version,
            steps=steps,
        )

    def cancel_run(
        self, op: Operator, public_id: UUID, version: int, reason: str | None
    ) -> PlaybookRunOut:
        self._check_permissions(op, frozenset({Permission.RESPONSE_MANAGE}), "cancel", public_id)
        run = self._run(public_id, lock=True)
        if run.version != version:
            raise ResponseConflictError(
                "The playbook run changed; reload it",
                details=[{"current_version": run.version, "status": run.status}],
            )
        if run.status != "running":
            raise ResponseStateError("Only running playbooks can be cancelled")
        active = self._session.scalars(
            select(ResponseExecution)
            .where(
                ResponseExecution.playbook_run_id == run.id,
                ResponseExecution.status.in_(ACTIVE_EXECUTION_STATUSES),
            )
            .with_for_update()
        ).all()
        self._cancel_commands([e.id for e in active])
        for execution in active:
            self._finish(execution, "cancelled", op.actor, error_code="cancelled_by_operator")
        if reason:
            run.reason = clean_text(reason, 500)
        self._session.flush()
        self._finish_run(run, "cancelled", "cancelled_by_operator", "Cancelled by an operator")
        audit_service.record(
            self._session,
            op.actor,
            "response_cancelled",
            target_type="asset",
            target_id=run.target_public_id,
            details={"run": str(run.public_id), "playbook": run.playbook_key},
        )
        return self.get_run(public_id)


_MESSAGES = {
    "asset_archived": "The asset was archived; pending agent actions were cancelled",
    "agent_reassigned": "The agent is no longer the current agent of the asset",
    "command_expired": "The agent did not pick up the command before it expired",
    "agent_timeout": "The agent did not return a result in time",
    "deadline_exceeded": "The execution did not finish before its deadline",
}


def func_uuid() -> str:
    """Sufijo aleatorio corto para la clave de un playbook custom."""
    return uuid.uuid4().hex[:12]
