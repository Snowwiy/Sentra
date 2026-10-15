"""Response Engine y Playbooks (Fase 5D). Ver docs/response-engine.md y docs/playbooks.md.

Permisos (comprobados en el backend en cada petición; ocultar botones es solo UX):
- response:read (viewer, analyst, admin): catálogo, playbooks e historial;
- response:execute (analyst, admin): preview y ejecución de acciones LOW y de playbooks
  cuyos pasos permita el rol. Cada acción exige además sus permisos de dominio;
- response:manage (admin): acciones MEDIUM, administrar playbooks y cancelar.

Todas las mutaciones usan la sesión del dashboard con CSRF (require_permission). No existe
ningún endpoint que acepte un comando, script o plantilla: solo `action_id` del catálogo.
"""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.response import (
    ActionList,
    CancelRequest,
    ExecutionList,
    ExecutionOut,
    ExecutionRequest,
    PlaybookCreate,
    PlaybookList,
    PlaybookOut,
    PlaybookPreviewOut,
    PlaybookRunList,
    PlaybookRunOut,
    PlaybookRunRequest,
    PlaybookToggle,
    PlaybookUpdate,
    PreviewOut,
)
from app.services.auth_service import AuthContext
from app.services.discovery_runner import DiscoveryRunner, get_discovery_runner
from app.services.response_service import Operator, ResponseService
from app.services.site_service import resolve_site

router = APIRouter(prefix="/response", tags=["response"], responses=error_responses(401, 403))

Reader = Annotated[AuthContext, Depends(require_permission(Permission.RESPONSE_READ))]
Executor = Annotated[AuthContext, Depends(require_permission(Permission.RESPONSE_EXECUTE))]
Manager = Annotated[AuthContext, Depends(require_permission(Permission.RESPONSE_MANAGE))]

ExecutionStatus = Literal[
    "pending", "approval_required", "queued", "running", "succeeded", "failed", "cancelled",
    "timed_out", "blocked",
]  # fmt: skip
RunStatus = Literal["running", "succeeded", "failed", "cancelled", "blocked"]
_MUTATION_ERRORS = error_responses(404, 409, 422)


def get_response_service(
    session: DbSession,
    settings: AppSettings,
    runner: Annotated[DiscoveryRunner, Depends(get_discovery_runner)],
) -> ResponseService:
    # El runner de discovery se inyecta (los tests lo sustituyen); solo lo usa start_discovery.
    return ResponseService(session, settings, lambda: runner)


Service = Annotated[ResponseService, Depends(get_response_service)]


def _op(ctx: AuthContext) -> Operator:
    # Permisos del contexto de la sesión (los mismos que comprobó require_permission).
    return Operator(ctx.user, actor(ctx), ctx.permissions)


# --- Catálogo y ejecuciones ------------------------------------------------------------------


@router.get("/actions", response_model=ActionList, responses=error_responses(404))
def list_actions(ctx: Reader, service: Service, asset_id: UUID | None = None) -> ActionList:
    """Catálogo allowlisted. Con asset_id, qué bloquea cada acción en ese activo."""
    return service.list_actions(_op(ctx), asset_id)


@router.post("/preview", response_model=PreviewOut, responses=_MUTATION_ERRORS)
def preview(body: ExecutionRequest, ctx: Executor, service: Service) -> PreviewOut:
    """Sin efectos: objetivo, parámetros, riesgo, rol, precondiciones, bloqueos y avisos."""
    return service.preview(_op(ctx), body)


@router.post("/executions", response_model=ExecutionOut, responses=_MUTATION_ERRORS)
def execute(body: ExecutionRequest, ctx: Executor, service: Service) -> ExecutionOut:
    """Misma política que /preview, recalculada aquí. 409 response_blocked si algo bloquea."""
    return service.execute(_op(ctx), body)


@router.get("/executions", response_model=ExecutionList)
def list_executions(
    _: Reader,
    service: Service,
    session: DbSession,
    status: ExecutionStatus | None = None,
    action_id: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z0-9_]+$")] = None,
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    run_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    # Fase 5F: solo ejecuciones sobre activos de este site.
    site_id: Annotated[UUID | None, Query()] = None,
) -> ExecutionList:
    return service.list_executions(
        site_id=resolve_site(session, site_id),
        status=status,
        action_id=action_id,
        asset_public_id=asset_id,
        incident_public_id=incident_id,
        run_public_id=run_id,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/executions/{execution_id}", response_model=ExecutionOut, responses=error_responses(404)
)
def get_execution(execution_id: UUID, _: Reader, service: Service) -> ExecutionOut:
    return service.get_execution(execution_id)


@router.post(
    "/executions/{execution_id}/cancel", response_model=ExecutionOut, responses=_MUTATION_ERRORS
)
def cancel_execution(
    execution_id: UUID, body: CancelRequest, ctx: Manager, service: Service
) -> ExecutionOut:
    return service.cancel(_op(ctx), execution_id, body.version, body.reason)


# --- Playbooks -------------------------------------------------------------------------------


@router.get("/playbooks", response_model=PlaybookList, responses=error_responses(404))
def list_playbooks(ctx: Reader, service: Service, asset_id: UUID | None = None) -> PlaybookList:
    return service.list_playbooks(_op(ctx), asset_id)


@router.post("/playbooks", response_model=PlaybookOut, responses=_MUTATION_ERRORS)
def create_playbook(body: PlaybookCreate, ctx: Manager, service: Service) -> PlaybookOut:
    return service.create_playbook(_op(ctx), body)


@router.get("/playbooks/{playbook_id}", response_model=PlaybookOut, responses=error_responses(404))
def get_playbook(playbook_id: UUID, ctx: Reader, service: Service) -> PlaybookOut:
    return service.get_playbook(_op(ctx), playbook_id)


@router.patch("/playbooks/{playbook_id}", response_model=PlaybookOut, responses=_MUTATION_ERRORS)
def update_playbook(
    playbook_id: UUID, body: PlaybookUpdate, ctx: Manager, service: Service
) -> PlaybookOut:
    """Crea una versión nueva; las ejecuciones pasadas conservan la suya."""
    return service.update_playbook(_op(ctx), playbook_id, body)


@router.post(
    "/playbooks/{playbook_id}/enable", response_model=PlaybookOut, responses=_MUTATION_ERRORS
)
def enable_playbook(
    playbook_id: UUID, body: PlaybookToggle, ctx: Manager, service: Service
) -> PlaybookOut:
    return service.set_enabled(_op(ctx), playbook_id, body.revision, True)


@router.post(
    "/playbooks/{playbook_id}/disable", response_model=PlaybookOut, responses=_MUTATION_ERRORS
)
def disable_playbook(
    playbook_id: UUID, body: PlaybookToggle, ctx: Manager, service: Service
) -> PlaybookOut:
    return service.set_enabled(_op(ctx), playbook_id, body.revision, False)


@router.post(
    "/playbooks/{playbook_id}/preview",
    response_model=PlaybookPreviewOut,
    responses=_MUTATION_ERRORS,
)
def preview_playbook(
    playbook_id: UUID, body: PlaybookRunRequest, ctx: Executor, service: Service
) -> PlaybookPreviewOut:
    return service.preview_playbook(_op(ctx), playbook_id, body)


@router.post(
    "/playbooks/{playbook_id}/execute", response_model=PlaybookRunOut, responses=_MUTATION_ERRORS
)
def execute_playbook(
    playbook_id: UUID, body: PlaybookRunRequest, ctx: Executor, service: Service
) -> PlaybookRunOut:
    return service.execute_playbook(_op(ctx), playbook_id, body)


@router.get("/runs", response_model=PlaybookRunList)
def list_runs(
    _: Reader,
    service: Service,
    status: RunStatus | None = None,
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    playbook_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> PlaybookRunList:
    return service.list_runs(
        status=status,
        asset_public_id=asset_id,
        incident_public_id=incident_id,
        playbook_public_id=playbook_id,
        limit=limit,
        offset=offset,
    )


@router.get("/runs/{run_id}", response_model=PlaybookRunOut, responses=error_responses(404))
def get_run(run_id: UUID, _: Reader, service: Service) -> PlaybookRunOut:
    return service.get_run(run_id)


@router.post("/runs/{run_id}/cancel", response_model=PlaybookRunOut, responses=_MUTATION_ERRORS)
def cancel_run(run_id: UUID, body: CancelRequest, ctx: Manager, service: Service) -> PlaybookRunOut:
    return service.cancel_run(_op(ctx), run_id, body.version, body.reason)
