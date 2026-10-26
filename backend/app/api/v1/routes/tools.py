"""Analyst Tool Engine (Fase 7A). Ver docs/analyst-tool-engine.md.

Permisos (comprobados en el backend en cada petición; ocultar botones es solo UX):
- tools:read (viewer, analyst, admin): catálogo con sus esquemas e historial propio;
- tools:execute (analyst, admin): ejecutar, previsualizar, confirmar y cancelar. Cada
  herramienta exige además sus permisos de dominio (p. ej. telemetry:read, response:manage);
- tools:manage (admin): ver y cancelar ejecuciones de otros usuarios.

No hay ningún endpoint que acepte código, comandos, SQL ni el nombre de una función
arbitraria: `tool_id` se busca en el registro cerrado y su entrada la valida el modelo de la
herramienta. Las acciones solo se ejecutan con `confirm` sobre una vista previa vigente.
"""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.tools import (
    ToolCancelRequest,
    ToolCatalog,
    ToolConfirmRequest,
    ToolExecutionList,
    ToolExecutionOut,
    ToolOut,
    ToolRunRequest,
)
from app.services.auth_service import AuthContext
from app.services.discovery_runner import DiscoveryRunner, get_discovery_runner
from app.services.tool_service import ToolEngine, ToolOperator

router = APIRouter(prefix="/tools", tags=["tools"], responses=error_responses(401, 403))

Reader = Annotated[AuthContext, Depends(require_permission(Permission.TOOLS_READ))]
Executor = Annotated[AuthContext, Depends(require_permission(Permission.TOOLS_EXECUTE))]

ToolStatus = Literal[
    "previewed", "running", "succeeded", "failed", "cancelled", "timed_out", "rejected",
    "expired",
]  # fmt: skip
_MUTATION_ERRORS = error_responses(404, 409, 422, 429)


def get_tool_engine(
    request: Request,
    session: DbSession,
    settings: AppSettings,
    runner: Annotated[DiscoveryRunner, Depends(get_discovery_runner)],
) -> ToolEngine:
    # El limitador vive en app.state (memoria o PostgreSQL según RATE_LIMIT_BACKEND); el
    # runner de discovery se inyecta para que los tests lo sustituyan.
    limiter = getattr(request.app.state, "tools_limiter", None)
    return ToolEngine(session, settings, limiter, lambda: runner)


Engine = Annotated[ToolEngine, Depends(get_tool_engine)]


def _op(ctx: AuthContext) -> ToolOperator:
    return ToolOperator(ctx.user, actor(ctx), ctx.permissions)


@router.get("", response_model=ToolCatalog)
def list_tools(ctx: Reader, engine: Engine) -> ToolCatalog:
    """Registro completo: esquemas, permisos, riesgo, política y disponibilidad de cada una."""
    return engine.catalog(_op(ctx))


# Las rutas de ejecuciones van antes que /{tool_id} para que "executions" no se lea como id.
@router.get("/executions", response_model=ToolExecutionList)
def list_executions(
    ctx: Reader,
    engine: Engine,
    tool_id: Annotated[str | None, Query(max_length=64)] = None,
    status: ToolStatus | None = None,
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    mine: bool = True,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ToolExecutionList:
    """Historial. Sin tools:manage solo las propias (mine=false se ignora)."""
    return engine.list(
        _op(ctx),
        tool_id=tool_id,
        status=status,
        asset_public_id=asset_id,
        incident_public_id=incident_id,
        mine=mine,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/executions/{execution_id}", response_model=ToolExecutionOut, responses=error_responses(404)
)
def get_execution(execution_id: UUID, ctx: Reader, engine: Engine) -> ToolExecutionOut:
    return engine.get(_op(ctx), execution_id)


@router.post(
    "/executions/{execution_id}/confirm",
    response_model=ToolExecutionOut,
    responses=_MUTATION_ERRORS,
)
def confirm_execution(
    execution_id: UUID, body: ToolConfirmRequest, ctx: Executor, engine: Engine
) -> ToolExecutionOut:
    """Aprobación humana de una vista previa: ejecuta la acción con la misma entrada."""
    return engine.confirm(_op(ctx), execution_id, body.version, body.confirm, body.note)


@router.post(
    "/executions/{execution_id}/cancel",
    response_model=ToolExecutionOut,
    responses=_MUTATION_ERRORS,
)
def cancel_execution(
    execution_id: UUID, body: ToolCancelRequest, ctx: Executor, engine: Engine
) -> ToolExecutionOut:
    return engine.cancel(_op(ctx), execution_id, body.version)


@router.get("/{tool_id}", response_model=ToolOut, responses=error_responses(404))
def get_tool(tool_id: str, ctx: Reader, engine: Engine) -> ToolOut:
    return engine.definition(_op(ctx), tool_id)


@router.post("/{tool_id}/execute", response_model=ToolExecutionOut, responses=_MUTATION_ERRORS)
def execute_tool(
    tool_id: str, body: ToolRunRequest, ctx: Executor, engine: Engine
) -> ToolExecutionOut:
    """Lecturas e investigaciones. Una acción responde 422 tool_preview_required."""
    return engine.execute(_op(ctx), tool_id, body)


@router.post("/{tool_id}/preview", response_model=ToolExecutionOut, responses=_MUTATION_ERRORS)
def preview_tool(
    tool_id: str, body: ToolRunRequest, ctx: Executor, engine: Engine
) -> ToolExecutionOut:
    """Vista previa sin efectos de una acción (caduca en ANALYST_TOOLS_PREVIEW_TTL_MINUTES)."""
    return engine.preview(_op(ctx), tool_id, body)
