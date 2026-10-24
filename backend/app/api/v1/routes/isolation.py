"""Aislamiento seguro (Fase 6E.7). Ver docs/safe-isolation.md.

- containment:preview (analista y admin): disponibilidad, impacto, sesión viva e historial;
- containment:isolate (admin): aislar con confirmación escrita, motivo y duración máxima;
- containment:release (admin): levantar el aislamiento.

El servidor nunca aplica nada por su cuenta: crea una ejecución `isolate_host` del Response
Engine que el helper local del equipo valida contra su propia política.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.isolation import (
    IsolationOverview,
    IsolationRequest,
    IsolationSessionList,
    IsolationSessionRead,
    ReleaseRequest,
)
from app.services.auth_service import AuthContext
from app.services.isolation_service import IsolationService
from app.services.response_service import Operator

router = APIRouter(prefix="/assets", tags=["isolation"], responses=error_responses(401, 403))
overview_router = APIRouter(
    prefix="/isolation", tags=["isolation"], responses=error_responses(401, 403)
)

PREVIEW = Depends(require_permission(Permission.CONTAINMENT_PREVIEW))
Isolator = Annotated[AuthContext, Depends(require_permission(Permission.CONTAINMENT_ISOLATE))]
Releaser = Annotated[AuthContext, Depends(require_permission(Permission.CONTAINMENT_RELEASE))]
_MUTATION_ERRORS = error_responses(404, 409, 422)


def get_service(session: DbSession, settings: AppSettings) -> IsolationService:
    return IsolationService(session, settings)


Service = Annotated[IsolationService, Depends(get_service)]


def _op(ctx: AuthContext) -> Operator:
    return Operator(ctx.user, actor(ctx), ctx.permissions)


@router.get(
    "/{asset_id}/isolation",
    response_model=IsolationOverview,
    dependencies=[PREVIEW],
    responses=error_responses(404),
)
def isolation_overview(asset_id: UUID, service: Service) -> IsolationOverview:
    """Si se puede aislar y por qué no; impacto, recomendaciones manuales y sesión viva."""
    return service.overview(asset_id)


@router.get(
    "/{asset_id}/isolation/sessions",
    response_model=IsolationSessionList,
    dependencies=[PREVIEW],
    responses=error_responses(404),
)
def isolation_history(
    asset_id: UUID, service: Service, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> IsolationSessionList:
    return service.history(asset_id, limit)


@router.post(
    "/{asset_id}/isolation", response_model=IsolationSessionRead, responses=_MUTATION_ERRORS
)
def isolate(
    asset_id: UUID, body: IsolationRequest, ctx: Isolator, service: Service
) -> IsolationSessionRead:
    """Aísla con confirmación escrita (`confirm_name` = nombre del equipo). 409 si el
    servidor lo tiene desactivado, el equipo no lo admite o la política lo bloquea."""
    return service.isolate(_op(ctx), asset_id, body)


@router.post(
    "/{asset_id}/isolation/release",
    response_model=IsolationSessionRead,
    responses=_MUTATION_ERRORS,
)
def release(
    asset_id: UUID, body: ReleaseRequest, ctx: Releaser, service: Service
) -> IsolationSessionRead:
    return service.release(_op(ctx), asset_id, body)


@overview_router.get("/sessions", response_model=IsolationSessionList, dependencies=[PREVIEW])
def active_sessions(service: Service) -> IsolationSessionList:
    """Sesiones vivas de todos los activos (aisladas, aplicándose, revirtiéndose o unknown)."""
    return service.list_active()
