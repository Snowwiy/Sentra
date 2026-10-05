"""Gestión de agentes desde el dashboard: tokens de enrollment, revocar y rehabilitar.

Fase 4G: protegido por login y permisos (enrollment:manage y agents:manage, hoy solo admin)
en lugar de la guarda temporal de consola local. Mismas operaciones y servicios que la API
de administración legacy (/agent-enrollment-tokens, X-Admin-Key) y la CLI. La ruta
/console se mantiene para no romper el contrato con el frontend.

El valor del token de enrollment se devuelve una sola vez, en la creación; nada aquí
devuelve un token de agente, un hash ni un secreto guardado, y la auditoría tampoco.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status

from app.api.auth import actor, require_permission
from app.api.deps import (
    AppSettings,
    DbSession,
    get_agent_management_service,
    get_enrollment_token_service,
)
from app.api.responses import error_responses
from app.core.exceptions import SentraError
from app.core.permissions import Permission
from app.schemas.agent_management import AgentRead, ConsoleInfo
from app.schemas.enrollment import (
    EnrollmentTokenCreate,
    EnrollmentTokenCreated,
    EnrollmentTokenList,
    EnrollmentTokenRead,
)
from app.services import audit_service
from app.services.agent_management_service import AgentManagementService, suggested_server_urls
from app.services.auth_service import AuthContext
from app.services.enrollment_token_service import EnrollmentTokenService

VIA = "dashboard"

router = APIRouter(prefix="/console", tags=["console"], responses=error_responses(401, 403))
Tokens = Annotated[EnrollmentTokenService, Depends(get_enrollment_token_service)]
Agents = Annotated[AgentManagementService, Depends(get_agent_management_service)]
EnrollmentAdmin = Annotated[AuthContext, Depends(require_permission(Permission.ENROLLMENT_MANAGE))]
AgentAdmin = Annotated[AuthContext, Depends(require_permission(Permission.AGENTS_MANAGE))]


def _failed(
    session: DbSession, ctx: AuthContext, action: str, kind: str, target: UUID, exc: SentraError
) -> None:
    session.rollback()
    audit_service.record(
        session,
        actor(ctx),
        action,
        audit_service.FAILURE,
        kind,
        target,
        details={"error": exc.code},
    )


@router.get("", response_model=ConsoleInfo)
def console_info(request: Request, settings: AppSettings, _: EnrollmentAdmin) -> ConsoleInfo:
    """Datos para el asistente "Añadir agente" (200 si la sesión puede crear tokens)."""
    server = request.scope.get("server")
    port = server[1] if server else None
    return ConsoleInfo(
        enrollment_token_ttl_minutes=settings.enrollment_token_ttl_minutes,
        suggested_server_urls=suggested_server_urls(settings.agent_server_url, port),
        server_url_configured=settings.agent_server_url is not None,
    )


@router.post(
    "/enrollment-tokens", response_model=EnrollmentTokenCreated, status_code=status.HTTP_201_CREATED
)
def create_enrollment_token(
    payload: EnrollmentTokenCreate, tokens: Tokens, ctx: EnrollmentAdmin, session: DbSession
) -> EnrollmentTokenCreated:
    created = tokens.create(payload, created_via=VIA)
    # Solo el id del token y sus restricciones, nunca el valor.
    audit_service.record(
        session,
        actor(ctx),
        "enrollment_token_created",
        target_type="enrollment_token",
        target_id=created.token_id,
        details={
            "max_uses": created.max_uses,
            "platform": payload.expected_platform,
            "hostname": payload.expected_hostname,
        },
    )
    return created


@router.get("/enrollment-tokens", response_model=EnrollmentTokenList)
def list_enrollment_tokens(tokens: Tokens, _: EnrollmentAdmin) -> EnrollmentTokenList:
    return tokens.list(100)


@router.post(
    "/enrollment-tokens/{token_id}/revoke",
    response_model=EnrollmentTokenRead,
    responses=error_responses(404, 409),
)
def revoke_enrollment_token(
    token_id: UUID, tokens: Tokens, ctx: EnrollmentAdmin, session: DbSession
) -> EnrollmentTokenRead:
    action = "enrollment_token_revoked"
    try:
        revoked = tokens.revoke(token_id)
    except SentraError as exc:
        _failed(session, ctx, action, "enrollment_token", token_id, exc)
        raise
    audit_service.record(
        session, actor(ctx), action, target_type="enrollment_token", target_id=token_id
    )
    return revoked


@router.post("/agents/{asset_id}/revoke", response_model=AgentRead, responses=error_responses(404))
def revoke_agent(asset_id: UUID, agents: Agents, ctx: AgentAdmin, session: DbSession) -> AgentRead:
    """Cut the agent off now. Keeps the asset and all its history."""
    try:
        result = agents.revoke(asset_id, via=VIA)
    except SentraError as exc:
        _failed(session, ctx, "agent_revoked", "asset", asset_id, exc)
        raise
    audit_service.record(
        session,
        actor(ctx),
        "agent_revoked",
        target_type="asset",
        target_id=asset_id,
        details={"hostname": result.hostname},
    )
    return result


@router.post(
    "/agents/{asset_id}/reinstate", response_model=AgentRead, responses=error_responses(404, 409)
)
def reinstate_agent(
    asset_id: UUID, agents: Agents, ctx: AgentAdmin, session: DbSession
) -> AgentRead:
    """Lift a revocation; the host must enroll again with a new one-time token."""
    try:
        result = agents.reinstate(asset_id, via=VIA)
    except SentraError as exc:
        _failed(session, ctx, "agent_reactivated", "asset", asset_id, exc)
        raise
    audit_service.record(
        session,
        actor(ctx),
        "agent_reactivated",
        target_type="asset",
        target_id=asset_id,
        details={"hostname": result.hostname},
    )
    return result
