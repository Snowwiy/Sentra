"""Dashboard console: agent administration for the browser on the Sentra server.

SENSITIVE and TEMPORARY (see api/console.py): the same operations as the administration
API (/agent-enrollment-tokens, X-Admin-Key) and the CLI (revoke-agent, reinstate-agent),
through the same services, guarded by `require_local_console` instead of a key the
browser would have to hold. To be replaced by dashboard login/RBAC.

The enrollment token value is returned once, by the create call; nothing here ever returns
an agent token, a hash or a stored secret.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status

from app.api.console import require_local_console
from app.api.deps import (
    AppSettings,
    get_agent_management_service,
    get_enrollment_token_service,
)
from app.api.responses import error_responses
from app.schemas.agent_management import AgentRead, ConsoleInfo
from app.schemas.enrollment import (
    EnrollmentTokenCreate,
    EnrollmentTokenCreated,
    EnrollmentTokenList,
    EnrollmentTokenRead,
)
from app.services.agent_management_service import AgentManagementService, suggested_server_urls
from app.services.enrollment_token_service import EnrollmentTokenService

VIA = "dashboard"

router = APIRouter(
    prefix="/console",
    tags=["console"],
    dependencies=[Depends(require_local_console)],
    responses=error_responses(403),
)
Tokens = Annotated[EnrollmentTokenService, Depends(get_enrollment_token_service)]
Agents = Annotated[AgentManagementService, Depends(get_agent_management_service)]


@router.get("", response_model=ConsoleInfo)
def console_info(request: Request, settings: AppSettings) -> ConsoleInfo:
    """Answers 200 when the console is usable from this browser (403 with the reason if not)."""
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
    payload: EnrollmentTokenCreate, tokens: Tokens
) -> EnrollmentTokenCreated:
    return tokens.create(payload, created_via=VIA)


@router.get("/enrollment-tokens", response_model=EnrollmentTokenList)
def list_enrollment_tokens(tokens: Tokens) -> EnrollmentTokenList:
    return tokens.list(100)


@router.post(
    "/enrollment-tokens/{token_id}/revoke",
    response_model=EnrollmentTokenRead,
    responses=error_responses(404, 409),
)
def revoke_enrollment_token(token_id: UUID, tokens: Tokens) -> EnrollmentTokenRead:
    return tokens.revoke(token_id)


@router.post("/agents/{asset_id}/revoke", response_model=AgentRead, responses=error_responses(404))
def revoke_agent(asset_id: UUID, agents: Agents) -> AgentRead:
    """Cut the agent off now. Keeps the asset and all its history."""
    return agents.revoke(asset_id, via=VIA)


@router.post(
    "/agents/{asset_id}/reinstate", response_model=AgentRead, responses=error_responses(404, 409)
)
def reinstate_agent(asset_id: UUID, agents: Agents) -> AgentRead:
    """Lift a revocation; the host must enroll again with a new one-time token."""
    return agents.reinstate(asset_id, via=VIA)
