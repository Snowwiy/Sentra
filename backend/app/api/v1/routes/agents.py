from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from app.api.deps import (
    AgentToken,
    EnrollmentKey,
    EnrollmentTokenHeader,
    get_agent_management_service,
    get_agent_service,
)
from app.api.responses import error_responses
from app.schemas.agent import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    HeartbeatRequest,
    HeartbeatResponse,
)
from app.schemas.agent_management import AgentList
from app.services.agent_management_service import AgentManagementService
from app.services.agent_service import AgentService

router = APIRouter(prefix="/agents", tags=["agents"])
Service = Annotated[AgentService, Depends(get_agent_service)]


@router.post(
    "/register",
    response_model=AgentRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_200_OK: {
            "model": AgentRegisterResponse,
            "description": "Existing agent re-enrolled, token rotated (same body as 201)",
        },
        **error_responses(401, 403, 409, 413),
    },
)
def register_agent(
    payload: AgentRegisterRequest,
    service: Service,
    response: Response,
    enrollment_key: EnrollmentKey = None,
    # Recommended credential: a one-time token (see /agent-enrollment-tokens). When sent,
    # the shared key is not consulted.
    enrollment_token: EnrollmentTokenHeader = None,
) -> AgentRegisterResponse:
    result, created = service.register(payload, enrollment_key, enrollment_token)
    if not created:
        response.status_code = status.HTTP_200_OK
    return result


@router.post("/heartbeat", response_model=HeartbeatResponse, responses=error_responses(401, 413))
def heartbeat(payload: HeartbeatRequest, service: Service, token: AgentToken) -> HeartbeatResponse:
    return service.heartbeat(payload, token)


@router.get("", response_model=AgentList)
def list_agents(
    service: Annotated[AgentManagementService, Depends(get_agent_management_service)],
) -> AgentList:
    """Enrolled agents with liveness and credential state (read-only, like /assets).

    Never returns tokens, hashes or enrollment tokens.
    """
    return service.list_agents()
