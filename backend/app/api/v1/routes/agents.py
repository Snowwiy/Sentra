from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from app.api.deps import AgentToken, EnrollmentKey, get_agent_service
from app.schemas.agent import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    HeartbeatRequest,
    HeartbeatResponse,
)
from app.services.agent_service import AgentService

router = APIRouter(prefix="/agents", tags=["agents"])
Service = Annotated[AgentService, Depends(get_agent_service)]


@router.post(
    "/register",
    response_model=AgentRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    responses={status.HTTP_200_OK: {"description": "Existing agent re-enrolled, token rotated"}},
)
def register_agent(
    payload: AgentRegisterRequest,
    service: Service,
    response: Response,
    enrollment_key: EnrollmentKey = None,
) -> AgentRegisterResponse:
    result, created = service.register(payload, enrollment_key)
    if not created:
        response.status_code = status.HTTP_200_OK
    return result


@router.post("/heartbeat", response_model=HeartbeatResponse)
def heartbeat(payload: HeartbeatRequest, service: Service, token: AgentToken) -> HeartbeatResponse:
    return service.heartbeat(payload, token)
