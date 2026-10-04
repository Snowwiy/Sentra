"""Administration: one-time agent enrollment tokens.

SENSITIVE. A token lets a new host enroll as an agent. Every route here requires the
operator key (X-Admin-Key = ADMIN_API_KEY) and is disabled (403) while that is unset. The
token value is returned only by the create call; listing shows state, never the token.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import get_enrollment_token_service, require_admin
from app.api.responses import error_responses
from app.schemas.enrollment import (
    EnrollmentTokenCreate,
    EnrollmentTokenCreated,
    EnrollmentTokenList,
    EnrollmentTokenRead,
)
from app.services.enrollment_token_service import EnrollmentTokenService

router = APIRouter(
    prefix="/agent-enrollment-tokens",
    tags=["administration"],
    dependencies=[Depends(require_admin)],
    responses=error_responses(401, 403),
)
Service = Annotated[EnrollmentTokenService, Depends(get_enrollment_token_service)]


@router.post("", response_model=EnrollmentTokenCreated, status_code=status.HTTP_201_CREATED)
def create_token(payload: EnrollmentTokenCreate, service: Service) -> EnrollmentTokenCreated:
    return service.create(payload, created_via="api")


@router.get("", response_model=EnrollmentTokenList)
def list_tokens(
    service: Service, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> EnrollmentTokenList:
    return service.list(limit)


@router.post(
    "/{token_id}/revoke", response_model=EnrollmentTokenRead, responses=error_responses(404, 409)
)
def revoke_token(token_id: UUID, service: Service) -> EnrollmentTokenRead:
    return service.revoke(token_id)
