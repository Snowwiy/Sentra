from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from app.api.deps import get_health_service
from app.schemas.health import HealthRead
from app.services.health_service import HealthService

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthRead,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": HealthRead}},
)
def health(
    response: Response, service: Annotated[HealthService, Depends(get_health_service)]
) -> HealthRead:
    result = service.check()
    # 503 lets load balancers and monitors detect a degraded API without parsing the body.
    if result.status != "ok":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return result
