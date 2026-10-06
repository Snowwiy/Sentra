from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import get_health_service
from app.schemas.health import LivenessRead, ReadinessRead
from app.services.health_service import HealthService

router = APIRouter(tags=["health"])


@router.get("/health", response_model=LivenessRead)
def liveness() -> LivenessRead:
    """Liveness: el proceso está vivo. No toca la base de datos a propósito: si PostgreSQL
    cae, reiniciar la API no lo arregla (eso lo dice /health/ready)."""
    return LivenessRead(status="ok")


@router.get(
    "/health/ready",
    response_model=ReadinessRead,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessRead}},
)
def readiness(
    request: Request,
    response: Response,
    service: Annotated[HealthService, Depends(get_health_service)],
) -> ReadinessRead:
    result = service.readiness(draining=getattr(request.app.state, "draining", False))
    # 503 lets load balancers and monitors detect a degraded API without parsing the body.
    if result.status != "ready":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return result
