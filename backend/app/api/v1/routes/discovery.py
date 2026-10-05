"""Discovery read endpoints (permiso monitoring:read, como el resto de lecturas).

Iniciar y cancelar un descubrimiento es una operación activa sobre la red: vive en
routes/console_discovery.py, con el permiso discovery:run. La CLI
(`python -m app.cli discover`) queda como herramienta administrativa/debug.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from app.api.auth import READ
from app.api.deps import get_exposure_service
from app.api.responses import error_responses
from app.schemas.discovery import (
    DiscoveryJobDetail,
    DiscoveryJobList,
    DiscoveryScheduleRead,
    DiscoveryScopeRead,
)
from app.services.background import PeriodicJob
from app.services.exposure_service import ExposureService

router = APIRouter(prefix="/discovery", tags=["discovery"], dependencies=[READ])
Service = Annotated[ExposureService, Depends(get_exposure_service)]


@router.get("/scope", response_model=DiscoveryScopeRead)
def get_scope(service: Service) -> DiscoveryScopeRead:
    return service.scope()


@router.get("/schedule", response_model=DiscoveryScheduleRead)
def get_schedule(request: Request, service: Service) -> DiscoveryScheduleRead:
    # El PeriodicJob vive en este proceso (lifespan); sin él no hay próxima ejecución que
    # mostrar, aunque la configuración diga que el scheduler está activo.
    job: PeriodicJob | None = getattr(request.app.state, "discovery_schedule", None)
    return service.schedule(job.next_run_at if job else None, job.running if job else False)


@router.get("/jobs", response_model=DiscoveryJobList)
def list_jobs(
    service: Service, limit: Annotated[int, Query(ge=1, le=200)] = 20
) -> DiscoveryJobList:
    return service.jobs(limit)


@router.get("/jobs/{job_id}", response_model=DiscoveryJobDetail, responses=error_responses(404))
def get_job(job_id: UUID, service: Service) -> DiscoveryJobDetail:
    """Estado, progreso real y resultado de un job (la web lo consulta mientras corre)."""
    return service.job(job_id)
