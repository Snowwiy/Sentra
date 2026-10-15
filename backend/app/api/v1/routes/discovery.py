"""Discovery read endpoints (permiso monitoring:read, como el resto de lecturas).

Iniciar y cancelar un descubrimiento es una operación activa sobre la red: vive en
routes/console_discovery.py, con el permiso discovery:run. La CLI
(`python -m app.cli discover`) queda como herramienta administrativa/debug.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from app.api.auth import READ, require_permission
from app.api.deps import AppSettings, DbSession, get_exposure_service
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.discovery import (
    DiscoveryJobDetail,
    DiscoveryJobList,
    DiscoveryProfilesRead,
    DiscoveryScheduleRead,
    DiscoveryScopeRead,
    ObservationList,
)
from app.services.auth_service import AuthContext
from app.services.background import PeriodicJob
from app.services.exposure_service import ExposureService
from app.services.observation_service import ObservationFilters, ObservationService, profiles_read
from app.services.site_service import resolve_site

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
    service: Service,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    site_id: Annotated[UUID | None, Query()] = None,
) -> DiscoveryJobList:
    return service.jobs(limit, resolve_site(session, site_id))


@router.get("/jobs/{job_id}", response_model=DiscoveryJobDetail, responses=error_responses(404))
def get_job(job_id: UUID, service: Service) -> DiscoveryJobDetail:
    """Estado, progreso real y resultado de un job (la web lo consulta mientras corre)."""
    return service.job(job_id)


Reader = Annotated[AuthContext, Depends(require_permission(Permission.MONITORING_READ))]


@router.get("/profiles", response_model=DiscoveryProfilesRead)
def get_profiles(ctx: Reader, settings: AppSettings) -> DiscoveryProfilesRead:
    """Fase 6A: perfiles de Advanced Discovery con sus valores efectivos y los topes.

    can_tune solo orienta a la UI; el servidor vuelve a comprobar discovery:tune al crear.
    """
    return profiles_read(settings, ctx.has(Permission.DISCOVERY_TUNE))


@router.get("/observations", response_model=ObservationList, responses=error_responses(422))
def list_observations(
    session: DbSession,
    job_id: Annotated[UUID | None, Query()] = None,
    site_id: Annotated[UUID | None, Query()] = None,
    network: Annotated[str | None, Query(max_length=64)] = None,
    sensor_id: Annotated[UUID | None, Query()] = None,
    executor: Annotated[str | None, Query(max_length=16)] = None,
    method: Annotated[str | None, Query(max_length=16)] = None,
    reachability: Annotated[str | None, Query(max_length=16)] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    latest: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ObservationList:
    """Fase 6A: evidencia de discovery paginada y filtrada en el servidor.

    latest=true devuelve la última observación de cada (site, IP): la vista de red.
    """
    filters = ObservationFilters(
        job_id=job_id,
        site_id=site_id,
        network=network,
        sensor_id=sensor_id,
        executor=executor,
        method=method,
        reachability=reachability,
        q=q,
        latest=latest,
    )
    return ObservationService(session).search(filters, limit, offset)
