"""Discovery read endpoints. Runs are started from the server CLI (`python -m app.cli
discover`) or the periodic job, never over HTTP: probing the network is an active operation
and the dashboard has no authentication yet."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_exposure_service
from app.schemas.discovery import DiscoveryJobList, DiscoveryScopeRead
from app.services.exposure_service import ExposureService

router = APIRouter(prefix="/discovery", tags=["discovery"])
Service = Annotated[ExposureService, Depends(get_exposure_service)]


@router.get("/scope", response_model=DiscoveryScopeRead)
def get_scope(service: Service) -> DiscoveryScopeRead:
    return service.scope()


@router.get("/jobs", response_model=DiscoveryJobList)
def list_jobs(
    service: Service, limit: Annotated[int, Query(ge=1, le=200)] = 20
) -> DiscoveryJobList:
    return service.jobs(limit)
