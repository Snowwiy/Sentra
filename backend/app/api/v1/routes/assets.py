from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import IPvAnyNetwork

from app.api.deps import (
    get_asset_service,
    get_exposure_service,
    get_inventory_service,
    get_process_service,
    get_telemetry_service,
)
from app.api.params import text_query
from app.api.responses import error_responses
from app.models.asset import AssetStatus, MonitoringMethod
from app.models.change import ChangeCategory
from app.schemas.asset import AssetList, AssetRead
from app.schemas.change import ChangeList
from app.schemas.discovery import ExposureRead
from app.schemas.inventory import InventoryRead
from app.schemas.process import ProcessSnapshotRead
from app.schemas.telemetry import TelemetryHistory
from app.services.asset_service import AssetFilter, AssetService
from app.services.exposure_service import ExposureService
from app.services.inventory_service import InventoryService
from app.services.process_service import ProcessService
from app.services.telemetry_service import TelemetryService

router = APIRouter(prefix="/assets", tags=["assets"])
Service = Annotated[AssetService, Depends(get_asset_service)]


@router.get("", response_model=AssetList)
def list_assets(
    service: Service,
    # discovered / agentless / agent (DISCOVERED / MONITORED / MANAGED).
    method: MonitoringMethod | None = None,
    status: AssetStatus | None = None,
    # A type from app/discovery/classify.py, or "unknown".
    device_type: Annotated[str | None, Query(pattern=r"^[a-z_]{1,32}$")] = None,
    # Only assets whose address is inside this network, e.g. 192.168.1.0/24.
    subnet: IPvAnyNetwork | None = None,
    q: Annotated[str | None, text_query(200)] = None,
) -> AssetList:
    search = q.strip() if q else None
    return service.list_assets(
        AssetFilter(
            method=method, status=status, device_type=device_type, subnet=subnet, search=search
        )
    )


@router.get("/{asset_id}", response_model=AssetRead, responses=error_responses(404))
def get_asset(asset_id: UUID, service: Service) -> AssetRead:
    return service.get_asset(asset_id)


@router.get(
    "/{asset_id}/telemetry", response_model=TelemetryHistory, responses=error_responses(404)
)
def get_asset_telemetry(
    asset_id: UUID,
    service: Annotated[TelemetryService, Depends(get_telemetry_service)],
    # Bounded so a single request cannot pull an asset's entire history into memory.
    limit: Annotated[int, Query(ge=1, le=1000)] = 120,
) -> TelemetryHistory:
    return service.history(asset_id, limit)


@router.get(
    "/{asset_id}/inventory",
    response_model=InventoryRead,
    # 404 also when the asset exists but has not reported an inventory yet.
    responses=error_responses(404),
)
def get_asset_inventory(
    asset_id: UUID, service: Annotated[InventoryService, Depends(get_inventory_service)]
) -> InventoryRead:
    return service.get(asset_id)


@router.get(
    "/{asset_id}/processes",
    response_model=ProcessSnapshotRead,
    # 404 also when the asset exists but has not sent a process snapshot yet.
    responses=error_responses(404),
)
def get_asset_processes(
    asset_id: UUID, service: Annotated[ProcessService, Depends(get_process_service)]
) -> ProcessSnapshotRead:
    return service.get(asset_id)


@router.get("/{asset_id}/exposure", response_model=ExposureRead, responses=error_responses(404))
def get_asset_exposure(
    asset_id: UUID, service: Annotated[ExposureService, Depends(get_exposure_service)]
) -> ExposureRead:
    """Ports reachable from the Sentra server, correlated with the agent's listeners."""
    return service.exposure(asset_id)


@router.get("/{asset_id}/changes", response_model=ChangeList, responses=error_responses(404))
def get_asset_changes(
    asset_id: UUID,
    service: Annotated[InventoryService, Depends(get_inventory_service)],
    category: ChangeCategory | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ChangeList:
    return service.changes(asset_id, category, limit, offset)
