from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.deps import (
    get_asset_service,
    get_inventory_service,
    get_process_service,
    get_telemetry_service,
)
from app.api.responses import error_responses
from app.models.change import ChangeCategory
from app.schemas.asset import AssetList, AssetRead
from app.schemas.change import ChangeList
from app.schemas.inventory import InventoryRead
from app.schemas.process import ProcessSnapshotRead
from app.schemas.telemetry import TelemetryHistory
from app.services.asset_service import AssetService
from app.services.inventory_service import InventoryService
from app.services.process_service import ProcessService
from app.services.telemetry_service import TelemetryService

router = APIRouter(prefix="/assets", tags=["assets"])
Service = Annotated[AssetService, Depends(get_asset_service)]


@router.get("", response_model=AssetList)
def list_assets(service: Service) -> AssetList:
    return service.list_assets()


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


@router.get("/{asset_id}/changes", response_model=ChangeList, responses=error_responses(404))
def get_asset_changes(
    asset_id: UUID,
    service: Annotated[InventoryService, Depends(get_inventory_service)],
    category: ChangeCategory | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ChangeList:
    return service.changes(asset_id, category, limit, offset)
