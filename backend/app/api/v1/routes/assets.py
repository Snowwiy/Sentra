from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_asset_service, get_inventory_service, get_telemetry_service
from app.schemas.asset import AssetList, AssetRead
from app.schemas.inventory import InventoryRead
from app.schemas.telemetry import TelemetryHistory
from app.services.asset_service import AssetService
from app.services.inventory_service import InventoryService
from app.services.telemetry_service import TelemetryService

router = APIRouter(prefix="/assets", tags=["assets"])
Service = Annotated[AssetService, Depends(get_asset_service)]


@router.get("", response_model=AssetList)
def list_assets(service: Service) -> AssetList:
    return service.list_assets()


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: UUID, service: Service) -> AssetRead:
    return service.get_asset(asset_id)


@router.get("/{asset_id}/telemetry", response_model=TelemetryHistory)
def get_asset_telemetry(
    asset_id: UUID,
    service: Annotated[TelemetryService, Depends(get_telemetry_service)],
    # Bounded so a single request cannot pull an asset's entire history into memory.
    limit: Annotated[int, Query(ge=1, le=1000)] = 120,
) -> TelemetryHistory:
    return service.history(asset_id, limit)


@router.get("/{asset_id}/inventory", response_model=InventoryRead)
def get_asset_inventory(
    asset_id: UUID, service: Annotated[InventoryService, Depends(get_inventory_service)]
) -> InventoryRead:
    return service.get(asset_id)
