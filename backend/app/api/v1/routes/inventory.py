from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import AgentToken, get_inventory_service
from app.schemas.inventory import InventoryAccepted, InventoryCreate
from app.services.inventory_service import InventoryService

router = APIRouter(prefix="/inventory", tags=["inventory"])


@router.post("", response_model=InventoryAccepted, status_code=status.HTTP_201_CREATED)
def ingest_inventory(
    payload: InventoryCreate,
    service: Annotated[InventoryService, Depends(get_inventory_service)],
    token: AgentToken,
) -> InventoryAccepted:
    return service.ingest(payload, token)
