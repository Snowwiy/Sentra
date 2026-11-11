from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import AgentToken, get_inventory_service
from app.api.ingest import Guard
from app.api.responses import error_responses
from app.schemas.inventory import InventoryAccepted, InventoryCreate
from app.services.inventory_service import InventoryService

router = APIRouter(prefix="/inventory", tags=["inventory"])


@router.post(
    "",
    response_model=InventoryAccepted,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(401, 413, 429),
)
def ingest_inventory(
    payload: InventoryCreate,
    service: Annotated[InventoryService, Depends(get_inventory_service)],
    token: AgentToken,
    guard: Guard,
) -> InventoryAccepted:
    # Fase 7D.2 (H06): el inventario es el cuerpo más grande; lo acota el cubo de bytes.
    with guard.admit("inventory", payload.agent_id, token):
        return service.ingest(payload, token)
