from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.inventory import AssetInventory
from app.repositories.asset_repository import AssetRepository
from app.schemas.inventory import (
    InventoryAccepted,
    InventoryCreate,
    InventoryRead,
    InventorySections,
)
from app.services.agent_service import authenticate_agent, mark_seen


class InventoryService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._assets = AssetRepository(session)

    def ingest(self, data: InventoryCreate, token: str | None) -> InventoryAccepted:
        asset = authenticate_agent(self._assets, data.agent_id, token)
        # mode="json" turns IPs and datetimes into strings that JSONB can store.
        document = data.model_dump(mode="json", include=set(InventorySections.model_fields))
        inventory = self._session.get(AssetInventory, asset.id)
        if inventory is None:
            self._session.add(
                AssetInventory(asset_id=asset.id, collected_at=data.collected_at, data=document)
            )
        # A delayed snapshot (e.g. flushed after an outage) must not replace a newer one.
        elif data.collected_at >= inventory.collected_at:
            inventory.collected_at = data.collected_at
            inventory.data = document
        mark_seen(asset, datetime.now(UTC))
        self._session.commit()
        return InventoryAccepted(asset_id=asset.public_id, collected_at=data.collected_at)

    def get(self, asset_public_id: UUID) -> InventoryRead:
        asset = self._assets.get_by_public_id(asset_public_id)
        if asset is None:
            raise NotFoundError("Asset not found")
        inventory = self._session.get(AssetInventory, asset.id)
        if inventory is None:
            raise NotFoundError("No inventory reported for this asset yet")
        return InventoryRead(
            asset_id=asset.public_id,
            collected_at=inventory.collected_at,
            received_at=inventory.received_at,
            **InventorySections.model_validate(inventory.data).model_dump(),
        )
