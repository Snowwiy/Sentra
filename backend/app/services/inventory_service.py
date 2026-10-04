from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.asset import Asset
from app.models.change import AssetChange, ChangeCategory
from app.models.inventory import AssetInventory
from app.repositories.asset_repository import AssetRepository
from app.repositories.telemetry_repository import TelemetryRepository
from app.schemas.change import ChangeList, ChangeRead
from app.schemas.inventory import (
    InventoryAccepted,
    InventoryCreate,
    InventoryRead,
    InventorySections,
)
from app.services.agent_service import authenticate_agent, record_contact
from app.services.alert_service import AlertService, AlertThresholds
from app.services.change_detection import admin_changes, diff_inventory

# Services start one by one after a reboot: their state changes are not news then.
BOOT_GRACE = timedelta(minutes=10)


class InventoryService:
    def __init__(self, session: Session, thresholds: AlertThresholds) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._telemetry = TelemetryRepository(session)
        self._alerts = AlertService(session, thresholds)

    def ingest(self, data: InventoryCreate, token: str | None) -> InventoryAccepted:
        asset = authenticate_agent(self._assets, data.agent_id, token)
        # mode="json" turns IPs and datetimes into strings that JSONB can store.
        document = data.model_dump(mode="json", include=set(InventorySections.model_fields))
        # The previous snapshot, locked so two snapshots of one asset are diffed in order.
        previous = self._session.scalar(
            select(AssetInventory.data).where(AssetInventory.asset_id == asset.id).with_for_update()
        )
        # One atomic upsert instead of read-then-write. With two snapshots in flight for the
        # same asset (e.g. two hosts sharing a cloned agent identity), read-then-write either
        # failed on the primary key (HTTP 500) or let the older snapshot overwrite a newer one
        # committed in between.
        stmt = insert(AssetInventory).values(
            asset_id=asset.id, collected_at=data.collected_at, data=document
        )
        upsert = stmt.on_conflict_do_update(
            index_elements=[AssetInventory.asset_id],
            set_={
                "collected_at": stmt.excluded.collected_at,
                "data": stmt.excluded.data,
                "received_at": func.now(),
            },
            # A delayed snapshot (e.g. flushed after an outage) must not replace a newer one.
            where=stmt.excluded.collected_at >= AssetInventory.collected_at,
        ).returning(AssetInventory.asset_id)
        # RETURNING gives a row only when this snapshot was stored (insert or replace).
        applied = self._session.execute(upsert).first() is not None
        now = datetime.now(UTC)
        record_contact(self._session, asset, now)
        if applied:
            # Changes and rules only from the snapshot that is now current; a stale one is
            # older information than what the dashboard already shows.
            if previous is not None:
                self._record_changes(asset, previous, document, data.collected_at, now)
            self._alerts.evaluate_services(asset, document.get("services") or [])
        self._session.commit()
        return InventoryAccepted(asset_id=asset.public_id, collected_at=data.collected_at)

    def _record_changes(
        self,
        asset: Asset,
        previous: dict[str, object],
        current: dict[str, object],
        collected_at: datetime,
        now: datetime,
    ) -> None:
        latest = self._telemetry.latest_by_asset([asset.id]).get(asset.id)
        booting = latest is not None and latest.uptime_seconds < BOOT_GRACE.total_seconds()
        changes = diff_inventory(previous, current, booting=booting)
        self._session.add_all(
            AssetChange(
                asset_id=asset.id,
                category=change.category,
                kind=change.kind,
                item=change.item[:512],
                details=change.details,
                collected_at=collected_at,
                detected_at=now,
            )
            for change in changes
        )
        self._alerts.record_admin_changes(asset, admin_changes(changes))

    def get(self, asset_public_id: UUID) -> InventoryRead:
        asset = self._require_asset(asset_public_id)
        inventory = self._session.get(AssetInventory, asset.id)
        if inventory is None:
            raise NotFoundError("No inventory reported for this asset yet")
        return InventoryRead(
            asset_id=asset.public_id,
            collected_at=inventory.collected_at,
            received_at=inventory.received_at,
            **InventorySections.model_validate(inventory.data).model_dump(),
        )

    def changes(
        self,
        asset_public_id: UUID,
        category: ChangeCategory | None,
        limit: int,
        offset: int = 0,
    ) -> ChangeList:
        asset = self._require_asset(asset_public_id)
        stmt = select(AssetChange).where(AssetChange.asset_id == asset.id)
        if category is not None:
            stmt = stmt.where(AssetChange.category == category)
        rows = list(
            self._session.scalars(
                stmt.order_by(AssetChange.detected_at.desc(), AssetChange.id.desc())
                .limit(limit + 1)
                .offset(offset)
            )
        )
        items = [
            ChangeRead(
                change_id=change.public_id,
                category=change.category,
                kind=change.kind,
                item=change.item,
                details=change.details,
                collected_at=change.collected_at,
                detected_at=change.detected_at,
            )
            for change in rows[:limit]
        ]
        return ChangeList(
            asset_id=asset.public_id, items=items, total=len(items), has_more=len(rows) > limit
        )

    def _require_asset(self, asset_public_id: UUID) -> Asset:
        asset = self._assets.get_by_public_id(asset_public_id)
        if asset is None:
            raise NotFoundError("Asset not found")
        return asset
