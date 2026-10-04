from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.asset import Asset, AssetStatus
from app.models.telemetry import TelemetrySample
from app.repositories.asset_repository import AssetRepository
from app.repositories.telemetry_repository import TelemetryRepository
from app.schemas.asset import AssetList, AssetRead
from app.schemas.telemetry import TelemetrySnapshot


def effective_status(asset: Asset, now: datetime, timeout: timedelta) -> AssetStatus:
    """Resolve the status shown to clients from the stored status and last contact time.

    Offline is derived here instead of being written by a background job: an agent that dies
    cannot report its own death, and computing it on read keeps the API correct without a
    scheduler. The stored `status` therefore only reflects the last agent activity; any future
    query that filters by status in SQL must apply the same timeout rule.
    """
    # Registered but never reported: we cannot claim it is up or down.
    if asset.last_seen_at is None:
        return AssetStatus.UNKNOWN
    if now - asset.last_seen_at > timeout:
        return AssetStatus.OFFLINE
    return asset.status


class AssetService:
    def __init__(self, session: Session, heartbeat_timeout: timedelta) -> None:
        self._assets = AssetRepository(session)
        self._telemetry = TelemetryRepository(session)
        self._timeout = heartbeat_timeout

    def list_assets(self) -> AssetList:
        assets = self._assets.list_all()
        latest = self._telemetry.latest_by_asset(asset.id for asset in assets)
        now = datetime.now(UTC)
        items = [self._to_read(asset, latest.get(asset.id), now) for asset in assets]
        return AssetList(items=items, total=len(items))

    def get_asset(self, public_id: UUID) -> AssetRead:
        asset = self._assets.get_by_public_id(public_id)
        if asset is None:
            raise NotFoundError("Asset not found")
        latest = self._telemetry.latest_by_asset([asset.id]).get(asset.id)
        return self._to_read(asset, latest, datetime.now(UTC))

    def _to_read(self, asset: Asset, latest: TelemetrySample | None, now: datetime) -> AssetRead:
        return AssetRead(
            asset_id=asset.public_id,
            hostname=asset.hostname,
            os_name=asset.os_name,
            os_version=asset.os_version,
            architecture=asset.architecture,
            primary_ip=asset.primary_ip,
            agent_version=asset.agent_version,
            status=effective_status(asset, now, self._timeout),
            first_seen_at=asset.first_seen_at,
            last_seen_at=asset.last_seen_at,
            created_at=asset.created_at,
            updated_at=asset.updated_at,
            latest_telemetry=TelemetrySnapshot.model_validate(latest) if latest else None,
        )
