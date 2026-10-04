from datetime import datetime
from uuid import UUID

from app.models.asset import AssetStatus
from app.schemas.common import ResponseModel
from app.schemas.telemetry import TelemetrySnapshot


class AssetRead(ResponseModel):
    asset_id: UUID
    hostname: str
    os_name: str
    os_version: str
    architecture: str
    primary_ip: str
    agent_version: str
    status: AssetStatus
    first_seen_at: datetime
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime
    latest_telemetry: TelemetrySnapshot | None


class AssetList(ResponseModel):
    items: list[AssetRead]
    total: int
