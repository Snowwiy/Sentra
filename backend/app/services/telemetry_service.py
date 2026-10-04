from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.repositories.asset_repository import AssetRepository
from app.repositories.telemetry_repository import TelemetryRepository
from app.schemas.telemetry import (
    TelemetryAccepted,
    TelemetryCreate,
    TelemetryHistory,
    TelemetrySnapshot,
)
from app.services.agent_service import authenticate_agent, record_contact
from app.services.alert_service import AlertService, AlertThresholds


class TelemetryService:
    def __init__(self, session: Session, thresholds: AlertThresholds) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._telemetry = TelemetryRepository(session)
        self._alerts = AlertService(session, thresholds)

    def ingest(self, data: TelemetryCreate, token: str | None) -> TelemetryAccepted:
        asset = authenticate_agent(self._assets, data.agent_id, token)
        stored = self._telemetry.insert_once(
            {
                "asset_id": asset.id,
                "sample_id": data.sample_id,
                "recorded_at": data.timestamp,
                "cpu_percent": data.cpu_percent,
                "ram_percent": data.ram_percent,
                "disk_percent": data.disk_percent,
                "uptime_seconds": data.uptime_seconds,
            }
        )
        # Receiving telemetry proves the agent is alive. Server time is used, not the
        # agent's clock, so a skewed agent cannot fake its liveness.
        now = datetime.now(UTC)
        record_contact(self._session, asset, now)
        if stored:
            # Same transaction as the sample: alerts never reference data that was rolled back.
            # A duplicate changes no data, so there is nothing new to evaluate.
            self._alerts.evaluate_metrics(asset)
        self._session.commit()
        return TelemetryAccepted(
            asset_id=asset.public_id, recorded_at=data.timestamp, stored=stored
        )

    def history(self, asset_public_id: UUID, limit: int) -> TelemetryHistory:
        asset = self._assets.get_by_public_id(asset_public_id)
        if asset is None:
            raise NotFoundError("Asset not found")
        samples = self._telemetry.recent_for_asset(asset.id, limit)
        # Returned oldest first, the natural order for plotting a time series.
        items = [TelemetrySnapshot.model_validate(sample) for sample in reversed(samples)]
        return TelemetryHistory(asset_id=asset.public_id, items=items)
