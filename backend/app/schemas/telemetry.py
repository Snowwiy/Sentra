from datetime import UTC, datetime, timedelta
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from app.schemas.common import BIGINT_MAX, Percentage, RequestModel, ResponseModel

# Tolerated clock skew between agents and the server. Samples further in the future are
# rejected because they would permanently sort as "latest" and hide real measurements.
MAX_FUTURE_SKEW = timedelta(minutes=5)


class TelemetryCreate(RequestModel):
    agent_id: UUID
    # Optional client-generated id. Resending the same sample_id is accepted and stored once,
    # which makes retries after a lost response safe.
    sample_id: UUID | None = None
    # AwareDatetime rejects naive timestamps: guessing their timezone would silently shift data.
    timestamp: AwareDatetime = Field(description="Measurement time, with timezone offset.")
    cpu_percent: Percentage
    ram_percent: Percentage
    disk_percent: Percentage
    uptime_seconds: int = Field(ge=0, le=BIGINT_MAX)

    @field_validator("timestamp")
    @classmethod
    def _normalize_timestamp(cls, value: datetime) -> datetime:
        value = value.astimezone(UTC)
        if value > datetime.now(UTC) + MAX_FUTURE_SKEW:
            raise ValueError("timestamp is too far in the future")
        return value


class TelemetryAccepted(ResponseModel):
    asset_id: UUID
    recorded_at: datetime
    # False when the sample_id was already stored (a retry); nothing was written twice.
    stored: bool = True


class TelemetrySnapshot(ResponseModel):
    recorded_at: datetime
    cpu_percent: float
    ram_percent: float
    disk_percent: float
    uptime_seconds: int


class TelemetryHistory(ResponseModel):
    asset_id: UUID
    items: list[TelemetrySnapshot]
