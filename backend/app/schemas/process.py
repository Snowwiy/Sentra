from datetime import UTC, datetime
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from app.schemas.common import BIGINT_MAX, RequestModel, ResponseModel
from app.schemas.inventory import MAX_PATH
from app.schemas.telemetry import MAX_FUTURE_SKEW

# A busy server runs a few hundred processes; the cap keeps a snapshot well under the body
# limit (~350 bytes per entry).
MAX_SNAPSHOT_PROCESSES = 2000


class ProcessEntry(RequestModel):
    pid: int = Field(ge=0, le=BIGINT_MAX)
    ppid: int | None = Field(default=None, ge=0, le=BIGINT_MAX)
    name: str = Field(min_length=1, max_length=255)
    exe: str | None = Field(default=None, max_length=MAX_PATH)
    # Other users' processes need admin rights to read the owner: null then.
    username: str | None = Field(default=None, max_length=255)
    # Share of the whole machine (all cores), 0-100, measured by the agent over ~1 s.
    cpu_percent: float | None = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    memory_bytes: int = Field(ge=0, le=BIGINT_MAX)
    started_at: AwareDatetime | None = None
    status: str | None = Field(default=None, max_length=32)


class ProcessSnapshotCreate(RequestModel):
    agent_id: UUID
    collected_at: AwareDatetime
    processes: list[ProcessEntry] = Field(max_length=MAX_SNAPSHOT_PROCESSES)

    @field_validator("collected_at")
    @classmethod
    def _normalize_collected_at(cls, value: datetime) -> datetime:
        value = value.astimezone(UTC)
        if value > datetime.now(UTC) + MAX_FUTURE_SKEW:
            raise ValueError("collected_at is too far in the future")
        return value


class ProcessSnapshotAccepted(ResponseModel):
    asset_id: UUID
    collected_at: datetime
    # False when a newer snapshot was already stored (delayed resend): nothing replaced.
    stored: bool


class ProcessSnapshotRead(ResponseModel):
    asset_id: UUID
    collected_at: datetime
    received_at: datetime
    processes: list[ProcessEntry]
