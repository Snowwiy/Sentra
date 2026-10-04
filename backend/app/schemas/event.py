from datetime import UTC, datetime
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from app.models.event import EventLevel
from app.schemas.common import BIGINT_MAX, RequestModel, ResponseModel
from app.schemas.telemetry import MAX_FUTURE_SKEW

MAX_EVENTS_PER_BATCH = 500
MAX_MESSAGE_LENGTH = 4000


class EventIn(RequestModel):
    source: str = Field(min_length=1, max_length=32, examples=["windows_eventlog"])
    channel: str = Field(min_length=1, max_length=255, examples=["System"])
    record_id: int = Field(ge=0, le=BIGINT_MAX)
    event_code: int = Field(ge=0, le=2**31 - 1)
    provider: str = Field(min_length=1, max_length=255)
    level: EventLevel
    # Long messages are truncated by the agent; the bound protects the API either way.
    message: str = Field(max_length=MAX_MESSAGE_LENGTH)
    # Host name the event was recorded on (Windows <Computer>); optional for older agents.
    computer: str | None = Field(default=None, max_length=255)
    occurred_at: AwareDatetime

    @field_validator("occurred_at")
    @classmethod
    def _normalize(cls, value: datetime) -> datetime:
        value = value.astimezone(UTC)
        if value > datetime.now(UTC) + MAX_FUTURE_SKEW:
            raise ValueError("occurred_at is too far in the future")
        return value


class EventBatch(RequestModel):
    agent_id: UUID
    events: list[EventIn] = Field(min_length=1, max_length=MAX_EVENTS_PER_BATCH)


class EventBatchAccepted(ResponseModel):
    asset_id: UUID
    received: int
    stored: int  # lower than `received` when some events were already stored (resend)


class EventRead(ResponseModel):
    event_id: UUID
    asset_id: UUID
    hostname: str
    source: str
    channel: str
    event_code: int
    provider: str
    level: EventLevel
    message: str
    record_id: int
    computer: str | None
    occurred_at: datetime


class EventList(ResponseModel):
    items: list[EventRead]
    # Number of items in this page. Event tables grow large, so they are not counted.
    total: int
    # True when more events match after this page (use `offset` to read them).
    has_more: bool = False
