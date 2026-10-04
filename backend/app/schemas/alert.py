from datetime import datetime
from typing import Any
from uuid import UUID

from app.models.alert import AlertRule, AlertSeverity, AlertStatus
from app.schemas.common import ResponseModel


class AlertRead(ResponseModel):
    alert_id: UUID
    asset_id: UUID
    hostname: str
    rule: AlertRule
    severity: AlertSeverity
    status: AlertStatus
    message: str
    value: float | None
    # Structured context (stopped services, changed account, triggering event...).
    details: dict[str, Any] | None
    # Times the condition fired while the alert was active (event-based rules count every
    # matching event; condition rules stay at 1) and the last of them.
    occurrences: int
    last_triggered_at: datetime | None
    # Public id of the host event that triggered it, while that event is still stored.
    event_id: UUID | None
    opened_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None


class AlertList(ResponseModel):
    items: list[AlertRead]
    # Alerts matching the filters (all pages), not only the ones in `items`.
    total: int
