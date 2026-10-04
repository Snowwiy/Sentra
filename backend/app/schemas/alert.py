from datetime import datetime
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
    opened_at: datetime
    resolved_at: datetime | None


class AlertList(ResponseModel):
    items: list[AlertRead]
    total: int
