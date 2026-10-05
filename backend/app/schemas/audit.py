from datetime import datetime
from typing import Any

from app.schemas.common import ResponseModel


class AuditEventRead(ResponseModel):
    created_at: datetime
    actor: str
    action: str
    target_type: str | None
    target_id: str | None
    result: str
    client_ip: str | None
    details: dict[str, Any] | None


class AuditEventList(ResponseModel):
    items: list[AuditEventRead]
