from datetime import datetime
from typing import Any
from uuid import UUID

from app.models.change import ChangeCategory, ChangeKind
from app.schemas.common import ResponseModel


class ChangeRead(ResponseModel):
    change_id: UUID
    category: ChangeCategory
    kind: ChangeKind
    # Service, software or account name.
    item: str
    # Before/after values (status, start type, versions...).
    details: dict[str, Any] | None
    # Snapshot time on the host, and when the server noticed the change.
    collected_at: datetime
    detected_at: datetime


class ChangeList(ResponseModel):
    asset_id: UUID
    items: list[ChangeRead]
    # Items in this page; `has_more` tells whether older changes exist.
    total: int
    has_more: bool
