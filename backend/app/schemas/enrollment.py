from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from app.models.enrollment import EnrollmentTokenState
from app.schemas.common import RequestModel, ResponseModel

Platform = Literal["windows", "linux"]


class EnrollmentTokenCreate(RequestModel):
    # Minutes until it expires (default ENROLLMENT_TOKEN_TTL_MINUTES, at most one day).
    ttl_minutes: int | None = Field(default=None, ge=1, le=1440)
    # 1 = one agent. More only for imaging/batch installs; still expires.
    max_uses: int = Field(default=1, ge=1, le=100)
    expected_platform: Platform | None = None
    expected_hostname: str | None = Field(default=None, min_length=1, max_length=255)
    note: str | None = Field(default=None, max_length=200)


class EnrollmentTokenRead(ResponseModel):
    """A token as listed: never contains the token itself (it is not stored)."""

    token_id: UUID
    state: EnrollmentTokenState
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    max_uses: int
    use_count: int
    expected_platform: str | None
    expected_hostname: str | None
    note: str | None
    created_via: str
    # Asset of the agent that used it last (null until used, or if that asset was deleted).
    last_asset_id: UUID | None


class EnrollmentTokenCreated(EnrollmentTokenRead):
    # Shown only in this response, once. Store it nowhere but the target host.
    token: str


class EnrollmentTokenList(ResponseModel):
    items: list[EnrollmentTokenRead]
