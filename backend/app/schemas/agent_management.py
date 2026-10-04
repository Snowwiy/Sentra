"""Agents as the dashboard manages them. Never carries a token, a hash or any secret."""

import enum
from datetime import datetime
from typing import Literal
from uuid import UUID

from app.models.asset import AssetStatus, MonitoringMethod
from app.schemas.common import ResponseModel

AgentPlatform = Literal["windows", "linux", "other"]


class CredentialStatus(enum.StrEnum):
    """State of the agent's own credential (derived, never stored)."""

    # Holds a valid per-agent token.
    ACTIVE = "active"
    # Cut off by an operator: its calls get 401 and re-enrollment is refused (403).
    REVOKED = "revoked"
    # Not revoked, but without a valid token (reinstated, or token lost): it must enroll
    # again with a new one-time token.
    RE_ENROLLMENT_REQUIRED = "re_enrollment_required"


class AgentRead(ResponseModel):
    asset_id: UUID
    agent_id: UUID
    display_name: str
    hostname: str | None
    primary_ip: str
    os_name: str | None
    os_version: str | None
    architecture: str | None
    platform: AgentPlatform
    agent_version: str | None
    monitoring_method: MonitoringMethod
    # Liveness of the agent (unknown = enrolled, never reported yet).
    status: AssetStatus
    credential_status: CredentialStatus
    # First enrollment, and when the current credential was issued (last enrollment).
    enrolled_at: datetime
    credential_issued_at: datetime | None
    revoked_at: datetime | None
    last_seen_at: datetime | None


class AgentSummary(ResponseModel):
    total: int
    online: int
    offline: int
    # Enrolled but never reported (or waiting to re-enroll).
    pending: int
    revoked: int


class AgentList(ResponseModel):
    summary: AgentSummary
    items: list[AgentRead]


class ConsoleInfo(ResponseModel):
    """What the dashboard needs to offer agent management (console available)."""

    # Lifetime of a new enrollment token when none is given.
    enrollment_token_ttl_minutes: int
    # AGENT_SERVER_URL if configured, else URLs built from this machine's addresses.
    suggested_server_urls: list[str]
    server_url_configured: bool
