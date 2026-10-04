import enum
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AssetStatus(enum.StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class Asset(Base):
    """A monitored host. In this phase every asset is backed by exactly one agent."""

    __tablename__ = "assets"

    # Internal surrogate key; never exposed through the API.
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # Identity generated and kept by the agent itself.
    agent_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True)

    # SHA-256 of the agent's bearer token (see core/security.py). Null means the agent has no
    # valid credential and must enroll again.
    agent_token_hash: Mapped[str | None] = mapped_column(String(64))
    # When the current token was issued. Groundwork for rotation (e.g. force re-enrollment of
    # tokens older than N days); not enforced yet.
    agent_token_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set by an operator to cut this agent off (stolen laptop, decommissioned host). While set,
    # the agent has no valid token and re-enrollment is refused, even with the enrollment key.
    agent_token_revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    hostname: Mapped[str] = mapped_column(String(255))
    os_name: Mapped[str] = mapped_column(String(64))
    os_version: Mapped[str] = mapped_column(String(128))
    architecture: Mapped[str] = mapped_column(String(32))
    # Validated as IPv4/IPv6 at the API boundary; 45 chars fits the longest IPv6 text form.
    primary_ip: Mapped[str] = mapped_column(String(45))
    agent_version: Mapped[str] = mapped_column(String(64))

    # Last status set by agent activity. Staleness (offline) is resolved at read time.
    status: Mapped[AssetStatus] = mapped_column(
        Enum(
            AssetStatus,
            name="asset_status",
            values_callable=lambda members: [member.value for member in members],
        ),
        default=AssetStatus.UNKNOWN,
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
