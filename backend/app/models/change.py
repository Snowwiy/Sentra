import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Enum, ForeignKey, Index, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ChangeCategory(enum.StrEnum):
    SERVICE = "service"
    SOFTWARE = "software"
    ACCOUNT = "account"
    # Ports reachable from the Sentra server (discovery).
    EXPOSURE = "exposure"
    # The asset's presence on the network (discovery).
    NETWORK = "network"


class ChangeKind(enum.StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    STARTED = "started"
    STOPPED = "stopped"
    START_TYPE_CHANGED = "start_type_changed"
    VERSION_CHANGED = "version_changed"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ADMIN_GRANTED = "admin_granted"
    ADMIN_REVOKED = "admin_revoked"
    PORT_OPENED = "port_opened"
    PORT_CLOSED = "port_closed"
    APPEARED = "appeared"
    DISAPPEARED = "disappeared"


def _enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    return Enum(enum_cls, name=name, values_callable=lambda members: [m.value for m in members])


class AssetChange(Base):
    """A difference Sentra found between two inventory snapshots of an asset.

    Derived on the server when a newer snapshot arrives (services, software, local accounts),
    so it works for every agent version and needs no privileged host log; and by network
    discovery (exposed ports, presence on the network). Append-only; old rows go with
    CHANGE_RETENTION_DAYS.
    """

    __tablename__ = "asset_changes"
    __table_args__ = (
        Index("ix_asset_changes_asset_detected", "asset_id", "detected_at"),
        Index("ix_asset_changes_detected", "detected_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))

    category: Mapped[ChangeCategory] = mapped_column(_enum(ChangeCategory, "change_category"))
    kind: Mapped[ChangeKind] = mapped_column(_enum(ChangeKind, "change_kind"))
    # Service name, software name or account name.
    item: Mapped[str] = mapped_column(String(512))
    # Before/after values of what changed (status, start type, version...).
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Snapshot time on the host, and when the server noticed.
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
