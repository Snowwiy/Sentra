import enum
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, Float, ForeignKey, Index, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    # Store the lowercase values (what the API exposes), not the Python member names.
    return Enum(enum_cls, name=name, values_callable=lambda members: [m.value for m in members])


class AlertRule(enum.StrEnum):
    ASSET_OFFLINE = "asset_offline"
    HIGH_CPU = "high_cpu"
    HIGH_RAM = "high_ram"
    DISK_CRITICAL = "disk_critical"


class AlertSeverity(enum.StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(enum.StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"


class Alert(Base):
    """A rule violation on an asset. Opened when the condition starts, resolved when it ends."""

    __tablename__ = "alerts"
    __table_args__ = (
        # At most one open alert per asset and rule. This is the deduplication guarantee:
        # concurrent evaluations (several API workers, telemetry racing the offline sweeper)
        # cannot open duplicates because the database rejects the second insert.
        Index(
            "uq_alerts_open_asset_rule",
            "asset_id",
            "rule",
            unique=True,
            postgresql_where=text("status = 'open'"),
        ),
        Index("ix_alerts_status_opened", "status", "opened_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))

    rule: Mapped[AlertRule] = mapped_column(_enum(AlertRule, "alert_rule"))
    severity: Mapped[AlertSeverity] = mapped_column(_enum(AlertSeverity, "alert_severity"))
    status: Mapped[AlertStatus] = mapped_column(
        _enum(AlertStatus, "alert_status"), default=AlertStatus.OPEN
    )
    message: Mapped[str] = mapped_column(String(500))
    # Metric value that triggered the alert, when the rule is metric based.
    value: Mapped[float | None] = mapped_column(Float)

    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
