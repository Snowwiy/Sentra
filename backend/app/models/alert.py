import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
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
    # A service on the watch list (ALERT_WATCHED_SERVICES) is present but not running.
    SERVICE_STOPPED = "service_stopped"
    # Many error/critical host events in a short window (ALERT_EVENT_BURST_*).
    EVENT_BURST = "event_burst"
    # A local account gained or lost administrator rights.
    ADMIN_CHANGED = "admin_changed"
    # A host event from the critical list (ALERT_CRITICAL_EVENTS), e.g. unexpected shutdown.
    CRITICAL_EVENT = "critical_event"
    # Network discovery (after the first, baseline run of a network):
    # a host not known before appeared; identified (name or type) or not.
    ASSET_DISCOVERED = "asset_discovered"
    UNKNOWN_DEVICE = "unknown_device"
    # A discovered asset was not seen for DISCOVERY_OFFLINE_AFTER_MISSES complete runs.
    ASSET_DISAPPEARED = "asset_disappeared"
    # A port became reachable / stopped being reachable from the Sentra server.
    PORT_EXPOSED = "port_exposed"
    PORT_CLOSED = "port_closed"
    # The host answers on the network but its agent stopped reporting.
    MONITORING_LOST = "monitoring_lost"
    # Fase 4H: el motor de detección concluyó algo grave en el activo (severidad igual o
    # superior a DETECTION_ALERT_MIN_SEVERITY). La alerta notifica; la evidencia y la
    # explicación están en la detección enlazada (details.detection_id).
    SECURITY_DETECTION = "security_detection"
    # Fase 4I: el riesgo del activo cruzó hacia "critical" (Risk Engine). Solo al subir y
    # con cooldown; se resuelve sola cuando el activo sale de critical.
    RISK_CRITICAL = "risk_critical"


class AlertSeverity(enum.StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(enum.StrEnum):
    OPEN = "open"
    # Seen by an operator, condition still active: it stays deduplicated against new
    # occurrences and is resolved like an open alert.
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


# Not resolved yet (open or acknowledged): at most one per asset and rule.
ACTIVE_STATUSES = (AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED)


class Alert(Base):
    """A rule violation on an asset. Opened when the condition starts, resolved when it ends."""

    __tablename__ = "alerts"
    __table_args__ = (
        # At most one active (open or acknowledged) alert per asset and rule. This is the
        # deduplication guarantee: concurrent evaluations (several API workers, telemetry
        # racing the offline sweeper) cannot open duplicates because the database rejects
        # the second insert. Written as "not resolved" so the predicate does not depend on
        # the enum values added later.
        Index(
            "uq_alerts_active_asset_rule",
            "asset_id",
            "rule",
            unique=True,
            postgresql_where=text("status <> 'resolved'"),
        ),
        Index("ix_alerts_status_opened", "status", "opened_at"),
        # Alert list of one asset (detail page), newest first.
        Index("ix_alerts_asset_opened", "asset_id", "opened_at"),
        # FK lookup when retention deletes events (ON DELETE SET NULL): without it each
        # deleted event scans the whole alerts table.
        Index(
            "ix_alerts_source_event",
            "source_event_id",
            postgresql_where=text("source_event_id IS NOT NULL"),
        ),
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

    # Structured context for the operator (e.g. which services are stopped, which account
    # changed, the triggering event). Never secrets: built from inventory and event fields.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # The host event that triggered an event-based alert. Kept as NULL when retention
    # deletes the event; the alert itself is the incident record.
    source_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("system_events.id", ondelete="SET NULL")
    )
    # How many times the condition fired while the alert was active, and the last time.
    # Event-based alerts resolve once nothing fired for ALERT_EVENT_QUIET_MINUTES.
    occurrences: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
