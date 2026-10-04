import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, Enum, Index, Integer, String, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class DiscoveryJobStatus(enum.StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    # Stopped early (shutdown, deadline): results are partial.
    CANCELLED = "cancelled"
    FAILED = "failed"


class DiscoveryTrigger(enum.StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class DiscoveryJob(Base):
    """One discovery run over one allowed network."""

    __tablename__ = "discovery_jobs"
    __table_args__ = (
        # At most one running job per network: a second scheduler, API worker or a manual
        # run started meanwhile is refused by the database instead of scanning twice.
        Index(
            "uq_discovery_jobs_running_target",
            "target",
            unique=True,
            postgresql_where=text("status = 'running'"),
        ),
        Index("ix_discovery_jobs_started", "started_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    target: Mapped[str] = mapped_column(String(64))
    trigger: Mapped[DiscoveryTrigger] = mapped_column(
        Enum(
            DiscoveryTrigger,
            name="discovery_trigger",
            values_callable=lambda members: [m.value for m in members],
        )
    )
    status: Mapped[DiscoveryJobStatus] = mapped_column(
        Enum(
            DiscoveryJobStatus,
            name="discovery_job_status",
            values_callable=lambda members: [m.value for m in members],
        ),
        default=DiscoveryJobStatus.RUNNING,
    )
    # First completed run of this network: it records the baseline and raises no
    # "new asset"/"new port" alerts.
    baseline: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hosts_scanned: Mapped[int] = mapped_column(Integer, default=0)
    hosts_alive: Mapped[int] = mapped_column(Integer, default=0)
    hosts_new: Mapped[int] = mapped_column(Integer, default=0)
    open_ports: Mapped[int] = mapped_column(Integer, default=0)
    probes: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    # First errors (bounded) for the operator.
    errors: Mapped[list[str] | None] = mapped_column(JSONB)
    # Ports, timeout and concurrency the run used.
    parameters: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return round((self.completed_at - self.started_at).total_seconds(), 3)
