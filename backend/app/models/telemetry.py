import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Index, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TelemetrySample(Base):
    """One point-in-time resource measurement. Rows are append-only to keep history."""

    __tablename__ = "telemetry_samples"
    __table_args__ = (
        Index("ix_telemetry_samples_asset_recorded", "asset_id", "recorded_at"),
        # Idempotency key: an agent that lost the response to a POST resends the same sample_id
        # and the duplicate is ignored. NULLs (older agents) never conflict with each other.
        Index("uq_telemetry_samples_asset_sample", "asset_id", "sample_id", unique=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    sample_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    cpu_percent: Mapped[float] = mapped_column(Float)
    ram_percent: Mapped[float] = mapped_column(Float)
    disk_percent: Mapped[float] = mapped_column(Float)
    uptime_seconds: Mapped[int] = mapped_column(BigInteger)
