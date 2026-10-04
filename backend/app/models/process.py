from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AssetProcessSnapshot(Base):
    """Latest process list of an asset (one row per asset, replaced on every snapshot).

    Processes change every few seconds and a host runs hundreds of them: keeping history
    would grow without bound for little value, so only the newest snapshot is stored. The
    agent sends it far more often than the rest of the inventory (PROCESSES interval).
    """

    __tablename__ = "asset_process_snapshots"

    asset_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
