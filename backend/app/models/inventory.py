from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AssetInventory(Base):
    """Latest software/system inventory snapshot of an asset (one row per asset).

    Stored as JSONB rather than normalized tables: the snapshot is always read and replaced as
    a whole, its shape is validated by the API schemas, and the lists (software, services) are
    large but rarely queried individually. Normalize a section when it needs SQL filtering
    (e.g. "which assets run software X") or change history.
    """

    __tablename__ = "asset_inventories"

    asset_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
