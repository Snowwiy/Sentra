import enum
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PortStateValue(enum.StrEnum):
    OPEN = "open"
    # Was open, then found not open in consecutive complete scans of a live host.
    CLOSED = "closed"


class AssetPort(Base):
    """A TCP port of an asset as reachable from the Sentra server (the exposure baseline).

    One row per asset and port, updated in place by every discovery run: the history of
    openings and closings is in asset_changes (category "exposure"), so this table stays
    bounded by assets times configured ports.
    """

    __tablename__ = "asset_ports"
    __table_args__ = (
        UniqueConstraint("asset_id", "protocol", "port", name="uq_asset_ports_asset_port"),
        # Fase 5B: vista consolidada de exposición (puertos abiertos de todos los activos,
        # los más recientes primero) paginada sin recorrer la tabla.
        Index("ix_asset_ports_state_last_seen", "state", "last_seen_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    port: Mapped[int] = mapped_column(Integer)
    state: Mapped[PortStateValue] = mapped_column(
        Enum(
            PortStateValue,
            name="port_state",
            values_callable=lambda members: [m.value for m in members],
        )
    )
    # IANA name for the port number (a hint: the service itself is never contacted).
    service_hint: Mapped[str | None] = mapped_column(String(32))
    # First time ever seen open; start of the current open period; last time seen open.
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Consecutive complete scans that found it not open while the host was up. A port is
    # only considered closed after 2, so one lost packet does not raise "port closed".
    misses: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
