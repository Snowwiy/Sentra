from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RateLimitHit(Base):
    """Un intento contado por un limitador compartido (Fase 4M, core/rate_limit.py).

    Estado operativo efímero, no historial: las filas se borran al salir de su ventana y no
    entran en ninguna pantalla. La clave es un SHA-256 (ni usuarios ni IPs en claro).
    """

    __tablename__ = "rate_limit_hits"
    __table_args__ = (
        # Recuento por clave dentro de la ventana y purga por antigüedad.
        Index("ix_rate_limit_hits_lookup", "scope", "key_hash", "hit_at"),
        Index("ix_rate_limit_hits_hit_at", "hit_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    scope: Mapped[str] = mapped_column(String(32))
    key_hash: Mapped[str] = mapped_column(String(64))
    hit_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
