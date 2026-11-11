from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, Float, Index, String, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class IngestQuotaBucket(Base):
    """Cubo de tokens de una cuota de ingesta (Fase 7D.2, core/ingest_quota.py).

    Estado operativo efímero, no historial: como mucho 8 filas por agente más 3 globales, y
    las que llevan un día sin uso se purgan solas (un cubo sin uso está lleno). La clave es
    "agent:<agent_id>:<dimensión>" o "global:<dimensión>": el agent_id no es secreto (viaja
    en cada petición y se muestra en el panel) y no hay tokens ni IPs.

    Sin clave foránea a assets a propósito: el cubo se crea al gastar y se purga solo; una FK
    obligaría a ordenar su borrado con el del activo y no aporta integridad útil.
    """

    __tablename__ = "ingest_quota_buckets"
    __table_args__ = (
        # Estado de limitación por agente para GET /agents (solo filas con rechazos).
        Index(
            "ix_ingest_quota_buckets_agent_rejected",
            "agent_id",
            postgresql_where=text("last_rejected_at IS NOT NULL"),
        ),
        # Purga por antigüedad.
        Index("ix_ingest_quota_buckets_updated_at", "updated_at"),
    )

    bucket_key: Mapped[str] = mapped_column(String(96), primary_key=True)
    agent_id: Mapped[UUID | None] = mapped_column(Uuid)
    tokens: Mapped[float] = mapped_column(Float)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    rejected_total: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    last_rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
