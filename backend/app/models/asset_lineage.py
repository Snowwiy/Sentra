import enum
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class LineageEndReason(enum.StrEnum):
    # El agente se movió de este activo a otro (este era el activo "nuevo" duplicado).
    REASSIGNED = "reassigned"
    # Este activo histórico recibió otro agente: el que tenía queda como histórico, sin
    # credencial (su token se descarta, nunca se reutiliza).
    REPLACED = "replaced"


class AssetAgentLineage(Base):
    """Linaje de agentes de un activo (Fase 5C.2): qué agentes informaron en él y ya no.

    El agente actual está en assets.agent_id; aquí queda cada asociación que terminó por una
    reconciliación, para no perder qué agent_id generó el historial del activo (antes se
    sobrescribía y solo quedaba en la auditoría). Sirve también como evidencia fuerte de
    duplicado ("same_agent_lineage") si un agente antiguo vuelve a enrolarse.

    No guarda tokens, hashes de token ni la identidad de máquina: solo identificadores.
    """

    __tablename__ = "asset_agent_lineage"
    __table_args__ = (
        Index("ix_asset_agent_lineage_asset", "asset_id"),
        # Búsqueda de linaje por agente (duplicados y auditoría).
        Index("ix_asset_agent_lineage_agent", "agent_id"),
        Index("ix_asset_agent_lineage_related", "related_asset_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    agent_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    end_reason: Mapped[str] = mapped_column(String(16))
    # El otro activo de la reconciliación (destino si REASSIGNED, origen si REPLACED). SET
    # NULL: el linaje sobrevive aunque el otro activo llegara a borrarse.
    related_asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL")
    )
    # Agrupa las filas (y la auditoría) de una misma reconciliación.
    reconciliation_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    agent_version: Mapped[str | None] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(64))
