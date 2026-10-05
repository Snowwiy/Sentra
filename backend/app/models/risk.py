"""Riesgo de activos (Fase 4I). Ver docs/risk-engine.md.

Tres tablas con responsabilidades distintas:
- asset_risk: estado ACTUAL de cada activo (una fila por activo, mutable). Sirve los listados
  y el detalle sin recalcular, y hace de cola de recálculo (`dirty_at`).
- risk_snapshots: HISTORIAL inmutable. Solo se escribe cuando el riesgo cambia de forma
  material (cambio de nivel, delta mínimo, contribución nueva o intervalo), no en cada
  recálculo: el job de decay recalcula a menudo y una fila por cálculo crecería sin límite.
- risk_contributions: por qué cada snapshot tiene ese valor (normalizado, con referencia a la
  detección), para poder auditar una puntuación pasada aunque la detección ya no exista.

El cálculo vive en app/risk/ (puro, sin base de datos); aquí solo se persiste el resultado.
"""

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
    SmallInteger,
    String,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    return Enum(enum_cls, name=name, values_callable=lambda members: [m.value for m in members])


class RiskLevel(enum.StrEnum):
    """Nivel derivado de la puntuación con umbrales centralizados (app/risk/config.py)."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskConfidence(enum.StrEnum):
    """Cuánto respalda la evidencia la puntuación; independiente del score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


RISK_LEVEL_RANK = {level: rank for rank, level in enumerate(RiskLevel)}


class AssetRisk(Base):
    """Riesgo actual de un activo y su explicación vigente."""

    __tablename__ = "asset_risk"
    __table_args__ = (
        # Listado y overview: activos por riesgo descendente.
        Index("ix_asset_risk_score", "score"),
        Index("ix_asset_risk_level", "level"),
        # Cola de recálculo: solo las filas pendientes (índice parcial pequeño).
        Index("ix_asset_risk_dirty", "dirty_at", postgresql_where=text("dirty_at IS NOT NULL")),
        # Job de decay: los evaluados hace más tiempo primero.
        Index("ix_asset_risk_calculated", "calculated_at"),
    )

    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    score: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    level: Mapped[RiskLevel] = mapped_column(
        _enum(RiskLevel, "risk_level"),
        default=RiskLevel.INFORMATIONAL,
        server_default=RiskLevel.INFORMATIONAL.value,
    )
    confidence: Mapped[RiskConfidence] = mapped_column(
        _enum(RiskConfidence, "risk_confidence"),
        default=RiskConfidence.LOW,
        server_default=RiskConfidence.LOW.value,
    )
    # Versión de la fórmula que produjo el valor: si cambia la fórmula, el historial sigue
    # siendo interpretable (se sabe con qué reglas se calculó cada punto).
    formula_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    # Null = todavía no evaluado (fila creada solo para encolar el primer cálculo).
    calculated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Último cambio material (el del último snapshot): lo que la UI llama "último cambio".
    changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Factor principal en texto, para listados sin leer el JSON de contribuciones.
    top_factor: Mapped[str | None] = mapped_column(String(255))
    # Contribuciones vigentes y desglose del cálculo (acotados por app/risk/calculator.py).
    # El historial auditable está normalizado en risk_contributions por snapshot.
    contributions: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB)
    breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    # Estado del historial, para decidir si el siguiente cálculo merece snapshot.
    last_snapshot_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_snapshot_score: Mapped[int | None] = mapped_column(SmallInteger)

    # Cola de recálculo: algo relevante cambió (detección, resolución, exposición,
    # criticidad). El job lo procesa por lotes; null = al día.
    dirty_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Fallos consecutivos al calcular este activo (aislamiento de fallos): el job lo reintenta
    # en la siguiente vuelta sin bloquear al resto ni la API.
    error_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Última alerta de riesgo abierta para este activo (cooldown anti-spam).
    last_alert_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RiskSnapshot(Base):
    """Punto del historial de riesgo de un activo (solo cambios materiales)."""

    __tablename__ = "risk_snapshots"
    __table_args__ = (
        # Gráfico de tendencia y cambios recientes de un activo, siempre por ventana temporal.
        Index("ix_risk_snapshots_asset_calculated", "asset_id", "calculated_at"),
        # Retención (purga por fecha) y transiciones recientes del overview.
        Index("ix_risk_snapshots_calculated", "calculated_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    score: Mapped[int] = mapped_column(SmallInteger)
    level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "risk_level"))
    confidence: Mapped[RiskConfidence] = mapped_column(_enum(RiskConfidence, "risk_confidence"))
    # Valor anterior (null en el primer snapshot) y sentido del cambio de nivel: "up",
    # "down" o null si el nivel no cambió. Los descensos se registran (timeline) pero no
    # alertan.
    previous_score: Mapped[int | None] = mapped_column(SmallInteger)
    previous_level: Mapped[RiskLevel | None] = mapped_column(_enum(RiskLevel, "risk_level"))
    transition: Mapped[str | None] = mapped_column(String(8))
    # Por qué se guardó: initial, level_change, material_change, new_contribution, interval.
    reason: Mapped[str] = mapped_column(String(32))
    formula_version: Mapped[int] = mapped_column(Integer)
    top_factor: Mapped[str | None] = mapped_column(String(255))
    # Desglose completo (base, modificadores, saturación, reducciones, factores de
    # confianza) para reconstruir la explicación sin recalcular.
    breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class RiskContributionRecord(Base):
    """Una contribución (positiva o negativa) a un snapshot de riesgo."""

    __tablename__ = "risk_contributions"
    __table_args__ = (
        Index("ix_risk_contributions_snapshot", "snapshot_id", "position"),
        # FK hacia detections (ON DELETE SET NULL al purgar detecciones resueltas).
        Index(
            "ix_risk_contributions_detection",
            "detection_id",
            postgresql_where=text("detection_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("risk_snapshots.id", ondelete="CASCADE"))
    position: Mapped[int] = mapped_column(SmallInteger)
    # detection, exposure, criticality, asset_type o saturation.
    factor: Mapped[str] = mapped_column(String(16))
    # Categoría de la regla (authentication, defense...), "exposure" o "context".
    category: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(String(255))
    # Puntos efectivos que aportó (negativos si redujo) y puntos nominales antes de decay,
    # estado y rendimientos decrecientes.
    points: Mapped[float] = mapped_column(Float)
    nominal_points: Mapped[float | None] = mapped_column(Float)
    # Referencias navegables. El id público y la regla se copian: si la retención purga la
    # detección, la FK pasa a null pero el snapshot sigue diciendo de qué detección se trató.
    detection_id: Mapped[int | None] = mapped_column(
        ForeignKey("detections.id", ondelete="SET NULL")
    )
    detection_public_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    rule_id: Mapped[str | None] = mapped_column(String(32))
    port: Mapped[int | None] = mapped_column(Integer)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
