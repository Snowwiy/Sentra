"""Insights de IA (Fase 4J). Ver docs/ai-security-insights.md.

Se persisten (tabla ai_insights) en vez de un caché en memoria porque:
- cada análisis es auditable: qué modelo, qué versión de prompt, sobre qué datos (huella y
  referencias de entrada) y quién lo pidió;
- la caché sobrevive a reinicios y evita repetir llamadas caras al modelo;
- el estado stale se calcula comparando la huella guardada con la actual.

Lo que NO se guarda: el prompt, el contexto enviado, la clave del proveedor ni la respuesta
cruda. Solo el resultado validado (con referencias resueltas) y métricas técnicas.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AIInsight(Base):
    __tablename__ = "ai_insights"
    __table_args__ = (
        # Búsqueda de caché: mismo tipo, entidad, datos, modelo y prompt; el más reciente.
        Index("ix_ai_insights_cache", "cache_key", "generated_at"),
        # Listado general y por entidad (Asset Detail, Detection Detail).
        Index("ix_ai_insights_generated", "generated_at"),
        Index(
            "ix_ai_insights_asset",
            "asset_id",
            "generated_at",
            postgresql_where=text("asset_id IS NOT NULL"),
        ),
        Index(
            "ix_ai_insights_detection",
            "detection_id",
            postgresql_where=text("detection_id IS NOT NULL"),
        ),
        Index(
            "ix_ai_insights_snapshot",
            "risk_snapshot_id",
            postgresql_where=text("risk_snapshot_id IS NOT NULL"),
        ),
        Index(
            "ix_ai_insights_incident",
            "incident_id",
            "generated_at",
            postgresql_where=text("incident_id IS NOT NULL"),
        ),
        Index(
            "ix_ai_insights_vulnerability",
            "vulnerability_finding_id",
            postgresql_where=text("vulnerability_finding_id IS NOT NULL"),
        ),
        Index(
            "ix_ai_insights_user",
            "requested_by_user_id",
            postgresql_where=text("requested_by_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # asset_summary, detection_analysis, risk_explanation, soc_summary o ask.
    kind: Mapped[str] = mapped_column(String(32))
    # asset, detection, incident o fleet: sobre qué datos se construyó el contexto.
    scope: Mapped[str] = mapped_column(String(16))
    # Entidades analizadas. SET NULL: borrar un activo no borra el historial de análisis
    # (queda marcado stale por datos inexistentes).
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    detection_id: Mapped[int | None] = mapped_column(
        ForeignKey("detections.id", ondelete="SET NULL")
    )
    # Último punto del historial de riesgo cuando se generó (riesgo "de referencia").
    risk_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("risk_snapshots.id", ondelete="SET NULL")
    )
    # Incidente analizado (Fase 4K): asistencia de IA de solo lectura sobre un caso.
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    # Finding de vulnerabilidad analizado (Fase 5B): explicación de solo lectura.
    vulnerability_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("vulnerability_findings.id", ondelete="SET NULL")
    )
    # Pregunta del analista (solo Ask); acotada y sin datos del contexto.
    question: Mapped[str | None] = mapped_column(String(500))

    # Caché: sha256 de (tipo, entidad, huella de datos, proveedor, modelo, prompt, pregunta).
    cache_key: Mapped[str] = mapped_column(String(64))
    # Huella de los datos que respaldan el insight (app/ai/freshness.py).
    data_version: Mapped[str] = mapped_column(String(64))
    prompt_version: Mapped[str] = mapped_column(String(48))
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))

    # Resultado validado: resumen, hallazgos con certeza, acciones, referencias resueltas,
    # limitaciones y avisos del guardia de grounding.
    result: Mapped[dict[str, Any]] = mapped_column(JSONB)
    # Referencias de entrada (tipo e id de lo que vio el modelo), sin contenido.
    input_refs: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    dropped_refs: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    # Métricas técnicas (nunca contenido): elementos de contexto, latencia, tamaños.
    context_items: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    input_chars: Mapped[int | None] = mapped_column(Integer)
    output_chars: Mapped[int | None] = mapped_column(Integer)
    usage_input: Mapped[int | None] = mapped_column(Integer)
    usage_output: Mapped[int | None] = mapped_column(Integer)

    # Quién lo pidió (nombre copiado: sobrevive al borrado del usuario, como en detecciones).
    requested_by: Mapped[str] = mapped_column(String(64))
    requested_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Pasada esta fecha el insight es stale aunque los datos no hayan cambiado.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
