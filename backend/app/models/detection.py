"""Detecciones de seguridad (Fase 4H). Ver docs/detection-engine.md.

Capas, de menos a más elaboradas:
- evento: hecho registrado por el host o por Sentra (system_events, asset_changes, puertos);
- señal (DetectionSignal): un hecho relevante para seguridad, normalizado (quién, qué, cuándo)
  y guardado poco tiempo para poder correlacionar en ventanas temporales;
- detección (Detection): conclusión de una regla con severidad, confianza y evidencia;
- alerta (Alert): notificación operacional; solo las detecciones graves abren una.

Las reglas viven en código (app/detection/rules.py) con un id estable ("AUTH-001"): no hay
tabla detection_rules para no tener dos fuentes de verdad mientras no exista edición de
reglas desde la UI. Las filas guardan rule_id y rule_version para saber qué versión decidió.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    return Enum(enum_cls, name=name, values_callable=lambda members: [m.value for m in members])


class DetectionSeverity(enum.StrEnum):
    """Impacto si la detección es cierta (criterios en docs/detection-engine.md)."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionConfidence(enum.StrEnum):
    """Cuánto respalda la evidencia la conclusión; independiente de la severidad."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DetectionStatus(enum.StrEnum):
    OPEN = "open"
    # Vista por un analista; sigue activa (absorbe nuevas ocurrencias) hasta resolverse.
    ACKNOWLEDGED = "acknowledged"
    # Cerrada por un analista. Nunca se borra al resolver: es el historial de la investigación.
    RESOLVED = "resolved"


SEVERITY_RANK = {severity: rank for rank, severity in enumerate(DetectionSeverity)}
CONFIDENCE_RANK = {confidence: rank for rank, confidence in enumerate(DetectionConfidence)}


class Detection(Base):
    """Conclusión de una regla sobre un activo, deduplicada por (activo, regla, clave)."""

    __tablename__ = "detections"
    __table_args__ = (
        # Deduplicación garantizada por la base de datos: como mucho una detección activa por
        # activo, regla y clave (usuario, servicio, puerto...). Dos evaluaciones concurrentes
        # no pueden abrir duplicados; la segunda suma una ocurrencia a la primera.
        Index(
            "uq_detections_active_key",
            "asset_id",
            "rule_id",
            "dedup_key",
            unique=True,
            postgresql_where=text("status <> 'resolved'"),
        ),
        # Listado por defecto (más recientes primero) y filtros habituales.
        Index("ix_detections_last_seen", "last_seen_at"),
        Index("ix_detections_status_last_seen", "status", "last_seen_at"),
        Index("ix_detections_asset_last_seen", "asset_id", "last_seen_at"),
        Index("ix_detections_rule_last_seen", "rule_id", "last_seen_at"),
        Index("ix_detections_first_seen", "first_seen_at"),
        # Retención: solo se purgan detecciones resueltas.
        Index(
            "ix_detections_resolved_at",
            "resolved_at",
            postgresql_where=text("status = 'resolved'"),
        ),
        # FK hacia alerts (ON DELETE SET NULL al purgar alertas).
        Index("ix_detections_alert", "alert_id", postgresql_where=text("alert_id IS NOT NULL")),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))

    rule_id: Mapped[str] = mapped_column(String(32))
    rule_version: Mapped[int] = mapped_column(Integer)
    # "single" (una regla sobre una señal) o "correlation" (varias señales en una ventana).
    kind: Mapped[str] = mapped_column(String(16))
    # Lo que identifica "la misma detección" dentro de la regla y el activo: la cuenta, el
    # servicio, el puerto... Normalizada (minúsculas) para que "Admin" y "admin" coincidan.
    dedup_key: Mapped[str] = mapped_column(String(255))

    severity: Mapped[DetectionSeverity] = mapped_column(
        _enum(DetectionSeverity, "detection_severity")
    )
    confidence: Mapped[DetectionConfidence] = mapped_column(
        _enum(DetectionConfidence, "detection_confidence")
    )
    status: Mapped[DetectionStatus] = mapped_column(
        _enum(DetectionStatus, "detection_status"), default=DetectionStatus.OPEN
    )
    # Texto generado con plantillas deterministas (sin IA) a partir de datos no confiables
    # ya saneados (app/detection/text.py). La UI lo muestra como texto, nunca como HTML.
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(String(1000))
    # Hechos estructurados de la conclusión (cuenta, contadores, ventana...): base para el
    # futuro Risk Engine y para la Fase 4J sin tener que reinterpretar texto.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    # MITRE ATT&CK solo cuando el mapeo es defendible; nulo en las demás.
    mitre_tactic: Mapped[str | None] = mapped_column(String(16))
    mitre_technique: Mapped[str | None] = mapped_column(String(16))
    mitre_subtechnique: Mapped[str | None] = mapped_column(String(16))

    # Ocurrencias (oleadas separadas por el cooldown de la regla) y tiempos del host: primera
    # y última evidencia, no cuándo la procesó el servidor.
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    # Flujo del analista. El nombre del usuario se copia (no FK): la detección conserva quién
    # actuó aunque el usuario se borre; el detalle completo está en audit_events.
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str | None] = mapped_column(String(64))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[str | None] = mapped_column(String(64))
    resolution_note: Mapped[str | None] = mapped_column(String(500))

    # Alerta operacional asociada (solo detecciones graves, ver DETECTION_ALERT_MIN_SEVERITY).
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"))


class DetectionEvidence(Base):
    """Una señal que respalda una detección, copiada para que sobreviva a su origen.

    Las señales se purgan a las pocas horas y los eventos según EVENT_RETENTION_DAYS; la
    evidencia guarda lo necesario (resumen y datos acotados) para que la detección siga siendo
    explicable aunque el origen ya no exista. Nunca blobs: los datos vienen acotados.
    """

    __tablename__ = "detection_evidence"
    __table_args__ = (
        # La misma señal no se añade dos veces (reevaluaciones, carreras entre workers).
        UniqueConstraint("detection_id", "signal_id", name="uq_detection_evidence_signal"),
        # Timeline de una detección.
        Index("ix_detection_evidence_detection_occurred", "detection_id", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    detection_id: Mapped[int] = mapped_column(ForeignKey("detections.id", ondelete="CASCADE"))
    # Sin FK: la señal se purga mucho antes que la detección.
    signal_id: Mapped[int | None] = mapped_column(BigInteger)
    # Señal de la que sale ("auth_failure", "service_installed"...) y su papel en la regla
    # ("failure", "success", "admin_change"...).
    signal_kind: Mapped[str] = mapped_column(String(48))
    role: Mapped[str | None] = mapped_column(String(32))
    # Origen del hecho: system_event, asset_change, process_snapshot, inventory, discovery.
    source_type: Mapped[str] = mapped_column(String(32))
    # Id público del origen cuando existe (p. ej. el event_id de /events).
    source_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    summary: Mapped[str] = mapped_column(String(500))
    data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DetectionSignal(Base):
    """Señal normalizada pendiente de evaluar o disponible para correlación (estado temporal).

    La ingesta solo escribe señales (barato, en su transacción); el motor las evalúa aparte
    (job interno), así una regla lenta o rota nunca retrasa ni rechaza telemetría. Se purgan
    tras DETECTION_SIGNAL_RETENTION_HOURS: la evidencia útil ya está copiada en
    detection_evidence.
    """

    __tablename__ = "detection_signals"
    __table_args__ = (
        # Consultas de reglas y correlaciones: siempre por activo, tipo y ventana temporal.
        Index("ix_detection_signals_asset_kind_occurred", "asset_id", "kind", "occurred_at"),
        # Cola del motor: solo las pendientes (índice parcial pequeño).
        Index(
            "ix_detection_signals_pending",
            "id",
            postgresql_where=text("evaluated_at IS NULL"),
        ),
        Index("ix_detection_signals_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(48))
    # Sujeto normalizado (cuenta, servicio, puerto, ruta) para agrupar y correlacionar.
    subject: Mapped[str | None] = mapped_column(String(255))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source_type: Mapped[str] = mapped_column(String(32))
    source_id: Mapped[str | None] = mapped_column(String(64))
    data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DetectionBaseline(Base):
    """Lo ya visto en un activo (hoy: rutas de ejecutables) para distinguir "nuevo".

    El primer snapshot de procesos solo rellena la línea base, sin señales: instalar el
    agente no debe producir cientos de "proceso nuevo".
    """

    __tablename__ = "detection_baselines"

    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    kind: Mapped[str] = mapped_column(String(32), primary_key=True)
    key: Mapped[str] = mapped_column(String(512), primary_key=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
