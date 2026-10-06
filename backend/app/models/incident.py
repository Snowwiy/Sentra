"""Gestión de incidentes SOC (Fase 4K). Ver docs/incident-management.md.

Capas, de menos a más elaboradas (cada una con su tabla, nunca mezcladas):
- evento: hecho registrado por el host o por Sentra;
- detección: conclusión de una regla (4H), con evidencia propia;
- alerta: notificación operacional;
- incidente: CASO de investigación y flujo de trabajo humano. Agrupa detecciones, alertas y
  activos por referencia; nunca copia su evidencia ni se crea automáticamente por cada
  detección (lo crea un analista, a mano o promoviendo una detección/alerta).

Las relaciones guardan, además de la FK, un snapshot mínimo (id público, regla, título,
severidad): la retención puede purgar detecciones o alertas resueltas antiguas y el caso
debe seguir diciendo qué contenía. La FK pasa a NULL (ON DELETE SET NULL) en ese caso.
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
    Sequence,
    SmallInteger,
    String,
    Text,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    return Enum(enum_cls, name=name, values_callable=lambda members: [m.value for m in members])


class IncidentStatus(enum.StrEnum):
    OPEN = "open"
    TRIAGE = "triage"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    # Absorbido por otro incidente (merge manual de admin). Terminal: conserva su historial y
    # su número, pero ya no se trabaja; el caso vivo es merged_into.
    MERGED = "merged"


class IncidentLevel(enum.StrEnum):
    """Escala común de severity y priority (valores distintos, misma escala)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentConfidence(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ResolutionCategory(enum.StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_ACTIVITY = "benign_activity"
    # Mismo caso que otro incidente: se resuelve apuntando al principal sin mover nada
    # (distinto de merge, que absorbe las relaciones en el principal).
    DUPLICATE = "duplicate"
    ACCEPTED_RISK = "accepted_risk"
    OTHER = "other"


LEVEL_RANK = {level: rank for rank, level in enumerate(IncidentLevel)}
# Estados en los que el caso sigue vivo (cuenta como "abierto" en listados y sugerencias).
ACTIVE_STATUSES = (
    IncidentStatus.OPEN,
    IncidentStatus.TRIAGE,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.CONTAINED,
)

# Número legible INC-000001. Secuencia propia: nunca se reutiliza ni depende del id interno
# (que sigue siendo la PK); dos altas concurrentes reciben números distintos sin locks.
incident_number_seq = Sequence("incident_number_seq", metadata=Base.metadata)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        # Listado por defecto (última actividad) y filtros habituales.
        Index("ix_incidents_last_activity", "last_activity_at"),
        Index("ix_incidents_status_last_activity", "status", "last_activity_at"),
        Index("ix_incidents_created", "created_at"),
        Index(
            "ix_incidents_owner",
            "owner_user_id",
            "last_activity_at",
            postgresql_where=text("owner_user_id IS NOT NULL"),
        ),
        Index(
            "ix_incidents_merged_into",
            "merged_into_id",
            postgresql_where=text("merged_into_id IS NOT NULL"),
        ),
        Index(
            "ix_incidents_duplicate_of",
            "duplicate_of_id",
            postgresql_where=text("duplicate_of_id IS NOT NULL"),
        ),
        Index("ix_incidents_created_by", "created_by_user_id"),
        Index(
            "ix_incidents_assigned_by",
            "assigned_by_user_id",
            postgresql_where=text("assigned_by_user_id IS NOT NULL"),
        ),
        Index(
            "ix_incidents_updated_by",
            "updated_by_user_id",
            postgresql_where=text("updated_by_user_id IS NOT NULL"),
        ),
        Index(
            "ix_incidents_resolved_by",
            "resolved_by_user_id",
            postgresql_where=text("resolved_by_user_id IS NOT NULL"),
        ),
        Index(
            "ix_incidents_risk_snapshot",
            "risk_snapshot_id",
            postgresql_where=text("risk_snapshot_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    number: Mapped[int] = mapped_column(
        BigInteger,
        incident_number_seq,
        unique=True,
        server_default=incident_number_seq.next_value(),
    )
    # Texto del analista (no confiable): la UI lo muestra como texto, nunca como HTML.
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    # Gravedad técnica observada y urgencia operacional: independientes (ver docs).
    severity: Mapped[IncidentLevel] = mapped_column(_enum(IncidentLevel, "incident_level"))
    priority: Mapped[IncidentLevel] = mapped_column(_enum(IncidentLevel, "incident_level"))
    status: Mapped[IncidentStatus] = mapped_column(
        _enum(IncidentStatus, "incident_status"), default=IncidentStatus.OPEN
    )
    # Null = sin evidencia de la que derivarla (incidente manual): no se inventa.
    confidence: Mapped[IncidentConfidence | None] = mapped_column(
        _enum(IncidentConfidence, "incident_confidence")
    )

    # Asignación. SET NULL por coherencia de FK, aunque los usuarios no se borran (se
    # desactivan) y un owner desactivado sigue apareciendo como owner histórico.
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    assigned_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    updated_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Ventana de la evidencia (detecciones/alertas): primera y última observación real.
    # Null en un incidente manual sin evidencia: no se inventan tiempos.
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Cualquier actividad del caso (cambio, nota, adjunto): orden por defecto del listado.
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Primera salida de "open" (triage o investigating): base de time_to_triage observado.
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolution_category: Mapped[ResolutionCategory | None] = mapped_column(
        _enum(ResolutionCategory, "incident_resolution")
    )
    resolution_summary: Mapped[str | None] = mapped_column(String(2000))
    # Resolución "duplicate": incidente principal (referencia, sin mover relaciones).
    duplicate_of_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL")
    )
    # Merge: incidente que absorbió a este.
    merged_into_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL")
    )
    merged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Último snapshot del riesgo (4I) leído, nunca calculado aquí: el activo relacionado de
    # mayor puntuación en el momento de crear o resolver el caso.
    risk_score_snapshot: Mapped[int | None] = mapped_column(SmallInteger)
    risk_level_snapshot: Mapped[str | None] = mapped_column(String(16))
    risk_confidence_snapshot: Mapped[str | None] = mapped_column(String(16))
    risk_snapshot_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("risk_snapshots.id", ondelete="SET NULL")
    )

    # Token de concurrencia optimista: cada cambio de campos del caso lo incrementa y el
    # cliente debe enviar el valor que leyó. Notas y adjuntos (append-only) no lo cambian.
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class IncidentAsset(Base):
    __tablename__ = "incident_assets"
    __table_args__ = (
        Index(
            "uq_incident_assets_asset",
            "incident_id",
            "asset_id",
            unique=True,
            postgresql_where=text("asset_id IS NOT NULL"),
        ),
        # "¿Qué incidentes tiene este activo?" (sugerencias, búsqueda por hostname/IP).
        Index(
            "ix_incident_assets_asset", "asset_id", postgresql_where=text("asset_id IS NOT NULL")
        ),
        Index(
            "ix_incident_assets_added_by",
            "added_by_user_id",
            postgresql_where=text("added_by_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    asset_public_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    # Nombre en el momento de añadirlo (sobrevive al borrado del activo).
    asset_name: Mapped[str] = mapped_column(String(255))
    # manual, detection, alert o merge.
    source: Mapped[str] = mapped_column(String(16))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    added_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    # Fase 4L: contexto crítico del activo al vincularlo (al crear el caso o al añadirlo) y
    # al resolver el caso. Mínimo (criticidad, rol, entorno, sensibilidad, zona,
    # exposición): conserva el contexto histórico sin copiar Asset Context entero (ni
    # etiquetas ni responsable). Null en vínculos anteriores a 4L.
    context_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    resolved_context_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class IncidentDetection(Base):
    __tablename__ = "incident_detections"
    __table_args__ = (
        Index(
            "uq_incident_detections_detection",
            "incident_id",
            "detection_id",
            unique=True,
            postgresql_where=text("detection_id IS NOT NULL"),
        ),
        # "¿Ya está esta detección en un caso?" y FK de la retención (SET NULL).
        Index(
            "ix_incident_detections_detection",
            "detection_id",
            postgresql_where=text("detection_id IS NOT NULL"),
        ),
        # Sugerencias por regla y búsqueda por título de detección.
        Index("ix_incident_detections_rule", "rule_id"),
        Index(
            "ix_incident_detections_attached_by",
            "attached_by_user_id",
            postgresql_where=text("attached_by_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    detection_id: Mapped[int | None] = mapped_column(
        ForeignKey("detections.id", ondelete="SET NULL")
    )
    # Snapshot mínimo para cuando la retención purgue la detección.
    detection_public_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    rule_id: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    # detection (promoción), alert (vía alerta), manual (adjunto) o merge.
    source: Mapped[str] = mapped_column(String(16))
    attached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    attached_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    __table_args__ = (
        Index(
            "uq_incident_alerts_alert",
            "incident_id",
            "alert_id",
            unique=True,
            postgresql_where=text("alert_id IS NOT NULL"),
        ),
        Index(
            "ix_incident_alerts_alert", "alert_id", postgresql_where=text("alert_id IS NOT NULL")
        ),
        Index(
            "ix_incident_alerts_attached_by",
            "attached_by_user_id",
            postgresql_where=text("attached_by_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"))
    alert_public_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    rule: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    message: Mapped[str] = mapped_column(String(500))
    source: Mapped[str] = mapped_column(String(16))
    attached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    attached_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class IncidentVulnerability(Base):
    """Finding de vulnerabilidad vinculado a un caso (Fase 5B).

    Igual que detecciones y alertas: referencia + snapshot mínimo (CVE, título, severidad,
    componente, versión, activo). El catálogo y la evidencia completos siguen en el finding;
    el caso nunca los copia. SET NULL si el finding desaparece (borrado del activo).
    """

    __tablename__ = "incident_vulnerabilities"
    __table_args__ = (
        Index(
            "uq_incident_vulnerabilities_finding",
            "incident_id",
            "finding_id",
            unique=True,
            postgresql_where=text("finding_id IS NOT NULL"),
        ),
        Index(
            "ix_incident_vulnerabilities_finding",
            "finding_id",
            postgresql_where=text("finding_id IS NOT NULL"),
        ),
        Index(
            "ix_incident_vulnerabilities_attached_by",
            "attached_by_user_id",
            postgresql_where=text("attached_by_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("vulnerability_findings.id", ondelete="SET NULL")
    )
    finding_public_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    vulnerability_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(16))
    component: Mapped[str] = mapped_column(String(512))
    installed_version: Mapped[str | None] = mapped_column(String(128))
    asset_name: Mapped[str] = mapped_column(String(255))
    # vulnerability (caso creado desde el finding) o merge.
    source: Mapped[str] = mapped_column(String(16))
    attached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    attached_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class IncidentNote(Base):
    """Nota del analista. Append-only en 4K: no hay edición ni borrado desde la API."""

    __tablename__ = "incident_notes"
    __table_args__ = (
        Index("ix_incident_notes_incident_created", "incident_id", "created_at"),
        Index(
            "ix_incident_notes_author",
            "author_user_id",
            postgresql_where=text("author_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    author_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # Nombre copiado: la nota conserva su autor aunque cambie la cuenta.
    author: Mapped[str] = mapped_column(String(64))
    # Texto plano no confiable (nunca HTML).
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IncidentActivity(Base):
    """Actividad del caso (creación, estado, asignación, adjuntos, riesgo, merge...).

    Es la parte "humana" del timeline; el resto (eventos, detecciones, alertas, cambios de
    riesgo) se lee por referencia de sus tablas, sin copiarlo. Solo se añaden filas.
    """

    __tablename__ = "incident_activity"
    __table_args__ = (
        Index("ix_incident_activity_incident_occurred", "incident_id", "occurred_at", "id"),
        # Actividad reciente del overview SOC.
        Index("ix_incident_activity_occurred", "occurred_at"),
        Index(
            "ix_incident_activity_actor",
            "actor_user_id",
            postgresql_where=text("actor_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # created, updated, status_changed, assigned, unassigned, detection_attached,
    # alert_attached, asset_added, resolved, closed, reopened, merged, merged_into,
    # risk_snapshot.
    action: Mapped[str] = mapped_column(String(32))
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor: Mapped[str] = mapped_column(String(64))
    # Entidad afectada (detection, alert, asset, incident, user) por id público.
    entity_type: Mapped[str | None] = mapped_column(String(16))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    # Resumen generado por Sentra (plantilla fija) con datos ya acotados.
    summary: Mapped[str] = mapped_column(String(300))
    # Contexto mínimo (de/a estado, categoría, riesgo...). Nunca evidencia completa.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class IncidentFeedback(Base):
    """Feedback estructurado de falso positivo por regla (para tuning futuro).

    Solo se guarda: no desactiva reglas, no cambia severidades y no "aprende" nada (4K).
    """

    __tablename__ = "incident_feedback"
    __table_args__ = (
        Index("ix_incident_feedback_incident", "incident_id"),
        # Agregado por regla para el futuro tuning.
        Index("ix_incident_feedback_rule", "rule_id", "created_at"),
        Index(
            "ix_incident_feedback_detection",
            "detection_id",
            postgresql_where=text("detection_id IS NOT NULL"),
        ),
        Index(
            "ix_incident_feedback_user",
            "created_by_user_id",
            postgresql_where=text("created_by_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    detection_id: Mapped[int | None] = mapped_column(
        ForeignKey("detections.id", ondelete="SET NULL")
    )
    detection_public_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    rule_id: Mapped[str] = mapped_column(String(32))
    rule_version: Mapped[int | None] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str | None] = mapped_column(String(2000))
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
