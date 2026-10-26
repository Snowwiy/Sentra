"""Tareas de un caso y solicitudes de control de red (Fase 7A.6, docs/case-operations.md).

Las dos cuelgan de un incidente existente (4K): no hay un motor de casos paralelo.

- Una TAREA es trabajo humano delegado dentro del caso (investigar un puerto, revisar una
  vulnerabilidad, verificar una corrección...). Asignar una tarea no ejecuta nada: la
  evidencia que se adjunta puede apuntar a una ejecución del Analyst Tool Engine o del
  Response Engine, pero esas se piden por su propio flujo con su vista previa y su permiso.
- Una SOLICITUD DE CONTROL DE RED describe una restricción (puerto, servicio, dirección,
  dominio, acceso a un sitio web, subida de ficheros) que alguien propone y un admin aprueba
  o rechaza. Sentra solo la aplicaría a través de un punto de control instalado que lo
  soporte; hoy no hay ninguno, así que la aprobación queda registrada con
  `enforcement_status = no_enforcement_point` y, si alguien la aplica fuera de Sentra, se
  registra como `applied_manually` con quién y cuándo. Nada se crea ni se aprueba desde el
  motor de riesgo ni desde una clasificación.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


TASK_KINDS = (
    "investigate_port",
    "verify_service",
    "review_vulnerability",
    "analyze_evidence",
    "investigate_script",
    "review_network_activity",
    "request_policy",
    "verify_remediation",
    "prepare_block_rule",
    "document_exception",
    "other",
)
TASK_STATUSES = ("open", "in_progress", "blocked", "done", "cancelled")
# Estados en los que la tarea sigue pendiente (contadores del caso y "mis tareas").
OPEN_TASK_STATUSES = ("open", "in_progress", "blocked")


class IncidentTask(Base):
    __tablename__ = "incident_tasks"
    __table_args__ = (
        CheckConstraint(_in("kind", TASK_KINDS), name="ck_incident_tasks_kind"),
        CheckConstraint(_in("status", TASK_STATUSES), name="ck_incident_tasks_status"),
        # Una tarea terminada siempre dice qué se encontró o se hizo.
        CheckConstraint(
            "status <> 'done' OR (result IS NOT NULL AND length(result) > 0)",
            name="ck_incident_tasks_done_result",
        ),
        Index("ix_incident_tasks_incident", "incident_id", "created_at"),
        # "Mis tareas": solo las pendientes, que son las que se consultan a menudo.
        Index(
            "ix_incident_tasks_assignee_open",
            "assignee_user_id",
            "status",
            postgresql_where=text("assignee_user_id IS NOT NULL"),
        ),
        Index(
            "ix_incident_tasks_creator",
            "created_by_user_id",
            postgresql_where=text("created_by_user_id IS NOT NULL"),
        ),
        Index("ix_incident_tasks_asset", "asset_id", postgresql_where=text("asset_id IS NOT NULL")),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(200))
    # Texto plano no confiable (nunca HTML), como las notas del caso.
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="open")
    # Activo sobre el que trata la tarea (opcional; debe estar vinculado al caso).
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    assignee_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    # Nombre copiado: la tarea conserva a quién se asignó aunque cambie la cuenta.
    assignee: Mapped[str | None] = mapped_column(String(64))
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_by: Mapped[str] = mapped_column(String(64))
    # Referencias validadas en el servidor: [{"type", "id", "label", "added_by", "added_at"}].
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    result: Mapped[str | None] = mapped_column(Text)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_by: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, default=1)


CONTROL_TYPES = (
    "block_port",
    "block_service",
    "block_address",
    "block_domain",
    "restrict_site_access",
    "prevent_upload",
)
CONTROL_STATUSES = ("pending_approval", "approved", "rejected", "cancelled", "expired")
# Qué pasó con una solicitud aprobada. `not_evaluated` mientras no está aprobada.
ENFORCEMENT_STATUSES = ("not_evaluated", "no_enforcement_point", "applied_manually")
OPEN_CONTROL_STATUSES = ("pending_approval", "approved")


class NetworkControlRequest(Base):
    __tablename__ = "network_control_requests"
    __table_args__ = (
        CheckConstraint(_in("control_type", CONTROL_TYPES), name="ck_network_controls_type"),
        CheckConstraint(_in("status", CONTROL_STATUSES), name="ck_network_controls_status"),
        CheckConstraint(
            _in("enforcement_status", ENFORCEMENT_STATUSES),
            name="ck_network_controls_enforcement",
        ),
        CheckConstraint(
            "direction IS NULL OR direction IN ('inbound', 'outbound', 'both')",
            name="ck_network_controls_direction",
        ),
        Index("ix_network_controls_incident", "incident_id", "created_at"),
        # Bandeja de aprobación y barrido de caducidad: solo las vivas.
        Index(
            "ix_network_controls_open",
            "status",
            "expires_at",
            postgresql_where=text("status IN ('pending_approval', 'approved')"),
        ),
        Index("ix_network_controls_task", "task_id", postgresql_where=text("task_id IS NOT NULL")),
        Index(
            "ix_network_controls_asset", "asset_id", postgresql_where=text("asset_id IS NOT NULL")
        ),
        Index("ix_network_controls_site", "site_id", postgresql_where=text("site_id IS NOT NULL")),
        Index(
            "ix_network_controls_requester",
            "requested_by_user_id",
            postgresql_where=text("requested_by_user_id IS NOT NULL"),
        ),
        Index(
            "ix_network_controls_decider",
            "decided_by_user_id",
            postgresql_where=text("decided_by_user_id IS NOT NULL"),
        ),
        Index(
            "ix_network_controls_applier",
            "applied_by_user_id",
            postgresql_where=text("applied_by_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    task_id: Mapped[int | None] = mapped_column(
        ForeignKey("incident_tasks.id", ondelete="SET NULL")
    )
    control_type: Mapped[str] = mapped_column(String(32))
    # Objetivo ya validado y normalizado según el tipo (ver schemas/case_operations.py).
    target: Mapped[dict[str, Any]] = mapped_column(JSONB)
    direction: Mapped[str | None] = mapped_column(String(8))
    # Alcance: un activo, un site o, si ambos son NULL, toda la instalación.
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"))
    # Etiqueta copiada del alcance para leer el historial aunque el activo se borre.
    scope_label: Mapped[str] = mapped_column(String(255))
    justification: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(24), default="pending_approval")
    enforcement_status: Mapped[str] = mapped_column(String(24), default="not_evaluated")
    # Puntos de control evaluados al aprobar y por qué no se puede aplicar (si es el caso).
    enforcement: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    requested_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    requested_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    decided_by: Mapped[str | None] = mapped_column(String(64))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(String(1000))
    applied_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    applied_by: Mapped[str | None] = mapped_column(String(64))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_note: Mapped[str | None] = mapped_column(String(1000))
    version: Mapped[int] = mapped_column(Integer, default=1)
