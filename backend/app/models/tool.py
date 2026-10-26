"""Ejecuciones del Analyst Tool Engine (Fase 7A, docs/analyst-tool-engine.md).

Una fila por cada petición a una herramienta del registro cerrado (app/tools/registry.py):
lecturas, investigaciones y acciones. Es evidencia SOC y no se borra por defecto
(ANALYST_TOOLS_RETENTION_DAYS opt-in).

Lo que se guarda permite verificar después qué se pidió y qué se obtuvo:
- `input`: los parámetros YA validados por el modelo de la herramienta (nunca texto libre
  fuera de los campos acotados que declara) y su SHA-256 canónico;
- `output`: la salida estructurada y acotada, con el SHA-256 del JSON canónico guardado;
- `evidence` y `provenance`: referencias a los registros originales (detecciones, eventos,
  procesos...) y de dónde salió el dato, para que la salida no sea una afirmación suelta.

Las herramientas de acción nunca ejecutan nada propio: delegan en el Response Engine o en el
servicio de casos tras una vista previa (`previewed`) y una confirmación explícita, que queda
registrada (`approved_*`). `invoker` es siempre `user` en 7A: una futura consola o modelo
(7B/7C) tendrá que ejecutar en nombre de un usuario concreto y con sus permisos.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

TOOL_EXECUTION_STATUSES = (
    "previewed",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "timed_out",
    "rejected",
    "expired",
)
# Vivas: una vista previa pendiente de confirmar o una ejecución en curso.
ACTIVE_TOOL_STATUSES = frozenset({"previewed", "running"})
ACTIVE_TOOL_PREDICATE = "status IN ('previewed', 'running')"
TOOL_INVOKERS = ("user",)


class ToolExecution(Base):
    __tablename__ = "tool_executions"
    __table_args__ = (
        CheckConstraint(
            "status IN (" + ", ".join(f"'{s}'" for s in TOOL_EXECUTION_STATUSES) + ")",
            name="ck_tool_executions_status",
        ),
        CheckConstraint(
            "invoker IN (" + ", ".join(f"'{s}'" for s in TOOL_INVOKERS) + ")",
            name="ck_tool_executions_invoker",
        ),
        # Historial global (más recientes primero) y por usuario, herramienta, activo y caso.
        Index("ix_tool_executions_created", "created_at"),
        Index("ix_tool_executions_actor", "actor_user_id", "created_at"),
        Index("ix_tool_executions_tool", "tool_id", "created_at"),
        Index("ix_tool_executions_asset", "asset_id", "created_at"),
        Index(
            "ix_tool_executions_incident",
            "incident_id",
            postgresql_where=text("incident_id IS NOT NULL"),
        ),
        Index("ix_tool_executions_site", "site_id", postgresql_where=text("site_id IS NOT NULL")),
        Index(
            "ix_tool_executions_response",
            "response_execution_id",
            postgresql_where=text("response_execution_id IS NOT NULL"),
        ),
        Index(
            "ix_tool_executions_approver",
            "approved_by_user_id",
            postgresql_where=text("approved_by_user_id IS NOT NULL"),
        ),
        # Barrido de plazos (vistas previas caducadas, ejecuciones interrumpidas) y conteo de
        # concurrencia: solo filas vivas, la tabla completa puede ser enorme.
        Index(
            "ix_tool_executions_active",
            "status",
            "deadline_at",
            postgresql_where=text(ACTIVE_TOOL_PREDICATE),
        ),
        # Anti-duplicado: la misma petición del mismo usuario mientras la primera sigue en
        # curso (doble clic, reintento del navegador) devuelve la primera.
        Index(
            "uq_tool_executions_running_dedupe",
            "actor_user_id",
            "tool_id",
            "input_sha256",
            unique=True,
            postgresql_where=text("status = 'running'"),
        ),
        # Clave de idempotencia del cliente: repetir la petición devuelve la misma ejecución.
        Index(
            "uq_tool_executions_idempotency",
            "actor_user_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # Correlación con logs, auditoría y la ejecución de Response en la que se delegue.
    correlation_id: Mapped[uuid.UUID] = mapped_column(Uuid, default=uuid.uuid4)
    tool_id: Mapped[str] = mapped_column(String(64))
    tool_version: Mapped[int] = mapped_column(Integer)
    category: Mapped[str] = mapped_column(String(16))
    risk_level: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    invoker: Mapped[str] = mapped_column(String(16), default="user")
    actor: Mapped[str] = mapped_column(String(64))
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    input: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    input_sha256: Mapped[str] = mapped_column(String(64))
    output: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    output_sha256: Mapped[str | None] = mapped_column(String(64))
    output_bytes: Mapped[int | None] = mapped_column(Integer)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    summary: Mapped[str | None] = mapped_column(String(500))
    evidence: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB)
    provenance: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(String(500))
    # Objetivo copiado (id público y nombre) para leer el historial aunque se borre después.
    target_type: Mapped[str | None] = mapped_column(String(16))
    target_public_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    target_label: Mapped[str | None] = mapped_column(String(255))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    # Ejecución del Response Engine en la que delegó una herramienta de acción/investigación.
    response_execution_id: Mapped[int | None] = mapped_column(
        ForeignKey("response_executions.id", ondelete="SET NULL")
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(64))
    # Aprobación humana de una acción: quién confirmó la vista previa y cuándo.
    approved_by: Mapped[str | None] = mapped_column(String(64))
    approved_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approval_note: Mapped[str | None] = mapped_column(String(500))
    cancelled_by: Mapped[str | None] = mapped_column(String(64))
    # PID del backend de PostgreSQL que ejecuta la consulta: permite cancelarla de verdad
    # (pg_cancel_backend) desde otra petición mientras la ejecución está running.
    backend_pid: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Plazo: fin de la ejecución (running) o caducidad de la vista previa (previewed).
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    # Concurrencia optimista de confirmar y cancelar.
    version: Mapped[int] = mapped_column(Integer, default=1)
