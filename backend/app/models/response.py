"""Response Engine y Playbooks (Fase 5D, docs/response-engine.md).

Cinco tablas, todas evidencia SOC que no se borra por defecto:
- response_executions: cada petición de una acción del catálogo (manual o paso de playbook),
  con su actor, objetivo, parámetros saneados, estado y resultado acotado;
- agent_commands: la parte de protocolo de las acciones que ejecuta un agente. Un comando
  pertenece a un agente concreto (agent_id) y a un activo concreto: solo ese par lo recibe;
- playbooks y playbook_versions: definiciones declarativas (pasos = acciones del catálogo).
  Cada cambio crea una versión inmutable;
- playbook_runs: una ejecución de playbook con la copia exacta de los pasos que usó, para
  que editar el playbook después no cambie el historial.

Nunca se guarda un token, hash, contraseña ni comando de shell: no existe ningún campo donde
pudiera ir uno (las acciones son tipos cerrados, ver app/response/catalog.py).
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
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

# Estados de una ejecución. "approval_required" queda reservado para acciones HIGH/CRITICAL
# futuras con aprobación separada: en 5D ninguna acción del catálogo lo usa.
EXECUTION_STATUSES = (
    "pending",
    "approval_required",
    "queued",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "timed_out",
    "blocked",
)
ACTIVE_EXECUTION_STATUSES = frozenset({"pending", "approval_required", "queued", "running"})
TERMINAL_EXECUTION_STATUSES = frozenset(
    {"succeeded", "failed", "cancelled", "timed_out", "blocked"}
)
# Predicado de los índices parciales "solo ejecuciones vivas" (dedupe y barrido).
ACTIVE_PREDICATE = "status IN ('pending', 'approval_required', 'queued', 'running')"

COMMAND_STATUSES = ("queued", "delivered", "completed", "failed", "expired", "cancelled")
COMMAND_OPEN_STATUSES = frozenset({"queued", "delivered"})

RUN_STATUSES = ("running", "succeeded", "failed", "cancelled", "blocked")
ACTIVE_RUN_STATUSES = frozenset({"running"})


class ResponseExecution(Base):
    __tablename__ = "response_executions"
    __table_args__ = (
        # Historial por activo (Asset Detail → Response) y conteo de activas por activo.
        Index("ix_response_executions_asset", "asset_id", "created_at"),
        Index(
            "ix_response_executions_incident",
            "incident_id",
            postgresql_where=text("incident_id IS NOT NULL"),
        ),
        # Fase 6E.6: recogidas forenses de una investigación.
        Index(
            "ix_response_executions_investigation",
            "investigation_id",
            postgresql_where=text("investigation_id IS NOT NULL"),
        ),
        Index(
            "ix_response_executions_actor",
            "actor_user_id",
            postgresql_where=text("actor_user_id IS NOT NULL"),
        ),
        # Un paso de un playbook tiene como mucho una ejecución: si dos procesos avanzan el
        # mismo run a la vez (job de barrido y resultado de un agente), el segundo choca aquí
        # y abandona en vez de ejecutar el paso dos veces.
        Index(
            "uq_response_executions_run_step",
            "playbook_run_id",
            "step_index",
            unique=True,
            postgresql_where=text("playbook_run_id IS NOT NULL"),
        ),
        # Listado global del historial (más recientes primero, paginado).
        Index("ix_response_executions_created", "created_at"),
        # Barrido de plazos vencidos: solo filas vivas, la tabla completa puede ser enorme.
        Index(
            "ix_response_executions_deadline",
            "deadline_at",
            postgresql_where=text(ACTIVE_PREDICATE),
        ),
        # Anti-duplicado: dos peticiones iguales simultáneas (doble clic, reintento del
        # navegador) no crean dos ejecuciones vivas de la misma acción sobre el mismo objetivo.
        # La segunda choca con este índice y recibe la primera (services/response_service.py).
        Index(
            "uq_response_executions_active_dedupe",
            "dedupe_key",
            unique=True,
            postgresql_where=text(f"dedupe_key IS NOT NULL AND {ACTIVE_PREDICATE}"),
        ),
        # Clave de idempotencia del cliente (una por diálogo de confirmación en la UI): repetir
        # la misma petición devuelve la misma ejecución, esté viva o terminada.
        Index(
            "uq_response_executions_idempotency",
            "actor_user_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # Identificador de correlación de la acción en logs, auditoría y protocolo del agente.
    correlation_id: Mapped[uuid.UUID] = mapped_column(Uuid, default=uuid.uuid4)
    action_id: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20))
    risk_level: Mapped[str] = mapped_column(String(16))
    requires_agent: Mapped[bool] = mapped_column(Boolean, default=False)
    # "asset" o "incident". El objetivo se copia (id público y nombre) para que el historial
    # se lea aunque el activo se borre después (las FK pasan a NULL, la fila se conserva).
    target_type: Mapped[str] = mapped_column(String(16))
    target_public_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    target_label: Mapped[str] = mapped_column(String(255))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    # Incidente objetivo o de contexto (ejecución lanzada desde un caso): trazabilidad.
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    # Fase 6E.6: investigación forense a la que pertenece la recogida (acciones forensic_*).
    investigation_id: Mapped[int | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="SET NULL")
    )
    # Detección de contexto (botón Investigar). Solo el id público: es una referencia.
    detection_public_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    # Agente al que va dirigido el comando (el actual del activo al crear la ejecución).
    agent_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    # Parámetros ya validados por el modelo de la acción (sin texto libre fuera de los
    # campos acotados que la acción declara).
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # Resultado estructurado y acotado (RESPONSE_RESULT_MAX_KB): {"summary", "data"}.
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    result_summary: Mapped[str | None] = mapped_column(String(500))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(String(500))
    # Bloqueos de la política en el momento de crearla (status blocked), para el historial.
    blockers: Mapped[list[dict[str, str]] | None] = mapped_column(JSONB)
    actor: Mapped[str] = mapped_column(String(64))
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    reason: Mapped[str | None] = mapped_column(String(500))
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(64))
    dedupe_key: Mapped[str | None] = mapped_column(String(200))
    playbook_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("playbook_runs.id", ondelete="SET NULL")
    )
    step_index: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Plazo total: al vencer, una ejecución viva pasa a timed_out (nunca queda "running").
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Concurrencia optimista de cancelar.
    version: Mapped[int] = mapped_column(Integer, default=1)


class AgentCommand(Base):
    """Comando estructurado para un agente: tipo allowlisted y parámetros validados.

    Nunca lleva un comando de shell ni un script: el agente solo conoce un conjunto cerrado
    de tipos (agent/sentra_agent/commands.py) y rechaza cualquier otro.
    """

    __tablename__ = "agent_commands"
    __table_args__ = (
        # Entrega: comandos en cola de un activo (el agente pregunta por los suyos).
        Index("ix_agent_commands_asset_status", "asset_id", "status", "created_at"),
        Index("ix_agent_commands_execution", "execution_id"),
        # Barrido de TTL y leases: solo comandos abiertos.
        Index(
            "ix_agent_commands_open",
            "status",
            "expires_at",
            postgresql_where=text("status IN ('queued', 'delivered')"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # Lo que ve el agente: aleatorio, de un solo uso y ligado a (agente, activo).
    request_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    execution_id: Mapped[int] = mapped_column(
        ForeignKey("response_executions.id", ondelete="CASCADE")
    )
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    agent_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    command_type: Mapped[str] = mapped_column(String(48))
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # TTL obligatorio: un comando no recogido antes de esta hora caduca.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivery_count: Mapped[int] = mapped_column(Integer, default=0)
    max_deliveries: Mapped[int] = mapped_column(Integer, default=1)


class Playbook(Base):
    __tablename__ = "playbooks"
    __table_args__ = (
        Index(
            "ix_playbooks_created_by",
            "created_by_user_id",
            postgresql_where=text("created_by_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # Identificador estable ("investigate_endpoint" en los built-in).
    key: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(String(1000))
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    risk_level: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[str] = mapped_column(String(64))
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Concurrencia optimista de editar/activar/desactivar.
    revision: Mapped[int] = mapped_column(Integer, default=1)


class PlaybookVersion(Base):
    """Versión inmutable de un playbook: nunca se edita, editar crea la siguiente."""

    __tablename__ = "playbook_versions"
    __table_args__ = (Index("uq_playbook_versions", "playbook_id", "version", unique=True),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    playbook_id: Mapped[int] = mapped_column(ForeignKey("playbooks.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(String(1000))
    # [{"order", "action_id", "parameters", "on_success", "on_failure", "timeout_seconds"}]
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    risk_level: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    __table_args__ = (
        Index("ix_playbook_runs_playbook", "playbook_id", "created_at"),
        Index("ix_playbook_runs_asset", "asset_id", "created_at"),
        Index(
            "ix_playbook_runs_incident",
            "incident_id",
            postgresql_where=text("incident_id IS NOT NULL"),
        ),
        Index(
            "ix_playbook_runs_actor",
            "actor_user_id",
            postgresql_where=text("actor_user_id IS NOT NULL"),
        ),
        Index("ix_playbook_runs_active", "status", postgresql_where=text("status = 'running'")),
        Index("ix_playbook_runs_created", "created_at"),
        Index(
            "uq_playbook_runs_active_dedupe",
            "dedupe_key",
            unique=True,
            postgresql_where=text("dedupe_key IS NOT NULL AND status = 'running'"),
        ),
        Index(
            "uq_playbook_runs_idempotency",
            "actor_user_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    playbook_id: Mapped[int | None] = mapped_column(ForeignKey("playbooks.id", ondelete="SET NULL"))
    # Copia de lo que se ejecutó: clave, nombre, versión y pasos exactos.
    playbook_key: Mapped[str] = mapped_column(String(64))
    playbook_name: Mapped[str] = mapped_column(String(120))
    playbook_version: Mapped[int] = mapped_column(Integer)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    risk_level: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    # Índice (0..n-1) del paso actual; == len(steps) al terminar con éxito.
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    target_public_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    target_label: Mapped[str] = mapped_column(String(255))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    detection_public_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor: Mapped[str] = mapped_column(String(64))
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    reason: Mapped[str | None] = mapped_column(String(500))
    idempotency_key: Mapped[str | None] = mapped_column(String(64))
    dedupe_key: Mapped[str | None] = mapped_column(String(200))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, default=1)
