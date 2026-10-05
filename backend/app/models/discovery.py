import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, Enum, Index, Integer, String, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class DiscoveryJobStatus(enum.StrEnum):
    # Creado desde el dashboard y esperando al runner del proceso de la API.
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    # Stopped early (operator, shutdown, deadline): results are partial.
    CANCELLED = "cancelled"
    FAILED = "failed"


class DiscoveryTrigger(enum.StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"


# Estados en los que un job ocupa su red (índice único parcial y cancelación).
ACTIVE_JOB_STATUSES = (DiscoveryJobStatus.QUEUED, DiscoveryJobStatus.RUNNING)


class DiscoveryStopReason(enum.StrEnum):
    """Por qué un job terminó sin ser un scan completo (texto en stop_reason)."""

    OPERATOR = "operator"
    SHUTDOWN = "shutdown"
    TIMEOUT = "timeout"
    # El proceso que lo ejecutaba dejó de dar señales de vida (caída, kill).
    INTERRUPTED = "interrupted"
    ERROR = "error"


class DiscoveryJob(Base):
    """One discovery run over one allowed network."""

    __tablename__ = "discovery_jobs"
    __table_args__ = (
        # At most one running job per network: a second scheduler, API worker or a manual
        # run started meanwhile is refused by the database instead of scanning twice.
        # Un job en cola cuenta como activo: reserva la red desde que se pide en la web.
        Index(
            "uq_discovery_jobs_running_target",
            "target",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
        Index("ix_discovery_jobs_started", "started_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    target: Mapped[str] = mapped_column(String(64))
    trigger: Mapped[DiscoveryTrigger] = mapped_column(
        Enum(
            DiscoveryTrigger,
            name="discovery_trigger",
            values_callable=lambda members: [m.value for m in members],
        )
    )
    status: Mapped[DiscoveryJobStatus] = mapped_column(
        Enum(
            DiscoveryJobStatus,
            name="discovery_job_status",
            values_callable=lambda members: [m.value for m in members],
        ),
        default=DiscoveryJobStatus.RUNNING,
    )
    # First completed run of this network: it records the baseline and raises no
    # "new asset"/"new port" alerts.
    baseline: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hosts_scanned: Mapped[int] = mapped_column(Integer, default=0)
    hosts_alive: Mapped[int] = mapped_column(Integer, default=0)
    hosts_new: Mapped[int] = mapped_column(Integer, default=0)
    open_ports: Mapped[int] = mapped_column(Integer, default=0)
    probes: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    # First errors (bounded) for the operator.
    errors: Mapped[list[str] | None] = mapped_column(JSONB)
    # Ports, timeout and concurrency the run used.
    parameters: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Quién lo pidió: "dashboard", "cli" o "scheduler" (trigger sigue siendo manual/scheduled
    # por compatibilidad). Null en jobs anteriores a 0014.
    requested_via: Mapped[str | None] = mapped_column(String(16))
    # Direcciones a sondear (denominador del progreso); hosts_scanned avanza durante el scan.
    hosts_total: Mapped[int] = mapped_column(Integer, default=0)
    ports_opened: Mapped[int] = mapped_column(Integer, default=0)
    ports_closed: Mapped[int] = mapped_column(Integer, default=0)
    # La cancelación se pide en la base de datos y no en memoria: así funciona aunque la
    # petición llegue a otro worker de la API distinto del que ejecuta el scan.
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Latido del proceso que tiene el job; sin latido reciente el job se considera huérfano
    # y se marca como fallido para no bloquear la red para siempre.
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # DiscoveryStopReason cuando el resultado no es un scan completo.
    stop_reason: Mapped[str | None] = mapped_column(String(32))
    # Fase y contadores de la fase de detalle mientras corre (ver DiscoveryProgress).
    progress: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # public_id de los activos creados por este job (acotado), para "Ver dispositivos".
    new_asset_ids: Mapped[list[str] | None] = mapped_column(JSONB)

    @property
    def duration_seconds(self) -> float | None:
        # Un job en cola aún no ha empezado; started_at es la hora de la petición.
        if self.completed_at is None or self.status == DiscoveryJobStatus.QUEUED:
            return None
        return round((self.completed_at - self.started_at).total_seconds(), 3)
