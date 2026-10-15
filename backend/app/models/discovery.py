import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.site import DEFAULT_SITE_SQL


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
    # Fase 5F: job de sensor que nadie empezó antes de su plazo.
    EXPIRED = "expired"
    # Fase 5F: el sensor cerró el job pero faltaban lotes de resultados (descartados por
    # el propio sensor). Se aplica como parcial: sin conclusiones negativas.
    INCOMPLETE = "incomplete"


class DiscoveryJob(Base):
    """One discovery run over one allowed network."""

    __tablename__ = "discovery_jobs"
    __table_args__ = (
        # At most one running job per network: a second scheduler, API worker or a manual
        # run started meanwhile is refused by the database instead of scanning twice.
        # Un job en cola cuenta como activo: reserva la red desde que se pide en la web.
        # Fase 5F: la red se reserva POR SITE. 192.168.1.0/24 de dos sites son redes distintas
        # que pueden escanearse a la vez (cada una por su sensor).
        Index(
            "uq_discovery_jobs_running_target",
            "site_id",
            "target",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
        Index("ix_discovery_jobs_started", "started_at"),
        Index("ix_discovery_jobs_site_started", "site_id", "started_at"),
        Index("ix_discovery_jobs_sensor", "sensor_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    target: Mapped[str] = mapped_column(String(64))
    # Fase 5F: site de la red escaneada (por defecto el local) y dónde se ejecuta: "local" (el
    # propio servidor, histórico) o "sensor" (un sensor del site, que sube observaciones).
    site_id: Mapped[int] = mapped_column(
        ForeignKey("sites.id", ondelete="RESTRICT"), server_default=text(DEFAULT_SITE_SQL)
    )
    execution_target: Mapped[str] = mapped_column(
        String(16), default="local", server_default="local"
    )
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
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
    # Fase 6A: perfil de Advanced Discovery (quick/standard/deep). Null = discovery básico
    # (comportamiento y parámetros anteriores a 6A, sin cambios).
    profile: Mapped[str | None] = mapped_column(String(16))

    @property
    def duration_seconds(self) -> float | None:
        # Un job en cola aún no ha empezado; started_at es la hora de la petición.
        if self.completed_at is None or self.status == DiscoveryJobStatus.QUEUED:
            return None
        return round((self.completed_at - self.started_at).total_seconds(), 3)


# Fase 6A: estado de reachability de una observación. "unknown" = no hay evidencia suficiente
# (nunca se convierte en "no existe").
REACHABILITY_VALUES = ("responded", "no_response", "unknown")
OBSERVATION_CHANGE_KINDS = (
    "new_host",
    "host_unresponsive",
    "port_new",
    "port_unresponsive",
    "hostname_changed",
    "address_changed",
)


class DiscoveryObservation(Base):
    """Lo que UN job vio (o no vio) en UNA dirección, con procedencia (Fase 6A).

    Mismo formato para el discovery del servidor y para el de un sensor: el servidor sigue
    siendo la autoridad sobre identidad (asset_id lo decide ResultApplier) y esto es solo
    evidencia auditable. Una fila "no_response" registra que un activo conocido no respondió
    en un scan COMPLETO; no es una desaparición (eso sigue siendo network_misses y la política
    de ciclo de vida) ni dice nada de compromiso o vulnerabilidad.

    (job, address) único: un reintento del mismo job nunca duplica la evidencia.
    """

    __tablename__ = "discovery_observations"
    __table_args__ = (
        UniqueConstraint("job_id", "address", name="uq_discovery_observations_job_address"),
        # Vista de red (última observación por site e IP) y filtros por site.
        Index("ix_discovery_observations_site_address", "site_id", "address", "observed_at"),
        Index("ix_discovery_observations_asset", "asset_id", "observed_at"),
        Index("ix_discovery_observations_sensor", "sensor_id"),
        Index("ix_discovery_observations_observed", "observed_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    job_id: Mapped[int] = mapped_column(ForeignKey("discovery_jobs.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    # "local" (el propio servidor) o "sensor". sensor_id se conserva aunque el sensor se
    # revoque; SET NULL solo si alguna vez se borra la fila del sensor.
    executor: Mapped[str] = mapped_column(String(16))
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    # Activo al que el servidor asoció la observación. SET NULL: borrar un activo descubierto
    # (limpieza 5C.2) no borra la evidencia histórica de lo que se vio en la red.
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    address: Mapped[str] = mapped_column(String(45))
    mac: Mapped[str | None] = mapped_column(String(17))
    hostname: Mapped[str | None] = mapped_column(String(255))
    reverse_dns: Mapped[str | None] = mapped_column(String(255))
    forward_dns_match: Mapped[bool | None] = mapped_column(Boolean)
    open_ports: Mapped[list[int]] = mapped_column(JSONB)
    # Métodos que aportaron evidencia: icmp, tcp, arp, dns.
    methods: Mapped[list[str]] = mapped_column(JSONB)
    reachability: Mapped[str] = mapped_column(String(16))
    rtt_ms: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[str] = mapped_column(String(8))
    # [{"field", "value", "method", "state": "observed"|"inferred"}], acotado.
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    # [{"kind", "previous", "current", "state"}]: diferencias con la observación anterior del
    # mismo activo. Evidencia de cambio, no el motor de Network Change Detection (Fase 6E).
    changes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    profile: Mapped[str | None] = mapped_column(String(16))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
