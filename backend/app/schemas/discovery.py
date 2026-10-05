from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from app.models.asset import MonitoringMethod
from app.models.change import ChangeCategory, ChangeKind
from app.models.discovery import DiscoveryJobStatus, DiscoveryTrigger
from app.models.exposure import PortStateValue
from app.schemas.common import RequestModel, ResponseModel


class DiscoveryNetworkRead(ResponseModel):
    """Una red autorizada y cuántas direcciones se sondearían en ella (sin exclusiones)."""

    network: str
    hosts: int


class DiscoveryScopeRead(ResponseModel):
    """What discovery may probe (configuration, read-only)."""

    enabled: bool
    allowed_networks: list[str]
    # Mismo orden que allowed_networks, con el alcance real de cada una.
    networks: list[DiscoveryNetworkRead]
    max_hosts_per_network: int
    excluded: list[str]
    ports: list[int]
    interval_minutes: int | None
    icmp: bool
    reverse_dns: bool
    timeout_ms: int
    concurrency: int
    max_probes_per_second: int


class DiscoveryProgressRead(ResponseModel):
    """Fase del scan en curso. Solo "liveness" tiene un total exacto (hosts_total); en
    "details" el total son los hosts vivos encontrados. No hay porcentaje global."""

    phase: str
    details_total: int = 0
    details_done: int = 0


class DiscoveryJobRead(ResponseModel):
    job_id: UUID
    target: str
    trigger: DiscoveryTrigger
    status: DiscoveryJobStatus
    baseline: bool
    # Hora de inicio del scan; mientras está en cola, hora de la petición.
    started_at: datetime
    completed_at: datetime | None
    duration_seconds: float | None
    # Durante el scan avanzan hosts_scanned (evaluados) y hosts_alive (encontrados).
    hosts_scanned: int
    hosts_alive: int
    hosts_new: int
    open_ports: int
    probes: int
    error_count: int
    errors: list[str]
    # --- Fase 4D (aditivo) ---
    # "dashboard", "cli" o "scheduler"; null en jobs anteriores.
    requested_via: str | None
    hosts_total: int
    # Activos ya conocidos vistos en este job; null hasta que termina.
    hosts_updated: int | None
    ports_opened: int
    ports_closed: int
    cancel_requested: bool
    # operator, shutdown, timeout, interrupted o error cuando no fue un scan completo.
    stop_reason: str | None
    progress: DiscoveryProgressRead | None
    # Perfil usado: puertos, timeout, concurrencia, ICMP, DNS inverso.
    parameters: dict[str, Any] | None


class DiscoveryJobList(ResponseModel):
    items: list[DiscoveryJobRead]


class DiscoveryAssetRef(ResponseModel):
    asset_id: UUID
    display_name: str
    primary_ip: str
    mac_address: str | None
    device_type: str | None
    monitoring_method: MonitoringMethod


class DiscoveryChangeRead(ResponseModel):
    asset_id: UUID
    display_name: str
    primary_ip: str
    category: ChangeCategory
    kind: ChangeKind
    item: str
    detected_at: datetime


class DiscoveryJobDetail(DiscoveryJobRead):
    """Un job con lo que cambió: activos nuevos y cambios de red/exposición que detectó."""

    new_assets: list[DiscoveryAssetRef]
    changes: list[DiscoveryChangeRead]


class DiscoveryJobCreate(RequestModel):
    # Una red de DISCOVERY_ALLOWED_NETWORKS (o una subred suya). El backend la valida con
    # la misma allowlist que la CLI; la lista desplegable del frontend no es una garantía.
    target: str = Field(min_length=1, max_length=64)


class DiscoveryScheduleRead(ResponseModel):
    """Estado del descubrimiento automático (solo lectura: se configura con variables de
    entorno del servidor)."""

    enabled: bool
    # Por qué está apagado: no_networks, no_interval o background_jobs_disabled.
    disabled_reason: str | None
    interval_minutes: int | None
    last_run_at: datetime | None
    last_run_status: DiscoveryJobStatus | None
    # Estimación de este proceso de la API; null si no hay programación o está ejecutando.
    next_run_at: datetime | None
    running: bool


class PortProcess(ResponseModel):
    """The agent's view of who listens on a port (correlation with its inventory)."""

    pid: int | None
    name: str | None
    exe: str | None
    username: str | None
    local_address: str | None


class ExposedPort(ResponseModel):
    protocol: str
    port: int
    state: PortStateValue
    service_hint: str | None
    # Remote administration, file sharing or database port.
    sensitive: bool
    first_seen_at: datetime
    opened_at: datetime
    last_seen_at: datetime
    closed_at: datetime | None
    process: PortProcess | None


class AgentListener(ResponseModel):
    """A port the agent reports listening on, and whether the network can reach it."""

    protocol: str
    port: int
    process: PortProcess
    # True: reachable from the Sentra server; False: probed and not reachable (firewall or
    # bound to localhost); null: the port is not in DISCOVERY_PORTS, never probed.
    exposed: bool | None


class ExposureRead(ResponseModel):
    asset_id: UUID
    baseline_at: datetime | None
    last_network_seen_at: datetime | None
    ports: list[ExposedPort]
    agent_listeners: list[AgentListener]
