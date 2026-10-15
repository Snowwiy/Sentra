from datetime import datetime
from typing import Any, Literal
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
    # --- Fase 5F (aditivo) ---
    site_id: UUID
    site_name: str
    # "local": lo ejecuta el propio servidor; "sensor": un sensor del site.
    execution_target: Literal["local", "sensor"]
    sensor_id: UUID | None
    sensor_name: str | None
    # Fase 6A. profile null = discovery básico (anterior a 6A).
    profile: Literal["quick", "standard", "deep"] | None = None
    job_type: Literal["discovery_basic", "discovery_advanced"] = "discovery_basic"
    # Filas de observación del job (incluidas las "no_response") y activos conocidos que no
    # respondieron en un scan completo (evidencia, no desaparición).
    observations_total: int = 0
    hosts_unresponsive: int = 0


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
    # Fase 5F. Sin site: el site por defecto. "local" solo existe en el site por defecto
    # (DISCOVERY_ALLOWED_NETWORKS del servidor); "sensor" exige sensor_id del mismo site y un
    # target dentro de una red habilitada de ese site.
    site_id: UUID | None = None
    execution_target: Literal["local", "sensor"] = "local"
    sensor_id: UUID | None = None
    # Fase 6A. Sin profile: discovery básico de siempre (ports/limits no se admiten).
    profile: Literal["quick", "standard", "deep"] | None = None
    # Subconjunto de los puertos del perfil; fuera del perfil exige discovery:tune. El tope
    # real (HARD_MAX_PORTS) lo aplica el servicio; este solo evita listas absurdas.
    ports: list[int] | None = Field(default=None, max_length=1024)
    limits: "DiscoveryLimitsIn | None" = None


class DiscoveryLimitsIn(RequestModel):
    """Ajustes por job (solo discovery:tune). Los topes del servidor los aplica el servicio."""

    timeout_ms: int | None = Field(default=None, ge=50, le=120_000)
    dns_timeout_ms: int | None = Field(default=None, ge=50, le=120_000)
    concurrency: int | None = Field(default=None, ge=1, le=4096)
    max_probes_per_second: int | None = Field(default=None, ge=1, le=100_000)
    tcp_retries: int | None = Field(default=None, ge=0, le=10)
    max_hosts: int | None = Field(default=None, ge=1, le=1 << 20)
    deadline_minutes: int | None = Field(default=None, ge=1, le=1440)


class DiscoveryLimitsRead(ResponseModel):
    timeout_ms: int
    dns_timeout_ms: int
    concurrency: int
    max_probes_per_second: int
    tcp_retries: int
    max_hosts: int
    max_ports: int
    deadline_minutes: int
    max_dns_queries: int


class DiscoveryProfileRead(ResponseModel):
    name: Literal["quick", "standard", "deep"]
    label: str
    description: str
    ports: list[int]
    icmp: bool
    tcp: bool
    arp: bool
    reverse_dns: bool
    forward_dns: bool
    limits: DiscoveryLimitsRead


class DiscoveryProfilesRead(ResponseModel):
    default_profile: str
    can_tune: bool
    caps: DiscoveryLimitsRead
    profiles: list[DiscoveryProfileRead]


class ObservationEvidence(ResponseModel):
    field: str
    value: Any
    method: str
    state: Literal["observed", "inferred"]


class ObservationChange(ResponseModel):
    kind: str
    previous: str | None
    current: str | None
    state: Literal["observed", "inferred"]


class PortHint(ResponseModel):
    port: int
    hint: str
    # Siempre "inferred": el número de puerto sugiere un servicio, no lo confirma.
    state: Literal["inferred"] = "inferred"


class ObservationRead(ResponseModel):
    observation_id: UUID
    job_id: UUID
    site_id: UUID
    site_name: str
    executor: Literal["local", "sensor"]
    sensor_id: UUID | None
    sensor_name: str | None
    asset_id: UUID | None
    address: str
    mac: str | None
    hostname: str | None
    reverse_dns: str | None
    forward_dns_match: bool | None
    open_ports: list[int]
    port_hints: list[PortHint]
    methods: list[str]
    reachability: Literal["responded", "no_response", "unknown"]
    rtt_ms: int | None
    confidence: Literal["low", "medium", "high"]
    evidence: list[ObservationEvidence]
    changes: list[ObservationChange]
    profile: str | None
    observed_at: datetime


class ObservationList(ResponseModel):
    items: list[ObservationRead]
    total: int
    limit: int
    offset: int


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


DiscoveryJobCreate.model_rebuild()
