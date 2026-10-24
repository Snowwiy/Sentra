"""Contratos de la API de sites y sensores (Fase 5F, docs/sites.md, docs/distributed-sensors.md).

Dos superficies separadas:
- dashboard (sesión + RBAC): sites, redes autorizadas, sensores, tokens de enrolamiento;
- protocolo del sensor (credencial Bearer propia): enroll, heartbeat, poll, start, results,
  complete y rotación. Todo lo que envía un sensor se valida aquí con límites estrictos: es
  un dato no confiable aunque venga autenticado.
"""

import ipaddress
import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from app.discovery.probes import normalize_mac
from app.schemas.common import RequestModel, ResponseModel
from app.schemas.network_protocol import SnmpJobCredentials, SnmpJobSummary, SnmpRecord

SiteStatus = Literal["active", "disabled", "archived"]
SensorStatus = Literal["pending", "online", "offline", "stale", "disabled", "revoked"]
VersionStatus = Literal["current", "outdated", "unsupported", "unknown"]
SensorJobStatus = Literal[
    "pending", "leased", "running", "succeeded", "failed", "cancelled", "expired"
]
SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}$"
# Texto de nombres y etiquetas: sin caracteres de control (se muestran en la UI y en informes).
_NAME = Field(min_length=1, max_length=100, pattern=r"^[^\x00-\x1f\x7f]+$")


# --- Sites -----------------------------------------------------------------------------------


class SiteRead(ResponseModel):
    site_id: UUID
    name: str
    slug: str
    description: str | None
    location_label: str | None
    timezone: str
    status: SiteStatus
    is_default: bool
    version: int
    created_at: datetime
    updated_at: datetime
    archived_at: datetime | None
    asset_count: int
    sensor_count: int
    network_count: int


class SiteList(ResponseModel):
    items: list[SiteRead]


class SiteCreate(RequestModel):
    name: str = _NAME
    slug: str | None = Field(default=None, pattern=SLUG_PATTERN)
    description: str | None = Field(default=None, max_length=500)
    location_label: str | None = Field(default=None, max_length=200)
    timezone: str = Field(default="UTC", min_length=1, max_length=64)


class SiteUpdate(RequestModel):
    version: int = Field(ge=1)
    name: str | None = Field(
        default=None, min_length=1, max_length=100, pattern=r"^[^\x00-\x1f\x7f]+$"
    )
    description: str | None = Field(default=None, max_length=500)
    location_label: str | None = Field(default=None, max_length=200)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    # Archivar tiene su propio endpoint (con motivo); aquí solo activar o deshabilitar.
    status: Literal["active", "disabled"] | None = None


class SiteArchive(RequestModel):
    version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=500)


class SiteVersion(RequestModel):
    version: int = Field(ge=1)


class SiteNetworkRead(ResponseModel):
    network_id: UUID
    site_id: UUID
    cidr: str
    name: str | None
    enabled: bool
    host_count: int
    created_at: datetime
    updated_at: datetime


class SiteNetworkList(ResponseModel):
    items: list[SiteNetworkRead]


class SiteNetworkCreate(RequestModel):
    cidr: str = Field(min_length=3, max_length=64)
    name: str | None = Field(default=None, min_length=1, max_length=100)
    enabled: bool = True


class SiteNetworkUpdate(RequestModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    enabled: bool | None = None


class AssetSiteChange(RequestModel):
    site_id: UUID
    reason: str = Field(min_length=1, max_length=500)
    # lifecycle_version del activo (misma concurrencia optimista que archivar/reconciliar).
    version: int = Field(ge=0)


# --- Sensores (dashboard) ---------------------------------------------------------------------


class SensorJobRead(ResponseModel):
    job_id: UUID
    site_id: UUID
    sensor_id: UUID
    job_type: str
    status: SensorJobStatus
    attempt: int
    max_attempts: int
    created_at: datetime
    created_by: str
    expires_at: datetime
    leased_at: datetime | None
    lease_expires_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    error_code: str | None
    discovery_job_id: UUID | None
    target: str | None
    observations_received: int
    batches_received: int


class SensorJobList(ResponseModel):
    items: list[SensorJobRead]


class SensorRead(ResponseModel):
    sensor_id: UUID
    name: str
    site_id: UUID
    site_name: str
    status: SensorStatus
    hostname: str | None
    platform: str | None
    sensor_version: str | None
    version_status: VersionStatus
    capabilities: list[str]
    last_seen_at: datetime | None
    enrolled_at: datetime
    created_at: datetime
    disabled_at: datetime | None
    revoked_at: datetime | None
    revoke_reason: str | None
    rotation_pending: bool
    credential_issued_at: datetime | None
    queue_depth: int | None
    spool_items: int | None
    uptime_seconds: int | None
    last_successful_job_at: datetime | None
    clock_skew_seconds: int | None
    pending_jobs: int
    last_job: SensorJobRead | None
    version: int


class SensorSummary(ResponseModel):
    total: int
    pending: int
    online: int
    offline: int
    stale: int
    disabled: int
    revoked: int


class SensorList(ResponseModel):
    items: list[SensorRead]
    summary: SensorSummary


class SensorAction(RequestModel):
    version: int = Field(ge=1)


class SensorRevoke(RequestModel):
    version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=500)


class SensorEnrollmentCreate(RequestModel):
    site_id: UUID
    name: str = _NAME
    ttl_minutes: int | None = Field(default=None, ge=5, le=1440)


class SensorEnrollmentRead(ResponseModel):
    enrollment_id: UUID
    site_id: UUID
    site_name: str
    name: str
    state: Literal["active", "consumed", "expired", "revoked"]
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None
    sensor_id: UUID | None
    created_by: str


class SensorEnrollmentCreated(SensorEnrollmentRead):
    # Se devuelve UNA vez; el servidor solo guarda su SHA-256.
    token: str
    command_example: str


class SensorEnrollmentList(ResponseModel):
    items: list[SensorEnrollmentRead]


# --- Protocolo del sensor ------------------------------------------------------------------

Capability = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.]+$")


class SensorConfig(ResponseModel):
    """Configuración autorizada que el servidor impone al sensor (el sensor no la decide)."""

    site_id: UUID
    site_name: str
    allowed_networks: list[str]
    jobs_enabled: bool
    heartbeat_interval_seconds: int
    poll_interval_seconds: int
    max_observations_per_batch: int
    max_batch_bytes: int
    max_ports_per_observation: int
    max_hosts_per_job: int
    max_concurrency: int
    max_probes_per_second: int
    max_timeout_ms: int
    # Fase 6A: topes de discovery_advanced (los sensores 0.1.x ignoran estas claves).
    advanced_max_timeout_ms: int
    max_dns_timeout_ms: int
    max_tcp_retries: int
    max_dns_queries: int
    advanced_max_ports: int
    max_deadline_seconds: int


class SensorEnrollRequest(RequestModel):
    hostname: str = Field(min_length=1, max_length=255, pattern=r"^[^\x00-\x1f\x7f]+$")
    platform: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9 ._-]+$")
    sensor_version: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9._+-]+$")
    capabilities: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("capabilities")
    @classmethod
    def _capabilities(cls, value: list[str]) -> list[str]:
        return _check_capabilities(value)


def _check_capabilities(value: list[str]) -> list[str]:
    for item in value:
        if not re.fullmatch(r"[a-z0-9_.]{1,64}", item):
            raise ValueError("invalid capability name")
    return value


class SensorEnrollResponse(ResponseModel):
    sensor_id: UUID
    site_id: UUID
    site_name: str
    credential: str
    credential_issued_at: datetime
    config: SensorConfig


class SensorHeartbeatRequest(RequestModel):
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    platform: str | None = Field(default=None, min_length=1, max_length=32)
    sensor_version: str | None = Field(
        default=None, min_length=1, max_length=32, pattern=r"^[A-Za-z0-9._+-]+$"
    )
    capabilities: list[str] | None = Field(default=None, max_length=32)
    queue_depth: int | None = Field(default=None, ge=0, le=10_000_000)
    spool_items: int | None = Field(default=None, ge=0, le=10_000_000)
    spool_bytes: int | None = Field(default=None, ge=0, le=2**40)
    uptime_seconds: int | None = Field(default=None, ge=0, le=10 * 365 * 86_400)
    last_successful_job_at: AwareDatetime | None = None
    sent_at: AwareDatetime | None = None

    @field_validator("capabilities")
    @classmethod
    def _capabilities(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _check_capabilities(value)


class SensorHeartbeatResponse(ResponseModel):
    sensor_id: UUID
    site_id: UUID
    status: Literal["active", "disabled"]
    server_time: datetime
    version_status: VersionStatus
    rotate_credential: bool
    pending_jobs: int
    cancel_job_ids: list[UUID]
    config: SensorConfig


class SensorPollRequest(RequestModel):
    max_jobs: int = Field(default=1, ge=1, le=5)


class SensorJobOut(ResponseModel):
    job_id: UUID
    site_id: UUID
    sensor_id: UUID
    job_type: str
    parameters: dict[str, object]
    created_at: datetime
    expires_at: datetime
    lease_expires_at: datetime
    attempt: int
    idempotency_key: str


class SensorPollResponse(ResponseModel):
    jobs: list[SensorJobOut]
    config: SensorConfig


class SensorJobStart(RequestModel):
    attempt: int = Field(ge=1, le=100)


class SensorJobStarted(ResponseModel):
    job_id: UUID
    status: Literal["running"]
    lease_expires_at: datetime
    # Fase 6B: solo en jobs snmp_inventory. Los sensores anteriores nunca reciben esos jobs
    # y para ellos la clave es siempre null.
    credentials: SnmpJobCredentials | None = None


class PortObservation(RequestModel):
    port: int = Field(ge=1, le=65535)
    state: Literal["open", "closed", "filtered"]


# Corrección 6C: texto que publica un dispositivo ajeno (UPnP, SSDP). Imprimible y acotado
# igual que en el discovery local (app/discovery/names.py: MAX_TEXT, clean_text).
_DEVICE_TEXT = r"^[^\x00-\x1f\x7f]{1,128}$"
_DEVICE_NAME = r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}$"


class SensorUpnpIn(RequestModel):
    friendly_name: str | None = Field(default=None, pattern=_DEVICE_TEXT)
    manufacturer: str | None = Field(default=None, pattern=_DEVICE_TEXT)
    model_name: str | None = Field(default=None, pattern=_DEVICE_TEXT)
    model_number: str | None = Field(default=None, pattern=_DEVICE_TEXT)
    device_type: str | None = Field(default=None, pattern=_DEVICE_TEXT)


class SensorIdentityIn(RequestModel):
    """Nombres que el host publica de sí mismo, vistos por el sensor (discovery_advanced v2).

    Mismo contenido que guardan las sondas locales en identity_observations: el servidor los
    interpreta con el mismo motor (app/discovery/classify.py). El sensor nunca envía
    clasificaciones, solo lo observado.
    """

    mdns_name: str | None = Field(default=None, pattern=_DEVICE_NAME)
    netbios_name: str | None = Field(default=None, pattern=_DEVICE_NAME, max_length=15)
    ssdp_server: str | None = Field(default=None, pattern=_DEVICE_TEXT)
    upnp: SensorUpnpIn | None = None


class ObservationIn(RequestModel):
    address: str = Field(min_length=2, max_length=45)
    mac: str | None = Field(default=None, max_length=17)
    hostname: str | None = Field(
        default=None, min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._-]+$"
    )
    reverse_dns: str | None = Field(
        default=None, min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._-]+$"
    )
    ports: list[PortObservation] = Field(default_factory=list)
    sources: list[Literal["icmp", "tcp", "arp"]] = Field(default_factory=list, max_length=3)
    # Fase 6A (discovery_advanced): tiempo de TCP connect medido y confirmación del DNS
    # inverso con una consulta directa. Opcionales: un sensor 0.1.x no los envía.
    rtt_ms: int | None = Field(default=None, ge=0, le=120_000)
    forward_dns_match: bool | None = None
    # Corrección 6C (discovery_advanced v2): nombres publicados por el host. Opcional: los
    # sensores anteriores a 0.5.0 y los jobs v1 no lo envían.
    identity: SensorIdentityIn | None = None
    observed_at: AwareDatetime

    @field_validator("address")
    @classmethod
    def _address(cls, value: str) -> str:
        # Forma canónica: "192.168.001.020" o mayúsculas IPv6 no crean otra fila.
        return str(ipaddress.ip_address(value))

    @field_validator("mac")
    @classmethod
    def _mac(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = normalize_mac(value)
        if normalized is None:
            raise ValueError("invalid or non-unicast MAC address")
        return normalized


class SensorLeaseIn(RequestModel):
    """Fase 6E.2: un lease DHCP leído por el sensor 0.6.0 (job dhcp_leases)."""

    ip: str = Field(max_length=45)
    mac: str = Field(max_length=17)
    hostname: str | None = Field(default=None, max_length=255)
    client_id: str | None = Field(default=None, max_length=80)
    starts_at: AwareDatetime | None = None
    ends_at: AwareDatetime | None = None
    state: Literal["active", "expired", "released", "unknown"]

    @field_validator("ip")
    @classmethod
    def _ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))

    @field_validator("mac")
    @classmethod
    def _mac(cls, value: str) -> str:
        normalized = normalize_mac(value)
        if normalized is None:
            raise ValueError("invalid or non-unicast MAC address")
        return normalized


class SensorDhcpSummary(RequestModel):
    """Fase 6E.2: resumen de la lectura de un fichero de leases (sin rutas ni contenido)."""

    # Null solo con dhcp_source_unknown: el sensor no conoce el formato de una fuente que
    # no tiene configurada.
    format: Literal["dnsmasq", "isc_dhcpd", "kea_csv", "windows_dhcp_csv", "generic_csv"] | None
    lines: int = Field(default=0, ge=0, le=10_000_000)
    parsed: int = Field(default=0, ge=0, le=10_000_000)
    skipped: int = Field(default=0, ge=0, le=10_000_000)
    truncated: bool = False
    file_mtime: AwareDatetime | None = None
    error_code: (
        Literal[
            "dhcp_source_unknown",
            "dhcp_file_missing",
            "dhcp_file_unreadable",
            "dhcp_file_too_large",
            "dhcp_format_invalid",
        ]
        | None
    ) = None


class SensorResultsRequest(RequestModel):
    batch_id: UUID
    attempt: int = Field(ge=1, le=100)
    # El tope real (SENSOR_MAX_OBSERVATIONS_PER_BATCH) lo aplica el servicio; este es de
    # defensa para que pydantic no construya listas absurdas.
    observations: list[ObservationIn] = Field(default_factory=list, max_length=5000)
    # Fase 6B: registros SNMP normalizados de un job snmp_inventory (nunca junto con
    # observaciones de discovery: el servicio exige la lista que corresponde al tipo de job).
    records: list[SnmpRecord] = Field(default_factory=list, max_length=5000)
    # Fase 6E.2: leases de un job dhcp_leases (nunca junto con las otras dos listas).
    leases: list[SensorLeaseIn] = Field(default_factory=list, max_length=5000)


class SensorResultsResponse(ResponseModel):
    job_id: UUID
    batch_id: UUID
    accepted: int
    duplicate: bool
    observations_total: int
    cancel_requested: bool


class SensorJobComplete(RequestModel):
    attempt: int = Field(ge=1, le=100)
    outcome: Literal["completed", "cancelled", "timed_out", "failed"]
    hosts_scanned: int = Field(default=0, ge=0, le=1_000_000)
    hosts_checked: int = Field(default=0, ge=0, le=1_000_000)
    probes: int = Field(default=0, ge=0, le=100_000_000)
    unprobed: list[str] = Field(default_factory=list, max_length=4096)
    errors: list[str] = Field(default_factory=list, max_length=50)
    batches_sent: int = Field(default=0, ge=0, le=100_000)
    # Fase 6B: resumen de módulos y error de un job snmp_inventory.
    snmp: SnmpJobSummary | None = None
    # Fase 6E.2: resumen de un job dhcp_leases.
    dhcp: SensorDhcpSummary | None = None

    @field_validator("unprobed")
    @classmethod
    def _unprobed(cls, value: list[str]) -> list[str]:
        return [str(ipaddress.ip_address(item)) for item in value]

    @field_validator("errors")
    @classmethod
    def _errors(cls, value: list[str]) -> list[str]:
        return [item[:300] for item in value]


class SensorJobCompleted(ResponseModel):
    job_id: UUID
    status: SensorJobStatus
    duplicate: bool
    discovery_job_id: UUID | None
    hosts_alive: int
    hosts_new: int
    open_ports: int


class SensorRotateResponse(ResponseModel):
    credential: str
    credential_issued_at: datetime
