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


class PortObservation(RequestModel):
    port: int = Field(ge=1, le=65535)
    state: Literal["open", "closed", "filtered"]


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


class SensorResultsRequest(RequestModel):
    batch_id: UUID
    attempt: int = Field(ge=1, le=100)
    # El tope real (SENSOR_MAX_OBSERVATIONS_PER_BATCH) lo aplica el servicio; este es de
    # defensa para que pydantic no construya listas absurdas.
    observations: list[ObservationIn] = Field(max_length=5000)


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
