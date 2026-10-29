from datetime import UTC, date, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, Field, IPvAnyAddress, field_validator

from app.schemas.common import BIGINT_MAX, RequestModel, ResponseModel
from app.schemas.telemetry import MAX_FUTURE_SKEW
from app.schemas.wlan import WirelessReport

# Upper bounds keep one request from storing an unbounded document; they sit well above what
# a normal workstation or server reports.
MAX_INTERFACES = 128
MAX_USERS = 256
MAX_PROCESSES = 500
MAX_SERVICES = 2000
MAX_SOFTWARE = 5000
MAX_DISKS = 64
MAX_CONNECTIONS = 1000
MAX_ACCOUNTS = 1000
MAX_PATH = 1024

# Nombre de sección tal como lo envía el agente; acotado pero no enumerado, para que un agente
# más nuevo con una sección extra no haga rechazar todo el inventario.
SectionName = Annotated[str, Field(min_length=1, max_length=32, pattern=r"^[a-z_]+$")]


class _Item(RequestModel):
    """Items are both accepted from agents and returned to clients, so they share one model.

    The inbound rules (unknown fields, no NUL characters) also hold for what was stored.
    """


class NetworkInterface(_Item):
    name: str = Field(min_length=1, max_length=255)
    mac: str | None = Field(default=None, max_length=64)
    addresses: list[IPvAnyAddress] = Field(default_factory=list, max_length=64)
    is_up: bool
    speed_mbps: int | None = Field(default=None, ge=0)


class LoggedInUser(_Item):
    name: str = Field(min_length=1, max_length=255)
    terminal: str | None = Field(default=None, max_length=255)
    host: str | None = Field(default=None, max_length=255)
    started_at: AwareDatetime | None = None


class ProcessInfo(_Item):
    pid: int = Field(ge=0, le=BIGINT_MAX)
    name: str = Field(min_length=1, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    memory_bytes: int = Field(ge=0, le=BIGINT_MAX)
    # Optional (newer agents). CPU is a share of the whole machine (0-100, all cores), the
    # same scale as the asset's CPU metric.
    exe: str | None = Field(default=None, max_length=MAX_PATH)
    ppid: int | None = Field(default=None, ge=0, le=BIGINT_MAX)
    cpu_percent: float | None = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    started_at: AwareDatetime | None = None


class ServiceSignature(_Item):
    """Firma Authenticode del ejecutable del servicio, tal como la informa el agente."""

    status: str = Field(min_length=1, max_length=32)
    signer: str | None = Field(default=None, max_length=512)


class ServiceInfo(_Item):
    name: str = Field(min_length=1, max_length=255)
    display_name: str | None = Field(default=None, max_length=512)
    status: str = Field(min_length=1, max_length=32)
    start_type: str | None = Field(default=None, max_length=32)
    # Process id while running (Windows services; newer agents).
    pid: int | None = Field(default=None, ge=0, le=BIGINT_MAX)
    # Fase 7B-Fix1 (agente 0.6.2, Windows): línea de comandos, cuenta, tipo del registro,
    # ejecutable y firma. Con ellos el servidor distingue una instancia de servicio por
    # usuario de una instalación sin fiarse del nombre (app/detection/service_identity.py).
    binpath: str | None = Field(default=None, max_length=MAX_PATH)
    username: str | None = Field(default=None, max_length=255)
    service_type: int | None = Field(default=None, ge=0, le=0xFFFFFFFF)
    image: str | None = Field(default=None, max_length=MAX_PATH)
    image_signature: ServiceSignature | None = None


class SoftwareInfo(_Item):
    name: str = Field(min_length=1, max_length=512)
    version: str | None = Field(default=None, max_length=128)
    publisher: str | None = Field(default=None, max_length=512)
    # When the host records them (newer agents): install date, and the package/registry
    # architecture (e.g. x64, x86, amd64).
    install_date: date | None = None
    architecture: str | None = Field(default=None, max_length=16)


class DiskInfo(_Item):
    device: str = Field(min_length=1, max_length=255)
    mountpoint: str = Field(min_length=1, max_length=255)
    fstype: str | None = Field(default=None, max_length=32)
    total_bytes: int = Field(ge=0, le=BIGINT_MAX)
    used_bytes: int = Field(ge=0, le=BIGINT_MAX)
    free_bytes: int = Field(ge=0, le=BIGINT_MAX)
    percent: float = Field(ge=0, le=100, allow_inf_nan=False)


class NetworkConnection(_Item):
    # Only listening sockets and established connections are collected: enough to answer
    # "what is exposed / talking to what" without the noise (and size) of every socket state.
    protocol: Literal["tcp", "udp"]
    local_address: IPvAnyAddress | None = None
    local_port: int | None = Field(default=None, ge=0, le=65535)
    remote_address: IPvAnyAddress | None = None
    remote_port: int | None = Field(default=None, ge=0, le=65535)
    status: Literal["listen", "established"]
    pid: int | None = Field(default=None, ge=0, le=BIGINT_MAX)
    process_name: str | None = Field(default=None, max_length=255)


class AccountInfo(_Item):
    """A local account. Only identity and state: never passwords, hashes or other secrets."""

    name: str = Field(min_length=1, max_length=255)
    # Null when the host does not tell (e.g. Linux without access to the shadow file).
    enabled: bool | None = None
    # Member of the local Administrators group (Windows) or of sudo/wheel/admin (Linux).
    is_admin: bool | None = None
    last_logon: AwareDatetime | None = None


class NetworkSummary(_Item):
    """Host-wide network configuration (not per interface)."""

    gateways: list[IPvAnyAddress] = Field(default_factory=list, max_length=16)
    dns_servers: list[IPvAnyAddress] = Field(default_factory=list, max_length=16)


class InventorySections(BaseModel):
    interfaces: list[NetworkInterface] = Field(default_factory=list, max_length=MAX_INTERFACES)
    users: list[LoggedInUser] = Field(default_factory=list, max_length=MAX_USERS)
    processes: list[ProcessInfo] = Field(default_factory=list, max_length=MAX_PROCESSES)
    services: list[ServiceInfo] = Field(default_factory=list, max_length=MAX_SERVICES)
    software: list[SoftwareInfo] = Field(default_factory=list, max_length=MAX_SOFTWARE)
    disks: list[DiskInfo] = Field(default_factory=list, max_length=MAX_DISKS)
    connections: list[NetworkConnection] = Field(default_factory=list, max_length=MAX_CONNECTIONS)
    # Newer agents: local accounts (as opposed to `users`, the logged-in sessions) and the
    # host's gateways/DNS servers.
    accounts: list[AccountInfo] = Field(default_factory=list, max_length=MAX_ACCOUNTS)
    network: NetworkSummary | None = None
    # Fase 5B (agentes nuevos): de dónde sale el software (el gestor de paquetes decide el
    # ecosistema con el que se comparan versiones) y qué secciones fallaron al recogerse.
    # Sin esto una lista vacía por fallo parecería "no hay software" y resolvería findings.
    # None = agente antiguo que no lo informa (completitud desconocida), distinto de [].
    software_source: Literal["windows_registry", "dpkg", "rpm"] | None = None
    incomplete_sections: list[SectionName] | None = Field(default=None, max_length=32)


class InventoryCreate(InventorySections, RequestModel):
    agent_id: UUID
    collected_at: AwareDatetime
    # Fase 6C.3: observación Wi-Fi pasiva del sistema operativo. Opcional (los agentes
    # antiguos no la envían) y fuera de InventorySections a propósito: no se guarda en el
    # documento de inventario ni entra en el diff de cambios; va al inventario Wi-Fi del site.
    wireless: WirelessReport | None = None

    @field_validator("collected_at")
    @classmethod
    def _normalize_collected_at(cls, value: datetime) -> datetime:
        value = value.astimezone(UTC)
        if value > datetime.now(UTC) + MAX_FUTURE_SKEW:
            raise ValueError("collected_at is too far in the future")
        return value


class InventoryAccepted(ResponseModel):
    asset_id: UUID
    collected_at: datetime


class InventoryRead(InventorySections, ResponseModel):
    asset_id: UUID
    collected_at: datetime
    received_at: datetime
