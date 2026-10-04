from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

from app.schemas.common import RequestModel, ResponseModel
from app.schemas.telemetry import MAX_FUTURE_SKEW

# Upper bounds keep one request from storing an unbounded document; they sit well above what
# a normal workstation or server reports.
MAX_INTERFACES = 128
MAX_USERS = 256
MAX_PROCESSES = 500
MAX_SERVICES = 2000
MAX_SOFTWARE = 5000
MAX_DISKS = 64
MAX_CONNECTIONS = 1000


class _Item(BaseModel):
    # Items are both accepted from agents and returned to clients, so they share one model.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


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
    pid: int = Field(ge=0)
    name: str = Field(min_length=1, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    memory_bytes: int = Field(ge=0)


class ServiceInfo(_Item):
    name: str = Field(min_length=1, max_length=255)
    display_name: str | None = Field(default=None, max_length=512)
    status: str = Field(min_length=1, max_length=32)
    start_type: str | None = Field(default=None, max_length=32)


class SoftwareInfo(_Item):
    name: str = Field(min_length=1, max_length=512)
    version: str | None = Field(default=None, max_length=128)
    publisher: str | None = Field(default=None, max_length=512)


class DiskInfo(_Item):
    device: str = Field(min_length=1, max_length=255)
    mountpoint: str = Field(min_length=1, max_length=255)
    fstype: str | None = Field(default=None, max_length=32)
    total_bytes: int = Field(ge=0)
    used_bytes: int = Field(ge=0)
    free_bytes: int = Field(ge=0)
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
    pid: int | None = Field(default=None, ge=0)
    process_name: str | None = Field(default=None, max_length=255)


class InventorySections(BaseModel):
    interfaces: list[NetworkInterface] = Field(default_factory=list, max_length=MAX_INTERFACES)
    users: list[LoggedInUser] = Field(default_factory=list, max_length=MAX_USERS)
    processes: list[ProcessInfo] = Field(default_factory=list, max_length=MAX_PROCESSES)
    services: list[ServiceInfo] = Field(default_factory=list, max_length=MAX_SERVICES)
    software: list[SoftwareInfo] = Field(default_factory=list, max_length=MAX_SOFTWARE)
    disks: list[DiskInfo] = Field(default_factory=list, max_length=MAX_DISKS)
    connections: list[NetworkConnection] = Field(default_factory=list, max_length=MAX_CONNECTIONS)


class InventoryCreate(InventorySections, RequestModel):
    agent_id: UUID
    collected_at: AwareDatetime

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
