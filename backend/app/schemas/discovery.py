from datetime import datetime
from uuid import UUID

from app.models.discovery import DiscoveryJobStatus, DiscoveryTrigger
from app.models.exposure import PortStateValue
from app.schemas.common import ResponseModel


class DiscoveryScopeRead(ResponseModel):
    """What discovery may probe (configuration, read-only)."""

    enabled: bool
    allowed_networks: list[str]
    excluded: list[str]
    ports: list[int]
    interval_minutes: int | None
    icmp: bool
    reverse_dns: bool
    timeout_ms: int
    concurrency: int
    max_probes_per_second: int


class DiscoveryJobRead(ResponseModel):
    job_id: UUID
    target: str
    trigger: DiscoveryTrigger
    status: DiscoveryJobStatus
    baseline: bool
    started_at: datetime
    completed_at: datetime | None
    duration_seconds: float | None
    hosts_scanned: int
    hosts_alive: int
    hosts_new: int
    open_ports: int
    probes: int
    error_count: int
    errors: list[str]


class DiscoveryJobList(ResponseModel):
    items: list[DiscoveryJobRead]


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
