from datetime import datetime
from uuid import UUID

from app.models.asset import AssetStatus, MonitoringMethod
from app.schemas.common import ResponseModel
from app.schemas.telemetry import TelemetrySnapshot


class AssetRead(ResponseModel):
    asset_id: UUID
    # Hostname, reverse DNS name or address: always present, for display.
    display_name: str
    monitoring_method: MonitoringMethod
    # Reported by the agent; null for assets only seen on the network.
    hostname: str | None
    os_name: str | None
    os_version: str | None
    architecture: str | None
    primary_ip: str
    agent_version: str | None
    # Agent assets: the agent's liveness (as before). Others: their network status.
    status: AssetStatus
    # Liveness of the agent (null without agent) and reachability on the network (null
    # until a discovery run sees it).
    agent_status: AssetStatus | None
    network_status: AssetStatus | None
    first_seen_at: datetime
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime
    latest_telemetry: TelemetrySnapshot | None
    # Network view (discovery); null/empty when unknown.
    mac_address: str | None
    reverse_dns: str | None
    vendor: str | None
    device_type: str | None
    device_type_reason: str | None
    discovery_sources: list[str]
    discovery_network: str | None
    discovered_at: datetime | None
    last_network_seen_at: datetime | None
    # Open TCP ports reachable from the Sentra server.
    open_ports: list[int]


class AssetList(ResponseModel):
    items: list[AssetRead]
    total: int
