import enum
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, Index, Integer, String, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AssetStatus(enum.StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class MonitoringMethod(enum.StrEnum):
    """How Sentra knows about an asset (the DISCOVERED → MONITORED → MANAGED path)."""

    # Found on the network by discovery; only what is observable from the network is known.
    DISCOVERED = "discovered"
    # Monitored remotely without an agent (WinRM/WMI, SSH, SNMP). Reserved: the adapters
    # are prepared (app/agentless) but none collects yet.
    AGENTLESS = "agentless"
    # Runs the Sentra agent (MANAGED). Every asset created before hybrid monitoring.
    AGENT = "agent"


def _enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    return Enum(enum_cls, name=name, values_callable=lambda members: [m.value for m in members])


class Asset(Base):
    """A host known to Sentra: through its agent, through network discovery, or both.

    Agent assets (`monitoring_method = agent`) have an `agent_id` and the host fields the
    agent reports. Discovered assets have none of those (null) and only network facts. When
    an agent is installed on a discovered host, both records converge into the agent's asset
    (services/reconciliation.py), keeping the discovery history.
    """

    __tablename__ = "assets"
    __table_args__ = (
        # Discovery and reconciliation look assets up by address.
        Index("ix_assets_primary_ip", "primary_ip"),
        Index("ix_assets_mac_address", "mac_address"),
    )

    # Internal surrogate key; never exposed through the API.
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # Identity generated and kept by the agent itself. Null for assets without an agent.
    agent_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, unique=True)
    monitoring_method: Mapped[MonitoringMethod] = mapped_column(
        _enum(MonitoringMethod, "asset_monitoring_method"),
        default=MonitoringMethod.AGENT,
        server_default=MonitoringMethod.AGENT.value,
    )

    # SHA-256 of the agent's bearer token (see core/security.py). Null means the agent has no
    # valid credential and must enroll again.
    agent_token_hash: Mapped[str | None] = mapped_column(String(64))
    # When the current token was issued. Groundwork for rotation (e.g. force re-enrollment of
    # tokens older than N days); not enforced yet.
    agent_token_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set by an operator to cut this agent off (stolen laptop, decommissioned host). While set,
    # the agent has no valid token and re-enrollment is refused, even with the enrollment key.
    agent_token_revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Reported by the agent; null (unknown) for assets only seen on the network.
    hostname: Mapped[str | None] = mapped_column(String(255))
    os_name: Mapped[str | None] = mapped_column(String(64))
    os_version: Mapped[str | None] = mapped_column(String(128))
    architecture: Mapped[str | None] = mapped_column(String(32))
    # Validated as IPv4/IPv6 at the API boundary; 45 chars fits the longest IPv6 text form.
    primary_ip: Mapped[str] = mapped_column(String(45))
    agent_version: Mapped[str | None] = mapped_column(String(64))

    # --- Network view (discovery). Null until the asset is seen by a discovery run. ---------
    # Unicast MAC (aa:bb:cc:dd:ee:ff), only known on the server's own L2 segment.
    mac_address: Mapped[str | None] = mapped_column(String(17))
    reverse_dns: Mapped[str | None] = mapped_column(String(255))
    # Vendor from the MAC prefix: needs an OUI database, not shipped yet (always null).
    vendor: Mapped[str | None] = mapped_column(String(128))
    # Probable type (app/discovery/classify.py) and why; null when it cannot be told.
    device_type: Mapped[str | None] = mapped_column(String(32))
    device_type_reason: Mapped[str | None] = mapped_column(String(255))
    # How discovery saw it: any of "icmp", "tcp", "arp".
    discovery_sources: Mapped[list[str] | None] = mapped_column(JSONB)
    # Allowed network (CIDR) of the run that last saw it.
    discovery_network: Mapped[str | None] = mapped_column(String(64))
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_network_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    network_status: Mapped[AssetStatus | None] = mapped_column(
        Enum(
            AssetStatus,
            name="asset_status",
            values_callable=lambda members: [member.value for member in members],
            create_type=False,
        )
    )
    # Consecutive complete discovery runs that did not see it (offline after N).
    network_misses: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Set by the first port scan of the asset: later scans report changes against it.
    exposure_baseline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Last status set by agent activity. Staleness (offline) is resolved at read time.
    status: Mapped[AssetStatus] = mapped_column(
        Enum(
            AssetStatus,
            name="asset_status",
            values_callable=lambda members: [member.value for member in members],
        ),
        default=AssetStatus.UNKNOWN,
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def is_managed(self) -> bool:
        return self.agent_id is not None

    @property
    def display_name(self) -> str:
        """Best available name: reported hostname, reverse DNS, or the address."""
        return self.hostname or self.reverse_dns or self.primary_ip

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
