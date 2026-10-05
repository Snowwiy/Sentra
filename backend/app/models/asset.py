import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Enum, Index, Integer, String, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.discovery.device_types import ClassificationConfidence


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
    # Fabricante de la tarjeta de red según el prefijo de la MAC (OUI, DISCOVERY_OUI_FILE).
    # Es el "network_adapter_vendor": NO tiene por qué ser el fabricante del dispositivo
    # (un adaptador Realtek en una consola), que va en device_vendor.
    vendor: Mapped[str | None] = mapped_column(String(128))
    # --- Identificación (Fase 4E, app/discovery/classify.py). Se recalcula con cada dato
    # nuevo (discovery, agente, fusión); nunca se escribe a mano. -------------------------
    # Tipo (app/discovery/device_types.DeviceType) y resumen del porqué; null = desconocido.
    device_type: Mapped[str | None] = mapped_column(String(32))
    device_type_reason: Mapped[str | None] = mapped_column(String(255))
    # Nombre resuelto por prioridad (agente > DNS inverso > mDNS > NetBIOS > UPnP >
    # fabricante+modelo) y de qué fuente salió. Null si nada lo nombra: la UI muestra un
    # texto de reserva ("Dispositivo desconocido") con la IP aparte.
    device_name: Mapped[str | None] = mapped_column(String(255))
    name_source: Mapped[str | None] = mapped_column(String(16))
    device_vendor: Mapped[str | None] = mapped_column(String(128))
    device_model: Mapped[str | None] = mapped_column(String(128))
    # SO deducido desde la red, sin versión. Solo activos sin agente: con agente manda
    # os_name/os_version.
    probable_os: Mapped[str | None] = mapped_column(String(64))
    classification_confidence: Mapped[ClassificationConfidence | None] = mapped_column(
        _enum(ClassificationConfidence, "classification_confidence")
    )
    # [{"source": "...", "value": "..."}]: por qué se concluyó lo anterior.
    classification_evidence: Mapped[list[dict[str, str]] | None] = mapped_column(JSONB)
    # Últimos datos de identidad observados en la red (mDNS, NetBIOS, SSDP/UPnP, gateway),
    # guardados en bruto para poder recalcular la identificación sin volver a escanear.
    identity_observations: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
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
        """Nombre resuelto, hostname del agente, DNS inverso o, en último caso, la IP.

        Se usa en alertas, eventos y CLI, donde un identificador concreto es más útil que
        "Dispositivo desconocido"; ese texto de reserva solo lo pone la UI.
        """
        return self.device_name or self.hostname or self.reverse_dns or self.primary_ip

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
