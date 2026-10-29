"""Servicio del motor de topología (Fase 6D, docs/topology-engine.md).

- Carga la evidencia de UN site en pocas consultas (una por tabla, solo las columnas
  necesarias y filtradas por site en SQL: sin N+1 ni listas IN gigantes).
- Reconstruye con upsert por (site_id, link_key): lo derivado queda present=true con
  last_seen_at y last_evidence_at al día; lo que deja de derivarse queda present=false sin
  borrarse, y la revisión humana (review_state/review_note) se conserva siempre.
- Una sola reconstrucción por site a la vez: advisory lock de TRANSACCIÓN por site; quien no
  lo obtiene recibe 409 topology_build_running. El lock muere con la transacción, así un
  proceso caído no deja el site bloqueado.
- Las lecturas componen los nodos desde el inventario (no se guardan), filtran por site y
  devuelven 404 genérico para lo que no es del site (anti-IDOR).
"""

import ipaddress
import logging
import re
import time
from collections import Counter, defaultdict
from collections.abc import Collection, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import case, exists, func, or_, select
from sqlalchemy.orm import Session, load_only

from app.core.config import Settings, get_settings
from app.core.exceptions import SiteConflictError, SiteNotFoundError
from app.db.locks import topology_site_lock_key
from app.discovery.probes import normalize_mac
from app.models.asset import Asset
from app.models.inventory import AssetInventory
from app.models.network import NetworkDevice, NetworkInterface, NetworkMacEntry, NetworkNeighbor
from app.models.risk import AssetRisk
from app.models.site import Site, SiteNetwork
from app.models.topology import LINK_KINDS, TopologyBuild, TopologyLink
from app.models.wlan import WlanAccessPoint, WlanClient
from app.schemas.topology import (
    TopologyBuild as TopologyBuildRead,
)
from app.schemas.topology import (
    TopologyCoverage,
    TopologyEvidence,
    TopologyEvidenceAvailability,
    TopologyGraph,
    TopologyGroup,
    TopologyLimits,
    TopologyLinkDetail,
    TopologyLinkList,
    TopologyNode,
    TopologyNodeDetail,
    TopologyReviewUpdate,
    TopologySiteRef,
    TopologyStatus,
)
from app.schemas.topology import (
    TopologyLink as TopologyLinkRead,
)
from app.services import audit_service
from app.services.asset_service import effective_status, observed_name_items
from app.services.audit_service import Actor
from app.topology.builder import (
    DEVICE_CLASS_TYPES,
    INFRASTRUCTURE_TYPES,
    KIND_RANK,
    AccessPointIn,
    AssetIn,
    ClientIn,
    DerivedLink,
    DeriveResult,
    DeviceIn,
    GatewayIn,
    InterfaceIn,
    MacIn,
    NeighborIn,
    Snapshot,
    derive_links,
    interface_names,
)
from app.topology.errors import (
    TopologyBuildFailedError,
    TopologyLinkNotFoundError,
    TopologyNodeNotFoundError,
)
from app.topology.history import ssid_of, vlan_of
from app.topology.history_service import SnapshotContent, record_history

logger = logging.getLogger(__name__)

SYSTEM = Actor("topology-builder")
# Enlaces de un nodo en su detalle (contrato) y tope de parámetros por consulta: PostgreSQL
# admite 65535 parámetros por sentencia; se trocean las listas largas muy por debajo.
NODE_DETAIL_LINKS = 200
CHUNK = 5000
MAX_GATEWAYS = 16
COUNT_KEYS = (
    "links_created",
    "links_updated",
    "links_absent",
    "links_present",
    "links_dropped",
    "nodes",
    "ambiguous_macs",
    "skipped_cross_site",
    # Fase 6E.1: cambios de red registrados y si la reconstrucción creó un snapshot nuevo.
    "changes_detected",
    "snapshot_created",
)
_NODE_ID = re.compile(
    r"^(asset|network_device|wlan_ap):([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$|^external:[0-9a-f]{16}$"
)
_KIND_ORDER = case({kind: rank for kind, rank in KIND_RANK.items()}, value=TopologyLink.kind)
# Campos de la revisión que no se tocan al reconstruir; lo demás sí (es dato derivado).
_MATERIAL = ("kind", "relation", "confidence", "medium", "source_node", "target_node")


def chunks[T](values: Sequence[T], size: int = CHUNK) -> Iterator[Sequence[T]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def _now() -> datetime:
    return datetime.now(UTC)


# --- carga de la evidencia ------------------------------------------------------------------


def _device_label(device: NetworkDevice) -> str:
    return device.name or device.sys_name or device.management_address


def _gateways(value: Any) -> tuple[str, ...]:
    # El JSON lo validó el esquema de inventario al recibirlo, pero se relee defensivamente:
    # solo cadenas y como mucho MAX_GATEWAYS.
    if not isinstance(value, list):
        return ()
    return tuple(str(v)[:45] for v in value[:MAX_GATEWAYS] if isinstance(v, str))


def load_snapshot(session: Session, site_id: int) -> Snapshot:
    """Evidencia de un site: una consulta por tabla, columnas justas, todo filtrado por site."""
    assets = [
        AssetIn(row.id, row.public_id, row.primary_ip, row.mac_address, row.archived_at is not None)
        for row in session.execute(
            select(
                Asset.id, Asset.public_id, Asset.primary_ip, Asset.mac_address, Asset.archived_at
            ).where(Asset.site_id == site_id)
        )
    ]
    devices = [
        DeviceIn(
            id=row.id,
            public_id=row.public_id,
            address=row.management_address,
            label=row.name or row.sys_name or row.management_address,
            asset_id=row.asset_id,
            ip_forwarding=row.ip_forwarding,
            chassis_id=row.lldp_chassis_id,
            bridge_mac=row.base_bridge_address,
            archived=row.status == "archived" or row.archived_at is not None,
        )
        for row in session.execute(
            select(
                NetworkDevice.id,
                NetworkDevice.public_id,
                NetworkDevice.management_address,
                NetworkDevice.name,
                NetworkDevice.sys_name,
                NetworkDevice.asset_id,
                NetworkDevice.ip_forwarding,
                NetworkDevice.lldp_chassis_id,
                NetworkDevice.base_bridge_address,
                NetworkDevice.status,
                NetworkDevice.archived_at,
            ).where(NetworkDevice.site_id == site_id)
        )
    ]
    interfaces = [
        InterfaceIn(
            id=row.id,
            device_id=row.device_id,
            label=row.if_name or row.if_descr or f"ifIndex {row.if_index}",
            names=interface_names(row.if_name, row.if_descr, row.if_alias),
        )
        for row in session.execute(
            select(
                NetworkInterface.id,
                NetworkInterface.device_id,
                NetworkInterface.if_name,
                NetworkInterface.if_descr,
                NetworkInterface.if_alias,
                NetworkInterface.if_index,
            ).where(NetworkInterface.site_id == site_id)
        )
    ]
    neighbors = [
        NeighborIn(
            id=row.id,
            device_id=row.device_id,
            protocol=row.protocol,
            last_seen_at=row.last_seen_at,
            local_port=row.local_port_label,
            interface_id=row.interface_id,
            remote_device_id=row.remote_device_id,
            remote_chassis_id=row.remote_chassis_id,
            remote_chassis_subtype=row.remote_chassis_id_subtype,
            remote_port=row.remote_port_id or row.remote_port_descr,
            remote_sys_name=row.remote_sys_name,
            remote_mgmt_address=row.remote_mgmt_address,
            remote_platform=row.remote_platform,
            reciprocal=row.reciprocal,
        )
        for row in session.execute(
            select(
                NetworkNeighbor.id,
                NetworkNeighbor.device_id,
                NetworkNeighbor.protocol,
                NetworkNeighbor.last_seen_at,
                NetworkNeighbor.local_port_label,
                NetworkNeighbor.interface_id,
                NetworkNeighbor.remote_device_id,
                NetworkNeighbor.remote_chassis_id,
                NetworkNeighbor.remote_chassis_id_subtype,
                NetworkNeighbor.remote_port_id,
                NetworkNeighbor.remote_port_descr,
                NetworkNeighbor.remote_sys_name,
                NetworkNeighbor.remote_mgmt_address,
                NetworkNeighbor.remote_platform,
                NetworkNeighbor.reciprocal,
            ).where(NetworkNeighbor.site_id == site_id, NetworkNeighbor.present.is_(True))
        )
    ]
    macs = [
        MacIn(
            id=row.id,
            device_id=row.device_id,
            mac=row.mac,
            location=row.location,
            last_seen_at=row.last_seen_at,
            interface_id=row.interface_id,
            bridge_port=row.bridge_port,
            vlan_id=row.vlan_id,
        )
        for row in session.execute(
            select(
                NetworkMacEntry.id,
                NetworkMacEntry.device_id,
                NetworkMacEntry.mac,
                NetworkMacEntry.location,
                NetworkMacEntry.last_seen_at,
                NetworkMacEntry.interface_id,
                NetworkMacEntry.bridge_port,
                NetworkMacEntry.vlan_id,
            ).where(NetworkMacEntry.site_id == site_id, NetworkMacEntry.present.is_(True))
        )
    ]
    aps = [
        AccessPointIn(
            id=row.id,
            public_id=row.public_id,
            label=row.name or row.management_ip or row.radio_mac or row.ap_key,
            last_seen_at=row.last_seen_at,
            present=row.present,
            asset_id=row.asset_id,
            network_device_id=row.network_device_id,
            source_device_id=row.source_device_id,
        )
        for row in session.execute(
            select(
                WlanAccessPoint.id,
                WlanAccessPoint.public_id,
                WlanAccessPoint.name,
                WlanAccessPoint.management_ip,
                WlanAccessPoint.radio_mac,
                WlanAccessPoint.ap_key,
                WlanAccessPoint.last_seen_at,
                WlanAccessPoint.present,
                WlanAccessPoint.asset_id,
                WlanAccessPoint.network_device_id,
                WlanAccessPoint.source_device_id,
            ).where(WlanAccessPoint.site_id == site_id)
        )
    ]
    clients = [
        ClientIn(
            id=row.id,
            identity_confidence=row.identity_confidence,
            last_seen_at=row.last_seen_at,
            asset_id=row.asset_id,
            access_point_id=row.access_point_id,
            ssid=row.ssid,
            mac=row.mac,
            bssid=row.bssid,
        )
        for row in session.execute(
            select(
                WlanClient.id,
                WlanClient.identity_confidence,
                WlanClient.last_seen_at,
                WlanClient.asset_id,
                WlanClient.access_point_id,
                WlanClient.ssid,
                WlanClient.mac,
                WlanClient.bssid,
            ).where(
                WlanClient.site_id == site_id,
                WlanClient.present.is_(True),
                WlanClient.asset_id.is_not(None),
                # Fase 7B-Fix1: también los asociados a un BSS sin AP inventariado.
                or_(WlanClient.access_point_id.is_not(None), WlanClient.bssid.is_not(None)),
            )
        )
    ]
    # Solo la ruta network.gateways del JSON (no el inventario entero, que puede pesar MB).
    gateways = [
        GatewayIn(row.asset_id, _gateways(row.gateways), row.collected_at)
        for row in session.execute(
            select(
                AssetInventory.asset_id,
                AssetInventory.collected_at,
                AssetInventory.data["network"]["gateways"].label("gateways"),
            )
            .join(Asset, Asset.id == AssetInventory.asset_id)
            .where(Asset.site_id == site_id, Asset.archived_at.is_(None))
        )
    ]
    return Snapshot(
        assets=assets,
        devices=devices,
        interfaces=interfaces,
        neighbors=neighbors,
        macs=macs,
        access_points=aps,
        clients=clients,
        gateways=[g for g in gateways if g.gateways],
    )


# --- lectura de filas -----------------------------------------------------------------------


_PHYSICAL_RELATIONS = frozenset({"lldp", "cdp", "fdb"})


def coverage(nodes: Sequence[TopologyNode], links: Sequence[TopologyLink]) -> TopologyCoverage:
    """Qué evidencia hay detrás del grafo y qué falta (Fase 7B-Fix1).

    Sentra no dibuja enlaces al gateway por compartir subred: sin LLDP/CDP, tabla FDB de un
    switch gestionable, asociación Wi-Fi verificada o gateway informado por un agente, un
    nodo queda sin enlaces y se dice explícitamente.
    """
    by_kind: dict[str, int] = defaultdict(int)
    for row in links:
        by_kind[row.kind] += 1
    unlinked = [n for n in nodes if n.link_count == 0]
    limitations: list[str] = []
    if unlinked:
        limitations.append("nodes_without_link_evidence")
    if not any(row.relation in _PHYSICAL_RELATIONS for row in links):
        limitations.append("no_physical_link_evidence")
    if any(
        row.relation == "wlan_association" and row.target_node.startswith("external:")
        for row in links
    ):
        limitations.append("access_point_not_inventoried")
    return TopologyCoverage(
        nodes=len(nodes),
        nodes_without_links=len(unlinked),
        unlinked_by_type={
            key: count
            for key, count in sorted(Counter(n.device_type or "unknown" for n in unlinked).items())
        },
        links_by_kind=dict(sorted(by_kind.items())),
        limitations=limitations,
    )


def build_read(build: TopologyBuild, site_public: UUID) -> TopologyBuildRead:
    return TopologyBuildRead(
        id=build.public_id,
        site_id=site_public,
        status=build.status,
        trigger=build.trigger,
        requested_by=build.requested_by,
        started_at=build.started_at,
        finished_at=build.finished_at,
        duration_ms=build.duration_ms,
        counts=build.counts,
        error_code=build.error_code,
    )


def link_read(row: TopologyLink) -> TopologyLinkRead:
    return TopologyLinkRead.model_validate(
        {
            "id": row.public_id,
            "source": row.source_node,
            "target": row.target_node,
            "kind": row.kind,
            "medium": row.medium,
            "relation": row.relation,
            "confidence": row.confidence,
            "source_port": row.source_port,
            "target_port": row.target_port,
            "evidence_sources": list(row.evidence_sources or []),
            "present": row.present,
            "first_seen_at": row.first_seen_at,
            "last_seen_at": row.last_seen_at,
            "last_evidence_at": row.last_evidence_at,
            "review_state": row.review_state,
        }
    )


def link_detail(row: TopologyLink) -> TopologyLinkDetail:
    base = link_read(row).model_dump()
    return TopologyLinkDetail.model_validate(
        {
            **base,
            "evidence": [
                TopologyEvidence.model_validate(entry) for entry in (row.evidence or [])[:8]
            ],
            "target_external": row.target_external,
            "review_note": row.review_note,
            "reviewed_by": row.reviewed_by,
            "reviewed_at": row.reviewed_at,
            "version": row.version,
        }
    )


# --- catálogo de nodos ------------------------------------------------------------------------


@dataclass
class _Node:
    read: TopologyNode
    # Texto en minúsculas sobre el que busca `q` (IP, nombres, etiqueta, MAC).
    search: str
    observed_names: list[dict[str, Any]] = field(default_factory=list)
    inventory_path: str | None = None


def _role(device_type: str | None, infrastructure: bool) -> str:
    if infrastructure or (device_type in INFRASTRUCTURE_TYPES):
        return "infrastructure"
    return "endpoint" if device_type else "unknown"


class _Catalog:
    """Nodos del site compuestos desde el inventario (activos no archivados, equipos activos
    sin activo, APs sin equipo ni activo). Unas pocas consultas por site, todas filtradas."""

    def __init__(self, session: Session, settings: Settings, site_id: int) -> None:
        now = _now()
        timeout = timedelta(seconds=settings.heartbeat_timeout_seconds)
        assets = session.scalars(
            select(Asset)
            .options(
                load_only(
                    Asset.id,
                    Asset.public_id,
                    Asset.agent_id,
                    Asset.primary_ip,
                    Asset.mac_address,
                    Asset.vendor,
                    Asset.device_vendor,
                    Asset.device_type,
                    Asset.device_name,
                    Asset.hostname,
                    Asset.reverse_dns,
                    Asset.custom_label,
                    Asset.status,
                    Asset.network_status,
                    Asset.last_seen_at,
                    Asset.criticality,
                    Asset.discovery_sources,
                    Asset.discovered_at,
                    Asset.classification_confidence,
                    Asset.observed_names,
                )
            )
            .where(Asset.site_id == site_id, Asset.archived_at.is_(None))
        ).all()
        risk = {
            row.asset_id: (row.score, str(row.level))
            for row in session.execute(
                select(AssetRisk.asset_id, AssetRisk.score, AssetRisk.level)
                .join(Asset, Asset.id == AssetRisk.asset_id)
                .where(
                    Asset.site_id == site_id,
                    Asset.archived_at.is_(None),
                    AssetRisk.calculated_at.is_not(None),
                )
            )
        }
        devices = session.scalars(
            select(NetworkDevice).where(
                NetworkDevice.site_id == site_id,
                NetworkDevice.status != "archived",
                NetworkDevice.archived_at.is_(None),
            )
        ).all()
        aps = session.scalars(
            select(WlanAccessPoint).where(WlanAccessPoint.site_id == site_id)
        ).all()
        self.networks: list[tuple[str, str | None, Any]] = []
        for cidr, name in session.execute(
            select(SiteNetwork.cidr, SiteNetwork.name)
            .where(SiteNetwork.site_id == site_id, SiteNetwork.enabled.is_(True))
            .order_by(SiteNetwork.cidr)
        ):
            try:
                self.networks.append((cidr, name, ipaddress.ip_network(cidr, strict=False)))
            except ValueError:
                continue

        self.nodes: dict[str, _Node] = {}
        self.asset_node: dict[int, str] = {}
        self.device_node: dict[int, str] = {}
        by_id = {a.id: a for a in assets}
        device_for_asset: dict[int, NetworkDevice] = {}
        for device in devices:
            if device.asset_id is not None and device.asset_id in by_id:
                device_for_asset.setdefault(device.asset_id, device)
        ap_for_asset: set[int] = set()
        ap_for_device: set[int] = set()
        for ap in aps:
            if ap.network_device_id is not None:
                ap_for_device.add(ap.network_device_id)
            elif ap.asset_id is not None:
                ap_for_asset.add(ap.asset_id)

        for asset in assets:
            key = f"asset:{asset.public_id}"
            self.asset_node[asset.id] = key
            linked = device_for_asset.get(asset.id)
            device_type = asset.device_type or (
                DEVICE_CLASS_TYPES.get(linked.classification) if linked is not None else None
            )
            sources = set()
            if asset.agent_id is not None:
                sources.add("agent")
            if asset.discovered_at is not None or asset.discovery_sources:
                sources.add("discovery")
            if linked is not None:
                sources.add("snmp")
            if asset.id in ap_for_asset or (linked is not None and linked.id in ap_for_device):
                sources.add("wlan")
            if asset.agent_id is not None or asset.custom_label:
                identity = "high"
            elif asset.classification_confidence is not None:
                identity = str(asset.classification_confidence.value)
            else:
                identity = "none"
            score_level = risk.get(asset.id)
            read = TopologyNode.model_validate(
                {
                    "id": key,
                    "kind": "asset",
                    "label": asset.display_name,
                    "automatic_name": asset.automatic_name,
                    "custom_label": asset.custom_label,
                    "asset_id": asset.public_id,
                    "network_device_id": linked.public_id if linked is not None else None,
                    "ip": asset.primary_ip,
                    "mac": asset.mac_address,
                    "vendor": asset.device_vendor or asset.vendor,
                    "device_type": device_type,
                    "role": _role(device_type, linked is not None),
                    "status": str(effective_status(asset, now, timeout).value),
                    "managed": asset.agent_id is not None,
                    "risk_score": score_level[0] if score_level else None,
                    "risk_level": score_level[1] if score_level else None,
                    "criticality": str(asset.criticality.value) if asset.criticality else None,
                    "groups": [],
                    "sources": sorted(sources),
                    "identity_confidence": identity,
                    "link_count": 0,
                }
            )
            search = " ".join(
                v
                for v in (
                    asset.custom_label,
                    asset.device_name,
                    asset.hostname,
                    asset.reverse_dns,
                    asset.primary_ip,
                    asset.mac_address,
                    linked.name if linked is not None else None,
                    linked.sys_name if linked is not None else None,
                )
                if v
            ).lower()
            self.nodes[key] = _Node(
                read,
                search,
                observed_names=list(asset.observed_names or []),
                inventory_path=f"/assets/{asset.public_id}",
            )
        for device in devices:
            if device.asset_id is not None and device.asset_id in by_id:
                self.device_node[device.id] = self.asset_node[device.asset_id]
                continue
            key = f"network_device:{device.public_id}"
            self.device_node[device.id] = key
            device_type = DEVICE_CLASS_TYPES.get(device.classification)
            read = TopologyNode.model_validate(
                {
                    "id": key,
                    "kind": "network_device",
                    "label": _device_label(device),
                    "automatic_name": device.sys_name or device.management_address,
                    "custom_label": None,
                    "asset_id": None,
                    "network_device_id": device.public_id,
                    "ip": device.management_address,
                    "mac": device.base_bridge_address,
                    "vendor": device.vendor,
                    "device_type": device_type,
                    "role": "infrastructure",
                    "status": None,
                    "managed": False,
                    "risk_score": None,
                    "risk_level": None,
                    "criticality": None,
                    "groups": [],
                    "sources": ["snmp", "wlan"] if device.id in ap_for_device else ["snmp"],
                    "identity_confidence": device.classification_confidence or "none",
                    "link_count": 0,
                }
            )
            search = " ".join(
                v
                for v in (
                    device.name,
                    device.sys_name,
                    device.management_address,
                    device.base_bridge_address,
                )
                if v
            ).lower()
            self.nodes[key] = _Node(
                read, search, inventory_path=f"/network?device={device.public_id}"
            )
        for ap in aps:
            if ap.network_device_id is not None and ap.network_device_id in self.device_node:
                continue
            if ap.asset_id is not None and ap.asset_id in by_id:
                continue
            key = f"wlan_ap:{ap.public_id}"
            label = ap.name or ap.management_ip or ap.radio_mac or ap.ap_key
            read = TopologyNode.model_validate(
                {
                    "id": key,
                    "kind": "wlan_ap",
                    "label": label,
                    "automatic_name": label,
                    "custom_label": None,
                    "asset_id": None,
                    "network_device_id": None,
                    "ip": ap.management_ip,
                    "mac": ap.ethernet_mac or ap.radio_mac,
                    "vendor": ap.vendor,
                    "device_type": "access_point",
                    "role": "infrastructure",
                    "status": None,
                    "managed": False,
                    "risk_score": None,
                    "risk_level": None,
                    "criticality": None,
                    "groups": [],
                    "sources": ["wlan"],
                    "identity_confidence": "medium",
                    "link_count": 0,
                }
            )
            search = " ".join(
                v for v in (ap.name, ap.management_ip, ap.ethernet_mac, ap.radio_mac) if v
            ).lower()
            self.nodes[key] = _Node(
                read, search, inventory_path=f"/network?access_point={ap.public_id}"
            )

    def add_external(self, row: TopologyLink) -> None:
        if row.target_node in self.nodes:
            return
        label = row.target_external_label or "unknown"
        read = TopologyNode.model_validate(
            {
                "id": row.target_node,
                "kind": "external",
                "label": label,
                "automatic_name": None,
                "custom_label": None,
                "asset_id": None,
                "network_device_id": None,
                "ip": None,
                "mac": None,
                "vendor": None,
                # Fase 7B-Fix1: un BSS lo sirve un punto de acceso (aunque no esté inventariado).
                "device_type": "access_point" if row.relation == "wlan_association" else None,
                "role": "unknown",
                "status": None,
                "managed": None,
                "risk_score": None,
                "risk_level": None,
                "criticality": None,
                "groups": [],
                "sources": [
                    row.relation
                    if row.relation in ("lldp", "cdp")
                    else "wlan"
                    if row.relation == "wlan_association"
                    else "lldp"
                ],
                "identity_confidence": "none",
                "link_count": 0,
            }
        )
        external = row.target_external or {}
        search = " ".join(
            str(v) for v in (label, external.get("chassis_id"), external.get("mgmt_address")) if v
        ).lower()
        self.nodes[row.target_node] = _Node(read, search)

    def groups_of(self, ip: str | None) -> list[str]:
        if ip:
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                address = None
            if address is not None:
                found = [
                    f"network:{cidr}"
                    for cidr, _, net in self.networks
                    if net.version == address.version and address in net
                ]
                if found:
                    return found
        return ["unassigned"]


# Fase 6E.1: diagnósticos SNMP que significan «la última consulta no dio evidencia válida».
# Con ellos, que falte un enlace de ese equipo no dice nada del enlace.
DEGRADED_SNMP = frozenset(
    {
        "no_response",
        "timeout",
        "unreachable",
        "auth_failed",
        "unsupported_version",
        "malformed_response",
        "collector_error",
    }
)


def snapshot_content(
    session: Session, settings: Settings, site_id: int, snapshot: Snapshot, result: DeriveResult
) -> SnapshotContent:
    """Estado compacto del grafo del site tras una reconstrucción (ver app/topology/history.py).

    Usa el mismo catálogo de nodos que el grafo (nada de inventario duplicado) y solo los
    enlaces presentes y no rechazados por un revisor: lo rechazado no forma parte de la red
    que el analista acepta, y sus idas y venidas no deben llenar el historial.
    """
    catalog = _Catalog(session, settings, site_id)
    rows = session.scalars(
        select(TopologyLink).where(
            TopologyLink.site_id == site_id,
            TopologyLink.present.is_(True),
            TopologyLink.review_state != "rejected",
        )
    ).all()
    for row in rows:
        if row.target_node.startswith("external:"):
            catalog.add_external(row)
    gateways: dict[str, list[str]] = {}
    for report in snapshot.gateways:
        key = catalog.asset_node.get(report.asset_id)
        if key is not None:
            gateways[key] = sorted(set(report.gateways))
    wifi: dict[str, dict[str, Any]] = {}
    links: dict[str, Any] = {}
    for row in rows:
        if row.source_node not in catalog.nodes or row.target_node not in catalog.nodes:
            continue
        evidence = list(row.evidence or [])
        links[row.link_key] = {
            "s": row.source_node,
            "t": row.target_node,
            "k": row.kind,
            "rel": row.relation,
            "c": row.confidence,
            "med": row.medium,
            "sp": row.source_port,
            "tp": row.target_port,
            "vlan": vlan_of(evidence),
            "id": str(row.public_id),
        }
        if row.relation == "wlan_association":
            wifi[row.target_node] = {"ap": row.source_node, "ssid": ssid_of(evidence)}
    nodes: dict[str, Any] = {}
    for key, node in catalog.nodes.items():
        read = node.read
        nodes[key] = {
            "kind": read.kind,
            "label": read.label,
            "ip": read.ip,
            "mac": read.mac,
            "vendor": read.vendor,
            "device_type": read.device_type,
            "role": read.role,
            "status": read.status,
            "managed": read.managed,
            "identity": read.identity_confidence,
            "gateways": gateways.get(key, []),
            "wifi": wifi.get(key),
        }
    degraded: set[str] = set()
    for device_id, status, paused in session.execute(
        select(
            NetworkDevice.id, NetworkDevice.snmp_status, NetworkDevice.monitoring_paused_at
        ).where(NetworkDevice.site_id == site_id, NetworkDevice.archived_at.is_(None))
    ):
        if status in DEGRADED_SNMP or paused is not None:
            node_key = catalog.device_node.get(device_id)
            if node_key is not None:
                degraded.add(node_key)
    for key, item in nodes.items():
        # Un agente sin contacto no informa su gateway: su enlace lógico puede faltar sin que
        # la red haya cambiado.
        if item["managed"] and item["status"] != "online":
            degraded.add(key)
    reasons: list[str] = []
    if result.links_dropped:
        reasons.append("links_truncated")
    if len(nodes) > settings.topology_max_nodes:
        reasons.append("nodes_over_limit")
    if reasons:
        quality = "partial"
    elif degraded:
        quality = "degraded"
        reasons.append("evidence_source_failed")
    else:
        quality = "complete"
    return SnapshotContent(
        nodes=nodes,
        links=links,
        quality=quality,
        reasons=reasons,
        degraded_nodes=frozenset(degraded),
    )


def _matches(node: _Node, q: str) -> bool:
    needle = q.strip().lower()
    if not needle:
        return True
    mac = normalize_mac(needle)
    if mac is not None and node.read.mac and node.read.mac.lower() == mac:
        return True
    return needle.replace("-", ":") in node.search or needle in node.read.label.lower()


def parse_node_id(node_id: str) -> str | None:
    """Clave de nodo canónica o None si está mal formada (UUID en minúsculas)."""
    if len(node_id) > 96 or not _NODE_ID.match(node_id):
        return None
    kind, _, rest = node_id.partition(":")
    if kind == "external":
        return node_id
    return f"{kind}:{UUID(rest)}"


# --- servicio ---------------------------------------------------------------------------------


@dataclass
class _Upserted:
    created: int = 0
    updated: int = 0
    absent: int = 0


class TopologyService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- site ---------------------------------------------------------------------------------

    def site(self, public_id: UUID | None) -> Site:
        """Site pedido o, sin site_id, el site por defecto. 404 site_not_found si no existe."""
        query = select(Site)
        query = (
            query.where(Site.public_id == public_id)
            if public_id is not None
            else query.where(Site.is_default.is_(True))
        )
        site = self._session.scalars(query).first()
        if site is None:
            raise SiteNotFoundError("Site not found")
        return site

    def _site_ref(self, site: Site) -> TopologySiteRef:
        return TopologySiteRef(id=site.public_id, name=site.name)

    def _last_build(self, site: Site) -> TopologyBuildRead | None:
        build = self._session.scalars(
            select(TopologyBuild)
            .where(TopologyBuild.site_id == site.id)
            .order_by(TopologyBuild.started_at.desc(), TopologyBuild.id.desc())
            .limit(1)
        ).first()
        return build_read(build, site.public_id) if build is not None else None

    # --- reconstrucción -----------------------------------------------------------------------

    def rebuild(self, site: Site, trigger: str, actor: Actor | None = None) -> TopologyBuildRead:
        """Reconstruye la topología del site en esta transacción.

        Manual (actor) se audita como topology_rebuilt; la periódica no, para no llenar la
        auditoría con una entrada por site cada pocos minutos (queda en topology_builds).
        """
        session = self._session
        site_id, site_public = site.id, site.public_id
        acquired = session.scalar(
            select(func.pg_try_advisory_xact_lock(topology_site_lock_key(site_id)))
        )
        if not acquired:
            session.rollback()
            raise SiteConflictError(
                "topology_build_running", "A topology rebuild is already running for this site"
            )
        started = _now()
        clock = time.perf_counter()
        build = TopologyBuild(
            site_id=site_id,
            trigger=trigger,
            requested_by=actor.name[:64] if actor is not None else None,
            status="running",
            started_at=started,
        )
        session.add(build)
        try:
            session.flush()
            snapshot = load_snapshot(session, site_id)
            result = derive_links(snapshot, self._settings.topology_max_links)
            upserted = self._upsert(site_id, result, started)
            # Fase 6E.1: snapshot y cambios en la MISMA transacción que los enlaces, para que
            # el historial nunca describa un estado que no llegó a guardarse.
            recorded = record_history(
                session,
                self._settings,
                site_id,
                build,
                snapshot_content(session, self._settings, site_id, snapshot, result),
            )
        except Exception:
            # Sin la traza en la respuesta ni en la fila: solo un código. El detalle va al log.
            logger.exception("topology rebuild failed", extra={"site_id": site_id})
            session.rollback()
            failed = TopologyBuild(
                site_id=site_id,
                trigger=trigger,
                requested_by=actor.name[:64] if actor is not None else None,
                status="failed",
                started_at=started,
                finished_at=_now(),
                duration_ms=int((time.perf_counter() - clock) * 1000),
                error_code="build_failed",
            )
            session.add(failed)
            if actor is not None:
                audit_service.record(
                    session,
                    actor,
                    "topology_rebuilt",
                    result=audit_service.FAILURE,
                    target_type="site",
                    target_id=site_public,
                    details={"error_code": "build_failed", "trigger": trigger},
                    commit=False,
                )
            session.commit()
            raise TopologyBuildFailedError("The topology rebuild failed") from None
        counts = {
            "links_created": upserted.created,
            "links_updated": upserted.updated,
            "links_absent": upserted.absent,
            "links_present": len(result.links),
            "links_dropped": result.links_dropped,
            "nodes": result.nodes,
            "ambiguous_macs": result.ambiguous_macs,
            "skipped_cross_site": result.skipped_cross_site,
            "changes_detected": recorded.changes,
            "snapshot_created": int(recorded.created),
        }
        build.status = "succeeded"
        build.counts = counts
        build.finished_at = _now()
        build.duration_ms = int((time.perf_counter() - clock) * 1000)
        if actor is not None:
            audit_service.record(
                session,
                actor,
                "topology_rebuilt",
                target_type="site",
                target_id=site_public,
                details={"build_id": str(build.public_id), "trigger": trigger, **counts},
                commit=False,
            )
        session.commit()
        return build_read(build, site_public)

    def _upsert(self, site_id: int, result: DeriveResult, now: datetime) -> _Upserted:
        session = self._session
        # FOR UPDATE: la revisión también bloquea su fila, así que una revisión concurrente
        # espera a la reconstrucción (o al revés) y nadie escribe una versión obsoleta. Sin el
        # bloqueo, un revisor podría aceptar con la versión nueva un enlace que la
        # reconstrucción ya había cambiado.
        existing = {
            row.link_key: row
            for row in session.scalars(
                select(TopologyLink)
                .where(TopologyLink.site_id == site_id)
                .order_by(TopologyLink.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        }
        out = _Upserted()
        for derived in result.links:
            row = existing.pop(derived.link_key, None)
            if row is None:
                row = TopologyLink(
                    site_id=site_id,
                    link_key=derived.link_key,
                    first_seen_at=now,
                    review_state="unreviewed",
                    version=1,
                )
                _apply(row, derived, now)
                session.add(row)
                out.created += 1
                continue
            before = (*(getattr(row, name) for name in _MATERIAL), row.present)
            _apply(row, derived, now)
            row.absent_builds = 0
            row.absent_since = None
            row.removed_at = None
            after = (*(getattr(row, name) for name in _MATERIAL), row.present)
            if before != after:
                # Solo un cambio material invalida la versión que tenga abierta un revisor; la
                # mera actualización de last_seen_at de cada vuelta no le da un 409.
                row.version += 1
                out.updated += 1
        for row in existing.values():
            if row.present:
                row.present = False
                row.version += 1
                row.absent_since = now
                row.absent_builds = 1
                out.absent += 1
            elif row.removed_at is None:
                # Solo se cuenta mientras no se haya concluido la eliminación: después el
                # contador ya no decide nada y no merece una escritura por reconstrucción.
                row.absent_builds = min((row.absent_builds or 0) + 1, 1_000_000)
        session.flush()
        return out

    # --- lecturas -----------------------------------------------------------------------------

    def graph(
        self,
        site: Site,
        *,
        kinds: Collection[str] | None,
        include_absent: bool,
        include_rejected: bool,
        device_type: str | None,
        q: str | None,
    ) -> TopologyGraph:
        session = self._session
        settings = self._settings
        max_nodes, max_links = settings.topology_max_nodes, settings.topology_max_links
        catalog = _Catalog(session, settings, site.id)
        query = select(TopologyLink).where(TopologyLink.site_id == site.id)
        if not include_absent:
            query = query.where(TopologyLink.present.is_(True))
        if not include_rejected:
            query = query.where(TopologyLink.review_state != "rejected")
        if kinds:
            query = query.where(TopologyLink.kind.in_(sorted(kinds)))
        rows = session.scalars(
            query.order_by(TopologyLink.present.desc(), _KIND_ORDER, TopologyLink.public_id).limit(
                max_links + 1
            )
        ).all()
        truncated = len(rows) > max_links
        rows = rows[:max_links]
        for row in rows:
            if row.target_node.startswith("external:"):
                catalog.add_external(row)
        # Un enlace cuyo extremo ya no es nodo (activo archivado tras la última
        # reconstrucción) no se muestra: la siguiente reconstrucción lo marcará ausente.
        links = [
            r for r in rows if r.source_node in catalog.nodes and r.target_node in catalog.nodes
        ]
        nodes = catalog.nodes
        selected: set[str] = set(nodes)
        if q or device_type:
            matched = {
                key
                for key, node in nodes.items()
                if (not q or _matches(node, q))
                and (not device_type or node.read.device_type == device_type)
            }
            links = [r for r in links if r.source_node in matched or r.target_node in matched]
            selected = matched | {r.source_node for r in links} | {r.target_node for r in links}
        if len(selected) > max_nodes:
            truncated = True
            linked = {r.source_node for r in links} | {r.target_node for r in links}
            ranked = sorted(
                selected,
                key=lambda key: (
                    key not in linked,
                    nodes[key].read.role != "infrastructure",
                    key,
                ),
            )
            selected = set(ranked[:max_nodes])
            links = [r for r in links if r.source_node in selected and r.target_node in selected]
        counts: dict[str, int] = defaultdict(int)
        for row in links:
            counts[row.source_node] += 1
            counts[row.target_node] += 1
        out_nodes: list[TopologyNode] = []
        group_sizes: dict[str, int] = defaultdict(int)
        for key in sorted(selected):
            groups = catalog.groups_of(nodes[key].read.ip)
            for group in groups:
                group_sizes[group] += 1
            out_nodes.append(
                nodes[key].read.model_copy(update={"groups": groups, "link_count": counts[key]})
            )
        names = {f"network:{cidr}": (cidr, name) for cidr, name, _ in catalog.networks}
        groups_out = [
            TopologyGroup(
                id=group,
                kind="unassigned" if group == "unassigned" else "network",
                cidr=names[group][0] if group in names else None,
                name=names[group][1] if group in names else None,
                node_count=size,
            )
            for group, size in sorted(group_sizes.items())
        ]
        return TopologyGraph(
            site=self._site_ref(site),
            generated_at=_now(),
            last_build=self._last_build(site),
            truncated=truncated,
            limits=TopologyLimits(max_nodes=max_nodes, max_links=max_links),
            nodes=out_nodes,
            links=sorted((link_read(r) for r in links), key=lambda link: str(link.id)),
            groups=groups_out,
            coverage=coverage(out_nodes, links),
        )

    def list_links(
        self,
        site: Site,
        *,
        kind: str | None,
        confidence: str | None,
        node: str | None,
        present: bool,
        review_state: str | None,
        limit: int,
        offset: int,
    ) -> TopologyLinkList:
        session = self._session
        query = select(TopologyLink).where(
            TopologyLink.site_id == site.id, TopologyLink.present.is_(present)
        )
        if kind is not None:
            query = query.where(TopologyLink.kind == kind)
        if confidence is not None:
            query = query.where(TopologyLink.confidence == confidence)
        if review_state is not None:
            query = query.where(TopologyLink.review_state == review_state)
        if node is not None:
            query = query.where(
                or_(TopologyLink.source_node == node, TopologyLink.target_node == node)
            )
        total = int(session.scalar(select(func.count()).select_from(query.subquery())) or 0)
        rows = session.scalars(
            query.order_by(TopologyLink.public_id).limit(limit).offset(offset)
        ).all()
        return TopologyLinkList(
            items=[link_read(r) for r in rows], total=total, limit=limit, offset=offset
        )

    def _link_row(self, link_id: str, site_id: int | None, lock: bool = False) -> TopologyLink:
        try:
            public_id = UUID(link_id)
        except ValueError:
            raise TopologyLinkNotFoundError("Topology link not found") from None
        query = select(TopologyLink).where(TopologyLink.public_id == public_id)
        if site_id is not None:
            query = query.where(TopologyLink.site_id == site_id)
        if lock:
            query = query.with_for_update()
        row = self._session.scalars(query).first()
        if row is None:
            raise TopologyLinkNotFoundError("Topology link not found")
        return row

    def get_link(self, link_id: str, site_id: int | None) -> TopologyLinkDetail:
        return link_detail(self._link_row(link_id, site_id))

    def review(
        self, link_id: str, site_id: int | None, body: TopologyReviewUpdate, actor: Actor
    ) -> TopologyLinkDetail:
        session = self._session
        row = self._link_row(link_id, site_id, lock=True)
        if body.version != row.version:
            raise SiteConflictError(
                "topology_link_conflict",
                "The link changed since it was read",
                [{"version": row.version, "review_state": row.review_state}],
            )
        previous = row.review_state
        note = body.note or None
        row.review_state = body.review_state
        row.review_note = note
        row.reviewed_by = actor.name[:64]
        row.reviewed_at = _now()
        row.version += 1
        audit_service.record(
            session,
            actor,
            "topology_link_reviewed",
            target_type="topology_link",
            target_id=row.public_id,
            details={
                "from": previous,
                "to": body.review_state,
                "note": note,
                "kind": row.kind,
                "relation": row.relation,
            },
            commit=False,
        )
        session.commit()
        return link_detail(row)

    def node_detail(self, site: Site, node_id: str) -> TopologyNodeDetail:
        key = parse_node_id(node_id)
        if key is None:
            raise TopologyNodeNotFoundError("Topology node not found")
        session = self._session
        catalog = _Catalog(session, self._settings, site.id)
        links = session.scalars(
            select(TopologyLink)
            .where(
                TopologyLink.site_id == site.id,
                TopologyLink.present.is_(True),
                or_(TopologyLink.source_node == key, TopologyLink.target_node == key),
            )
            .order_by(_KIND_ORDER, TopologyLink.public_id)
            .limit(NODE_DETAIL_LINKS)
        ).all()
        for row in links:
            if row.target_node.startswith("external:"):
                catalog.add_external(row)
        node = catalog.nodes.get(key)
        if node is None:
            raise TopologyNodeNotFoundError("Topology node not found")
        visible = [
            r for r in links if r.source_node in catalog.nodes and r.target_node in catalog.nodes
        ]
        # Mismo saneado que el detalle del activo: una entrada corrupta se descarta.
        observed = observed_name_items(node.observed_names)
        return TopologyNodeDetail(
            node=node.read.model_copy(
                update={"groups": catalog.groups_of(node.read.ip), "link_count": len(visible)}
            ),
            links=sorted((link_read(r) for r in visible), key=lambda link: str(link.id)),
            observed_names=observed,
            inventory_path=node.inventory_path,
        )

    def status(self, site: Site) -> TopologyStatus:
        session = self._session
        by_kind = dict.fromkeys(LINK_KINDS, 0)
        for kind, total in session.execute(
            select(TopologyLink.kind, func.count())
            .where(TopologyLink.site_id == site.id, TopologyLink.present.is_(True))
            .group_by(TopologyLink.kind)
        ):
            by_kind[kind] = int(total)
        gateways = AssetInventory.data["network"]["gateways"]
        available = TopologyEvidenceAvailability(
            lldp_cdp=bool(
                session.scalar(
                    select(
                        exists().where(
                            NetworkNeighbor.site_id == site.id, NetworkNeighbor.present.is_(True)
                        )
                    )
                )
            ),
            fdb=bool(
                session.scalar(
                    select(
                        exists().where(
                            NetworkMacEntry.site_id == site.id, NetworkMacEntry.present.is_(True)
                        )
                    )
                )
            ),
            wlan=bool(
                session.scalar(
                    select(
                        or_(
                            exists().where(
                                WlanClient.site_id == site.id, WlanClient.present.is_(True)
                            ),
                            exists().where(
                                WlanAccessPoint.site_id == site.id,
                                WlanAccessPoint.present.is_(True),
                            ),
                        )
                    )
                )
            ),
            agent_gateways=bool(
                session.scalar(
                    select(
                        exists()
                        .where(Asset.id == AssetInventory.asset_id)
                        .where(
                            Asset.site_id == site.id,
                            Asset.archived_at.is_(None),
                            func.jsonb_typeof(gateways) == "array",
                            func.jsonb_array_length(gateways) > 0,
                        )
                    )
                )
            ),
        )
        return TopologyStatus(
            site=self._site_ref(site),
            last_build=self._last_build(site),
            links_present=sum(by_kind.values()),
            links_by_kind=by_kind,
            evidence_available=available,
        )


def _apply(row: TopologyLink, derived: DerivedLink, now: datetime) -> None:
    """Copia lo derivado en la fila. Nunca toca review_state/review_note/reviewed_*."""
    row.kind = derived.kind
    row.medium = derived.medium
    row.relation = derived.relation
    row.confidence = derived.confidence
    row.source_node = derived.source.node
    row.target_node = derived.target.node
    for prefix, end in (("source", derived.source), ("target", derived.target)):
        setattr(row, f"{prefix}_asset_id", end.ref_id if end.kind == "asset" else None)
        setattr(row, f"{prefix}_device_id", end.ref_id if end.kind == "network_device" else None)
        setattr(row, f"{prefix}_ap_id", end.ref_id if end.kind == "wlan_ap" else None)
    row.source_interface_id = derived.source_interface_id
    row.source_port = derived.source_port
    row.target_port = derived.target_port
    row.target_external_label = derived.target_external_label
    row.target_external = derived.target_external
    row.evidence = derived.evidence
    row.evidence_sources = derived.evidence_sources
    row.present = True
    row.last_seen_at = now
    row.last_evidence_at = derived.last_evidence_at


# --- reconstrucción periódica -----------------------------------------------------------------


def due_sites(session: Session, interval: timedelta, now: datetime | None = None) -> list[Site]:
    """Sites activos cuya última reconstrucción (de cualquier tipo) es anterior al intervalo."""
    moment = now or _now()
    last = (
        select(TopologyBuild.site_id, func.max(TopologyBuild.started_at).label("last"))
        .group_by(TopologyBuild.site_id)
        .subquery()
    )
    return list(
        session.scalars(
            select(Site)
            .outerjoin(last, last.c.site_id == Site.id)
            .where(
                Site.status == "active",
                Site.archived_at.is_(None),
                or_(last.c.last.is_(None), last.c.last <= moment - interval),
            )
            .order_by(Site.id)
        )
    )


def run_scheduled_rebuilds(session: Session, settings: Settings) -> int:
    """Reconstruye los sites vencidos. Un site ocupado (409) o fallido no frena al resto."""
    minutes = settings.topology_rebuild_interval_minutes
    if minutes <= 0:
        return 0
    service = TopologyService(session, settings)
    done = 0
    for site in due_sites(session, timedelta(minutes=minutes)):
        try:
            service.rebuild(site, "scheduled")
            done += 1
        except SiteConflictError:
            continue
        except TopologyBuildFailedError:
            logger.warning("scheduled topology rebuild failed", extra={"site_id": site.id})
    return done


# --- informes v2 ------------------------------------------------------------------------------

_REPORT_KINDS = ("physical", "logical", "observed")


def _ids(session: Session, values: Iterable[int | UUID] | None, site_id: int) -> set[int] | None:
    if values is None:
        return None
    raw = list(values)
    internal = {v for v in raw if isinstance(v, int)}
    public = [v for v in raw if isinstance(v, UUID)]
    for part in chunks(public):
        internal.update(
            session.scalars(
                select(Asset.id).where(Asset.public_id.in_(part), Asset.site_id == site_id)
            )
        )
    return internal


def report_topology(
    session: Session,
    site_id: int | UUID,
    asset_ids: Iterable[int | UUID] | None = None,
    max_nodes: int = 60,
) -> dict[str, Any]:
    """Resumen de topología para los informes v2 (forma fija, ver docs/topology-engine.md).

    `site_id` y `asset_ids` admiten el id interno o el UUID público. Solo enlaces presentes,
    no rechazados y de clase physical, logical u observed: un informe no presenta candidatos
    ni relaciones de naturaleza desconocida como hechos. Con `asset_ids`, solo los enlaces
    que tocan esos activos. Determinista (ordenado) y acotado por `max_nodes`.
    """
    if isinstance(site_id, UUID):
        found = session.scalar(select(Site.id).where(Site.public_id == site_id))
        if found is None:
            raise SiteNotFoundError("Site not found")
        internal_site = int(found)
    else:
        internal_site = site_id
    wanted = _ids(session, asset_ids, internal_site)
    query = select(TopologyLink).where(
        TopologyLink.site_id == internal_site,
        TopologyLink.present.is_(True),
        TopologyLink.review_state != "rejected",
        TopologyLink.kind.in_(_REPORT_KINDS),
    )
    rows = session.scalars(query.order_by(_KIND_ORDER, TopologyLink.public_id)).all()
    if wanted is not None:
        # Filtro en Python sobre los enlaces del site (acotados por TOPOLOGY_MAX_LINKS) en vez
        # de un IN con miles de ids, que podría superar el límite de parámetros de PostgreSQL.
        rows = [r for r in rows if r.source_asset_id in wanted or r.target_asset_id in wanted]
    catalog = _Catalog(session, get_settings(), internal_site)
    for row in rows:
        if row.target_node.startswith("external:"):
            catalog.add_external(row)
    rows = [r for r in rows if r.source_node in catalog.nodes and r.target_node in catalog.nodes]
    degree: dict[str, int] = defaultdict(int)
    for row in rows:
        degree[row.source_node] += 1
        degree[row.target_node] += 1
    keys = sorted(
        degree,
        key=lambda key: (
            catalog.nodes[key].read.role != "infrastructure",
            -degree[key],
            key,
        ),
    )
    truncated = len(keys) > max_nodes
    kept = set(keys[:max_nodes])
    rows = [r for r in rows if r.source_node in kept and r.target_node in kept]
    built_at = session.scalar(
        select(func.max(TopologyBuild.finished_at)).where(
            TopologyBuild.site_id == internal_site, TopologyBuild.status == "succeeded"
        )
    )
    return {
        "nodes": [
            {
                "id": key,
                "label": catalog.nodes[key].read.label,
                "kind": catalog.nodes[key].read.kind,
                "device_type": catalog.nodes[key].read.device_type,
                "role": catalog.nodes[key].read.role,
            }
            for key in sorted(kept)
        ],
        "links": [
            {
                "source": r.source_node,
                "target": r.target_node,
                "kind": r.kind,
                "relation": r.relation,
                "confidence": r.confidence,
            }
            for r in sorted(rows, key=lambda r: (r.source_node, r.target_node, r.relation))
        ],
        "truncated": truncated,
        "built_at": built_at.isoformat() if built_at is not None else None,
    }
