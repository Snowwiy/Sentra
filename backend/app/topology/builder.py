"""Derivación pura de enlaces de topología de UN site (Fase 6D, docs/topology-engine.md).

Recibe la evidencia ya leída (dataclasses inmutables, sin sesión de base de datos) y devuelve
los enlaces derivados con su clave natural. Así cada regla se prueba sin PostgreSQL y el
resultado es determinista: mismas filas de entrada = mismos enlaces, en el mismo orden.

Reglas que este módulo garantiza (y que no dependen de quien lo llame):
- Todo lo que recibe es de un único site; aun así, una referencia a una fila que no está en
  la entrada (activo o equipo de otro site) nunca se resuelve y se cuenta como
  `skipped_cross_site`.
- Compartir subred o gateway nunca crea un enlace físico; solo LLDP/CDP crea `physical`.
- Una MAC que coincide con varios activos del site no crea enlace (`ambiguous_macs`), y nunca
  se fusionan activos ni se cambia una identidad.
- Los activos y equipos archivados no son nodos: sus enlaces no se derivan.
"""

import hashlib
import ipaddress
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from app.discovery.probes import normalize_mac

# Orden de prioridad de las clases (también para recortar al superar el tope de enlaces).
KIND_RANK = {"physical": 0, "logical": 1, "observed": 2, "candidate": 3, "unknown": 4}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
MAX_EVIDENCE = 8
MAX_DETAIL = 255
MAX_PORT = 255
MAX_LABEL = 255

# Clasificación de un equipo de red (6B) → tipo de dispositivo del inventario.
DEVICE_CLASS_TYPES = {
    "managed_switch": "network_switch",
    "router": "router",
    "access_point": "access_point",
    "firewall": "firewall",
}
INFRASTRUCTURE_TYPES = frozenset({"router", "network_switch", "access_point", "firewall"})


# --- entrada ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class AssetIn:
    id: int
    public_id: UUID
    ip: str | None
    mac: str | None
    archived: bool = False


@dataclass(frozen=True)
class DeviceIn:
    id: int
    public_id: UUID
    address: str
    label: str
    asset_id: int | None = None
    ip_forwarding: bool | None = None
    chassis_id: str | None = None
    bridge_mac: str | None = None
    archived: bool = False


@dataclass(frozen=True)
class InterfaceIn:
    id: int
    device_id: int
    label: str
    # Nombres alternativos (ifName, ifDescr, ifAlias) para casar el puerto que informa el
    # vecino con la interfaz local, ya normalizados.
    names: frozenset[str] = frozenset()


@dataclass(frozen=True)
class NeighborIn:
    id: int
    device_id: int
    protocol: str
    last_seen_at: datetime
    local_port: str | None = None
    interface_id: int | None = None
    remote_device_id: int | None = None
    remote_chassis_id: str | None = None
    remote_chassis_subtype: str | None = None
    remote_port: str | None = None
    remote_sys_name: str | None = None
    remote_mgmt_address: str | None = None
    remote_platform: str | None = None
    reciprocal: bool = False


@dataclass(frozen=True)
class MacIn:
    id: int
    device_id: int
    mac: str
    location: str
    last_seen_at: datetime
    interface_id: int | None = None
    bridge_port: int | None = None
    vlan_id: int | None = None


@dataclass(frozen=True)
class AccessPointIn:
    id: int
    public_id: UUID
    label: str
    last_seen_at: datetime
    present: bool = True
    asset_id: int | None = None
    network_device_id: int | None = None
    source_device_id: int | None = None


@dataclass(frozen=True)
class ClientIn:
    id: int
    identity_confidence: str
    last_seen_at: datetime
    asset_id: int | None = None
    access_point_id: int | None = None
    ssid: str | None = None
    mac: str | None = None


@dataclass(frozen=True)
class GatewayIn:
    asset_id: int
    gateways: tuple[str, ...]
    collected_at: datetime


@dataclass(frozen=True)
class Snapshot:
    """Evidencia de un site. Activos y equipos incluyen los archivados (marcados): así una
    referencia a uno archivado no se confunde con una referencia a otro site."""

    assets: Sequence[AssetIn] = ()
    devices: Sequence[DeviceIn] = ()
    interfaces: Sequence[InterfaceIn] = ()
    neighbors: Sequence[NeighborIn] = ()
    macs: Sequence[MacIn] = ()
    access_points: Sequence[AccessPointIn] = ()
    clients: Sequence[ClientIn] = ()
    gateways: Sequence[GatewayIn] = ()


# --- salida -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Endpoint:
    """Extremo de un enlace: clave de nodo y la fila a la que apunta (None si external)."""

    node: str
    kind: str
    ref_id: int | None = None


@dataclass
class DerivedLink:
    link_key: str
    kind: str
    medium: str
    relation: str
    confidence: str
    source: Endpoint
    target: Endpoint
    source_port: str | None
    target_port: str | None
    evidence: list[dict[str, Any]]
    evidence_sources: list[str]
    last_evidence_at: datetime | None
    source_interface_id: int | None = None
    target_external_label: str | None = None
    target_external: dict[str, Any] | None = None


@dataclass
class DeriveResult:
    links: list[DerivedLink]
    nodes: int
    ambiguous_macs: int
    skipped_cross_site: int
    links_dropped: int = 0
    external_nodes: list[str] = field(default_factory=list)


# --- utilidades -------------------------------------------------------------------------------


def norm_port(value: str | None) -> str:
    """Forma comparable de un nombre de puerto ("Gi1/0/1 " y "gi1/0/1" son el mismo)."""
    return " ".join((value or "").split()).lower()


def norm_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        return None


def _clip(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    text = " ".join(value.split())
    return text[:limit] if text else None


def link_key(kind: str, family: str, a: tuple[str, str], b: tuple[str, str]) -> str:
    """Clave natural (64 hex): clase + familia de relación + extremos ORDENADOS con puertos.

    Ordenar los extremos hace que los dos sentidos de un mismo cable (A informa de B y B de
    A) den la misma clave y, por tanto, una sola fila.
    """
    first, second = sorted((a, b))
    raw = "\x1f".join((kind, family, first[0], first[1], second[0], second[1]))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def external_key(chassis_id: str | None, sys_name: str | None, fallback: str) -> str:
    """Clave determinista de una identidad remota desconocida: chasis, si no sysName."""
    if chassis_id and chassis_id.strip():
        basis = "chassis:" + (normalize_mac(chassis_id) or chassis_id.strip().lower())
    elif sys_name and sys_name.strip():
        basis = "sysname:" + sys_name.strip().lower()
    else:
        basis = "neighbor:" + fallback
    return "external:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _evidence(source: str, detail: str, observed_at: datetime | None) -> dict[str, Any]:
    return {
        "source": source,
        "detail": (_clip(detail, MAX_DETAIL) or ""),
        "observed_at": observed_at.isoformat() if observed_at else None,
    }


# --- índice del site --------------------------------------------------------------------------


class _Index:
    def __init__(self, snap: Snapshot) -> None:
        self.all_assets = {a.id: a for a in snap.assets}
        self.assets = {a.id: a for a in snap.assets if not a.archived}
        self.all_devices = {d.id: d for d in snap.devices}
        self.devices = {d.id: d for d in snap.devices if not d.archived}
        self.interfaces = {i.id: i for i in snap.interfaces}
        self.aps = {ap.id: ap for ap in snap.access_points}
        self.assets_by_ip: dict[str, list[AssetIn]] = defaultdict(list)
        self.assets_by_mac: dict[str, list[AssetIn]] = defaultdict(list)
        for asset in sorted(self.assets.values(), key=lambda a: a.id):
            ip = norm_ip(asset.ip)
            if ip:
                self.assets_by_ip[ip].append(asset)
            mac = normalize_mac(asset.mac)
            if mac:
                self.assets_by_mac[mac].append(asset)
        self.devices_by_ip: dict[str, DeviceIn] = {}
        self.devices_by_chassis: dict[str, list[DeviceIn]] = defaultdict(list)
        for device in sorted(self.devices.values(), key=lambda d: d.id):
            ip = norm_ip(device.address)
            if ip:
                self.devices_by_ip.setdefault(ip, device)
            keys = set()
            for raw in (device.chassis_id, device.bridge_mac):
                if raw and raw.strip():
                    keys.add(normalize_mac(raw) or raw.strip().lower())
            for key in keys:
                self.devices_by_chassis[key].append(device)

    # Nodos: un equipo con activo (del site y no archivado) es SOLO el nodo del activo; un AP
    # vinculado es el nodo de su equipo o activo. Así ningún equipo aparece dos veces.

    def asset_ep(self, asset: AssetIn) -> Endpoint:
        return Endpoint(f"asset:{asset.public_id}", "asset", asset.id)

    def device_ep(self, device: DeviceIn) -> Endpoint:
        if device.asset_id is not None and device.asset_id in self.assets:
            return self.asset_ep(self.assets[device.asset_id])
        return Endpoint(f"network_device:{device.public_id}", "network_device", device.id)

    def ap_ep(self, ap: AccessPointIn) -> Endpoint:
        if ap.network_device_id is not None and ap.network_device_id in self.devices:
            return self.device_ep(self.devices[ap.network_device_id])
        if ap.asset_id is not None and ap.asset_id in self.assets:
            return self.asset_ep(self.assets[ap.asset_id])
        return Endpoint(f"wlan_ap:{ap.public_id}", "wlan_ap", ap.id)

    def node_count(self) -> int:
        nodes = {self.asset_ep(a).node for a in self.assets.values()}
        nodes.update(self.device_ep(d).node for d in self.devices.values())
        nodes.update(self.ap_ep(ap).node for ap in self.aps.values())
        return len(nodes)


class _Collector:
    """Acumula enlaces por clave y fusiona evidencias de la misma relación."""

    def __init__(self) -> None:
        self.links: dict[str, DerivedLink] = {}

    def add(self, link: DerivedLink) -> None:
        current = self.links.get(link.link_key)
        if current is None:
            self.links[link.link_key] = link
            return
        if CONFIDENCE_RANK[link.confidence] > CONFIDENCE_RANK[current.confidence]:
            current.confidence = link.confidence
        # LLDP manda sobre CDP como nombre de la relación cuando ambos informan del cable.
        if link.relation == "lldp" and current.relation == "cdp":
            current.relation = "lldp"
        seen = {(e["source"], e["detail"]) for e in current.evidence}
        for entry in link.evidence:
            if (entry["source"], entry["detail"]) not in seen and len(current.evidence) < (
                MAX_EVIDENCE
            ):
                current.evidence.append(entry)
                seen.add((entry["source"], entry["detail"]))
        current.evidence_sources = sorted({*current.evidence_sources, *link.evidence_sources})
        if link.last_evidence_at and (
            current.last_evidence_at is None or link.last_evidence_at > current.last_evidence_at
        ):
            current.last_evidence_at = link.last_evidence_at
        if current.source_port is None and link.source_port is not None:
            current.source_port = link.source_port
        if current.target_port is None and link.target_port is not None:
            current.target_port = link.target_port

    def pairs(self, kind: str) -> set[frozenset[str]]:
        return {
            frozenset((link.source.node, link.target.node))
            for link in self.links.values()
            if link.kind == kind
        }

    def nodes_with_links(self) -> set[str]:
        out: set[str] = set()
        for link in self.links.values():
            out.add(link.source.node)
            out.add(link.target.node)
        return out


# --- LLDP / CDP -------------------------------------------------------------------------------


@dataclass
class _Adjacency:
    row: NeighborIn
    local: Endpoint
    local_port: str | None
    local_names: frozenset[str]
    remote: Endpoint
    remote_port: str | None
    external_label: str | None = None
    external: dict[str, Any] | None = None


def _resolve_remote(
    index: _Index, row: NeighborIn, ambiguous: set[str], cross: list[int]
) -> tuple[Endpoint, str | None, dict[str, Any] | None]:
    """Extremo remoto: equipo informado, si no activo/equipo del MISMO site por dirección de
    gestión o MAC de chasis (solo si coincide con UNO), si no identidad externa."""
    if row.remote_device_id is not None:
        if row.remote_device_id in index.devices:
            return index.device_ep(index.devices[row.remote_device_id]), None, None
        if row.remote_device_id not in index.all_devices:
            # Apunta a un equipo que no es de este site: nunca se cruza.
            cross.append(row.id)
    ip = norm_ip(row.remote_mgmt_address)
    if ip:
        device = index.devices_by_ip.get(ip)
        if device is not None:
            return index.device_ep(device), None, None
        by_ip = index.assets_by_ip.get(ip, [])
        if len(by_ip) == 1:
            return index.asset_ep(by_ip[0]), None, None
    chassis = row.remote_chassis_id.strip() if row.remote_chassis_id else ""
    if chassis:
        mac = normalize_mac(chassis)
        devices = index.devices_by_chassis.get(mac or chassis.lower(), [])
        if len(devices) == 1:
            return index.device_ep(devices[0]), None, None
        if mac:
            by_mac = index.assets_by_mac.get(mac, [])
            if len(by_mac) == 1:
                return index.asset_ep(by_mac[0]), None, None
            if len(by_mac) > 1:
                ambiguous.add(mac)
    key = external_key(row.remote_chassis_id, row.remote_sys_name, f"{row.device_id}:{row.id}")
    label = _clip(row.remote_sys_name, MAX_LABEL) or _clip(chassis, MAX_LABEL) or "unknown"
    external = {
        "protocol": row.protocol,
        "chassis_id": _clip(row.remote_chassis_id, MAX_LABEL),
        "chassis_id_subtype": row.remote_chassis_subtype,
        "sys_name": _clip(row.remote_sys_name, MAX_LABEL),
        "platform": _clip(row.remote_platform, MAX_LABEL),
        "mgmt_address": row.remote_mgmt_address,
        "port_id": _clip(row.remote_port, MAX_PORT),
    }
    return Endpoint(key, "external", None), label, external


def _adjacencies(
    index: _Index, snap: Snapshot, ambiguous: set[str], cross: list[int]
) -> list[_Adjacency]:
    out: list[_Adjacency] = []
    for row in sorted(snap.neighbors, key=lambda n: n.id):
        device = index.devices.get(row.device_id)
        if device is None:
            continue
        local = index.device_ep(device)
        interface = index.interfaces.get(row.interface_id) if row.interface_id else None
        local_port = _clip(row.local_port, MAX_PORT) or (interface.label if interface else None)
        names = {norm_port(local_port)} | (set(interface.names) if interface else set())
        names.discard("")
        remote, label, external = _resolve_remote(index, row, ambiguous, cross)
        if remote.node == local.node:
            continue
        out.append(
            _Adjacency(
                row=row,
                local=local,
                local_port=local_port,
                local_names=frozenset(names),
                remote=remote,
                remote_port=_clip(row.remote_port, MAX_PORT),
                external_label=label,
                external=external,
            )
        )
    return out


def _ports_match(a: _Adjacency, b: _Adjacency) -> bool:
    """b es el sentido inverso de a si alguno de los dos informa del puerto del otro."""
    return bool(
        (a.remote_port and norm_port(a.remote_port) in b.local_names)
        or (b.remote_port and norm_port(b.remote_port) in a.local_names)
    )


def _adjacency_evidence(adj: _Adjacency) -> dict[str, Any]:
    remote = adj.external_label or adj.remote.node
    detail = (
        f"{adj.row.protocol.upper()}: port {adj.local_port or '?'} reports neighbor {remote}"
        f" port {adj.remote_port or '?'}"
    )
    return _evidence(adj.row.protocol, detail, adj.row.last_seen_at)


def _derive_link_layer(index: _Index, adjacencies: list[_Adjacency], out: _Collector) -> None:
    by_pair: dict[tuple[str, str], list[_Adjacency]] = defaultdict(list)
    for adj in adjacencies:
        by_pair[(adj.local.node, adj.remote.node)].append(adj)
    consumed: set[int] = set()
    for adj in adjacencies:
        if adj.row.id in consumed:
            continue
        consumed.add(adj.row.id)
        reverse: _Adjacency | None = None
        if adj.remote.kind != "external":
            candidates = [
                other
                for other in by_pair.get((adj.remote.node, adj.local.node), [])
                if other.row.id not in consumed
            ]
            matching = [other for other in candidates if _ports_match(adj, other)]
            if matching:
                reverse = matching[0]
            elif len(candidates) == 1 and (not adj.remote_port or not candidates[0].remote_port):
                # Un solo sentido inverso y sin puertos que lo contradigan: es el mismo cable.
                reverse = candidates[0]
        if reverse is not None:
            consumed.add(reverse.row.id)
            ends = sorted(
                [
                    (adj.local, adj.local_port, adj.row.interface_id),
                    (reverse.local, reverse.local_port, reverse.row.interface_id),
                ],
                key=lambda end: (end[0].node, norm_port(end[1])),
            )
            (src, src_port, src_if), (dst, dst_port, _) = ends
            protocols = {adj.row.protocol, reverse.row.protocol}
            out.add(
                DerivedLink(
                    link_key=link_key(
                        "physical",
                        "link_layer",
                        (src.node, norm_port(src_port)),
                        (dst.node, norm_port(dst_port)),
                    ),
                    kind="physical",
                    medium="wired",
                    relation="lldp" if "lldp" in protocols else "cdp",
                    confidence="high",
                    source=src,
                    target=dst,
                    source_port=src_port,
                    target_port=dst_port,
                    evidence=[_adjacency_evidence(adj), _adjacency_evidence(reverse)],
                    evidence_sources=sorted(protocols),
                    last_evidence_at=max(adj.row.last_seen_at, reverse.row.last_seen_at),
                    source_interface_id=src_if,
                )
            )
            continue
        # Sin el sentido inverso: la adyacencia la informa un equipo. Recíproca según el
        # propio colector (reciprocal) → high; resuelta sin reciprocidad o externa → medium.
        external = adj.remote.kind == "external"
        confidence = "high" if adj.row.reciprocal and not external else "medium"
        out.add(
            DerivedLink(
                link_key=link_key(
                    "physical",
                    "link_layer",
                    (adj.local.node, norm_port(adj.local_port)),
                    (adj.remote.node, norm_port(adj.remote_port)),
                ),
                kind="physical",
                medium="wired",
                relation=adj.row.protocol if adj.row.protocol in ("lldp", "cdp") else "lldp",
                confidence=confidence,
                source=adj.local,
                target=adj.remote,
                source_port=adj.local_port,
                target_port=adj.remote_port,
                evidence=[_adjacency_evidence(adj)],
                evidence_sources=[adj.row.protocol],
                last_evidence_at=adj.row.last_seen_at,
                source_interface_id=adj.row.interface_id,
                target_external_label=adj.external_label,
                target_external=adj.external,
            )
        )


# --- tablas MAC (FDB) -------------------------------------------------------------------------


def _port_key(row: MacIn) -> tuple[int, str]:
    if row.interface_id is not None:
        return (row.device_id, f"if:{row.interface_id}")
    return (row.device_id, f"bp:{row.bridge_port}")


def _derive_fdb(
    index: _Index, snap: Snapshot, out: _Collector, ambiguous: set[str]
) -> list[tuple[MacIn, Endpoint, Endpoint, str | None]]:
    """Enlaces edge/shared; devuelve los `unknown` para decidirlos al final."""
    rows = sorted(snap.macs, key=lambda m: m.id)
    macs_per_port: dict[tuple[int, str], set[str]] = defaultdict(set)
    for row in rows:
        macs_per_port[_port_key(row)].add(row.mac)
    physical = out.pairs("physical")
    deferred: list[tuple[MacIn, Endpoint, Endpoint, str | None]] = []
    for row in rows:
        device = index.devices.get(row.device_id)
        if device is None or row.location == "uplink_or_shared":
            # Un uplink ve todo lo que hay detrás: no dice dónde está conectado nada.
            continue
        mac = normalize_mac(row.mac)
        if mac is None:
            continue
        matches = index.assets_by_mac.get(mac, [])
        if len(matches) > 1:
            ambiguous.add(mac)
            continue
        if not matches:
            continue
        switch = index.device_ep(device)
        host = index.asset_ep(matches[0])
        if switch.node == host.node:
            continue
        interface = index.interfaces.get(row.interface_id) if row.interface_id else None
        port = (
            interface.label
            if interface
            else (f"bridge port {row.bridge_port}" if row.bridge_port is not None else None)
        )
        if row.location == "unknown":
            deferred.append((row, switch, host, port))
            continue
        if row.location != "edge_candidate":
            continue
        if frozenset((switch.node, host.node)) in physical:
            # LLDP/CDP ya demuestra la adyacencia: la tabla MAC no añade un enlace más débil.
            continue
        count = len(macs_per_port[_port_key(row)])
        kind, relation, confidence = (
            ("observed", "fdb_edge", "medium") if count == 1 else ("candidate", "fdb_shared", "low")
        )
        vlan = f" vlan {row.vlan_id}" if row.vlan_id is not None else ""
        out.add(
            DerivedLink(
                link_key=link_key(kind, relation, (switch.node, norm_port(port)), (host.node, "")),
                kind=kind,
                medium="wired",
                relation=relation,
                confidence=confidence,
                source=switch,
                target=host,
                source_port=port,
                target_port=None,
                evidence=[
                    _evidence(
                        "fdb",
                        f"MAC {mac} learned on port {port or '?'}{vlan}; {count} MAC(s) on the"
                        " port (access port candidate)",
                        row.last_seen_at,
                    )
                ],
                evidence_sources=["fdb"],
                last_evidence_at=row.last_seen_at,
                source_interface_id=row.interface_id,
            )
        )
    return deferred


def _derive_fdb_unmapped(
    deferred: list[tuple[MacIn, Endpoint, Endpoint, str | None]], out: _Collector
) -> None:
    linked = out.nodes_with_links()
    for row, switch, host, port in deferred:
        # Solo si esa MAC (su activo) no tiene ningún otro enlace en el site: si lo tiene, un
        # "algo hay en algún puerto" no aporta nada y solo añade ruido.
        if host.node in linked:
            continue
        out.add(
            DerivedLink(
                link_key=link_key(
                    "unknown", "fdb_unmapped", (switch.node, norm_port(port)), (host.node, "")
                ),
                kind="unknown",
                medium="unknown",
                relation="fdb_unmapped",
                confidence="low",
                source=switch,
                target=host,
                source_port=port,
                target_port=None,
                evidence=[
                    _evidence(
                        "fdb",
                        f"MAC {row.mac} learned on a bridge port that could not be mapped",
                        row.last_seen_at,
                    )
                ],
                evidence_sources=["fdb"],
                last_evidence_at=row.last_seen_at,
                source_interface_id=row.interface_id,
            )
        )


# --- WLAN -------------------------------------------------------------------------------------

_WLAN_CONFIDENCE = {"confirmed": "high", "probable": "medium"}


def _derive_wlan(index: _Index, snap: Snapshot, out: _Collector, cross: list[int]) -> None:
    for client in sorted(snap.clients, key=lambda c: c.id):
        if client.asset_id is None or client.access_point_id is None:
            continue
        if client.asset_id not in index.all_assets or client.access_point_id not in index.aps:
            cross.append(client.id)
            continue
        asset = index.assets.get(client.asset_id)
        confidence = _WLAN_CONFIDENCE.get(client.identity_confidence)
        if asset is None or confidence is None:
            # Archivado, o MAC aleatoria / sin correlación: no hay identidad que enlazar.
            continue
        ap = index.ap_ep(index.aps[client.access_point_id])
        host = index.asset_ep(asset)
        if ap.node == host.node:
            continue
        ssid = f" SSID {client.ssid}" if client.ssid else ""
        out.add(
            DerivedLink(
                link_key=link_key("observed", "wlan_association", (ap.node, ""), (host.node, "")),
                kind="observed",
                medium="wireless",
                relation="wlan_association",
                confidence=confidence,
                source=ap,
                target=host,
                source_port=None,
                target_port=None,
                evidence=[
                    _evidence(
                        "wlan",
                        f"Client associated to the access point{ssid}; identity"
                        f" {client.identity_confidence}",
                        client.last_seen_at,
                    )
                ],
                evidence_sources=["wlan"],
                last_evidence_at=client.last_seen_at,
            )
        )
    for row in sorted(snap.access_points, key=lambda a: a.id):
        if not row.present or row.source_device_id is None:
            continue
        controller_row = index.devices.get(row.source_device_id)
        if controller_row is None:
            if row.source_device_id not in index.all_devices:
                cross.append(row.id)
            continue
        controller = index.device_ep(controller_row)
        ap = index.ap_ep(row)
        if controller.node == ap.node:
            # AP autónomo consultado directamente: no hay relación de gestión que mostrar.
            continue
        out.add(
            DerivedLink(
                link_key=link_key(
                    "logical", "wlan_managed_by", (controller.node, ""), (ap.node, "")
                ),
                kind="logical",
                medium="unknown",
                relation="wlan_managed_by",
                confidence="high",
                source=controller,
                target=ap,
                source_port=None,
                target_port=None,
                evidence=[
                    _evidence(
                        "wlan",
                        f"Access point {row.label} reported by controller {controller_row.label}",
                        row.last_seen_at,
                    )
                ],
                evidence_sources=["wlan"],
                last_evidence_at=row.last_seen_at,
            )
        )


# --- gateways de agentes ----------------------------------------------------------------------


def _derive_gateways(index: _Index, snap: Snapshot, out: _Collector) -> None:
    for report in sorted(snap.gateways, key=lambda g: g.asset_id):
        asset = index.assets.get(report.asset_id)
        if asset is None:
            continue
        host = index.asset_ep(asset)
        for ip in sorted({ip for ip in (norm_ip(g) for g in report.gateways) if ip}):
            device = index.devices_by_ip.get(ip)
            candidates: dict[str, Endpoint] = {}
            if device is not None:
                endpoint = index.device_ep(device)
                candidates[endpoint.node] = endpoint
            for match in index.assets_by_ip.get(ip, []):
                endpoint = index.asset_ep(match)
                candidates[endpoint.node] = endpoint
            # Solo si la IP es de UN nodo del site: una IP repetida (duplicados, DHCP
            # reasignado) no permite saber cuál es el gateway.
            if len(candidates) != 1:
                continue
            (gateway,) = candidates.values()
            if gateway.node == host.node:
                continue
            forwarding = device is not None and device.ip_forwarding is True
            evidence = [
                _evidence("agent", f"Agent reports default gateway {ip}", report.collected_at)
            ]
            sources = ["agent"]
            if forwarding:
                evidence.append(
                    _evidence("snmp", "Gateway device reports IP forwarding enabled", None)
                )
                sources.append("snmp")
            out.add(
                DerivedLink(
                    link_key=link_key(
                        "logical", "default_gateway", (host.node, ""), (gateway.node, "")
                    ),
                    kind="logical",
                    medium="unknown",
                    relation="default_gateway",
                    confidence="high" if forwarding else "medium",
                    source=host,
                    target=gateway,
                    source_port=None,
                    target_port=None,
                    evidence=evidence,
                    evidence_sources=sorted(sources),
                    last_evidence_at=report.collected_at,
                )
            )


# --- entrada principal ------------------------------------------------------------------------


def derive_links(snap: Snapshot, max_links: int | None = None) -> DeriveResult:
    """Enlaces derivados de la evidencia de un site, ordenados por (clase, clave).

    ARP, DNS, mDNS, NetBIOS, SSDP y OUI no se usan aquí: alimentan la identidad del nodo y
    su pertenencia a redes, nunca un enlace.
    """
    index = _Index(snap)
    ambiguous: set[str] = set()
    cross: list[int] = []
    out = _Collector()
    _derive_link_layer(index, _adjacencies(index, snap, ambiguous, cross), out)
    _derive_wlan(index, snap, out, cross)
    _derive_gateways(index, snap, out)
    deferred = _derive_fdb(index, snap, out, ambiguous)
    _derive_fdb_unmapped(deferred, out)
    links = sorted(out.links.values(), key=lambda link: (KIND_RANK[link.kind], link.link_key))
    dropped = 0
    if max_links is not None and len(links) > max_links:
        dropped = len(links) - max_links
        links = links[:max_links]
    externals = sorted({link.target.node for link in links if link.target.kind == "external"})
    return DeriveResult(
        links=links,
        nodes=index.node_count() + len(externals),
        ambiguous_macs=len(ambiguous),
        skipped_cross_site=len(cross),
        links_dropped=dropped,
        external_nodes=externals,
    )


def interface_names(*values: str | None) -> frozenset[str]:
    return frozenset(name for name in (norm_port(v) for v in values) if name)
