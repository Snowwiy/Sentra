"""One asset per host: converge discovered records with the agent's asset.

A host can be known twice: discovery saw it on the network (no agent_id) and later an agent
enrolled from it. The agent's asset is the one that survives (its identity is stable and
authenticated); the discovered record is merged into it and deleted, keeping its network
history: first discovery time, exposed ports and their baseline, network changes and
alerts.

Matching, strongest first:
- MAC address: the discovered MAC is one of the agent's interface MACs;
- IP address: the discovered address is one of the agent's addresses, and the discovered
  record has no MAC or the same MAC. A known, different MAC means another device that now
  uses the address (e.g. DHCP): never merged.
If more than one discovered record matches, nothing is merged (ambiguous) and it is logged.
"""

import ipaddress
import logging
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app.discovery.probes import normalize_mac
from app.models.alert import Alert, AlertStatus
from app.models.asset import Asset, AssetCriticality
from app.models.change import AssetChange
from app.models.exposure import AssetPort, PortStateValue
from app.models.risk import RiskSnapshot
from app.repositories.alert_repository import AlertRepository
from app.risk.queue import request_recalculation
from app.services.asset_context_service import merge_context
from app.services.identification import refresh_identity
from app.vulnerabilities.queue import mark_dirty

logger = logging.getLogger(__name__)


def interface_identity(interfaces: Iterable[Mapping[str, Any]] | None) -> tuple[set[str], set[str]]:
    """(IP addresses, MACs) from an agent inventory's `interfaces` section."""
    ips: set[str] = set()
    macs: set[str] = set()
    for interface in interfaces or ():
        mac = normalize_mac(str(interface.get("mac") or ""))
        if mac:
            macs.add(mac)
        for raw in interface.get("addresses") or ():
            try:
                address = ipaddress.ip_address(str(raw).split("%")[0])
            except ValueError:
                continue
            if not (address.is_loopback or address.is_link_local or address.is_unspecified):
                ips.add(str(address))
    return ips, macs


def primary_mac(interfaces: Iterable[Mapping[str, Any]] | None, primary_ip: str) -> str | None:
    """MAC of the interface that carries the asset's primary address."""
    for interface in interfaces or ():
        addresses = {str(a).split("%")[0] for a in interface.get("addresses") or ()}
        if primary_ip in addresses:
            return normalize_mac(str(interface.get("mac") or ""))
    return None


def find_discovered_match(
    session: Session, ips: set[str], macs: set[str], exclude_id: int | None = None
) -> Asset | None:
    if not ips and not macs:
        return None
    conditions = []
    if macs:
        conditions.append(Asset.mac_address.in_(macs))
    if ips:
        conditions.append(Asset.primary_ip.in_(ips))
    query = select(Asset).where(Asset.agent_id.is_(None), or_(*conditions))
    if exclude_id is not None:
        query = query.where(Asset.id != exclude_id)
    candidates: Sequence[Asset] = session.scalars(query.with_for_update()).all()
    by_mac = [c for c in candidates if c.mac_address and c.mac_address in macs]
    by_ip = [
        c
        for c in candidates
        if c.primary_ip in ips and (not c.mac_address or c.mac_address in macs)
    ]
    matches = by_mac or by_ip
    if len(matches) > 1:
        logger.warning(
            "several discovered assets match one agent; not merged",
            extra={"candidates": [str(c.public_id) for c in matches]},
        )
        return None
    return matches[0] if matches else None


def adopt_discovered(session: Session, managed: Asset, ips: set[str], macs: set[str]) -> bool:
    """Merge the discovered record of this host (if any) into the agent's asset. No commit."""
    if managed.agent_id is None:
        return False
    if managed.primary_ip:
        ips = ips | {managed.primary_ip}
    if managed.mac_address:
        macs = macs | {managed.mac_address}
    source = find_discovered_match(session, ips, macs, exclude_id=managed.id)
    if source is None:
        return False
    merge_into(session, source=source, target=managed)
    return True


def merge_into(session: Session, *, source: Asset, target: Asset) -> None:
    """Move everything network-related from `source` to `target`, then delete `source`."""
    _merge_ports(session, source.id, target.id)
    session.execute(
        update(AssetChange).where(AssetChange.asset_id == source.id).values(asset_id=target.id)
    )
    alerts = AlertRepository(session)
    for alert in session.scalars(
        select(Alert).where(Alert.asset_id == source.id, Alert.status != AlertStatus.RESOLVED)
    ).all():
        # One active alert per asset and rule: keep the agent asset's, close the other.
        if alerts.get_active(target.id, alert.rule) is not None:
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = alert.last_triggered_at or alert.opened_at
    session.flush()
    session.execute(update(Alert).where(Alert.asset_id == source.id).values(asset_id=target.id))

    target.discovered_at = _earliest(target.discovered_at, source.discovered_at)
    target.exposure_baseline_at = _earliest(
        target.exposure_baseline_at, source.exposure_baseline_at
    )
    if source.last_network_seen_at and (
        target.last_network_seen_at is None
        or source.last_network_seen_at > target.last_network_seen_at
    ):
        target.last_network_seen_at = source.last_network_seen_at
        target.network_status = source.network_status
        target.network_misses = source.network_misses
        target.discovery_network = source.discovery_network
    target.discovery_sources = (
        sorted(set(target.discovery_sources or ()) | set(source.discovery_sources or ())) or None
    )
    target.mac_address = target.mac_address or source.mac_address
    target.reverse_dns = target.reverse_dns or source.reverse_dns
    target.vendor = target.vendor or source.vendor
    # Lo observado en la red (mDNS, NetBIOS, UPnP, gateway) se conserva como evidencia; lo
    # ya observado por el activo del agente gana si ambos tienen el mismo dato.
    observations = {**(source.identity_observations or {}), **(target.identity_observations or {})}
    target.identity_observations = observations or None
    # Se recalcula con el agente como fuente autoritativa: "PC probable" deducido de la red
    # pasa a ser el hostname y SO que reporta el agente. Sin puertos: con agente el tipo no
    # depende de ellos.
    refresh_identity(target)
    target.first_seen_at = min(target.first_seen_at, source.first_seen_at)
    # Fase 4I: la criticidad que un admin fijó en el activo descubierto no se pierde al
    # instalar el agente (salvo que el activo del agente ya tenga una no por defecto), y el
    # historial de riesgo sigue al activo superviviente.
    if target.criticality == AssetCriticality.MEDIUM:
        target.criticality = source.criticality
    session.execute(
        update(RiskSnapshot).where(RiskSnapshot.asset_id == source.id).values(asset_id=target.id)
    )
    # Fase 4L: el contexto que un admin configuró en el activo descubierto (rol, entorno,
    # etiquetas, historial...) sobrevive a la instalación del agente.
    merge_context(session, source=source, target=target)
    request_recalculation(session, [target.id])
    # Fase 5B: los puertos del activo descubierto pasan al del agente (exposición).
    mark_dirty(session, [target.id], "merge")
    logger.info(
        "discovered asset merged into agent asset",
        extra={"from": str(source.public_id), "into": str(target.public_id)},
    )
    session.delete(source)
    session.flush()


def _merge_ports(session: Session, source_id: int, target_id: int) -> None:
    existing = {
        (p.protocol, p.port): p
        for p in session.scalars(select(AssetPort).where(AssetPort.asset_id == target_id))
    }
    for port in session.scalars(select(AssetPort).where(AssetPort.asset_id == source_id)).all():
        kept = existing.get((port.protocol, port.port))
        if kept is None:
            port.asset_id = target_id
            continue
        kept.first_seen_at = min(kept.first_seen_at, port.first_seen_at)
        if port.last_seen_at > kept.last_seen_at:
            kept.last_seen_at = port.last_seen_at
            kept.state = port.state
            kept.opened_at = port.opened_at
            kept.closed_at = port.closed_at if port.state == PortStateValue.CLOSED else None
        session.delete(port)
    session.flush()


def _earliest(a: Any, b: Any) -> Any:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)
