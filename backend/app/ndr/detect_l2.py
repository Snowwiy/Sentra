"""Reglas de capa 2 sobre cada lote NDR (Fase 7E.2): ARP, puerta de enlace y DHCP.

Todo se evalúa por site y VLAN con la evidencia del lote recién ingerido más el estado
persistente (asociaciones IP-MAC y metadatos DHCP ya guardados). Ver el catálogo y los
criterios de veredicto en app/ndr/rules.py y docs/fase-7e-ndr-detections.md.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.ndr import NdrIpMacBinding, NdrProtocolObservation
from app.ndr.anomalies import Finding, record_finding
from app.ndr.ingest import IngestedBatch
from app.ndr.rules import ARP_001, ARP_002, ARP_003, DHCP_001, MITM_001

# Una asociación vista en las últimas 24 h es "activa": un cambio frente a ella se analiza.
BINDING_ACTIVE = timedelta(hours=24)
# Una MAC que apareció para esa IP hace menos de esto es "nueva" (no un par HA conocido).
BINDING_NEW = timedelta(hours=1)
# Un servidor DHCP visto por primera vez hace más de esto está "establecido".
DHCP_ESTABLISHED = timedelta(hours=1)
# Ventana para derivar puertas de enlace y servidores DNS de los metadatos DHCP guardados.
DHCP_LOOKBACK = timedelta(days=7)
ARP_002_IPS = 3
ARP_002_PROBABLE_UNSOLICITED = 10
UNSPECIFIED = {"0.0.0.0", "::"}  # noqa: S104  (sondas ARP RFC 5227, no un bind)


def _vlan(value: int | None) -> int:
    return value or 0


def gateway_ips(session: Session, site_id: int, now: datetime) -> set[str]:
    """IPs que algún servidor DHCP del site anuncia como router (opción 3), últimos 7 días."""
    rows = session.scalars(
        select(func.jsonb_array_elements_text(NdrProtocolObservation.data["routers"])).where(
            NdrProtocolObservation.site_id == site_id,
            NdrProtocolObservation.kind == "dhcp",
            NdrProtocolObservation.last_seen >= now - DHCP_LOOKBACK,
        )
    ).all()
    return {str(r) for r in rows}


def analyze_l2(session: Session, settings: Settings, batch: IngestedBatch) -> None:
    if not batch.arp and not batch.dhcp:
        return
    now = batch.received_at
    gateways = gateway_ips(session, batch.site.id, now)
    claims = _claims(batch)
    previous = _previous_bindings(session, batch.site.id, claims)
    _upsert_bindings(session, batch, claims, gateways)
    _rule_ip_mac_change(session, batch, claims, previous, gateways)
    _rule_multi_claim(session, batch, gateways)
    _rule_frame_mismatch(session, batch)
    _rule_dhcp_server(session, batch)


# --- asociaciones ---------------------------------------------------------------------------


def _claims(batch: IngestedBatch) -> dict[tuple[int, str], dict[str, dict[str, Any]]]:
    """(vlan, ip) -> mac -> {first, last, count, source, unsolicited} de este lote."""
    claims: dict[tuple[int, str], dict[str, dict[str, Any]]] = defaultdict(dict)

    def add(vlan: int, ip: str, mac: str, first: datetime, last: datetime, count: int, source: str,
            unsolicited: int = 0) -> None:  # fmt: skip
        entry = claims[(vlan, ip)].setdefault(
            mac,
            {"first": first, "last": last, "count": 0, "source": source, "unsolicited": 0},
        )
        entry["first"] = min(entry["first"], first)
        entry["last"] = max(entry["last"], last)
        entry["count"] += count
        entry["unsolicited"] += unsolicited
        if source == "dhcp":
            entry["source"] = "dhcp"

    for arp in batch.arp:
        if arp.sender_ip in UNSPECIFIED:
            continue
        add(_vlan(arp.vlan), arp.sender_ip, arp.sender_mac, arp.first_seen, arp.last_seen,
            arp.count, "arp", arp.unsolicited if arp.operation == "reply" else 0)  # fmt: skip
    for dhcp in batch.dhcp:
        if dhcp.message_type == "ack" and dhcp.your_ip and dhcp.your_ip not in UNSPECIFIED:
            add(_vlan(dhcp.vlan), dhcp.your_ip, dhcp.client_mac, dhcp.first_seen, dhcp.last_seen,
                dhcp.count, "dhcp")  # fmt: skip
    return claims


def _previous_bindings(
    session: Session, site_id: int, claims: dict[tuple[int, str], dict[str, dict[str, Any]]]
) -> dict[tuple[int, str], dict[str, NdrIpMacBinding]]:
    """Estado ANTES de este lote (se lee antes de actualizar las asociaciones)."""
    out: dict[tuple[int, str], dict[str, NdrIpMacBinding]] = defaultdict(dict)
    ips = list({ip for _, ip in claims})
    if not ips:
        return out
    for row in session.scalars(
        select(NdrIpMacBinding).where(
            NdrIpMacBinding.site_id == site_id, NdrIpMacBinding.ip.in_(ips)
        )
    ):
        out[(row.vlan_key, row.ip)][row.mac] = row
        session.expunge(row)
    return out


def _upsert_bindings(
    session: Session,
    batch: IngestedBatch,
    claims: dict[tuple[int, str], dict[str, dict[str, Any]]],
    gateways: set[str],
) -> None:
    rows = [
        {
            "site_id": batch.site.id,
            "vlan_key": vlan,
            "ip": ip,
            "mac": mac,
            "source": info["source"],
            "gateway": ip in gateways,
            "count": info["count"],
            "first_seen": info["first"],
            "last_seen": info["last"],
        }
        for (vlan, ip), macs in claims.items()
        for mac, info in macs.items()
    ]
    if not rows:
        return
    stmt = pg_insert(NdrIpMacBinding).values(rows)
    excluded = stmt.excluded
    session.execute(
        stmt.on_conflict_do_update(
            constraint="uq_ndr_ip_mac_bindings_key",
            set_={
                "count": NdrIpMacBinding.count + excluded.count,
                "first_seen": func.least(NdrIpMacBinding.first_seen, excluded.first_seen),
                "last_seen": func.greatest(NdrIpMacBinding.last_seen, excluded.last_seen),
                "source": excluded.source,
                "gateway": NdrIpMacBinding.gateway | excluded.gateway,
            },
        )
    )


# --- reglas ---------------------------------------------------------------------------------


def _rule_ip_mac_change(
    session: Session,
    batch: IngestedBatch,
    claims: dict[tuple[int, str], dict[str, dict[str, Any]]],
    previous: dict[tuple[int, str], dict[str, NdrIpMacBinding]],
    gateways: set[str],
) -> None:
    now = batch.received_at
    # MAC -> IPs que anuncia en este lote con respuestas no solicitadas (para MITM-001).
    unsolicited_by_mac: dict[str, set[str]] = defaultdict(set)
    for (_, ip), macs in claims.items():
        for mac, info in macs.items():
            if info["unsolicited"]:
                unsolicited_by_mac[mac].add(ip)
    for (vlan, ip), macs in claims.items():
        known = previous.get((vlan, ip), {})
        active = [row for row in known.values() if row.last_seen >= now - BINDING_ACTIVE]
        if not active:
            continue  # IP sin asociación activa previa: no hay referencia con la que comparar.
        # La asociación establecida es la más antigua de las activas; las demás MAC de este
        # lote son las candidatas (en una disputa, la establecida nunca es la "intrusa").
        established = min(active, key=lambda r: r.first_seen)
        disputed = established.mac in macs
        for mac, info in macs.items():
            if info["source"] == "dhcp" or mac == established.mac:
                # Una concesión DHCP para esa MAC explica el cambio (reasignación legítima).
                continue
            own = known.get(mac)
            is_new = own is None or own.first_seen >= now - BINDING_NEW
            if not is_new and not disputed:
                continue
            others = [row for row in active if row.mac != mac]
            in_batch = [established.mac] if disputed else []
            old = max(others, key=lambda r: r.last_seen)
            evidence = {
                "ip": ip,
                "vlan": vlan or None,
                "new_mac": mac,
                "previous_macs": [
                    {"mac": r.mac, "last_seen": r.last_seen, "first_seen": r.first_seen}
                    for r in others
                ],
                "both_in_window": bool(in_batch),
                "unsolicited_replies": info["unsolicited"],
            }
            if ip in gateways:
                other_claims = sorted(unsolicited_by_mac.get(mac, set()) - {ip})
                confirmed = bool(other_claims) and bool(in_batch)
                evidence["gateway"] = True
                evidence["other_ips_claimed"] = other_claims
                record_finding(
                    session,
                    batch.site.id,
                    batch.sensor.id,
                    Finding(
                        rule=MITM_001,
                        dedup_key=f"{vlan}|{ip}|{mac}",
                        verdict="confirmed" if confirmed else "probable",
                        severity="critical" if confirmed else "high",
                        summary=(
                            f"La puerta de enlace {ip} se anuncia con la MAC {mac} en lugar de"
                            f" {old.mac}."
                            + (
                                f" Esa MAC anuncia además {', '.join(other_claims[:5])} sin"
                                " petición previa y la MAC original sigue respondiendo:"
                                " envenenamiento ARP bidireccional."
                                if confirmed
                                else " Requiere verificar si hubo un cambio del router."
                            )
                        ),
                        evidence=evidence,
                        at=info["last"],
                        subject_ip=ip,
                        subject_mac=mac,
                    ),
                )
                continue
            record_finding(
                session,
                batch.site.id,
                batch.sensor.id,
                Finding(
                    rule=ARP_001,
                    dedup_key=f"{vlan}|{ip}|{mac}",
                    verdict="probable" if in_batch else "suspicious",
                    severity="medium",
                    summary=(
                        f"La IP {ip} se anuncia con la MAC {mac}; venía usando {old.mac}"
                        + (" y ambas alternan en la misma ventana." if in_batch else ".")
                    ),
                    evidence=evidence,
                    at=info["last"],
                    subject_ip=ip,
                    subject_mac=mac,
                ),
            )


def _rule_multi_claim(session: Session, batch: IngestedBatch, gateways: set[str]) -> None:
    # MACs de la propia puerta de enlace (proxy ARP legítimo de un router): no se evalúan.
    # Solo las establecidas antes de este lote: una MAC nueva que se apropia de la IP del
    # router no se vuelve "de confianza" por ello.
    gateway_macs = set(
        session.scalars(
            select(NdrIpMacBinding.mac).where(
                NdrIpMacBinding.site_id == batch.site.id,
                NdrIpMacBinding.ip.in_(gateways or {""}),
                NdrIpMacBinding.first_seen < batch.received_at - BINDING_NEW,
            )
        )
    )
    by_mac: dict[str, dict[str, Any]] = {}
    for arp in batch.arp:
        if arp.operation != "reply" or not arp.unsolicited or arp.sender_ip in UNSPECIFIED:
            continue
        entry = by_mac.setdefault(
            arp.sender_mac, {"ips": set(), "unsolicited": 0, "last": arp.last_seen}
        )
        entry["ips"].add(arp.sender_ip)
        entry["unsolicited"] += arp.unsolicited
        entry["last"] = max(entry["last"], arp.last_seen)
    for mac, entry in by_mac.items():
        if len(entry["ips"]) < ARP_002_IPS or mac in gateway_macs:
            continue
        probable = entry["unsolicited"] >= ARP_002_PROBABLE_UNSOLICITED
        ips = sorted(entry["ips"])
        record_finding(
            session,
            batch.site.id,
            batch.sensor.id,
            Finding(
                rule=ARP_002,
                dedup_key=mac,
                verdict="probable" if probable else "suspicious",
                severity="high" if probable else "medium",
                summary=(
                    f"La MAC {mac} anuncia {len(ips)} IP distintas con {entry['unsolicited']}"
                    " respuestas ARP no solicitadas."
                ),
                evidence={
                    "mac": mac,
                    "ips": ips,
                    "unsolicited_replies": entry["unsolicited"],
                    "includes_gateway": sorted(set(ips) & gateways),
                },
                at=entry["last"],
                subject_mac=mac,
            ),
        )


def _rule_frame_mismatch(session: Session, batch: IngestedBatch) -> None:
    for arp in batch.arp:
        if arp.operation != "reply" or not arp.eth_src_mac or arp.eth_src_mac == arp.sender_mac:
            continue
        record_finding(
            session,
            batch.site.id,
            batch.sensor.id,
            Finding(
                rule=ARP_003,
                dedup_key=f"{arp.sender_mac}|{arp.eth_src_mac}",
                verdict="suspicious",
                severity="low",
                summary=(
                    f"Respuesta ARP de {arp.sender_ip} con MAC {arp.sender_mac} enviada en una"
                    f" trama de la MAC {arp.eth_src_mac}."
                ),
                evidence={
                    "sender_ip": arp.sender_ip,
                    "sender_mac": arp.sender_mac,
                    "frame_mac": arp.eth_src_mac,
                    "target_ip": arp.target_ip,
                    "count": arp.count,
                },
                at=arp.last_seen,
                subject_ip=arp.sender_ip,
                subject_mac=arp.eth_src_mac,
            ),
        )


def _rule_dhcp_server(session: Session, batch: IngestedBatch) -> None:
    servers = [
        d
        for d in batch.dhcp
        if d.message_type in ("offer", "ack") and (d.server_ip or d.server_mac)
    ]
    if not servers:
        return
    now = batch.received_at
    established: dict[int, list[NdrProtocolObservation]] = defaultdict(list)
    for row in session.scalars(
        select(NdrProtocolObservation).where(
            NdrProtocolObservation.site_id == batch.site.id,
            NdrProtocolObservation.kind == "dhcp",
            NdrProtocolObservation.first_seen < now - DHCP_ESTABLISHED,
            NdrProtocolObservation.last_seen >= now - DHCP_LOOKBACK,
            NdrProtocolObservation.data["message_type"].astext.in_(("offer", "ack")),
        )
    ):
        established[_vlan(row.vlan)].append(row)
    for offer in servers:
        known = established.get(_vlan(offer.vlan), [])
        if not known:
            continue  # sin servidor establecido no hay referencia (instalación nueva).
        known_servers = {(r.peer_ip, (r.data or {}).get("server_mac")) for r in known}
        if (offer.server_ip, offer.server_mac) in known_servers or any(
            ip == offer.server_ip for ip, _ in known_servers
        ):
            continue
        routers = {tuple((r.data or {}).get("routers") or []) for r in known}
        dns = {tuple((r.data or {}).get("dns_servers") or []) for r in known}
        diverges = (offer.routers and tuple(offer.routers) not in routers) or (
            offer.dns_servers and tuple(offer.dns_servers) not in dns
        )
        record_finding(
            session,
            batch.site.id,
            batch.sensor.id,
            Finding(
                rule=DHCP_001,
                dedup_key=f"{_vlan(offer.vlan)}|{offer.server_ip}|{offer.server_mac}",
                verdict="probable" if diverges else "suspicious",
                severity="high" if diverges else "medium",
                summary=(
                    f"El servidor DHCP {offer.server_ip or '?'} ({offer.server_mac or '?'})"
                    " responde en un segmento ya servido por otro"
                    + (" y entrega otra puerta de enlace o DNS." if diverges else ".")
                ),
                evidence={
                    "server_ip": offer.server_ip,
                    "server_mac": offer.server_mac,
                    "offered_routers": list(offer.routers),
                    "offered_dns": list(offer.dns_servers),
                    "established_servers": sorted({f"{ip}|{mac}" for ip, mac in known_servers}),
                    "vlan": offer.vlan,
                },
                at=offer.last_seen,
                subject_ip=offer.server_ip,
                subject_mac=offer.server_mac,
            ),
        )
