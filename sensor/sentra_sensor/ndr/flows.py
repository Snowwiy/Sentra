"""Normalización determinista de flujos y agregación de metadatos de protocolo (Fase 7E.1).

Un flujo es la conversación bidireccional de una 5-tupla (más VLAN): los dos sentidos se unen
con una clave canónica (extremos ordenados), y el iniciador se infiere de lo observado (SYN
sin ACK, petición ICMP, puerto de servicio conocido). Lo que no se puede inferir se marca en
vez de suponerlo: `midstream` (la captura empezó con la conexión ya abierta, p. ej. tras un
reinicio del sensor), `asymmetric` (solo se vio un sentido: el SPAN no copia el retorno o la
ruta es asimétrica), `fragmented` y `retransmissions`.

Exportación incremental: un flujo largo se exporta cada `active_timeout` con contadores
ACUMULADOS y el mismo `uid`, de forma que el servidor puede deduplicar reenvíos y aplicar
segmentos fuera de orden quedándose con el máximo (idempotente). El `uid` mezcla un
identificador aleatorio de esta ejecución: tras un reinicio una conexión ya abierta es un flujo
nuevo marcado `midstream`, nunca la continuación inventada del anterior.

La ausencia de paquetes no se interpreta como ausencia de actividad: un flujo sin tráfico se
exporta por inactividad (`timeout`), que solo dice "dejó de verse desde este punto".
"""

import hashlib
import ipaddress
import os
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentra_sensor.ndr.decode import (
    DHCP_PORTS,
    PROTO_ICMP,
    PROTO_ICMPV6,
    PROTO_TCP,
    PROTO_UDP,
    TCP_ACK,
    TCP_FIN,
    TCP_RST,
    TCP_SYN,
    TRANSPORT_NAMES,
    Packet,
)

# Un flujo cerrado (FIN en los dos sentidos o RST) se exporta tras esta espera, por si llegan
# los últimos ACK; así no nace un "flujo nuevo" de dos paquetes por cada cierre.
CLOSE_LINGER_SECONDS = 2.0
# Peticiones ICMP/ICMPv6 que identifican al iniciador.
_ICMP_REQUESTS = frozenset({(PROTO_ICMP, 8), (PROTO_ICMP, 13), (PROTO_ICMPV6, 128)})
_ICMP_REPLIES = frozenset({(PROTO_ICMP, 0), (PROTO_ICMP, 14), (PROTO_ICMPV6, 129)})
# Puertos de servicio: con la conexión ya empezada, el extremo con uno de estos puertos (o el
# puerto más bajo por debajo de 1024) se toma como servidor. Es una inferencia y el flujo
# queda marcado `midstream` para que nadie la tome por un hecho.
_SERVICE_PORTS = frozenset({53, 67, 80, 123, 137, 161, 443, 445, 514, 1900, 3389, 5353, 8080})

# Topes de las tablas de observaciones por ventana de exportación.
MAX_ARP_ENTRIES = 5000
MAX_DNS_ENTRIES = 10_000
MAX_DHCP_ENTRIES = 2000
MAX_TLS_ENTRIES = 5000
MAX_RECENT_ARP_REQUESTS = 4096
ARP_REQUEST_MEMORY_SECONDS = 5.0


def iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat()


def _ip_key(value: str) -> tuple[int, int]:
    address = ipaddress.ip_address(value)
    return address.version, int(address)


@dataclass(slots=True)
class Flow:
    uid: str
    ip_version: int
    protocol: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    vlan: int | None
    first_seen: float
    last_seen: float
    client_mac: str | None = None
    server_mac: str | None = None
    packets_out: int = 0
    packets_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    flags_out: int = 0
    flags_in: int = 0
    midstream: bool = False
    syn_seen: bool = False
    synack_seen: bool = False
    fin_out: bool = False
    fin_in: bool = False
    reset: bool = False
    retransmissions: int = 0
    fragments: int = 0
    icmp_type: int | None = None
    last_seq_out: int | None = None
    last_seq_in: int | None = None
    closed_at: float | None = None
    segment: int = 0
    dirty: bool = True
    last_export: float = 0.0
    hints: set[str] = field(default_factory=set)

    def state(self, reason: str | None = None) -> str:
        if self.reset:
            return "reset"
        if self.fin_out and self.fin_in:
            return "closed"
        return reason or "open"

    def to_json(self, reason: str | None, final: bool) -> dict[str, Any]:
        flags: list[str] = []
        if self.midstream:
            flags.append("midstream")
        if (self.packets_out == 0) != (self.packets_in == 0):
            # Un solo sentido observado: no prueba que el otro no exista (ver docstring).
            flags.append("asymmetric")
        if self.fragments:
            flags.append("fragmented")
        if self.retransmissions:
            flags.append("retransmissions")
        if self.protocol == PROTO_TCP and self.syn_seen and not self.synack_seen:
            flags.append("no_handshake_reply")
        return {
            "uid": self.uid,
            "segment": self.segment,
            "ip_version": self.ip_version,
            "transport": TRANSPORT_NAMES.get(self.protocol, str(self.protocol)),
            "src_ip": self.client_ip,
            "src_port": self.client_port if self.protocol in (PROTO_TCP, PROTO_UDP) else None,
            "dst_ip": self.server_ip,
            "dst_port": self.server_port if self.protocol in (PROTO_TCP, PROTO_UDP) else None,
            "vlan": self.vlan,
            "src_mac": self.client_mac,
            "dst_mac": self.server_mac,
            "first_seen": iso(self.first_seen),
            "last_seen": iso(self.last_seen),
            "packets_out": self.packets_out,
            "packets_in": self.packets_in,
            "bytes_out": self.bytes_out,
            "bytes_in": self.bytes_in,
            "tcp_flags_out": self.flags_out,
            "tcp_flags_in": self.flags_in,
            "state": self.state(reason),
            "final": final,
            "flags": flags,
            "retransmissions": self.retransmissions,
            "fragments": self.fragments,
            "icmp_type": self.icmp_type,
            "app_hints": sorted(self.hints)[:4],
        }


@dataclass
class FlowStats:
    flows_created: int = 0
    flows_evicted: int = 0
    flows_exported: int = 0
    unattributed_fragments: int = 0
    non_ip: int = 0


class FlowTable:
    """Tabla de flujos activos acotada en número (LRU por última actividad)."""

    def __init__(
        self,
        max_flows: int,
        idle_timeout: float,
        active_timeout: float,
        run_id: str | None = None,
    ) -> None:
        self.max_flows = max_flows
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        # Identificador aleatorio de esta ejecución para el uid (ver docstring del módulo).
        self.run_id = run_id or os.urandom(8).hex()
        self._flows: OrderedDict[tuple[Any, ...], Flow] = OrderedDict()
        self._pending: list[dict[str, Any]] = []
        self.stats = FlowStats()

    def __len__(self) -> int:
        return len(self._flows)

    def _uid(self, key: tuple[Any, ...], first_seen: float) -> str:
        raw = f"{self.run_id}|{key}|{first_seen:.6f}".encode()
        return hashlib.sha256(raw).hexdigest()[:32]

    def add(self, packet: Packet) -> None:
        if packet.src_ip is None or packet.dst_ip is None or packet.protocol is None:
            self.stats.non_ip += 1
            return
        if packet.fragment and not packet.first_fragment:
            # Sin cabecera de transporte no hay puertos: no se inventa a qué flujo pertenece.
            self.stats.unattributed_fragments += 1
            return
        sport = packet.src_port or 0
        dport = packet.dst_port or 0
        if packet.protocol in (PROTO_ICMP, PROTO_ICMPV6):
            sport = dport = 0
        a = (_ip_key(packet.src_ip), sport)
        b = (_ip_key(packet.dst_ip), dport)
        key = (packet.ip_version, packet.protocol, vlan := packet.vlan, *sorted((a, b)))
        flow = self._flows.get(key)
        if flow is not None and flow.closed_at is not None and packet.tcp_flags & TCP_SYN:
            # Reutilización de la 5-tupla tras un cierre: es otra conexión.
            self._export(key, flow, None, final=True)
            flow = None
        if flow is None:
            flow = self._create(key, packet, vlan)
        else:
            self._flows.move_to_end(key)
        self._update(flow, packet)

    def _create(self, key: tuple[Any, ...], packet: Packet, vlan: int | None) -> Flow:
        if len(self._flows) >= self.max_flows:
            # Tabla llena: se exporta antes de tiempo el flujo menos reciente en vez de perder
            # el nuevo. Queda contado como degradación de cobertura (flows_evicted).
            old_key, old_flow = next(iter(self._flows.items()))
            self._export(old_key, old_flow, "evicted", final=True)
            self.stats.flows_evicted += 1
        assert packet.src_ip is not None and packet.dst_ip is not None  # noqa: S101
        assert packet.protocol is not None and packet.ip_version is not None  # noqa: S101
        client_is_src, midstream = _initiator(packet)
        src = (packet.src_ip, packet.src_port or 0, packet.src_mac)
        dst = (packet.dst_ip, packet.dst_port or 0, packet.dst_mac)
        client, server = (src, dst) if client_is_src else (dst, src)
        flow = Flow(
            uid=self._uid(key, packet.timestamp),
            ip_version=packet.ip_version,
            protocol=packet.protocol,
            client_ip=client[0],
            client_port=client[1],
            server_ip=server[0],
            server_port=server[1],
            vlan=vlan,
            first_seen=packet.timestamp,
            last_seen=packet.timestamp,
            client_mac=client[2],
            server_mac=server[2],
            midstream=midstream,
            last_export=packet.timestamp,
        )
        if packet.protocol in (PROTO_ICMP, PROTO_ICMPV6):
            flow.icmp_type = packet.icmp_type
        self._flows[key] = flow
        self.stats.flows_created += 1
        return flow

    def _update(self, flow: Flow, packet: Packet) -> None:
        outbound = packet.src_ip == flow.client_ip and (
            (packet.src_port or 0) == flow.client_port
            or packet.protocol in (PROTO_ICMP, PROTO_ICMPV6)
        )
        if flow.client_ip == flow.server_ip and flow.client_port == flow.server_port:
            outbound = True
        flow.last_seen = max(flow.last_seen, packet.timestamp)
        flow.dirty = True
        size = packet.wire_length
        flags = packet.tcp_flags
        if packet.fragment:
            flow.fragments += 1
        if outbound:
            flow.packets_out += 1
            flow.bytes_out += size
            flow.flags_out |= flags
            if flow.client_mac is None:
                flow.client_mac = packet.src_mac
        else:
            flow.packets_in += 1
            flow.bytes_in += size
            flow.flags_in |= flags
            if flow.server_mac is None:
                flow.server_mac = packet.src_mac
        if packet.protocol == PROTO_TCP:
            if flags & TCP_SYN and not flags & TCP_ACK:
                flow.syn_seen = True
            if flags & TCP_SYN and flags & TCP_ACK:
                flow.synack_seen = True
            if flags & TCP_RST:
                flow.reset = True
                flow.closed_at = packet.timestamp
            if flags & TCP_FIN:
                if outbound:
                    flow.fin_out = True
                else:
                    flow.fin_in = True
                if flow.fin_out and flow.fin_in:
                    flow.closed_at = packet.timestamp
            seq = packet.tcp_seq
            if packet.payload_length > 0 and seq is not None:
                # Retransmisión aproximada: el mismo número de secuencia con datos dos veces
                # seguidas en el mismo sentido. Suficiente como indicador de calidad.
                last = flow.last_seq_out if outbound else flow.last_seq_in
                if last == seq:
                    flow.retransmissions += 1
                if outbound:
                    flow.last_seq_out = seq
                else:
                    flow.last_seq_in = seq
        if packet.dns is not None:
            flow.hints.add("dns")
        elif packet.dhcp is not None:
            flow.hints.add("dhcp")
        elif packet.tls_sni is not None:
            flow.hints.add("tls")

    def _export(self, key: tuple[Any, ...], flow: Flow, reason: str | None, final: bool) -> None:
        self._pending.append(flow.to_json(reason, final))
        flow.segment += 1
        flow.dirty = False
        flow.last_export = flow.last_seen
        self.stats.flows_exported += 1
        if final:
            self._flows.pop(key, None)

    def expire(self, now: float) -> list[dict[str, Any]]:
        """Exporta lo cerrado, lo inactivo y los segmentos de flujos largos. `now` es la hora
        de la captura (último paquete o reloj si no hay tráfico)."""
        for key, flow in list(self._flows.items()):
            if flow.closed_at is not None and now - flow.closed_at >= CLOSE_LINGER_SECONDS:
                self._export(key, flow, None, final=True)
            elif now - flow.last_seen >= self.idle_timeout:
                self._export(key, flow, "timeout", final=True)
            elif flow.dirty and now - flow.last_export >= self.active_timeout:
                self._export(key, flow, None, final=False)
        pending, self._pending = self._pending, []
        return pending

    def drain(self) -> list[dict[str, Any]]:
        """Parada: todo lo activo sale como segmento no final (el flujo pudo seguir vivo)."""
        for key, flow in list(self._flows.items()):
            if flow.dirty or flow.segment == 0:
                self._export(key, flow, None, final=False)
        self._flows.clear()
        pending, self._pending = self._pending, []
        return pending


def _initiator(packet: Packet) -> tuple[bool, bool]:
    """(¿el emisor de este primer paquete es el cliente?, ¿se empezó a mitad?)."""
    protocol = packet.protocol
    if protocol == PROTO_TCP:
        flags = packet.tcp_flags
        if flags & TCP_SYN and not flags & TCP_ACK:
            return True, False
        if flags & TCP_SYN and flags & TCP_ACK:
            return False, False
        return _by_ports(packet), True
    if protocol in (PROTO_ICMP, PROTO_ICMPV6):
        kind = (protocol, packet.icmp_type)
        if kind in _ICMP_REQUESTS:
            return True, False
        if kind in _ICMP_REPLIES:
            return False, False
        return True, False
    if protocol == PROTO_UDP:
        if packet.src_port in DHCP_PORTS and packet.dst_port in DHCP_PORTS:
            return packet.src_port == 68, False
        if packet.dns is not None:
            return not packet.dns.is_response, False
        return _by_ports(packet), False
    return True, False


def _by_ports(packet: Packet) -> bool:
    sport, dport = packet.src_port or 0, packet.dst_port or 0
    if dport in _SERVICE_PORTS and sport not in _SERVICE_PORTS:
        return True
    if sport in _SERVICE_PORTS and dport not in _SERVICE_PORTS:
        return False
    if dport < 1024 <= sport:
        return True
    # Puerto de origen privilegiado y destino efímero: el emisor es el servidor.
    return not sport < 1024 <= dport


@dataclass
class ObservationStats:
    overflow: int = 0
    arp: int = 0
    dns: int = 0
    dhcp: int = 0
    tls: int = 0


class ObservationAggregator:
    """Metadatos de ARP, DNS, DHCP y SNI por ventana de exportación, agregados y acotados.

    Cada tipo se activa por separado según la configuración aprobada en el servidor: si DNS
    no está permitido, los nombres consultados no se guardan ni siquiera en memoria.
    """

    def __init__(self, arp: bool, dns: bool, dhcp: bool, tls: bool) -> None:
        self.enabled = {"arp": arp, "dns": dns, "dhcp": dhcp, "tls": tls}
        self._arp: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._dns: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._dhcp: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._tls: dict[tuple[Any, ...], dict[str, Any]] = {}
        # IPs por las que alguien preguntó hace poco: una respuesta ARP sin petición previa
        # ("no solicitada") es una de las señales del envenenamiento ARP.
        self._requested: OrderedDict[str, float] = OrderedDict()
        self.stats = ObservationStats()

    def _bump(
        self,
        table: dict[tuple[Any, ...], dict[str, Any]],
        limit: int,
        key: tuple[Any, ...],
        ts: float,
        base: dict[str, Any],
    ) -> dict[str, Any] | None:
        entry = table.get(key)
        if entry is None:
            if len(table) >= limit:
                self.stats.overflow += 1
                return None
            entry = {**base, "count": 0, "first_seen": ts, "last_seen": ts}
            table[key] = entry
        entry["count"] += 1
        entry["first_seen"] = min(entry["first_seen"], ts)
        entry["last_seen"] = max(entry["last_seen"], ts)
        return entry

    def add(self, packet: Packet) -> None:
        ts = packet.timestamp
        arp = packet.arp
        if arp is not None and self.enabled["arp"]:
            unsolicited = False
            if arp.operation == 1:
                self._requested[arp.target_ip] = ts
                self._requested.move_to_end(arp.target_ip)
                while len(self._requested) > MAX_RECENT_ARP_REQUESTS:
                    self._requested.popitem(last=False)
            elif arp.operation == 2:
                asked = self._requested.get(arp.sender_ip)
                unsolicited = asked is None or ts - asked > ARP_REQUEST_MEMORY_SECONDS
            key: tuple[Any, ...] = (
                arp.operation,
                arp.sender_ip,
                arp.sender_mac,
                arp.target_ip,
                packet.vlan,
            )
            entry = self._bump(
                self._arp,
                MAX_ARP_ENTRIES,
                key,
                ts,
                {
                    "operation": "request" if arp.operation == 1 else "reply",
                    "sender_ip": arp.sender_ip,
                    "sender_mac": arp.sender_mac,
                    "target_ip": arp.target_ip,
                    "gratuitous": arp.gratuitous,
                    "vlan": packet.vlan,
                    "unsolicited": 0,
                    "eth_src_mac": packet.src_mac,
                },
            )
            if entry is not None:
                self.stats.arp += 1
                if unsolicited:
                    entry["unsolicited"] += 1
                if packet.src_mac and packet.src_mac != arp.sender_mac:
                    # La MAC de la trama no coincide con la que dice el ARP: se conserva la
                    # de la trama, que es la que realmente emitió el paquete.
                    entry["eth_src_mac"] = packet.src_mac
        dns = packet.dns
        if dns is not None and self.enabled["dns"] and packet.src_ip and packet.dst_ip:
            client, resolver = (
                (packet.dst_ip, packet.src_ip)
                if dns.is_response
                else (packet.src_ip, packet.dst_ip)
            )
            key = (client, resolver, dns.qname, dns.qtype)
            entry = self._bump(
                self._dns,
                MAX_DNS_ENTRIES,
                key,
                ts,
                {
                    "client_ip": client,
                    "resolver_ip": resolver,
                    "qname": dns.qname,
                    "qtype": dns.qtype,
                    "queries": 0,
                    "responses": 0,
                    "rcodes": {},
                    "answers": [],
                    "min_ttl": None,
                    "transport": TRANSPORT_NAMES.get(packet.protocol or 0, "udp"),
                    "vlan": packet.vlan,
                },
            )
            if entry is not None:
                self.stats.dns += 1
                if dns.is_response:
                    entry["responses"] += 1
                    rcode = dns.rcode or "other"
                    entry["rcodes"][rcode] = entry["rcodes"].get(rcode, 0) + 1
                    for address in dns.answers:
                        if address not in entry["answers"] and len(entry["answers"]) < 8:
                            entry["answers"].append(address)
                    if dns.min_ttl is not None:
                        current = entry["min_ttl"]
                        entry["min_ttl"] = (
                            dns.min_ttl if current is None else min(current, dns.min_ttl)
                        )
                else:
                    entry["queries"] += 1
        dhcp = packet.dhcp
        if dhcp is not None and self.enabled["dhcp"]:
            sender = packet.src_ip if dhcp.message_type in ("offer", "ack", "nak") else None
            key = (
                dhcp.message_type,
                dhcp.client_mac,
                dhcp.server_ip or sender,
                dhcp.your_ip,
                dhcp.routers,
                dhcp.dns_servers,
            )
            entry = self._bump(
                self._dhcp,
                MAX_DHCP_ENTRIES,
                key,
                ts,
                {
                    "message_type": dhcp.message_type,
                    "client_mac": dhcp.client_mac,
                    "server_ip": dhcp.server_ip or sender,
                    "server_mac": packet.src_mac if sender else None,
                    "your_ip": dhcp.your_ip,
                    "routers": list(dhcp.routers),
                    "dns_servers": list(dhcp.dns_servers),
                    "vlan": packet.vlan,
                },
            )
            if entry is not None:
                self.stats.dhcp += 1
        if packet.tls_sni and self.enabled["tls"] and packet.src_ip and packet.dst_ip:
            key = (packet.src_ip, packet.dst_ip, packet.dst_port, packet.tls_sni)
            entry = self._bump(
                self._tls,
                MAX_TLS_ENTRIES,
                key,
                ts,
                {
                    "client_ip": packet.src_ip,
                    "server_ip": packet.dst_ip,
                    "server_port": packet.dst_port,
                    "sni": packet.tls_sni,
                },
            )
            if entry is not None:
                self.stats.tls += 1

    def collect(self) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        for name, table in (
            ("arp", self._arp),
            ("dns", self._dns),
            ("dhcp", self._dhcp),
            ("tls", self._tls),
        ):
            items = []
            for entry in table.values():
                item = dict(entry)
                item["first_seen"] = iso(entry["first_seen"])
                item["last_seen"] = iso(entry["last_seen"])
                items.append(item)
            result[name] = items
            table.clear()
        return result
