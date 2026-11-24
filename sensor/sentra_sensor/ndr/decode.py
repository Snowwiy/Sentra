"""Decodificación acotada de cabeceras de red (Fase 7E.1/7E.3), solo biblioteca estándar.

Qué se interpreta y qué no:
* Enlace: Ethernet II (con hasta dos etiquetas 802.1Q/802.1ad), DLT_NULL/LOOP (loopback de
  BSD/Npcap), DLT_RAW (IP sin enlace) y Linux "cooked" (SLL).
* Red y transporte: ARP, IPv4 (fragmentos marcados), IPv6 (cadena de cabeceras de extensión
  recorrida con tope), ICMP, ICMPv6, TCP (puertos, flags, secuencia) y UDP.
* Aplicación, SOLO metadatos: DNS sobre el puerto 53 (pregunta, tipo, rcode y direcciones
  A/AAAA de la respuesta), DHCPv4 (tipo de mensaje, MAC del cliente, servidor, gateway y
  resolvedores ofrecidos) y, si el servidor lo permite, el SNI del ClientHello de TLS.

Nunca se guarda ni se devuelve el payload: el resultado es un `Packet` con campos tipados y
cadenas acotadas. Un paquete malformado o truncado no lanza excepciones hacia fuera: queda
marcado (`malformed`/`truncated`) y cuenta en las métricas de calidad de la captura. Esto es
crítico porque el tráfico observado lo controla cualquiera en la red: el decodificador es
superficie de ataque y debe tratar cada byte como dato hostil.
"""

import ipaddress
import struct
from dataclasses import dataclass, field

# Tipos de enlace (valores DLT/LINKTYPE de libpcap).
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
LINKTYPE_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
SUPPORTED_LINKTYPES = frozenset(
    {DLT_NULL, DLT_EN10MB, DLT_RAW, LINKTYPE_RAW, DLT_LOOP, DLT_LINUX_SLL}
)

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD
ETH_VLAN = frozenset({0x8100, 0x88A8, 0x9100})

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58
TRANSPORT_NAMES = {PROTO_ICMP: "icmp", PROTO_TCP: "tcp", PROTO_UDP: "udp", PROTO_ICMPV6: "icmpv6"}

# Cabeceras de extensión IPv6 que se saltan para llegar al transporte (RFC 8200).
_IPV6_EXT = frozenset({0, 43, 60, 51})
_IPV6_FRAGMENT = 44
_MAX_IPV6_EXT = 8

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

DNS_PORT = 53
DHCP_PORTS = frozenset({67, 68})
TLS_PORTS = frozenset({443, 8443})
# Topes de la interpretación de DNS: una respuesta hostil con miles de registros o punteros
# de compresión en bucle no puede consumir CPU ni memoria.
MAX_DNS_NAME = 253
MAX_DNS_JUMPS = 16
MAX_DNS_ANSWERS = 16
MAX_DNS_ADDRESSES = 8
DNS_RCODES = {0: "noerror", 1: "formerr", 2: "servfail", 3: "nxdomain", 4: "notimp", 5: "refused"}
DNS_QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}
DHCP_MESSAGE_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}
_DHCP_MAGIC = b"\x63\x82\x53\x63"
_MAX_DHCP_LIST = 4
_MAX_SNI = 253
_SNI_CHARS = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")


class DecodeError(ValueError):
    """Error interno de decodificación; nunca sale de `decode_packet`."""


@dataclass(slots=True)
class ArpInfo:
    operation: int  # 1 = request, 2 = reply
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    @property
    def gratuitous(self) -> bool:
        # Anuncio gratuito: el emisor pregunta (o responde) por su propia IP. Es legítimo en
        # arranques y cambios de dirección, pero también es la forma de un envenenamiento.
        return self.sender_ip == self.target_ip


@dataclass(slots=True)
class DnsInfo:
    transaction_id: int
    is_response: bool
    qname: str
    qtype: str
    rcode: str | None
    answers: tuple[str, ...] = ()
    min_ttl: int | None = None
    truncated_flag: bool = False


@dataclass(slots=True)
class DhcpInfo:
    message_type: str
    client_mac: str
    your_ip: str | None
    server_ip: str | None
    routers: tuple[str, ...] = ()
    dns_servers: tuple[str, ...] = ()


@dataclass(slots=True)
class Packet:
    timestamp: float
    wire_length: int
    captured_length: int
    src_mac: str | None = None
    dst_mac: str | None = None
    vlan: int | None = None
    ethertype: int | None = None
    ip_version: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: int | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int = 0
    tcp_seq: int | None = None
    payload_length: int = 0
    icmp_type: int | None = None
    icmp_code: int | None = None
    # Fragmento IPv4/IPv6: el primero lleva puertos; los demás no se pueden atribuir a un
    # flujo por puertos y se cuentan aparte.
    fragment: bool = False
    first_fragment: bool = True
    truncated: bool = False
    malformed: bool = False
    unsupported: bool = False
    arp: ArpInfo | None = None
    dns: DnsInfo | None = None
    dhcp: DhcpInfo | None = None
    tls_sni: str | None = None
    notes: list[str] = field(default_factory=list)


def mac_text(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ipv4(raw: bytes) -> str:
    return str(ipaddress.IPv4Address(raw))


def _ipv6(raw: bytes) -> str:
    return str(ipaddress.IPv6Address(raw))


def decode_packet(data: bytes, timestamp: float, wire_length: int, linktype: int) -> Packet:
    """Decodifica un frame capturado. Nunca lanza: los problemas quedan marcados en el Packet."""
    packet = Packet(timestamp=timestamp, wire_length=wire_length, captured_length=len(data))
    if linktype not in SUPPORTED_LINKTYPES:
        packet.unsupported = True
        return packet
    try:
        _decode_link(packet, memoryview(data), linktype)
    except (DecodeError, struct.error, IndexError, ValueError):
        # Un campo fuera de rango o una longitud que no cuadra: el paquete cuenta como
        # malformado si no se pudo ni siquiera llegar a la capa de red; si ya se tenían las
        # direcciones, se conserva lo decodificado (útil para el flujo) y se marca truncado.
        if packet.src_ip is None and packet.arp is None:
            packet.malformed = True
        else:
            packet.truncated = True
    # Cortar la carga por snaplen es deliberado (no se guardan payloads): no cuenta como
    # truncado. Solo lo es un paquete al que le faltan cabeceras.
    return packet


def _decode_link(packet: Packet, view: memoryview, linktype: int) -> None:
    if linktype == DLT_EN10MB:
        if len(view) < 14:
            raise DecodeError("short ethernet")
        packet.dst_mac = mac_text(bytes(view[0:6]))
        packet.src_mac = mac_text(bytes(view[6:12]))
        ethertype = struct.unpack_from("!H", view, 12)[0]
        offset = 14
        # Hasta dos etiquetas (QinQ); se guarda la VLAN más interna, que es la del host.
        for _ in range(2):
            if ethertype not in ETH_VLAN:
                break
            tci, ethertype = struct.unpack_from("!HH", view, offset)
            packet.vlan = tci & 0x0FFF
            offset += 4
        _decode_ethertype(packet, view[offset:], ethertype)
    elif linktype in (DLT_NULL, DLT_LOOP):
        if len(view) < 4:
            raise DecodeError("short loopback header")
        family_le = struct.unpack_from("<I", view, 0)[0]
        family_be = struct.unpack_from("!I", view, 0)[0]
        family = family_le if family_le < 256 else family_be
        # AF_INET = 2 en todos; AF_INET6 vale 24, 28 o 30 según el sistema (BSD, macOS).
        if family == 2:
            _decode_ethertype(packet, view[4:], ETH_IPV4)
        elif family in (10, 23, 24, 28, 30):
            _decode_ethertype(packet, view[4:], ETH_IPV6)
        else:
            packet.unsupported = True
    elif linktype in (DLT_RAW, LINKTYPE_RAW):
        if len(view) < 1:
            raise DecodeError("empty raw packet")
        version = view[0] >> 4
        _decode_ethertype(packet, view, ETH_IPV4 if version == 4 else ETH_IPV6)
    elif linktype == DLT_LINUX_SLL:
        if len(view) < 16:
            raise DecodeError("short sll header")
        address_length = struct.unpack_from("!H", view, 4)[0]
        if address_length == 6:
            packet.src_mac = mac_text(bytes(view[6:12]))
        ethertype = struct.unpack_from("!H", view, 14)[0]
        _decode_ethertype(packet, view[16:], ethertype)


def _decode_ethertype(packet: Packet, view: memoryview, ethertype: int) -> None:
    packet.ethertype = ethertype
    if ethertype == ETH_IPV4:
        _decode_ipv4(packet, view)
    elif ethertype == ETH_IPV6:
        _decode_ipv6(packet, view)
    elif ethertype == ETH_ARP:
        _decode_arp(packet, view)
    else:
        packet.unsupported = True


def _decode_arp(packet: Packet, view: memoryview) -> None:
    if len(view) < 28:
        raise DecodeError("short arp")
    hw_type, proto_type, hw_len, proto_len, operation = struct.unpack_from("!HHBBH", view, 0)
    # Solo Ethernet + IPv4: es lo único que una red local usa y lo único que se interpreta.
    if hw_type != 1 or proto_type != ETH_IPV4 or hw_len != 6 or proto_len != 4:
        packet.unsupported = True
        return
    packet.arp = ArpInfo(
        operation=operation,
        sender_mac=mac_text(bytes(view[8:14])),
        sender_ip=_ipv4(bytes(view[14:18])),
        target_mac=mac_text(bytes(view[18:24])),
        target_ip=_ipv4(bytes(view[24:28])),
    )


def _decode_ipv4(packet: Packet, view: memoryview) -> None:
    if len(view) < 20:
        raise DecodeError("short ipv4")
    version_ihl = view[0]
    if version_ihl >> 4 != 4:
        raise DecodeError("not ipv4")
    header_length = (version_ihl & 0x0F) * 4
    if header_length < 20:
        raise DecodeError("bad ihl")
    total_length = struct.unpack_from("!H", view, 2)[0]
    flags_fragment = struct.unpack_from("!H", view, 6)[0]
    packet.ip_version = 4
    packet.protocol = view[9]
    packet.src_ip = _ipv4(bytes(view[12:16]))
    packet.dst_ip = _ipv4(bytes(view[16:20]))
    more_fragments = bool(flags_fragment & 0x2000)
    offset = flags_fragment & 0x1FFF
    if more_fragments or offset:
        packet.fragment = True
        packet.first_fragment = offset == 0
    if len(view) < header_length:
        raise DecodeError("truncated ipv4 options")
    # total_length acota la carga real (el relleno Ethernet de tramas cortas no cuenta).
    end = min(len(view), total_length) if total_length >= header_length else len(view)
    if not packet.first_fragment:
        packet.payload_length = max(0, total_length - header_length)
        return
    _decode_transport(packet, view[header_length:end], max(0, total_length - header_length))


def _decode_ipv6(packet: Packet, view: memoryview) -> None:
    if len(view) < 40:
        raise DecodeError("short ipv6")
    if view[0] >> 4 != 6:
        raise DecodeError("not ipv6")
    payload_length = struct.unpack_from("!H", view, 4)[0]
    next_header = view[6]
    packet.ip_version = 6
    packet.src_ip = _ipv6(bytes(view[8:24]))
    packet.dst_ip = _ipv6(bytes(view[24:40]))
    offset = 40
    for _ in range(_MAX_IPV6_EXT):
        if next_header in _IPV6_EXT:
            if len(view) < offset + 2:
                raise DecodeError("truncated ipv6 extension")
            length = (view[offset + 1] + 1) * 8
            if next_header == 51:  # AH usa unidades de 4 octetos
                length = (view[offset + 1] + 2) * 4
            next_header = view[offset]
            offset += length
            continue
        if next_header == _IPV6_FRAGMENT:
            if len(view) < offset + 8:
                raise DecodeError("truncated ipv6 fragment")
            fragment = struct.unpack_from("!H", view, offset + 2)[0]
            packet.fragment = True
            packet.first_fragment = (fragment >> 3) == 0
            next_header = view[offset]
            offset += 8
            if not packet.first_fragment:
                packet.protocol = next_header
                packet.payload_length = max(0, payload_length - (offset - 40))
                return
            continue
        break
    packet.protocol = next_header
    end = min(len(view), 40 + payload_length)
    if offset > end:
        raise DecodeError("ipv6 extensions beyond payload")
    _decode_transport(packet, view[offset:end], max(0, payload_length - (offset - 40)))


def _decode_transport(packet: Packet, view: memoryview, declared: int) -> None:
    protocol = packet.protocol
    if protocol == PROTO_TCP:
        if len(view) < 20:
            raise DecodeError("short tcp")
        packet.src_port, packet.dst_port, seq = struct.unpack_from("!HHI", view, 0)
        data_offset = (view[12] >> 4) * 4
        packet.tcp_flags = view[13] & 0x3F
        packet.tcp_seq = seq
        if data_offset < 20:
            raise DecodeError("bad tcp offset")
        packet.payload_length = max(0, declared - data_offset)
        payload = view[data_offset:] if len(view) > data_offset else memoryview(b"")
        if packet.payload_length and DNS_PORT in (packet.src_port, packet.dst_port):
            # DNS sobre TCP: dos octetos de longitud y el mensaje (solo el primer segmento).
            if len(payload) > 2:
                _decode_dns(packet, payload[2:])
        elif packet.payload_length and packet.dst_port in TLS_PORTS:
            packet.tls_sni = _tls_sni(payload)
    elif protocol == PROTO_UDP:
        if len(view) < 8:
            raise DecodeError("short udp")
        packet.src_port, packet.dst_port, length = struct.unpack_from("!HHH", view, 0)
        packet.payload_length = max(0, min(declared, length) - 8)
        payload = view[8:]
        if DNS_PORT in (packet.src_port, packet.dst_port):
            _decode_dns(packet, payload)
        elif packet.src_port in DHCP_PORTS and packet.dst_port in DHCP_PORTS:
            _decode_dhcp(packet, payload)
    elif protocol in (PROTO_ICMP, PROTO_ICMPV6):
        if len(view) < 4:
            raise DecodeError("short icmp")
        packet.icmp_type = view[0]
        packet.icmp_code = view[1]
        packet.payload_length = max(0, declared - 4)
    else:
        packet.payload_length = declared


def _dns_name(view: memoryview, offset: int) -> tuple[str, int]:
    """Lee un nombre DNS con compresión. Devuelve (nombre, offset tras el nombre original)."""
    labels: list[str] = []
    jumps = 0
    end_offset: int | None = None
    total = 0
    while True:
        if offset >= len(view):
            raise DecodeError("dns name out of bounds")
        length = view[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(view):
                raise DecodeError("dns pointer out of bounds")
            pointer = ((length & 0x3F) << 8) | view[offset + 1]
            if end_offset is None:
                end_offset = offset + 2
            jumps += 1
            if jumps > MAX_DNS_JUMPS or pointer >= len(view):
                raise DecodeError("dns pointer loop")
            offset = pointer
            continue
        if length & 0xC0:
            raise DecodeError("dns label type")
        offset += 1
        if length == 0:
            break
        if offset + length > len(view):
            raise DecodeError("dns label out of bounds")
        raw = bytes(view[offset : offset + length])
        # Etiquetas no imprimibles o con separadores se sustituyen: el nombre se mostrará en
        # la UI y nunca debe poder inyectar marcado ni caracteres de control.
        label = "".join(
            chr(c).lower() if 0x21 <= c < 0x7F and chr(c) not in "<>\"'`\\/" else "?" for c in raw
        )
        labels.append(label)
        total += length + 1
        if total > MAX_DNS_NAME + 1:
            raise DecodeError("dns name too long")
        offset += length
    return ".".join(labels), end_offset if end_offset is not None else offset


def _decode_dns(packet: Packet, view: memoryview) -> None:
    if len(view) < 12:
        packet.truncated = True
        return
    txid, flags, qdcount, ancount = struct.unpack_from("!HHHH", view, 0)
    if qdcount < 1 or qdcount > 4:
        # Sin pregunta (o con un número absurdo) no es DNS útil para estas reglas.
        packet.unsupported = True
        return
    is_response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0x0F
    if opcode != 0:
        return
    qname, offset = _dns_name(view, 12)
    if offset + 4 > len(view):
        raise DecodeError("dns question truncated")
    qtype_code = struct.unpack_from("!H", view, offset)[0]
    offset += 4
    rcode = DNS_RCODES.get(flags & 0x0F, "other") if is_response else None
    answers: list[str] = []
    min_ttl: int | None = None
    if is_response:
        # Las demás preguntas (raras) se saltan sin interpretarlas.
        for _ in range(qdcount - 1):
            _, offset = _dns_name(view, offset)
            offset += 4
        for _ in range(min(ancount, MAX_DNS_ANSWERS)):
            if offset >= len(view):
                break
            try:
                _, offset = _dns_name(view, offset)
                rtype, _rclass, ttl, rdlength = struct.unpack_from("!HHIH", view, offset)
            except (DecodeError, struct.error):
                packet.truncated = True
                break
            offset += 10
            if offset + rdlength > len(view):
                packet.truncated = True
                break
            rdata = bytes(view[offset : offset + rdlength])
            offset += rdlength
            if rtype in (1, 28):
                min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
            if rtype == 1 and rdlength == 4 and len(answers) < MAX_DNS_ADDRESSES:
                answers.append(_ipv4(rdata))
            elif rtype == 28 and rdlength == 16 and len(answers) < MAX_DNS_ADDRESSES:
                answers.append(_ipv6(rdata))
    packet.dns = DnsInfo(
        transaction_id=txid,
        is_response=is_response,
        qname=qname or ".",
        qtype=DNS_QTYPES.get(qtype_code, str(qtype_code)),
        rcode=rcode,
        answers=tuple(answers),
        min_ttl=min_ttl,
        truncated_flag=bool(flags & 0x0200),
    )


def _decode_dhcp(packet: Packet, view: memoryview) -> None:
    if len(view) < 240 or bytes(view[236:240]) != _DHCP_MAGIC:
        return
    hlen = view[2]
    yiaddr = bytes(view[16:20])
    chaddr = bytes(view[28 : 28 + 6]) if hlen == 6 else b""
    message_type: str | None = None
    server_ip: str | None = None
    routers: list[str] = []
    dns_servers: list[str] = []
    offset = 240
    # Opciones TLV acotadas al tamaño capturado; se ignora todo lo que no se usa (incluido
    # el nombre del host, opción 12: es un dato personal que estas reglas no necesitan).
    while offset < len(view):
        code = view[offset]
        if code == 255:
            break
        if code == 0:
            offset += 1
            continue
        if offset + 1 >= len(view):
            break
        length = view[offset + 1]
        value = bytes(view[offset + 2 : offset + 2 + length])
        offset += 2 + length
        if len(value) != length:
            packet.truncated = True
            break
        if code == 53 and length == 1:
            message_type = DHCP_MESSAGE_TYPES.get(value[0], "other")
        elif code == 54 and length == 4:
            server_ip = _ipv4(value)
        elif code == 3 and length >= 4:
            routers = [_ipv4(value[i : i + 4]) for i in range(0, length - length % 4, 4)]
        elif code == 6 and length >= 4:
            dns_servers = [_ipv4(value[i : i + 4]) for i in range(0, length - length % 4, 4)]
    if message_type is None or len(chaddr) != 6:
        return
    your_ip = _ipv4(yiaddr) if yiaddr != b"\x00\x00\x00\x00" else None
    packet.dhcp = DhcpInfo(
        message_type=message_type,
        client_mac=mac_text(chaddr),
        your_ip=your_ip,
        server_ip=server_ip,
        routers=tuple(routers[:_MAX_DHCP_LIST]),
        dns_servers=tuple(dns_servers[:_MAX_DHCP_LIST]),
    )


def _tls_sni(view: memoryview) -> str | None:
    """SNI del ClientHello de TLS si cabe en el primer segmento capturado.

    Solo metadatos en claro del saludo: no se descifra nada ni se inspecciona el resto de la
    sesión. Con ECH (Encrypted Client Hello) el SNI real no es visible y aquí no aparece.
    """
    try:
        if len(view) < 43 or view[0] != 0x16 or view[5] != 0x01:
            return None
        offset = 5 + 4 + 2 + 32  # registro, cabecera del handshake, versión, random
        session_len = view[offset]
        offset += 1 + session_len
        cipher_len = struct.unpack_from("!H", view, offset)[0]
        offset += 2 + cipher_len
        compression_len = view[offset]
        offset += 1 + compression_len
        extensions_end = offset + 2 + struct.unpack_from("!H", view, offset)[0]
        offset += 2
        while offset + 4 <= min(extensions_end, len(view)):
            ext_type, ext_len = struct.unpack_from("!HH", view, offset)
            offset += 4
            if ext_type == 0 and ext_len >= 5:
                name_len = struct.unpack_from("!H", view, offset + 3)[0]
                raw = bytes(view[offset + 5 : offset + 5 + name_len])
                if not raw or len(raw) != name_len or name_len > _MAX_SNI:
                    return None
                if not all(c in _SNI_CHARS for c in raw):
                    return None
                return raw.decode("ascii").lower()
            offset += ext_len
    except (struct.error, IndexError):
        return None
    return None
