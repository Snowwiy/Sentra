"""Constructores de tramas sintéticas para las pruebas de NDR (nunca tráfico real)."""

import ipaddress
import struct

MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"
MAC_GW = "02:00:00:00:00:01"
MAC_EVIL = "02:00:00:00:00:66"


def mac(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


def ethernet(src: str, dst: str, ethertype: int, payload: bytes, vlan: int | None = None) -> bytes:
    header = mac(dst) + mac(src)
    if vlan is not None:
        header += struct.pack("!HH", 0x8100, vlan)
    return header + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, flags_fragment: int = 0) -> bytes:
    total = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        1,
        flags_fragment,
        64,
        proto,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    return header + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes, ext: bytes = b"") -> bytes:
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(ext) + len(payload),
        next_header if not ext else 0,
        64,
        ipaddress.IPv6Address(src).packed,
        ipaddress.IPv6Address(dst).packed,
    )
    return header + ext + payload


def hop_by_hop(next_header: int) -> bytes:
    # Cabecera de extensión hop-by-hop de 8 octetos (PadN).
    return bytes([next_header, 0, 1, 4, 0, 0, 0, 0])


def tcp(sport: int, dport: int, flags: int, seq: int = 1, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(kind: int, code: int = 0) -> bytes:
    return struct.pack("!BBHHH", kind, code, 0, 1, 1)


def arp(op: int, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    return struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        op,
        mac(sender_mac),
        ipaddress.IPv4Address(sender_ip).packed,
        mac(target_mac),
        ipaddress.IPv4Address(target_ip).packed,
    )


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(name: str, txid: int = 0x1234, qtype: int = 1) -> bytes:
    return (
        struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        + dns_name(name)
        + struct.pack("!HH", qtype, 1)
    )


def dns_response(
    name: str,
    answers: list[str],
    txid: int = 0x1234,
    rcode: int = 0,
    qtype: int = 1,
    ttl: int = 300,
) -> bytes:
    body = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(answers), 0, 0)
    body += dns_name(name) + struct.pack("!HH", qtype, 1)
    for address in answers:
        ip = ipaddress.ip_address(address)
        rtype = 1 if ip.version == 4 else 28
        # Puntero de compresión al nombre de la pregunta (offset 12).
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, ttl, len(ip.packed)) + ip.packed
    return body


def dhcp(
    message_type: int,
    client_mac: str,
    your_ip: str = "0.0.0.0",  # noqa: S104  (campo yiaddr vacío de DHCP, no un bind)
    server_ip: str | None = None,
    routers: list[str] | None = None,
    dns_servers: list[str] | None = None,
) -> bytes:
    body = struct.pack("!BBBBIHH", 2 if message_type in (2, 5) else 1, 1, 6, 0, 0x1, 0, 0)
    body += b"\x00" * 4  # ciaddr
    body += ipaddress.IPv4Address(your_ip).packed
    body += b"\x00" * 8  # siaddr, giaddr
    body += mac(client_mac) + b"\x00" * 10
    body += b"\x00" * 192
    body += b"\x63\x82\x53\x63"
    body += bytes([53, 1, message_type])
    if server_ip:
        body += bytes([54, 4]) + ipaddress.IPv4Address(server_ip).packed
    if routers:
        raw = b"".join(ipaddress.IPv4Address(r).packed for r in routers)
        body += bytes([3, len(raw)]) + raw
    if dns_servers:
        raw = b"".join(ipaddress.IPv4Address(r).packed for r in dns_servers)
        body += bytes([6, len(raw)]) + raw
    # Nombre de host (opción 12): debe ignorarse.
    body += bytes([12, 6]) + b"laptop"
    return body + b"\xff"


def tls_client_hello(server_name: str) -> bytes:
    name = server_name.encode()
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack("!HH", 0, len(sni)) + sni
    hello = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    hello += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + struct.pack("!I", len(hello))[1:] + hello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tcp_frame(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    flags: int,
    payload: bytes = b"",
    seq: int = 1,
    src_mac: str = MAC_A,
    dst_mac: str = MAC_B,
) -> bytes:
    return ethernet(
        src_mac, dst_mac, 0x0800, ipv4(src, dst, 6, tcp(sport, dport, flags, seq, payload))
    )


def udp_frame(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    payload: bytes,
    src_mac: str = MAC_A,
    dst_mac: str = MAC_B,
) -> bytes:
    return ethernet(src_mac, dst_mac, 0x0800, ipv4(src, dst, 17, udp(sport, dport, payload)))


def arp_frame(
    op: int, sender_mac: str, sender_ip: str, target_ip: str, target_mac: str = "00:00:00:00:00:00"
) -> bytes:
    dst = "ff:ff:ff:ff:ff:ff" if op == 1 else target_mac
    return ethernet(sender_mac, dst, 0x0806, arp(op, sender_mac, sender_ip, target_mac, target_ip))
