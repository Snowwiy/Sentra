"""Cálculo puro de direcciones permitidas durante un aislamiento y de su complemento.

Windows Defender Firewall evalúa un bloqueo por encima de cualquier permiso, así que "bloquear
todo salvo X" no se puede expresar como "bloquear todo + permitir X": hay que bloquear el
complemento de X. Aquí se calcula ese complemento como lista mínima de rangos
inicio-fin por familia, recorriendo los huecos entre redes ordenadas y fusionadas (O(k log k)
en el número de redes permitidas, sin enumerar direcciones).
"""

import ipaddress
from collections.abc import Iterable

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address

LOOPBACK = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
DHCP_BROADCAST = ipaddress.ip_network("255.255.255.255/32")
# Solo si el servidor tiene IPv6: sin descubrimiento de vecinos no hay ruta IPv6.
IPV6_NEIGHBOR = (ipaddress.ip_network("fe80::/10"), ipaddress.ip_network("ff02::/16"))
# Una entrada de extra_allow más ancha que esto dejaría el aislamiento sin sentido.
MIN_PREFIX = {4: 8, 6: 16}


def parse_extra(entries: Iterable[str]) -> list[Network]:
    """Valida extra_allow de la política local: IPs o redes CIDR, nunca demasiado anchas."""
    networks: list[Network] = []
    for entry in entries:
        if not isinstance(entry, str):
            raise ValueError("extra_allow entries must be strings")
        network = ipaddress.ip_network(entry.strip(), strict=False)
        if network.prefixlen < MIN_PREFIX[network.version]:
            raise ValueError(f"extra_allow entry too broad: {entry}")
        networks.append(network)
    return networks


def _host(address: str | Address) -> Network | None:
    try:
        parsed = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return None
    if parsed.is_unspecified or parsed.is_multicast:
        return None
    return ipaddress.ip_network(parsed)


def allowed_networks(
    server_addresses: Iterable[str],
    dns_servers: Iterable[str] = (),
    dhcp_server: str | None = None,
    extra_allow: Iterable[Network] = (),
    allow_dns: bool = True,
) -> list[Network]:
    """Redes permitidas: servidor Sentra, loopback, DHCP, DNS (opcional) y extra_allow."""
    found: list[Network] = [*LOOPBACK, DHCP_BROADCAST]
    servers = [net for net in (_host(a) for a in server_addresses) if net is not None]
    found.extend(servers)
    if any(net.version == 6 for net in servers):
        found.extend(IPV6_NEIGHBOR)
    if dhcp_server:
        host = _host(dhcp_server)
        if host is not None:
            found.append(host)
    if allow_dns:
        found.extend(net for net in (_host(a) for a in dns_servers) if net is not None)
    found.extend(extra_allow)
    return collapse(found)


def collapse(networks: Iterable[Network]) -> list[Network]:
    v4 = [n for n in networks if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in networks if isinstance(n, ipaddress.IPv6Network)]
    return [*ipaddress.collapse_addresses(v4), *ipaddress.collapse_addresses(v6)]


def to_ranges(networks: Iterable[Network], version: int) -> list[tuple[int, int]]:
    """Redes de una familia como rangos enteros [inicio, fin] ordenados y fusionados."""
    ranges = sorted(
        (int(n.network_address), int(n.broadcast_address)) for n in networks if n.version == version
    )
    merged: list[tuple[int, int]] = []
    for start, end in ranges:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def complement_ranges(networks: Iterable[Network], version: int) -> list[tuple[int, int]]:
    """Huecos entre las redes permitidas de la familia: lo que hay que bloquear."""
    top = (1 << (32 if version == 4 else 128)) - 1
    gaps: list[tuple[int, int]] = []
    cursor = 0
    for start, end in to_ranges(networks, version):
        if start > cursor:
            gaps.append((cursor, start - 1))
        cursor = end + 1
    if cursor <= top:
        gaps.append((cursor, top))
    return gaps


def format_range(start: int, end: int, version: int) -> str:
    first = ipaddress.ip_address(start) if version == 4 else ipaddress.IPv6Address(start)
    if start == end:
        return str(first)
    last = ipaddress.ip_address(end) if version == 4 else ipaddress.IPv6Address(end)
    return f"{first}-{last}"


def parse_range_token(token: str) -> tuple[int, int, int]:
    """Interpreta lo que Windows devuelve (a, a-b, a/len, a/máscara): (versión, inicio, fin)."""
    text = token.strip()
    if "-" in text:
        first_text, last_text = text.split("-", 1)
        first = ipaddress.ip_address(first_text.strip())
        last = ipaddress.ip_address(last_text.strip())
        if first.version != last.version or int(last) < int(first):
            raise ValueError(f"bad range {token}")
        return first.version, int(first), int(last)
    network = ipaddress.ip_network(text, strict=False)
    return network.version, int(network.network_address), int(network.broadcast_address)


def normalize_tokens(tokens: Iterable[str]) -> dict[int, list[tuple[int, int]]]:
    """Rangos fusionados por familia a partir de textos de direcciones (verificación)."""
    by_version: dict[int, list[tuple[int, int]]] = {4: [], 6: []}
    for token in tokens:
        version, start, end = parse_range_token(token)
        by_version[version].append((start, end))
    result: dict[int, list[tuple[int, int]]] = {}
    for version, ranges in by_version.items():
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        result[version] = merged
    return result
