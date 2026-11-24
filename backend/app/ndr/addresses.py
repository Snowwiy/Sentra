"""Clasificación de direcciones para las reglas NDR (Fase 7E.3).

`ipaddress.is_private` mezcla redes internas con rangos especiales (documentación,
benchmarking, "this network"), así que aquí se define qué es "interno" de forma explícita:
lo que una red corporativa asigna a sus equipos. "Externo" es cualquier unicast que no sea
interno ni especial (loopback, multicast, no especificada, reservada), es decir, lo que sale
por la puerta de enlace hacia otra organización.
"""

import ipaddress

_INTERNAL = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
)


def _parse(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def is_internal(ip: str) -> bool:
    address = _parse(ip)
    return address is not None and any(address in net for net in _INTERNAL)


def is_external(ip: str) -> bool:
    address = _parse(ip)
    if address is None or any(address in net for net in _INTERNAL):
        return False
    return not (
        address.is_loopback
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or address.is_link_local
    )
