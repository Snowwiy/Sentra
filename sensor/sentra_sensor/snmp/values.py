"""Normalización de valores SNMP a la forma que espera el servidor (Fase 6B).

Un equipo puede devolver cualquier cosa (bytes arbitrarios en un DisplayString, longitudes
imposibles, enteros fuera de rango). Aquí todo se acota y se sanea: texto sin caracteres de
control y con longitud máxima, MAC e IP canónicas o nada, bitmaps decodificados a nombres
del catálogo. Lo que no se puede interpretar se descarta (None), nunca se inventa.
"""

import ipaddress
import re

from sentra_sensor.snmp.transport import ObjectId, Value

_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")

# LLDP-MIB LldpSystemCapabilitiesMap (BITS): bit 0 es el más significativo del primer octeto.
LLDP_CAPABILITY_BITS = (
    "other",
    "repeater",
    "bridge",
    "wlan_access_point",
    "router",
    "telephone",
    "docsis_cable_device",
    "station_only",
    "c_vlan",
    "s_vlan",
    "two_port_mac_relay",
)
# CISCO-CDP-MIB cdpCacheCapabilities: máscara de 32 bits en 4 octetos (big-endian).
CDP_CAPABILITY_MASKS = (
    (0x001, "router"),
    (0x002, "transparent_bridge"),
    (0x004, "source_route_bridge"),
    (0x008, "switch"),
    (0x010, "host"),
    (0x020, "igmp"),
    (0x040, "repeater"),
    (0x080, "phone"),
    (0x100, "remote_managed"),
    (0x200, "cvta"),
    (0x400, "two_port_mac_relay"),
)
MAX_PORTLIST_PORTS = 4096


def text(value: Value, limit: int) -> str | None:
    """DisplayString/SnmpAdminString saneado. Vacío = None."""
    if isinstance(value, ObjectId):
        raw = str(value)
    elif isinstance(value, bytes):
        raw = value.decode("utf-8", errors="replace")
    elif isinstance(value, int) and not isinstance(value, bool):
        raw = str(value)
    else:
        return None
    cleaned = _CONTROL.sub(" ", raw).strip()
    return cleaned[:limit] if cleaned else None


def integer(value: Value, low: int, high: int) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value if low <= value <= high else None


def mac(value: Value) -> str | None:
    """MacAddress (6 octetos) en minúsculas con dos puntos. Otra longitud = None."""
    if not isinstance(value, bytes) or len(value) != 6:
        return None
    return ":".join(f"{b:02x}" for b in value)


def mac_from_index(parts: tuple[int, ...]) -> str | None:
    if len(parts) != 6 or any(not 0 <= p <= 255 for p in parts):
        return None
    return ":".join(f"{p:02x}" for p in parts)


def ip_address(raw: bytes | tuple[int, ...]) -> str | None:
    octets = bytes(raw) if isinstance(raw, tuple) else raw
    if len(octets) == 4:
        return str(ipaddress.IPv4Address(octets))
    if len(octets) == 16:
        return str(ipaddress.IPv6Address(octets))
    return None


def chassis_or_port_id(
    subtype: int | None, value: Value, mac_subtype: int, addr_subtype: int
) -> str | None:
    """Identificador LLDP según su subtipo: MAC canónica, dirección de red o texto."""
    if isinstance(value, bytes) and subtype == mac_subtype:
        return mac(value) or _hex(value)
    if isinstance(value, bytes) and subtype == addr_subtype and len(value) >= 1:
        # networkAddress: primer octeto = familia IANA (1 IPv4, 2 IPv6) y luego la dirección.
        return ip_address(value[1:]) or _hex(value)
    if isinstance(value, bytes) and not _printable(value):
        return _hex(value)
    return text(value, 255)


def _printable(value: bytes) -> bool:
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return not _CONTROL.search(decoded.strip("\x00"))


def _hex(value: bytes) -> str | None:
    return ":".join(f"{b:02x}" for b in value[:64]) or None


def lldp_capabilities(value: Value) -> list[str]:
    if not isinstance(value, bytes):
        return []
    names = []
    for bit, name in enumerate(LLDP_CAPABILITY_BITS):
        byte, offset = divmod(bit, 8)
        if byte < len(value) and value[byte] & (0x80 >> offset):
            names.append(name)
    return names


def cdp_capabilities(value: Value) -> list[str]:
    if isinstance(value, bytes):
        if len(value) != 4:
            return []
        mask = int.from_bytes(value, "big")
    elif isinstance(value, int) and not isinstance(value, bool):
        mask = value
    else:
        return []
    return [name for bit, name in CDP_CAPABILITY_MASKS if mask & bit]


def port_list(value: Value) -> list[int]:
    """PortList (Q-BRIDGE-MIB): bit más significativo del primer octeto = puerto 1."""
    if not isinstance(value, bytes):
        return []
    ports: list[int] = []
    for index, byte in enumerate(value):
        if not byte:
            continue
        for offset in range(8):
            if byte & (0x80 >> offset):
                port = index * 8 + offset + 1
                if port > MAX_PORTLIST_PORTS:
                    return ports
                ports.append(port)
    return ports
