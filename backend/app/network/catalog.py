"""Catálogo cerrado de la Fase 6B: tipo de job, módulos SNMP, capacidades y tablas de
interpretación (tipos de interfaz, subtipos LLDP, números de empresa IANA).

El servidor nunca envía OIDs al sensor: envía NOMBRES de módulo de esta lista y el sensor
consulta su propio catálogo read-only (sensor/sentra_sensor/snmp/catalog.py). Así nadie con
acceso a la API puede convertir a un sensor en un cliente SNMP genérico, ni pedir un OID
fuera de las MIBs autorizadas, ni (por construcción) una operación SET.
"""

SNMP_JOB_TYPE = "snmp_inventory"
SNMP_SCHEMA_VERSION = 1

# Módulos en el orden en que el sensor los consulta. "system" siempre va: sin él no hay
# identidad del equipo y el resto no se puede interpretar.
# Fase 6C.3: "wlan" (IEEE802dot11-MIB, AIRESPACE-WIRELESS-MIB, UBNT-UniFi-MIB) solo se pide a
# sensores que declaran snmp.wlan (0.4.0+): un sensor 0.3.0 rechazaría un módulo desconocido.
MODULES: tuple[str, ...] = (
    "system",
    "entity",
    "interfaces",
    "lldp",
    "cdp",
    "bridge",
    "vlan",
    "wlan",
)
MODULE_CAPABILITY = {name: f"snmp.{name}" for name in MODULES}
VERSION_CAPABILITY = {"v3": "snmp.v3", "v2c": "snmp.v2c"}
SNMP_CAPABILITIES = frozenset(MODULE_CAPABILITY.values()) | frozenset(VERSION_CAPABILITY.values())
MODULE_STATUSES = frozenset({"complete", "partial", "unsupported", "failed", "skipped"})

# Errores que el sensor puede informar al cerrar (el resto los genera el servidor).
SENSOR_ERROR_CODES = frozenset(
    {
        "timeout",
        "host_unreachable",
        "auth_failed",
        "unsupported_version",
        "oid_unavailable",
        "partial",
        "cancelled",
        "limit_exceeded",
        "malformed_response",
        "internal",
    }
)

AUTH_PROTOCOLS = ("sha", "sha224", "sha256", "sha384", "sha512")
PRIV_PROTOCOLS = ("aes128", "aes192", "aes256")

# IANAifType → tipo de puerto de Sentra. Lo que no está aquí es "other": no se adivina.
_PHYSICAL_TYPES = frozenset({6, 7, 62, 69, 117})
IF_TYPE_KIND: dict[int, str] = {
    **dict.fromkeys(_PHYSICAL_TYPES, "physical"),
    71: "wireless",  # ieee80211
    161: "lag",  # ieee8023adLag
    135: "vlan",  # l2vlan
    136: "vlan",  # l3ipvlan
    53: "logical",  # propVirtual
    209: "logical",  # bridge
    24: "loopback",  # softwareLoopback
    131: "tunnel",  # tunnel
}


def port_kind(if_type: int | None) -> str:
    return IF_TYPE_KIND.get(if_type, "other") if if_type is not None else "other"


ADMIN_STATUS = {1: "up", 2: "down", 3: "testing"}
OPER_STATUS = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "not_present",
    7: "lower_layer_down",
}

# LLDP-MIB LldpChassisIdSubtype / LldpPortIdSubtype.
LLDP_CHASSIS_SUBTYPES = {
    1: "chassis_component",
    2: "interface_alias",
    3: "port_component",
    4: "mac_address",
    5: "network_address",
    6: "interface_name",
    7: "local",
}
LLDP_PORT_SUBTYPES = {
    1: "interface_alias",
    2: "port_component",
    3: "mac_address",
    4: "network_address",
    5: "interface_name",
    6: "agent_circuit_id",
    7: "local",
}
# Nombres de capacidad que acepta el servidor (el sensor decodifica los bitmaps LLDP y CDP).
LLDP_CAPABILITIES = frozenset(
    {
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
    }
)
CDP_CAPABILITIES = frozenset(
    {
        "router",
        "transparent_bridge",
        "source_route_bridge",
        "switch",
        "host",
        "igmp",
        "repeater",
        "phone",
        "remote_managed",
        "cvta",
        "two_port_mac_relay",
    }
)

# Números de empresa privados de IANA (1.3.6.1.4.1.<n>) de fabricantes de red habituales.
# Solo identifican al FABRICANTE del agente SNMP; el modelo y la versión vienen de
# ENTITY-MIB o no se muestran. Un número que no está aquí se muestra como número, sin nombre.
ENTERPRISE_VENDORS: dict[int, str] = {
    9: "Cisco",
    11: "HP",
    171: "D-Link",
    674: "Dell",
    890: "Zyxel",
    1916: "Extreme Networks",
    2011: "Huawei",
    2620: "Check Point",
    2636: "Juniper Networks",
    3097: "WatchGuard",
    4526: "Netgear",
    5624: "Enterasys",
    6027: "Force10 Networks",
    6486: "Alcatel-Lucent",
    8741: "SonicWall",
    11863: "TP-Link",
    12356: "Fortinet",
    14823: "Aruba Networks",
    14988: "MikroTik",
    25461: "Palo Alto Networks",
    25506: "H3C",
    30065: "Arista Networks",
    41112: "Ubiquiti",
}
# Fabricantes cuyo catálogo es principalmente de cortafuegos/appliances de seguridad. Solo
# da confianza media: también venden switches y APs.
FIREWALL_ENTERPRISES = frozenset({2620, 3097, 8741, 12356, 25461})
ENTERPRISE_PREFIX = "1.3.6.1.4.1."


def enterprise_number(sys_object_id: str | None) -> int | None:
    """Número de empresa de un sysObjectID (1.3.6.1.4.1.<n>...). None si no tiene esa forma."""
    if not sys_object_id or not sys_object_id.startswith(ENTERPRISE_PREFIX):
        return None
    head = sys_object_id[len(ENTERPRISE_PREFIX) :].split(".", 1)[0]
    return int(head) if head.isdigit() and len(head) <= 9 else None


def evidence_source(module: str) -> str:
    """Etiqueta de procedencia que muestra la UI junto a cada dato de inventario."""
    return {
        "interfaces": "snmp:IF-MIB",
        "lldp": "snmp:LLDP-MIB",
        "cdp": "snmp:CISCO-CDP-MIB",
        "bridge": "snmp:BRIDGE-MIB/Q-BRIDGE-MIB",
        "vlan": "snmp:Q-BRIDGE-MIB",
        "entity": "snmp:ENTITY-MIB",
        "system": "snmp:SNMPv2-MIB",
        "wlan": "snmp:IEEE802dot11-MIB/AIRESPACE-WIRELESS-MIB/UBNT-UniFi-MIB",
    }[module]
