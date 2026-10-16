"""Catálogo cerrado y de solo lectura de los OIDs que el sensor puede consultar (Fase 6B).

Solo objetos de lectura de MIBs estándar (SNMPv2-MIB, IP-MIB, IF-MIB, ENTITY-MIB, LLDP-MIB,
BRIDGE-MIB, Q-BRIDGE-MIB) y de CISCO-CDP-MIB. Nada fuera de esta tabla sale nunca del sensor:
`allowed()` lo comprueba antes de cada petición (defensa en profundidad frente a un bug del
propio colector).
"""

Oid = tuple[int, ...]


def oid(text: str) -> Oid:
    return tuple(int(part) for part in text.split("."))


# --- SNMPv2-MIB e IP-MIB (escalares, GET) ----------------------------------------------------
SYS_DESCR = oid("1.3.6.1.2.1.1.1.0")
SYS_OBJECT_ID = oid("1.3.6.1.2.1.1.2.0")
SYS_UPTIME = oid("1.3.6.1.2.1.1.3.0")
SYS_NAME = oid("1.3.6.1.2.1.1.5.0")
SYS_LOCATION = oid("1.3.6.1.2.1.1.6.0")
SYS_SERVICES = oid("1.3.6.1.2.1.1.7.0")
IP_FORWARDING = oid("1.3.6.1.2.1.4.1.0")
SYSTEM_SCALARS = (SYS_DESCR, SYS_OBJECT_ID, SYS_UPTIME, SYS_NAME, SYS_LOCATION, SYS_SERVICES)

# --- ENTITY-MIB entPhysicalTable --------------------------------------------------------------
ENT_PHYSICAL = oid("1.3.6.1.2.1.47.1.1.1.1")
ENT_CLASS = (*ENT_PHYSICAL, 5)
ENT_COLUMNS = {
    "descr": 2,
    "name": 7,
    "hardware_rev": 8,
    "firmware_rev": 9,
    "software_rev": 10,
    "serial": 11,
    "mfg_name": 12,
    "model_name": 13,
}

# --- IF-MIB -------------------------------------------------------------------------------
IF_ENTRY = oid("1.3.6.1.2.1.2.2.1")
IF_X_ENTRY = oid("1.3.6.1.2.1.31.1.1.1")
IF_COLUMNS = {
    "descr": (*IF_ENTRY, 2),
    "if_type": (*IF_ENTRY, 3),
    "mtu": (*IF_ENTRY, 4),
    "speed": (*IF_ENTRY, 5),
    "mac": (*IF_ENTRY, 6),
    "admin_status": (*IF_ENTRY, 7),
    "oper_status": (*IF_ENTRY, 8),
    "in_octets": (*IF_ENTRY, 10),
    "in_discards": (*IF_ENTRY, 13),
    "in_errors": (*IF_ENTRY, 14),
    "out_octets": (*IF_ENTRY, 16),
    "out_discards": (*IF_ENTRY, 19),
    "out_errors": (*IF_ENTRY, 20),
    "name": (*IF_X_ENTRY, 1),
    "hc_in_octets": (*IF_X_ENTRY, 6),
    "hc_out_octets": (*IF_X_ENTRY, 10),
    "high_speed": (*IF_X_ENTRY, 15),
    "alias": (*IF_X_ENTRY, 18),
}
IF_STACK_STATUS = oid("1.3.6.1.2.1.31.1.2.1.3")

# --- LLDP-MIB (IEEE 802.1AB-2005, lldpMIB 1.0.8802.1.1.2) ---------------------------------
LLDP = oid("1.0.8802.1.1.2.1")
LLDP_LOC_CHASSIS_SUBTYPE = (*LLDP, 3, 1, 0)
LLDP_LOC_CHASSIS_ID = (*LLDP, 3, 2, 0)
LLDP_LOC_SYS_NAME = (*LLDP, 3, 3, 0)
LLDP_LOC_CAP_ENABLED = (*LLDP, 3, 6, 0)
LLDP_LOC_SCALARS = (
    LLDP_LOC_CHASSIS_SUBTYPE,
    LLDP_LOC_CHASSIS_ID,
    LLDP_LOC_SYS_NAME,
    LLDP_LOC_CAP_ENABLED,
)
LLDP_LOC_PORT = (*LLDP, 3, 7, 1)
LLDP_LOC_PORT_COLUMNS = {"port_id_subtype": 2, "port_id": 3, "port_desc": 4}
LLDP_REM = (*LLDP, 4, 1, 1)
LLDP_REM_COLUMNS = {
    "chassis_id_subtype": 4,
    "chassis_id": 5,
    "port_id_subtype": 6,
    "port_id": 7,
    "port_desc": 8,
    "sys_name": 9,
    "sys_desc": 10,
    "capabilities": 12,
}
# lldpRemManAddrIfSubtype: la dirección viaja en el índice de la fila.
LLDP_REM_MAN_ADDR_IF_SUBTYPE = (*LLDP, 4, 2, 1, 3)

# --- CISCO-CDP-MIB cdpCacheTable ----------------------------------------------------------
CDP_CACHE = oid("1.3.6.1.4.1.9.9.23.1.2.1.1")
CDP_COLUMNS = {
    "address_type": 3,
    "address": 4,
    "software": 5,
    "device_id": 6,
    "device_port": 7,
    "platform": 8,
    "capabilities": 9,
    "native_vlan": 11,
}

# --- BRIDGE-MIB ---------------------------------------------------------------------------
DOT1D_BASE_BRIDGE_ADDRESS = oid("1.3.6.1.2.1.17.1.1.0")
DOT1D_BASE_NUM_PORTS = oid("1.3.6.1.2.1.17.1.2.0")
DOT1D_BASE_PORT_IF_INDEX = oid("1.3.6.1.2.1.17.1.4.1.2")
DOT1D_TP_FDB_PORT = oid("1.3.6.1.2.1.17.4.3.1.2")
DOT1D_TP_FDB_STATUS = oid("1.3.6.1.2.1.17.4.3.1.3")

# --- Q-BRIDGE-MIB -------------------------------------------------------------------------
QBRIDGE = oid("1.3.6.1.2.1.17.7.1")
DOT1Q_TP_FDB_PORT = (*QBRIDGE, 2, 2, 1, 2)
DOT1Q_TP_FDB_STATUS = (*QBRIDGE, 2, 2, 1, 3)
DOT1Q_VLAN_CURRENT = (*QBRIDGE, 4, 2, 1)
DOT1Q_VLAN_CURRENT_COLUMNS = {"fdb_id": 3, "egress": 4, "untagged": 5}
DOT1Q_VLAN_STATIC = (*QBRIDGE, 4, 3, 1)
DOT1Q_VLAN_STATIC_COLUMNS = {"name": 1, "egress": 2, "untagged": 4}
DOT1Q_PVID = (*QBRIDGE, 4, 5, 1, 1)

# Raíces autorizadas: todo OID pedido debe colgar de una de ellas.
ALLOWED_ROOTS: tuple[Oid, ...] = (
    oid("1.3.6.1.2.1.1"),
    IP_FORWARDING,
    ENT_PHYSICAL,
    IF_ENTRY,
    IF_X_ENTRY,
    IF_STACK_STATUS,
    (*LLDP, 3),
    (*LLDP, 4),
    CDP_CACHE,
    oid("1.3.6.1.2.1.17.1"),
    oid("1.3.6.1.2.1.17.4.3.1"),
    (*QBRIDGE, 2, 2, 1),
    (*QBRIDGE, 4, 2, 1),
    (*QBRIDGE, 4, 3, 1),
    DOT1Q_PVID,
)


def allowed(target: Oid) -> bool:
    return any(target[: len(root)] == root for root in ALLOWED_ROOTS)


def dotted(value: Oid) -> str:
    return ".".join(str(part) for part in value)
