"""Catálogo cerrado y de solo lectura de los OIDs que el sensor puede consultar (Fase 6B).

Solo objetos de lectura de MIBs estándar (SNMPv2-MIB, IP-MIB, IF-MIB, ENTITY-MIB, LLDP-MIB,
BRIDGE-MIB, Q-BRIDGE-MIB) y de CISCO-CDP-MIB. Fase 6C.3 (módulo wlan): columnas concretas de
IEEE802dot11-MIB, AIRESPACE-WIRELESS-MIB (controladoras Cisco) y UBNT-UniFi-MIB; la lista
autorizada es por COLUMNA, no por tabla, para que ninguna petición pueda alcanzar columnas con
claves WEP, nombres de usuario o IPs de clientes aunque compartan tabla con las permitidas.
Nada fuera de esta tabla sale nunca del sensor:
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

# --- Fase 6C.3: IEEE802dot11-MIB (1.2.840.10036), tablas indexadas por ifIndex -------------
DOT11 = oid("1.2.840.10036")
# dot11StationConfigEntry: dot11StationID(1), dot11DesiredSSID(9), dot11DesiredBSSType(10).
DOT11_STATION_CONFIG = (*DOT11, 1, 1, 1)
DOT11_STATION_COLUMNS = {"station_id": 1, "desired_ssid": 9, "bss_type": 10}
# dot11PrivacyEntry: dot11PrivacyInvoked(1), dot11ExcludeUnencrypted(4), dot11RSNAEnabled(7).
# Nunca dot11WEPDefaultKeysTable ni dot11WEPKeyMappingsTable (1.2.840.10036.1.3/1.4).
DOT11_PRIVACY = (*DOT11, 1, 5, 1)
DOT11_PRIVACY_COLUMNS = {"privacy_invoked": 1, "exclude_unencrypted": 4, "rsna_enabled": 7}
# dot11OperationEntry: dot11MACAddress(1).
DOT11_OPERATION = (*DOT11, 2, 1, 1)
DOT11_OPERATION_COLUMNS = {"mac_address": 1}
# dot11PhyOperationEntry: dot11PHYType(1).
DOT11_PHY_OPERATION = (*DOT11, 4, 1, 1)
DOT11_PHY_OPERATION_COLUMNS = {"phy_type": 1}
# dot11PhyDSSSEntry: dot11CurrentChannel(1); dot11PhyOFDMEntry: dot11CurrentFrequency(1)
# (número de canal OFDM, pese al nombre).
DOT11_PHY_DSSS = (*DOT11, 4, 5, 1)
DOT11_PHY_OFDM = (*DOT11, 4, 11, 1)
DOT11_PHY_CHANNEL_COLUMNS = {"channel": 1}

# --- Fase 6C.3: AIRESPACE-WIRELESS-MIB (controladoras Cisco, empresa 14179) ----------------
AIRESPACE = oid("1.3.6.1.4.1.14179")
# bsnAPEntry, índice bsnAPDot3MacAddress (6 octetos). Sin bsnAPReset ni columnas escribibles
# (solo se leen; aun así no se piden).
BSN_AP = (*AIRESPACE, 2, 2, 1, 1)
BSN_AP_COLUMNS = {
    "name": 3,
    "location": 4,
    "operation_status": 6,
    "software_version": 8,
    "model": 16,
    "serial": 17,
    "ip_address": 19,
    "ethernet_mac": 33,
}
# bsnAPIfEntry, índice (bsnAPDot3MacAddress, bsnAPIfSlotId).
BSN_AP_IF = (*AIRESPACE, 2, 2, 2, 1)
BSN_AP_IF_COLUMNS = {"radio_type": 2, "channel": 4, "oper_status": 12, "clients": 15}
# bsnDot11EssEntry, índice bsnDot11EssIndex: SSID y número de clientes de cada WLAN.
BSN_ESS = (*AIRESPACE, 2, 1, 1, 1)
BSN_ESS_COLUMNS = {"ssid": 2, "clients": 38}
# bsnMobileStationEntry, índice bsnMobileStationMacAddress. Minimización de datos: nunca
# bsnMobileStationUserName(3) ni bsnMobileStationIpAddress(2).
BSN_STATION = (*AIRESPACE, 2, 1, 4, 1)
BSN_STATION_COLUMNS = {
    "ap_mac": 4,
    "slot": 5,
    "ess_index": 6,
    "ssid": 7,
    "status": 9,
    "protocol": 25,
}

# --- Fase 6C.3: UBNT-UniFi-MIB (Ubiquiti UniFi AP, empresa 41112) ----------------------------
UNIFI = oid("1.3.6.1.4.1.41112.1.6")
# unifiVapEntry, índice unifiVapIndex.
UNIFI_VAP = (*UNIFI, 1, 2, 1)
UNIFI_VAP_COLUMNS = {
    "bssid": 2,
    "channel": 4,
    "essid": 6,
    "name": 7,
    "clients": 8,
    "radio": 9,
}
# unifiApSystem: IP(1), modelo(3) y versión(6), escalares.
UNIFI_SYSTEM_IP = (*UNIFI, 3, 1, 0)
UNIFI_SYSTEM_MODEL = (*UNIFI, 3, 3, 0)
UNIFI_SYSTEM_VERSION = (*UNIFI, 3, 6, 0)
UNIFI_SYSTEM_SCALARS = (UNIFI_SYSTEM_IP, UNIFI_SYSTEM_MODEL, UNIFI_SYSTEM_VERSION)


def _columns(entry: Oid, columns: dict[str, int]) -> tuple[Oid, ...]:
    return tuple((*entry, number) for number in columns.values())


WLAN_ROOTS: tuple[Oid, ...] = (
    *_columns(DOT11_STATION_CONFIG, DOT11_STATION_COLUMNS),
    *_columns(DOT11_PRIVACY, DOT11_PRIVACY_COLUMNS),
    *_columns(DOT11_OPERATION, DOT11_OPERATION_COLUMNS),
    *_columns(DOT11_PHY_OPERATION, DOT11_PHY_OPERATION_COLUMNS),
    *_columns(DOT11_PHY_DSSS, DOT11_PHY_CHANNEL_COLUMNS),
    *_columns(DOT11_PHY_OFDM, DOT11_PHY_CHANNEL_COLUMNS),
    *_columns(BSN_AP, BSN_AP_COLUMNS),
    *_columns(BSN_AP_IF, BSN_AP_IF_COLUMNS),
    *_columns(BSN_ESS, BSN_ESS_COLUMNS),
    *_columns(BSN_STATION, BSN_STATION_COLUMNS),
    *_columns(UNIFI_VAP, UNIFI_VAP_COLUMNS),
    *UNIFI_SYSTEM_SCALARS,
)

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
    *WLAN_ROOTS,
)


def allowed(target: Oid) -> bool:
    return any(target[: len(root)] == root for root in ALLOWED_ROOTS)


def dotted(value: Oid) -> str:
    return ".".join(str(part) for part in value)
