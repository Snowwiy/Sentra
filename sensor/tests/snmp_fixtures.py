"""Agente SNMP simulado en memoria (Fase 6B). Sin red: implementa GET y GETBULK sobre un
diccionario OID → valor ordenado, con modos de fallo para probar límites y errores."""

import bisect
from collections.abc import Sequence

from sentra_sensor.snmp import catalog as c
from sentra_sensor.snmp.transport import (
    ObjectId,
    Oid,
    SnmpError,
    SnmpTimeoutError,
    Value,
    VarBind,
)

SWITCH_MAC = bytes.fromhex("0011223344aa")
NEIGHBOR_MAC = bytes.fromhex("00aabbccdd01")


def _port_list(*ports: int, size: int = 4) -> bytes:
    data = bytearray(size)
    for port in ports:
        data[(port - 1) // 8] |= 0x80 >> ((port - 1) % 8)
    return bytes(data)


def switch_mib() -> dict[Oid, Value]:
    """Switch gestionable de 4 puertos + LAG, con LLDP, CDP, Q-BRIDGE y dos VLAN."""
    mib: dict[Oid, Value] = {
        c.SYS_DESCR: b"Example Switch OS 1.2\r\n",
        c.SYS_OBJECT_ID: ObjectId("1.3.6.1.4.1.11.2.3.7.11.1"),
        c.SYS_UPTIME: 123456,
        c.SYS_NAME: b"sw-core-01",
        c.SYS_LOCATION: b"Rack \x01A",
        c.SYS_SERVICES: 6,
        c.IP_FORWARDING: 2,
        # ENTITY-MIB: un chassis (1) y un módulo (2, clase 9) que no se informa.
        (*c.ENT_CLASS, 1): 3,
        (*c.ENT_CLASS, 2): 9,
        (*c.ENT_PHYSICAL, 2, 1): b"Chassis",
        (*c.ENT_PHYSICAL, 11, 1): b"SN-0001",
        (*c.ENT_PHYSICAL, 12, 1): b"Example Corp",
        (*c.ENT_PHYSICAL, 13, 1): b"EX-2400",
        (*c.ENT_PHYSICAL, 10, 1): b"1.2.3",
        # BRIDGE-MIB
        c.DOT1D_BASE_BRIDGE_ADDRESS: SWITCH_MAC,
        c.DOT1D_BASE_NUM_PORTS: 4,
        # LLDP local
        c.LLDP_LOC_CHASSIS_SUBTYPE: 4,
        c.LLDP_LOC_CHASSIS_ID: SWITCH_MAC,
        c.LLDP_LOC_SYS_NAME: b"sw-core-01",
        c.LLDP_LOC_CAP_ENABLED: bytes([0x20, 0x00]),  # bridge
    }
    interfaces = {
        1: (b"GigabitEthernet1/0/1", b"Gi1/0/1", 6, 1, 1),
        2: (b"GigabitEthernet1/0/2", b"Gi1/0/2", 6, 1, 1),
        3: (b"GigabitEthernet1/0/3", b"Gi1/0/3", 6, 1, 2),
        4: (b"GigabitEthernet1/0/4", b"Gi1/0/4", 6, 1, 1),
        100: (b"Port-channel1", b"Po1", 161, 1, 1),
    }
    for index, (descr, name, if_type, admin, oper) in interfaces.items():
        mib[(*c.IF_COLUMNS["descr"], index)] = descr
        mib[(*c.IF_COLUMNS["name"], index)] = name
        mib[(*c.IF_COLUMNS["if_type"], index)] = if_type
        mib[(*c.IF_COLUMNS["admin_status"], index)] = admin
        mib[(*c.IF_COLUMNS["oper_status"], index)] = oper
        mib[(*c.IF_COLUMNS["mtu"], index)] = 1500
        mib[(*c.IF_COLUMNS["speed"], index)] = 1_000_000_000
        mib[(*c.IF_COLUMNS["high_speed"], index)] = 1000
        mib[(*c.IF_COLUMNS["mac"], index)] = SWITCH_MAC[:5] + bytes([index])
        mib[(*c.IF_COLUMNS["hc_in_octets"], index)] = 2**40 + index
        mib[(*c.IF_COLUMNS["in_octets"], index)] = 7
        mib[(*c.IF_COLUMNS["in_errors"], index)] = 0
    # LAG Po1 sobre Gi1/0/3 y Gi1/0/4; 0 = sin capa inferior (no es relación).
    mib[(*c.IF_STACK_STATUS, 100, 3)] = 1
    mib[(*c.IF_STACK_STATUS, 100, 4)] = 1
    mib[(*c.IF_STACK_STATUS, 0, 1)] = 1
    # LLDP puertos locales y un vecino en el puerto 1 con IP de gestión 10.0.0.2.
    for port in (1, 2):
        mib[(*c.LLDP_LOC_PORT, 2, port)] = 5
        mib[(*c.LLDP_LOC_PORT, 3, port)] = f"Gi1/0/{port}".encode()
    rem = (0, 1, 7)
    mib[(*c.LLDP_REM, 4, *rem)] = 4
    mib[(*c.LLDP_REM, 5, *rem)] = NEIGHBOR_MAC
    mib[(*c.LLDP_REM, 6, *rem)] = 5
    mib[(*c.LLDP_REM, 7, *rem)] = b"Gi0/24"
    mib[(*c.LLDP_REM, 9, *rem)] = b"sw-access-02"
    mib[(*c.LLDP_REM, 12, *rem)] = bytes([0x28, 0x00])  # bridge + router
    mib[(*c.LLDP_REM_MAN_ADDR_IF_SUBTYPE, *rem, 1, 4, 10, 0, 0, 2)] = 2
    # CDP: vecino en ifIndex 2.
    cdp = (2, 1)
    mib[(*c.CDP_CACHE, 3, *cdp)] = 1
    mib[(*c.CDP_CACHE, 4, *cdp)] = bytes([10, 0, 0, 3])
    mib[(*c.CDP_CACHE, 6, *cdp)] = b"ap-hall.example"
    mib[(*c.CDP_CACHE, 7, *cdp)] = b"GigabitEthernet0"
    mib[(*c.CDP_CACHE, 8, *cdp)] = b"cisco AIR-AP"
    mib[(*c.CDP_CACHE, 9, *cdp)] = bytes([0, 0, 0, 0x0A])  # transparent_bridge + switch
    mib[(*c.CDP_CACHE, 11, *cdp)] = 10
    # Puertos de bridge 1-4 → ifIndex 1-4.
    for port in range(1, 5):
        mib[(*c.DOT1D_BASE_PORT_IF_INDEX, port)] = port
    # FDB Q-BRIDGE: dos MACs en el puerto 1 (VLAN fid 10), una multicast que se descarta y
    # la propia del switch (status self).
    for fdb, raw, port, status in (
        (10, bytes.fromhex("00163e000001"), 1, 3),
        (10, bytes.fromhex("00163e000002"), 2, 3),
        (10, bytes.fromhex("01005e000001"), 3, 3),
        (1, SWITCH_MAC, 0, 4),
    ):
        mib[(*c.DOT1Q_TP_FDB_PORT, fdb, *raw)] = port
        mib[(*c.DOT1Q_TP_FDB_STATUS, fdb, *raw)] = status
    # VLAN 1 (todos sin etiqueta) y 10 (puerto 1 sin etiqueta, puerto 3 etiquetado).
    mib[(*c.DOT1Q_VLAN_STATIC, 1, 1)] = b"default"
    mib[(*c.DOT1Q_VLAN_STATIC, 2, 1)] = _port_list(1, 2, 3, 4)
    mib[(*c.DOT1Q_VLAN_STATIC, 4, 1)] = _port_list(2, 4)
    mib[(*c.DOT1Q_VLAN_STATIC, 1, 10)] = b"users"
    mib[(*c.DOT1Q_VLAN_STATIC, 2, 10)] = _port_list(1, 3)
    mib[(*c.DOT1Q_VLAN_STATIC, 4, 10)] = _port_list(1)
    mib[(*c.DOT1Q_VLAN_CURRENT, 3, 0, 10)] = 10
    mib[(*c.DOT1Q_VLAN_CURRENT, 4, 0, 10)] = _port_list(1, 3)
    mib[(*c.DOT1Q_VLAN_CURRENT, 5, 0, 10)] = _port_list(1)
    for port, pvid in ((1, 10), (2, 1), (3, 1), (4, 1)):
        mib[(*c.DOT1Q_PVID, port)] = pvid
    return mib


def minimal_mib() -> dict[Oid, Value]:
    """Equipo que solo implementa system e IF-MIB (sin LLDP, CDP ni bridge)."""
    return {
        c.SYS_DESCR: b"Tiny router",
        c.SYS_OBJECT_ID: ObjectId("1.3.6.1.4.1.8072.3.2.10"),
        c.SYS_NAME: b"tiny",
        c.SYS_SERVICES: 72,
        c.IP_FORWARDING: 1,
        (*c.IF_COLUMNS["descr"], 1): b"eth0",
        (*c.IF_COLUMNS["if_type"], 1): 6,
    }


# --- Fase 6C.3: MIBs Wi-Fi sintéticas ------------------------------------------------------

AP1_RADIO = bytes.fromhex("00a0f8000100")
AP2_RADIO = bytes.fromhex("00a0f8000200")
AP1_ETH = bytes.fromhex("00a0f80001ff")
CLIENT_MAC = bytes.fromhex("3c2ef9000001")
RANDOM_CLIENT_MAC = bytes.fromhex("da1122334455")  # bit localmente administrado (0x02)


def dot11_ap_mib() -> dict[Oid, Value]:
    """AP autónomo con IEEE802dot11-MIB: radio 2,4 GHz WPA2 (ifIndex 2) y radio 5 GHz
    abierta (ifIndex 3)."""
    mib: dict[Oid, Value] = {
        c.SYS_DESCR: b"Autonomous AP 15.3",
        c.SYS_OBJECT_ID: ObjectId("1.3.6.1.4.1.9.1.2240"),
        c.SYS_NAME: b"ap-lobby",
        c.SYS_SERVICES: 2,
        (*c.IF_COLUMNS["descr"], 1): b"GigabitEthernet0",
        (*c.IF_COLUMNS["if_type"], 1): 6,
        (*c.IF_COLUMNS["descr"], 2): b"Dot11Radio0",
        (*c.IF_COLUMNS["if_type"], 2): 71,
        (*c.IF_COLUMNS["descr"], 3): b"Dot11Radio1",
        (*c.IF_COLUMNS["if_type"], 3): 71,
    }
    radios = {
        2: (bytes.fromhex("00cafe000010"), b"corp-wifi", 1, 1, 6, 6, None),
        3: (bytes.fromhex("00cafe000020"), b"guest", 2, 2, 9, None, 36),
    }
    for if_index, (mac, ssid, privacy, rsna, phy, dsss, ofdm) in radios.items():
        mib[(*c.DOT11_STATION_CONFIG, 1, if_index)] = mac
        mib[(*c.DOT11_STATION_CONFIG, 9, if_index)] = ssid
        mib[(*c.DOT11_STATION_CONFIG, 10, if_index)] = 1
        mib[(*c.DOT11_PRIVACY, 1, if_index)] = privacy
        mib[(*c.DOT11_PRIVACY, 7, if_index)] = rsna
        mib[(*c.DOT11_OPERATION, 1, if_index)] = mac
        mib[(*c.DOT11_PHY_OPERATION, 1, if_index)] = phy
        if dsss is not None:
            mib[(*c.DOT11_PHY_DSSS, 1, if_index)] = dsss
        if ofdm is not None:
            mib[(*c.DOT11_PHY_OFDM, 1, if_index)] = ofdm
    # Columna de claves WEP (dot11WEPDefaultKeyValue): existe en el agente pero el catálogo
    # no la permite; un test comprueba que nunca se pide.
    mib[(*c.DOT11, 1, 3, 1, 2, 2, 1)] = b"\x00" * 5
    return mib


def airespace_mib() -> dict[Oid, Value]:
    """Controladora Cisco AireOS con dos APs, sus radios, dos WLANs y tres clientes (uno con
    MAC aleatoria). Incluye columnas no autorizadas (usuario, IP de cliente)."""
    mib: dict[Oid, Value] = {
        c.SYS_DESCR: b"Cisco Controller",
        c.SYS_OBJECT_ID: ObjectId("1.3.6.1.4.1.9.1.1279"),
        c.SYS_NAME: b"wlc-01",
        c.SYS_SERVICES: 6,
    }
    aps = {
        AP1_RADIO: (
            b"AP-HALL",
            b"Hall",
            1,
            b"8.10.1",
            b"AIR-AP2802I-E-K9",
            b"FCW0001",
            (10, 70, 0, 21),
            AP1_ETH,
        ),
        AP2_RADIO: (
            b"AP-ROOF",
            b"",
            1,
            b"8.10.1",
            b"AIR-AP1832I",
            b"FCW0002",
            (10, 70, 0, 22),
            None,
        ),
    }
    for radio, (name, loc, status, sw, model, serial, ip, eth) in aps.items():
        index = tuple(radio)
        mib[(*c.BSN_AP, 3, *index)] = name
        mib[(*c.BSN_AP, 4, *index)] = loc
        mib[(*c.BSN_AP, 6, *index)] = status
        mib[(*c.BSN_AP, 8, *index)] = sw
        mib[(*c.BSN_AP, 16, *index)] = model
        mib[(*c.BSN_AP, 17, *index)] = serial
        mib[(*c.BSN_AP, 19, *index)] = bytes(ip)
        if eth is not None:
            mib[(*c.BSN_AP, 33, *index)] = eth
        for slot, (radio_type, channel, clients) in enumerate(((1, 11, 2), (2, 44, 1))):
            mib[(*c.BSN_AP_IF, 2, *index, slot)] = radio_type
            mib[(*c.BSN_AP_IF, 4, *index, slot)] = channel
            mib[(*c.BSN_AP_IF, 12, *index, slot)] = 2
            mib[(*c.BSN_AP_IF, 15, *index, slot)] = clients
    for ess, ssid, clients in ((1, b"corp-wifi", 2), (2, b"guest", 1)):
        mib[(*c.BSN_ESS, 2, ess)] = ssid
        mib[(*c.BSN_ESS, 38, ess)] = clients
    stations = (
        (CLIENT_MAC, AP1_RADIO, 0, 1, b"corp-wifi", 3, 6),
        (RANDOM_CLIENT_MAC, AP1_RADIO, 1, 2, b"guest", 3, 8),
        (bytes.fromhex("3c2ef9000002"), AP2_RADIO, 0, 1, b"corp-wifi", 0, 3),
    )
    for mac, ap, slot, ess, ssid, status, protocol in stations:
        index = tuple(mac)
        mib[(*c.BSN_STATION, 2, *index)] = bytes([10, 70, 0, 99])  # IP: no autorizada
        mib[(*c.BSN_STATION, 3, *index)] = b"alice@example.test"  # usuario: no autorizada
        mib[(*c.BSN_STATION, 4, *index)] = ap
        mib[(*c.BSN_STATION, 5, *index)] = slot
        mib[(*c.BSN_STATION, 6, *index)] = ess
        mib[(*c.BSN_STATION, 7, *index)] = ssid
        mib[(*c.BSN_STATION, 9, *index)] = status
        mib[(*c.BSN_STATION, 25, *index)] = protocol
    return mib


def unifi_mib() -> dict[Oid, Value]:
    """AP UniFi con dos VAPs en 2,4 GHz y 5 GHz (BSSID como texto, como en el firmware)."""
    mib: dict[Oid, Value] = {
        c.SYS_DESCR: b"UAP-AC-Pro 6.5.62",
        c.SYS_OBJECT_ID: ObjectId("1.3.6.1.4.1.41112"),
        c.SYS_NAME: b"uap-office",
        c.UNIFI_SYSTEM_IP: bytes([10, 70, 0, 31]),
        c.UNIFI_SYSTEM_MODEL: b"UAP-AC-Pro",
        c.UNIFI_SYSTEM_VERSION: b"6.5.62.14789",
    }
    vaps = (
        (1, b"78:8a:20:00:00:01", 6, b"office", b"ath0", 4, b"ng"),
        (2, b"78:8a:20:00:00:02", 100, b"office", b"ath1", 7, b"na"),
    )
    for index, bssid, channel, essid, name, clients, radio in vaps:
        mib[(*c.UNIFI_VAP, 2, index)] = bssid
        mib[(*c.UNIFI_VAP, 4, index)] = channel
        mib[(*c.UNIFI_VAP, 6, index)] = essid
        mib[(*c.UNIFI_VAP, 7, index)] = name
        mib[(*c.UNIFI_VAP, 8, index)] = clients
        mib[(*c.UNIFI_VAP, 9, index)] = radio
    return mib


class FakeAgent:
    """Implementa SnmpTransport sobre un diccionario. Cuenta peticiones y puede fallar."""

    def __init__(
        self,
        mib: dict[Oid, Value],
        *,
        fail_after: int | None = None,
        error: type[SnmpError] = SnmpTimeoutError,
        fail_prefix: Oid | None = None,
        loop_at: Oid | None = None,
    ) -> None:
        self._keys = sorted(mib)
        self._mib = mib
        self.requests: list[tuple[str, Oid | tuple[Oid, ...]]] = []
        self.closed = False
        self._fail_after = fail_after
        self._error = error
        self._fail_prefix = fail_prefix
        self._loop_at = loop_at

    def _maybe_fail(self, oid: Oid) -> None:
        if self._fail_after is not None and len(self.requests) > self._fail_after:
            raise self._error()
        if self._fail_prefix is not None and oid[: len(self._fail_prefix)] == self._fail_prefix:
            raise self._error()

    def get(self, oids: Sequence[Oid]) -> list[VarBind]:
        self.requests.append(("get", tuple(oids)))
        self._maybe_fail(oids[0])
        return [(o, self._mib.get(o)) for o in oids]

    def get_bulk(self, start: Oid, max_repetitions: int) -> list[VarBind]:
        self.requests.append(("bulk", start))
        self._maybe_fail(start)
        if self._loop_at is not None and start[: len(self._loop_at)] == self._loop_at:
            # Agente defectuoso: devuelve siempre el mismo OID (bucle infinito si no se corta).
            first = bisect.bisect_right(self._keys, self._loop_at)
            name = self._keys[first]
            return [(name, self._mib[name])]
        position = bisect.bisect_right(self._keys, start)
        names = self._keys[position : position + max_repetitions]
        return [(name, self._mib[name]) for name in names]

    def close(self) -> None:
        self.closed = True
