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
