"""Lectura de cada familia de MIBs y conversión a registros del contrato (Fase 6B).

Cada función recibe un Walker (que ya aplica catálogo, límites y plazo) y devuelve los
registros normalizados de su módulo y su estado:
- "complete": se leyó todo lo que el equipo ofrece;
- "partial": algo se recortó (tope de filas) o una tabla vino malformada;
- "unsupported": el equipo no implementa la MIB (no es un error).

Solo evidencia observada: aquí no se interpreta nada (ni tipo de puerto, ni VLAN de una MAC,
ni clasificación), eso lo hace el servidor con todos los datos juntos.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sentra_sensor.snmp import catalog, values
from sentra_sensor.snmp.transport import ObjectId, SnmpError, Value
from sentra_sensor.snmp.walker import Column, Walker, rows_by_index

Record = dict[str, Any]
MAX_INDEX = 2**31 - 1
MAX_COUNTER = 2**64 - 1
MAX_ENTITIES = 16
MAX_MGMT_ADDRESSES = 4
_OID_TEXT = re.compile(r"^[0-2](\.\d{1,10}){1,127}$")
# Subtipos LLDP: chassis macAddress(4)/networkAddress(5); puerto macAddress(3)/networkAddress(4).
_CHASSIS_MAC, _CHASSIS_ADDR = 4, 5
_PORT_MAC, _PORT_ADDR = 3, 4


class SnmpOidUnavailableError(SnmpError):
    """El equipo responde pero no ofrece ni siquiera SNMPv2-MIB system."""

    code = "oid_unavailable"


@dataclass
class ModuleResult:
    status: str
    records: list[Record] = field(default_factory=list)


def _clean(record: Record) -> Record:
    # Sin claves nulas: el lote es más pequeño y el servidor aplica sus valores por defecto.
    return {k: v for k, v in record.items() if v is not None and v != []}


def _single(index: tuple[int, ...]) -> int | None:
    if len(index) == 1 and 1 <= index[0] <= MAX_INDEX:
        return index[0]
    return None


def _status(columns: list[Column], present: bool) -> str:
    if not present:
        return "unsupported"
    if any(c.truncated or c.malformed for c in columns):
        return "partial"
    return "complete"


# --- SNMPv2-MIB ------------------------------------------------------------------------------


def system(walker: Walker) -> ModuleResult:
    scalars = walker.get([*catalog.SYSTEM_SCALARS, catalog.IP_FORWARDING])
    if all(scalars.get(o) is None for o in catalog.SYSTEM_SCALARS):
        raise SnmpOidUnavailableError("SNMPv2-MIB system group not available")
    object_id = scalars.get(catalog.SYS_OBJECT_ID)
    oid_text = str(object_id) if isinstance(object_id, ObjectId) else None
    forwarding = values.integer(scalars.get(catalog.IP_FORWARDING), 1, 2)
    record = {
        "kind": "system",
        "sys_descr": values.text(scalars.get(catalog.SYS_DESCR), 1024),
        "sys_object_id": oid_text if oid_text and _OID_TEXT.match(oid_text) else None,
        "sys_name": values.text(scalars.get(catalog.SYS_NAME), 255),
        "sys_location": values.text(scalars.get(catalog.SYS_LOCATION), 255),
        "sys_uptime_ticks": values.integer(scalars.get(catalog.SYS_UPTIME), 0, 2**32 - 1),
        "sys_services": values.integer(scalars.get(catalog.SYS_SERVICES), 0, 127),
        "ip_forwarding": forwarding,
    }
    return ModuleResult("complete", [_clean(record)])


# --- ENTITY-MIB --------------------------------------------------------------------------------


def entity(walker: Walker) -> ModuleResult:
    classes = walker.column(catalog.ENT_CLASS)
    if not classes.exists:
        return ModuleResult("unsupported")
    # Solo chassis (3) y stack (11): describen el equipo; módulos, ventiladores o fuentes no.
    wanted = sorted(
        index
        for index, value in classes.rows.items()
        if _single(index) is not None and values.integer(value, 1, 12) in (3, 11)
    )[:MAX_ENTITIES]
    oids = [
        (*catalog.ENT_PHYSICAL, column, *index)
        for index in wanted
        for column in catalog.ENT_COLUMNS.values()
    ]
    fetched = walker.get(oids)
    records = []
    for index in wanted:
        row = {
            name: fetched.get((*catalog.ENT_PHYSICAL, column, *index))
            for name, column in catalog.ENT_COLUMNS.items()
        }
        limits = {"descr": 255, "name": 255}
        record: Record = {
            "kind": "entity",
            "index": index[0],
            "phys_class": values.integer(classes.rows[index], 1, 12),
        }
        for name, value in row.items():
            record[name] = values.text(value, limits.get(name, 128))
        records.append(_clean(record))
    return ModuleResult(_status([classes], True), records)


# --- IF-MIB ------------------------------------------------------------------------------------


def _counter(value: Value) -> int | None:
    return values.integer(value, 0, MAX_COUNTER)


def interfaces(walker: Walker) -> ModuleResult:
    columns = {name: walker.column(base) for name, base in catalog.IF_COLUMNS.items()}
    present = columns["descr"].exists or columns["name"].exists
    records: list[Record] = []
    for index, row in sorted(rows_by_index(columns).items()):
        if_index = _single(index)
        if if_index is None:
            continue
        hc = row.get("hc_in_octets") is not None or row.get("hc_out_octets") is not None
        records.append(
            _clean(
                {
                    "kind": "interface",
                    "if_index": if_index,
                    "descr": values.text(row.get("descr"), 255),
                    "name": values.text(row.get("name"), 255),
                    "alias": values.text(row.get("alias"), 255),
                    "if_type": values.integer(row.get("if_type"), 1, 65535),
                    "mtu": values.integer(row.get("mtu"), 0, MAX_INDEX),
                    "speed": values.integer(row.get("speed"), 0, 2**32 - 1),
                    "high_speed": values.integer(row.get("high_speed"), 0, 2**32 - 1),
                    "mac": values.mac(row.get("mac")),
                    "admin_status": values.integer(row.get("admin_status"), 1, 3),
                    "oper_status": values.integer(row.get("oper_status"), 1, 7),
                    "in_octets": _counter(row.get("hc_in_octets") if hc else row.get("in_octets")),
                    "out_octets": _counter(
                        row.get("hc_out_octets") if hc else row.get("out_octets")
                    ),
                    "counters_hc": hc or None,
                    "in_errors": _counter(row.get("in_errors")),
                    "out_errors": _counter(row.get("out_errors")),
                    "in_discards": _counter(row.get("in_discards")),
                    "out_discards": _counter(row.get("out_discards")),
                }
            )
        )
    stack = walker.column(catalog.IF_STACK_STATUS)
    for index in sorted(stack.rows):
        # ifStackTable: (higher, lower); 0 significa "nada encima/debajo" y no es una relación.
        if len(index) == 2 and all(1 <= part <= MAX_INDEX for part in index):
            records.append({"kind": "if_stack", "higher": index[0], "lower": index[1]})
    return ModuleResult(_status([*columns.values(), stack], present), records)


# --- LLDP-MIB -----------------------------------------------------------------------------------


def lldp(walker: Walker) -> ModuleResult:
    local = walker.get(list(catalog.LLDP_LOC_SCALARS))
    ports = walker.table(catalog.LLDP_LOC_PORT, catalog.LLDP_LOC_PORT_COLUMNS)
    remote = walker.table(catalog.LLDP_REM, catalog.LLDP_REM_COLUMNS)
    addresses = walker.column(catalog.LLDP_REM_MAN_ADDR_IF_SUBTYPE)
    has_local = any(local.get(o) is not None for o in catalog.LLDP_LOC_SCALARS)
    present = (
        has_local or any(c.exists for c in ports.values()) or any(c.exists for c in remote.values())
    )
    if not present:
        return ModuleResult("unsupported")
    records: list[Record] = []
    if has_local:
        subtype = values.integer(local.get(catalog.LLDP_LOC_CHASSIS_SUBTYPE), 1, 7)
        records.append(
            _clean(
                {
                    "kind": "lldp_local",
                    "chassis_id_subtype": subtype,
                    "chassis_id": values.chassis_or_port_id(
                        subtype, local.get(catalog.LLDP_LOC_CHASSIS_ID), _CHASSIS_MAC, _CHASSIS_ADDR
                    ),
                    "sys_name": values.text(local.get(catalog.LLDP_LOC_SYS_NAME), 255),
                    "capabilities": values.lldp_capabilities(
                        local.get(catalog.LLDP_LOC_CAP_ENABLED)
                    ),
                }
            )
        )
    for index, row in sorted(rows_by_index(ports).items()):
        port_num = _single(index)
        if port_num is None:
            continue
        subtype = values.integer(row.get("port_id_subtype"), 1, 7)
        records.append(
            _clean(
                {
                    "kind": "lldp_local_port",
                    "port_num": port_num,
                    "port_id_subtype": subtype,
                    "port_id": values.chassis_or_port_id(
                        subtype, row.get("port_id"), _PORT_MAC, _PORT_ADDR
                    ),
                    "port_desc": values.text(row.get("port_desc"), 255),
                }
            )
        )
    # lldpRemManAddrTable: índice = timeMark, localPort, remIndex, subtipo, longitud, octetos.
    mgmt: dict[tuple[int, int], list[str]] = {}
    for index in addresses.rows:
        if len(index) < 6:
            continue
        _, local_port, rem_index, family, length, *octets = index
        if family not in (1, 2) or length != len(octets):
            continue
        parsed = values.ip_address(tuple(octets)) if all(0 <= o <= 255 for o in octets) else None
        if parsed is None:
            continue
        found = mgmt.setdefault((local_port, rem_index), [])
        if parsed not in found and len(found) < MAX_MGMT_ADDRESSES:
            found.append(parsed)
    # Varias filas con distinto timeMark para el mismo vecino: vale la más reciente (la
    # última en orden de OID).
    latest: dict[tuple[int, int], dict[str, Any]] = {}
    for index, row in sorted(rows_by_index(remote).items()):
        if len(index) != 3 or not all(1 <= part <= MAX_INDEX for part in index[1:]):
            continue
        latest[(index[1], index[2])] = row
    for (local_port, rem_index), row in sorted(latest.items()):
        chassis_subtype = values.integer(row.get("chassis_id_subtype"), 1, 7)
        port_subtype = values.integer(row.get("port_id_subtype"), 1, 7)
        records.append(
            _clean(
                {
                    "kind": "lldp_remote",
                    "local_port_num": local_port,
                    "rem_index": rem_index,
                    "chassis_id_subtype": chassis_subtype,
                    "chassis_id": values.chassis_or_port_id(
                        chassis_subtype, row.get("chassis_id"), _CHASSIS_MAC, _CHASSIS_ADDR
                    ),
                    "port_id_subtype": port_subtype,
                    "port_id": values.chassis_or_port_id(
                        port_subtype, row.get("port_id"), _PORT_MAC, _PORT_ADDR
                    ),
                    "port_desc": values.text(row.get("port_desc"), 255),
                    "sys_name": values.text(row.get("sys_name"), 255),
                    "sys_desc": values.text(row.get("sys_desc"), 1024),
                    "capabilities": values.lldp_capabilities(row.get("capabilities")),
                    "mgmt_addresses": mgmt.get((local_port, rem_index), []),
                }
            )
        )
    columns = [*ports.values(), *remote.values(), addresses]
    return ModuleResult(_status(columns, True), records)


# --- CISCO-CDP-MIB ------------------------------------------------------------------------------


def cdp(walker: Walker) -> ModuleResult:
    columns = walker.table(catalog.CDP_CACHE, catalog.CDP_COLUMNS)
    present = any(c.exists for c in columns.values())
    if not present:
        return ModuleResult("unsupported")
    records: list[Record] = []
    for index, row in sorted(rows_by_index(columns).items()):
        if len(index) != 2 or not all(1 <= part <= MAX_INDEX for part in index):
            continue
        raw_address = row.get("address")
        address = None
        # cdpCacheAddressType 1 = ip (CiscoNetworkProtocol); solo IPv4 de 4 octetos.
        if row.get("address_type") == 1 and isinstance(raw_address, bytes):
            address = values.ip_address(raw_address) if len(raw_address) == 4 else None
        records.append(
            _clean(
                {
                    "kind": "cdp_neighbor",
                    "if_index": index[0],
                    "device_index": index[1],
                    "device_id": values.text(row.get("device_id"), 255),
                    "device_port": values.text(row.get("device_port"), 255),
                    "platform": values.text(row.get("platform"), 255),
                    "software": values.text(row.get("software"), 512),
                    "address": address,
                    "capabilities": values.cdp_capabilities(row.get("capabilities")),
                    "native_vlan": values.integer(row.get("native_vlan"), 1, 4094),
                }
            )
        )
    return ModuleResult(_status(list(columns.values()), True), records)


# --- BRIDGE-MIB y Q-BRIDGE-MIB -------------------------------------------------------------------


def _unicast(mac: str | None) -> str | None:
    if mac is None or mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
        return None
    return mac


def bridge(walker: Walker) -> ModuleResult:
    base = walker.get([catalog.DOT1D_BASE_BRIDGE_ADDRESS, catalog.DOT1D_BASE_NUM_PORTS])
    port_map = walker.column(catalog.DOT1D_BASE_PORT_IF_INDEX)
    records: list[Record] = []
    if (
        base.get(catalog.DOT1D_BASE_BRIDGE_ADDRESS) is not None
        or base.get(catalog.DOT1D_BASE_NUM_PORTS) is not None
    ):
        records.append(
            _clean(
                {
                    "kind": "bridge_base",
                    "bridge_address": values.mac(base.get(catalog.DOT1D_BASE_BRIDGE_ADDRESS)),
                    "num_ports": values.integer(base.get(catalog.DOT1D_BASE_NUM_PORTS), 0, 65535),
                }
            )
        )
    for index, value in sorted(port_map.rows.items()):
        if_index = values.integer(value, 1, MAX_INDEX)
        if len(index) == 1 and 1 <= index[0] <= 65535 and if_index is not None:
            records.append({"kind": "bridge_port", "port": index[0], "if_index": if_index})
    # Q-BRIDGE (con VLAN) si existe; si no, la tabla clásica de BRIDGE-MIB.
    q_ports = walker.column(catalog.DOT1Q_TP_FDB_PORT)
    fdb: list[Column]
    if q_ports.exists:
        q_status = walker.column(catalog.DOT1Q_TP_FDB_STATUS)
        fdb = [q_ports, q_status]
        records.extend(_fdb(q_ports, q_status, "dot1q", lambda index: index[0], 7))
    else:
        d_ports = walker.column(catalog.DOT1D_TP_FDB_PORT)
        d_status = walker.column(catalog.DOT1D_TP_FDB_STATUS)
        fdb = [d_ports, d_status]
        records.extend(_fdb(d_ports, d_status, "dot1d", lambda index: 0, 6))
    present = bool(records) or port_map.exists or any(c.exists for c in fdb)
    return ModuleResult(_status([port_map, *fdb], present), records)


def _fdb(
    ports: Column,
    statuses: Column,
    source: str,
    fdb_of: Callable[[tuple[int, ...]], int],
    index_length: int,
) -> list[Record]:
    records = []
    for index, value in sorted(ports.rows.items()):
        if len(index) != index_length:
            continue
        mac = _unicast(values.mac_from_index(index[-6:]))
        port = values.integer(value, 0, 65535)
        fdb_id = fdb_of(index)
        if mac is None or port is None or not 0 <= fdb_id <= MAX_INDEX:
            continue
        status = values.integer(statuses.rows.get(index), 1, 5) or 3
        records.append(
            {
                "kind": "mac_entry",
                "mac": mac,
                "port": port,
                "fdb_id": fdb_id,
                "status": status,
                "source": source,
            }
        )
    return records


def vlan(walker: Walker) -> ModuleResult:
    static = walker.table(catalog.DOT1Q_VLAN_STATIC, catalog.DOT1Q_VLAN_STATIC_COLUMNS)
    current = walker.table(catalog.DOT1Q_VLAN_CURRENT, catalog.DOT1Q_VLAN_CURRENT_COLUMNS)
    pvids = walker.column(catalog.DOT1Q_PVID)
    columns = [*static.values(), *current.values(), pvids]
    if not any(c.exists for c in columns):
        return ModuleResult("unsupported")
    records: list[Record] = []
    for index, row in sorted(rows_by_index(static).items()):
        if len(index) != 1 or not 1 <= index[0] <= 4094:
            continue
        records.append(
            _clean(
                {
                    "kind": "vlan",
                    "vlan_id": index[0],
                    "name": values.text(row.get("name"), 64),
                    "source": "static",
                    "egress_ports": values.port_list(row.get("egress")),
                    "untagged_ports": values.port_list(row.get("untagged")),
                }
            )
        )
    # dot1qVlanCurrentTable: índice = timeMark, vlanIndex; vale la fila más reciente.
    latest: dict[int, dict[str, Any]] = {}
    for index, row in sorted(rows_by_index(current).items()):
        if len(index) == 2 and 1 <= index[1] <= 4094:
            latest[index[1]] = row
    for vlan_id, row in sorted(latest.items()):
        records.append(
            _clean(
                {
                    "kind": "vlan",
                    "vlan_id": vlan_id,
                    "source": "current",
                    "fdb_id": values.integer(row.get("fdb_id"), 0, MAX_INDEX),
                    "egress_ports": values.port_list(row.get("egress")),
                    "untagged_ports": values.port_list(row.get("untagged")),
                }
            )
        )
    for index, value in sorted(pvids.rows.items()):
        pvid = values.integer(value, 1, 4094)
        if len(index) == 1 and 1 <= index[0] <= 65535 and pvid is not None:
            records.append({"kind": "pvid", "port": index[0], "vlan_id": pvid})
    return ModuleResult(_status(columns, True), records)


READERS: dict[str, Callable[[Walker], ModuleResult]] = {
    "system": system,
    "entity": entity,
    "interfaces": interfaces,
    "lldp": lldp,
    "cdp": cdp,
    "bridge": bridge,
    "vlan": vlan,
}
