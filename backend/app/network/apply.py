"""Aplicación de una consulta SNMP al inventario (Fase 6B): evidencia → tablas de 6B.

Se ejecuta al cerrar el job, con todos los registros del área temporal, porque interpretar
exige cruzar datos que llegan en lotes distintos: puerto de bridge → ifIndex → interfaz,
puerto LLDP local → interfaz, bitmaps de VLAN → puertos, fdb id → VLAN.

Invariantes (docs/snmp-network-intelligence.md):
- Solo se aplican módulos que el sensor informa como complete o partial. Un módulo partial
  aporta evidencia positiva (lo visto se actualiza) pero NUNCA marca nada como ausente: le
  faltan filas. Solo un módulo complete de una consulta completa marca ausencias.
- Todo se resuelve dentro del site del equipo. El cruce de un vecino con otro equipo
  registrado, o de una MAC con un activo, jamás mira otro site.
- ifIndex no es identidad: la interfaz se identifica por stable_key (ifName, ifDescr o, en
  último caso, ifIndex) y el ifIndex se actualiza.
- Un vecino LLDP/CDP es lo que el equipo informa; no se deduce ningún enlace que el equipo
  no declare y nunca se marca como confirmado.
"""

import hashlib
import logging
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.asset import Asset
from app.models.network import (
    NetworkDevice,
    NetworkDevicePoll,
    NetworkInterface,
    NetworkMacEntry,
    NetworkNeighbor,
    NetworkVlan,
    NetworkVlanMembership,
)
from app.network.catalog import (
    ADMIN_STATUS,
    LLDP_CHASSIS_SUBTYPES,
    LLDP_PORT_SUBTYPES,
    OPER_STATUS,
    port_kind,
)
from app.network.classify import DeviceEvidence, classify

logger = logging.getLogger(__name__)

# BIGINT de PostgreSQL es con signo: un Counter64 real nunca llega aquí, pero un sensor
# comprometido podría mandar 2^64-1 y la inserción fallaría con un 500.
_BIGINT_MAX = 2**63 - 1
# ifSpeed satura en 2^32-1 bps: con ese valor, sin ifHighSpeed, la velocidad es desconocida.
_IF_SPEED_SATURATED = 2**32 - 1
MAX_ENTITIES = 16
MAC_STATUS = {1: "other", 2: "invalid", 3: "learned", 4: "self", 5: "mgmt"}
_INSERT_CHUNK = 2000


def _clamp(value: int | None) -> int | None:
    return None if value is None else min(int(value), _BIGINT_MAX)


def _speed_mbps(record: dict[str, Any]) -> int | None:
    high = record.get("high_speed")
    if isinstance(high, int) and high > 0:
        return high
    speed = record.get("speed")
    if not isinstance(speed, int) or speed == _IF_SPEED_SATURATED:
        return None
    return speed // 1_000_000


def _stable_key(record: dict[str, Any]) -> str:
    for key in ("name", "descr"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:240]
    return f"ifIndex:{record['if_index']}"


def _remote_key(*parts: object) -> str:
    """Huella de la identidad remota informada (para el índice único de observaciones)."""
    raw = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class ApplyResult:
    counts: dict[str, int] = field(default_factory=dict)
    changes: dict[str, Any] = field(default_factory=dict)


class PollApplier:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        device: NetworkDevice,
        poll: NetworkDevicePoll,
        now: datetime,
    ) -> None:
        self._session = session
        self._settings = settings
        self._device = device
        self._poll = poll
        self._now = now
        self._changes: dict[str, Any] = {
            "interfaces_added": 0,
            "interfaces_removed": 0,
            "oper_status_changes": 0,
            "neighbors_added": 0,
            "neighbors_removed": 0,
            "classification_changed": False,
        }

    # --- entrada ---------------------------------------------------------------------------

    def apply(
        self, records: Sequence[tuple[str, dict[str, Any]]], modules: dict[str, str], full: bool
    ) -> ApplyResult:
        """Aplica los registros. `full` = la consulta terminó completa (no cancelada,
        sin lotes perdidos ni plazo agotado): requisito para marcar ausencias."""
        by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for kind, data in records:
            by_kind[kind].append(data)

        def usable(module: str) -> bool:
            return modules.get(module) in ("complete", "partial")

        def authoritative(module: str) -> bool:
            return full and modules.get(module) == "complete"

        if usable("system"):
            self._system(by_kind.get("system", []))
        if usable("entity"):
            self._entities(by_kind.get("entity", []))
        interfaces = self._interfaces(
            by_kind.get("interface", []), by_kind.get("if_stack", []), usable("interfaces")
        )
        if authoritative("interfaces"):
            self._mark_absent_interfaces()
        by_index = self._present_by_index()
        port_map: dict[int, int] = {}
        if usable("bridge") or usable("vlan"):
            port_map = self._bridge(
                by_kind.get("bridge_base", []),
                by_kind.get("bridge_port", []),
                by_index,
                authoritative("bridge"),
            )
        fdb_vlan: dict[int, int] = {}
        if usable("vlan"):
            fdb_vlan = self._vlans(
                by_kind.get("vlan", []),
                by_kind.get("pvid", []),
                port_map,
                by_index,
                authoritative("vlan"),
            )
        if usable("lldp"):
            self._lldp(by_kind, by_index, authoritative("lldp"))
        if usable("cdp"):
            self._cdp(by_kind.get("cdp_neighbor", []), by_index, authoritative("cdp"))
        self._neighbor_counts()
        self._reciprocity()
        if usable("bridge"):
            self._macs(by_kind.get("mac_entry", []), port_map, by_index, fdb_vlan)
            if authoritative("bridge"):
                self._mark_absent(NetworkMacEntry)
        self._mac_counts_and_locations()
        self._classify()
        self._link_asset()
        counts = self._counts(len(records))
        logger.info(
            "network poll applied",
            extra={"device": str(self._device.public_id), "interfaces": len(interfaces)},
        )
        return ApplyResult(counts=counts, changes=dict(self._changes))

    # --- system / entity -------------------------------------------------------------------

    def _system(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        row = rows[-1]
        device = self._device
        device.sys_descr = row.get("sys_descr")
        device.sys_object_id = row.get("sys_object_id")
        device.sys_name = row.get("sys_name")
        device.sys_location = row.get("sys_location")
        ticks = row.get("sys_uptime_ticks")
        device.sys_uptime_seconds = ticks // 100 if isinstance(ticks, int) else None
        device.sys_services = row.get("sys_services")
        forwarding = row.get("ip_forwarding")
        device.ip_forwarding = None if forwarding is None else forwarding == 1

    def _entities(self, rows: list[dict[str, Any]]) -> None:
        keep = sorted(rows, key=lambda r: int(r["index"]))[:MAX_ENTITIES]
        self._device.entities = [
            {key: value for key, value in row.items() if key != "kind"} for row in keep
        ] or None

    # --- interfaces ------------------------------------------------------------------------

    def _interfaces(
        self, rows: list[dict[str, Any]], stack: list[dict[str, Any]], usable: bool
    ) -> list[NetworkInterface]:
        if not usable or not rows:
            return []
        session, device = self._session, self._device
        existing = {
            row.stable_key: row
            for row in session.scalars(
                select(NetworkInterface).where(NetworkInterface.device_id == device.id)
            )
        }
        seen: dict[str, NetworkInterface] = {}
        for record in sorted(rows, key=lambda r: int(r["if_index"])):
            key = _stable_key(record)
            if key in seen:
                # Dos interfaces con el mismo nombre (equipos baratos con ifDescr genérico):
                # se distinguen con su ifIndex en lugar de sobrescribirse.
                key = f"{key[:200]}#ifIndex:{record['if_index']}"
            row = existing.get(key)
            oper = OPER_STATUS.get(record.get("oper_status") or 0, "unknown")
            if row is None:
                row = NetworkInterface(
                    device_id=device.id,
                    site_id=device.site_id,
                    stable_key=key,
                    first_seen_at=self._now,
                    present=True,
                    if_index=int(record["if_index"]),
                )
                session.add(row)
                self._changes["interfaces_added"] += 1
            elif row.present and row.oper_status != oper:
                self._changes["oper_status_changes"] += 1
            row.if_index = int(record["if_index"])
            row.if_name = record.get("name")
            row.if_descr = record.get("descr")
            row.if_alias = record.get("alias")
            row.if_type = record.get("if_type")
            row.mtu = record.get("mtu")
            row.mac = record.get("mac")
            row.admin_status = ADMIN_STATUS.get(record.get("admin_status") or 0, "unknown")
            row.oper_status = oper
            row.speed_mbps = _speed_mbps(record)
            row.counters_hc = bool(record.get("counters_hc"))
            for name in ("in_octets", "out_octets", "in_errors", "out_errors"):
                setattr(row, name, _clamp(record.get(name)))
            row.in_discards = _clamp(record.get("in_discards"))
            row.out_discards = _clamp(record.get("out_discards"))
            row.counters_at = self._now
            row.port_kind = port_kind(row.if_type)
            row.lag_parent_if_index = None
            row.present = True
            row.last_seen_at = self._now
            row.last_poll_id = self._poll.id
            seen[key] = row
        session.flush()
        # ifStackTable: solo interesa "miembro de un LAG" (higher es un ieee8023adLag).
        by_index = {row.if_index: row for row in seen.values()}
        for entry in stack:
            higher, lower = by_index.get(entry["higher"]), by_index.get(entry["lower"])
            if higher is not None and lower is not None and higher.port_kind == "lag":
                lower.lag_parent_if_index = higher.if_index
        return list(seen.values())

    def _mark_absent_interfaces(self) -> None:
        removed = self._mark_absent(NetworkInterface)
        self._changes["interfaces_removed"] += removed

    def _mark_absent(self, model: Any) -> int:
        """present=false para lo que esta consulta COMPLETA no vio (sin borrar historial)."""
        result = self._session.execute(
            update(model)
            .where(
                model.device_id == self._device.id,
                model.present.is_(True),
                (model.last_poll_id.is_(None)) | (model.last_poll_id != self._poll.id),
            )
            .values(present=False)
            .execution_options(synchronize_session=False)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    def _present_by_index(self) -> dict[int, NetworkInterface]:
        """ifIndex → interfaz presente. Si dos comparten ifIndex, gana la vista más reciente."""
        rows = self._session.scalars(
            select(NetworkInterface)
            .where(NetworkInterface.device_id == self._device.id, NetworkInterface.present)
            .order_by(NetworkInterface.last_seen_at)
        ).all()
        return {row.if_index: row for row in rows}

    # --- bridge / VLAN ---------------------------------------------------------------------

    def _bridge(
        self,
        base: list[dict[str, Any]],
        ports: list[dict[str, Any]],
        by_index: dict[int, NetworkInterface],
        authoritative: bool,
    ) -> dict[int, int]:
        if base:
            self._device.base_bridge_address = base[-1].get("bridge_address")
            self._device.bridge_ports = base[-1].get("num_ports")
        port_map = {int(p["port"]): int(p["if_index"]) for p in ports}
        if port_map or authoritative:
            for interface in by_index.values():
                interface.bridge_port = None
            for port, if_index in port_map.items():
                target = by_index.get(if_index)
                if target is not None:
                    target.bridge_port = port
        return port_map

    def _vlans(
        self,
        vlans: list[dict[str, Any]],
        pvids: list[dict[str, Any]],
        port_map: dict[int, int],
        by_index: dict[int, NetworkInterface],
        authoritative: bool,
    ) -> dict[int, int]:
        session, device = self._session, self._device
        # La tabla "current" refleja la pertenencia real (incluida la dinámica); la "static",
        # la configurada. Se usa current si existe y el nombre se toma de static.
        merged: dict[int, dict[str, Any]] = {}
        for record in sorted(vlans, key=lambda r: r["source"] != "static"):
            entry = merged.setdefault(int(record["vlan_id"]), {"source": "q_bridge_static"})
            if record.get("name"):
                entry["name"] = record["name"]
            if record["source"] == "current" or "egress" not in entry:
                entry["egress"] = set(record.get("egress_ports") or ())
                entry["untagged"] = set(record.get("untagged_ports") or ())
            if record["source"] == "current":
                entry["source"] = "q_bridge_current"
            if record.get("fdb_id") is not None:
                entry["fdb_id"] = int(record["fdb_id"])
        existing = {
            row.vlan_id: row
            for row in session.scalars(
                select(NetworkVlan).where(NetworkVlan.device_id == device.id)
            )
        }
        fdb_vlan: dict[int, int] = {}
        for vlan_id, entry in merged.items():
            row = existing.get(vlan_id)
            if row is None:
                row = NetworkVlan(
                    device_id=device.id,
                    site_id=device.site_id,
                    vlan_id=vlan_id,
                    first_seen_at=self._now,
                )
                session.add(row)
            row.name = entry.get("name")
            row.source = entry["source"]
            row.fdb_id = entry.get("fdb_id")
            row.present = True
            row.last_seen_at = self._now
            row.last_poll_id = self._poll.id
            if row.fdb_id is not None:
                fdb_vlan[row.fdb_id] = vlan_id
        session.flush()
        memberships = {
            (row.interface_id, row.vlan_id): row
            for row in session.scalars(
                select(NetworkVlanMembership).where(NetworkVlanMembership.device_id == device.id)
            )
        }
        trunks: set[int] = set()
        for vlan_id, entry in merged.items():
            untagged = entry.get("untagged", set())
            for port in entry.get("egress", set()) | untagged:
                interface = by_index.get(port_map.get(port, -1))
                if interface is None:
                    continue
                tagged = port not in untagged
                key = (interface.id, vlan_id)
                membership = memberships.get(key)
                if membership is None:
                    membership = NetworkVlanMembership(
                        device_id=device.id, interface_id=interface.id, vlan_id=vlan_id
                    )
                    session.add(membership)
                    memberships[key] = membership
                membership.tagged = tagged
                membership.present = True
                membership.last_seen_at = self._now
                membership.last_poll_id = self._poll.id
                if tagged:
                    trunks.add(interface.id)
        for interface in by_index.values():
            # Un puerto que transporta tramas etiquetadas (802.1Q) de alguna VLAN es un trunk
            # (o un puerto híbrido): ve tráfico de muchos equipos y no es un puerto de acceso.
            # Con un módulo parcial solo se añade evidencia: no se quita la marca de trunk.
            if interface.id in trunks:
                interface.is_trunk = True
            elif authoritative:
                interface.is_trunk = False
        pvid_map = {int(p["port"]): int(p["vlan_id"]) for p in pvids}
        for port, vlan_id in pvid_map.items():
            interface = by_index.get(port_map.get(port, -1))
            if interface is not None:
                interface.pvid = vlan_id
        session.flush()
        if authoritative:
            self._mark_absent(NetworkVlan)
            self._mark_absent(NetworkVlanMembership)
        return fdb_vlan

    # --- vecinos ---------------------------------------------------------------------------

    def _match_local(
        self,
        port_num: int,
        local_port: dict[str, Any] | None,
        by_index: dict[int, NetworkInterface],
    ) -> tuple[NetworkInterface | None, str]:
        """Interfaz local de un puerto LLDP, con la base del cruce (si no, unmatched).

        LLDP numera sus puertos con lldpLocPortNum, que NO tiene por qué ser el ifIndex. Se
        cruza primero por nombre (lldpLocPortId de subtipo interfaceName/Alias o la
        descripción del puerto) y solo como último recurso por número igual al ifIndex.
        """
        interfaces = list(by_index.values())
        if local_port is not None:
            port_id = local_port.get("port_id")
            subtype = local_port.get("port_id_subtype")
            desc = local_port.get("port_desc")
            if port_id and subtype in (1, 5):
                for interface in interfaces:
                    if port_id in (interface.if_name, interface.if_alias):
                        return interface, "if_name"
            if desc:
                for interface in interfaces:
                    if desc == interface.if_name:
                        return interface, "if_name"
                for interface in interfaces:
                    if desc == interface.if_descr:
                        return interface, "if_descr"
        weak = by_index.get(port_num)
        return (weak, "if_index") if weak is not None else (None, "unmatched")

    def _resolve_remote(
        self, chassis: str | None, chassis_subtype: str | None, mgmt: str | None, name: str | None
    ) -> tuple[int | None, str | None]:
        """Equipo registrado del MISMO site que corresponde al vecino (o ninguno)."""
        session, device = self._session, self._device
        base = select(NetworkDevice.id).where(
            NetworkDevice.site_id == device.site_id,
            NetworkDevice.id != device.id,
            NetworkDevice.status == "active",
        )
        if chassis and chassis_subtype == "mac_address":
            found = session.scalars(
                base.where(
                    (NetworkDevice.lldp_chassis_id == chassis)
                    | (NetworkDevice.base_bridge_address == chassis)
                ).limit(2)
            ).all()
            if len(found) == 1:
                return int(found[0]), "chassis_mac"
        if mgmt:
            found = session.scalars(
                base.where(NetworkDevice.management_address == mgmt).limit(2)
            ).all()
            if len(found) == 1:
                return int(found[0]), "mgmt_address"
        if name:
            found = session.scalars(
                base.where(func.lower(NetworkDevice.sys_name) == name.lower()).limit(2)
            ).all()
            # Solo si es inequívoco: dos equipos con el mismo sysName no permiten elegir.
            if len(found) == 1:
                return int(found[0]), "sys_name"
        return None, None

    def _upsert_neighbors(
        self, protocol: str, entries: list[dict[str, Any]], authoritative: bool
    ) -> None:
        session, device = self._session, self._device
        existing = {
            (row.local_port_key, row.remote_key): row
            for row in session.scalars(
                select(NetworkNeighbor).where(
                    NetworkNeighbor.device_id == device.id, NetworkNeighbor.protocol == protocol
                )
            )
        }
        for entry in entries:
            key = (entry["local_port_key"], entry["remote_key"])
            row = existing.get(key)
            if row is None:
                row = NetworkNeighbor(
                    device_id=device.id,
                    site_id=device.site_id,
                    protocol=protocol,
                    local_port_key=entry["local_port_key"],
                    remote_key=entry["remote_key"],
                    first_seen_at=self._now,
                )
                session.add(row)
                existing[key] = row
                self._changes["neighbors_added"] += 1
            for name, value in entry.items():
                if name not in ("local_port_key", "remote_key"):
                    setattr(row, name, value)
            row.sensor_id = self._poll.sensor_id
            row.present = True
            row.last_seen_at = self._now
            row.last_poll_id = self._poll.id
        session.flush()
        if authoritative:
            result = session.execute(
                update(NetworkNeighbor)
                .where(
                    NetworkNeighbor.device_id == device.id,
                    NetworkNeighbor.protocol == protocol,
                    NetworkNeighbor.present.is_(True),
                    (NetworkNeighbor.last_poll_id.is_(None))
                    | (NetworkNeighbor.last_poll_id != self._poll.id),
                )
                .values(present=False)
                .execution_options(synchronize_session=False)
            )
            self._changes["neighbors_removed"] += int(getattr(result, "rowcount", 0) or 0)

    def _lldp(
        self,
        by_kind: dict[str, list[dict[str, Any]]],
        by_index: dict[int, NetworkInterface],
        authoritative: bool,
    ) -> None:
        device = self._device
        local = by_kind.get("lldp_local", [])
        if local:
            row = local[-1]
            device.lldp_chassis_id = row.get("chassis_id")
            device.lldp_chassis_id_subtype = LLDP_CHASSIS_SUBTYPES.get(
                row.get("chassis_id_subtype") or 0
            )
            device.lldp_sys_name = row.get("sys_name")
            device.lldp_capabilities = list(row.get("capabilities") or [])
        local_ports = {int(p["port_num"]): p for p in by_kind.get("lldp_local_port", [])}
        entries = []
        for remote in by_kind.get("lldp_remote", []):
            port_num = int(remote["local_port_num"])
            local_port = local_ports.get(port_num)
            interface, match = self._match_local(port_num, local_port, by_index)
            chassis_subtype = LLDP_CHASSIS_SUBTYPES.get(remote.get("chassis_id_subtype") or 0)
            mgmt = (remote.get("mgmt_addresses") or [None])[0]
            remote_device, basis = self._resolve_remote(
                remote.get("chassis_id"), chassis_subtype, mgmt, remote.get("sys_name")
            )
            label = None
            if local_port is not None:
                label = local_port.get("port_desc") or local_port.get("port_id")
            entries.append(
                {
                    "local_port_key": f"lldp:{port_num}",
                    "remote_key": _remote_key(
                        remote.get("chassis_id_subtype"),
                        remote.get("chassis_id"),
                        remote.get("port_id_subtype"),
                        remote.get("port_id"),
                    ),
                    "local_port_label": label,
                    "remote_chassis_id": remote.get("chassis_id"),
                    "remote_chassis_id_subtype": chassis_subtype,
                    "remote_port_id": remote.get("port_id"),
                    "remote_port_id_subtype": LLDP_PORT_SUBTYPES.get(
                        remote.get("port_id_subtype") or 0
                    ),
                    "remote_port_descr": remote.get("port_desc"),
                    "remote_sys_name": remote.get("sys_name"),
                    "remote_sys_descr": remote.get("sys_desc"),
                    "remote_platform": None,
                    "remote_software": None,
                    "remote_mgmt_address": mgmt,
                    "remote_capabilities": list(remote.get("capabilities") or []),
                    "remote_native_vlan": None,
                    "interface_id": interface.id if interface is not None else None,
                    "local_port_match": match,
                    "remote_device_id": remote_device,
                    "remote_match_basis": basis,
                }
            )
        self._upsert_neighbors("lldp", entries, authoritative)

    def _cdp(
        self,
        rows: list[dict[str, Any]],
        by_index: dict[int, NetworkInterface],
        authoritative: bool,
    ) -> None:
        entries = []
        for row in rows:
            # cdpCacheIfIndex ES el ifIndex local (a diferencia de lldpLocPortNum).
            interface = by_index.get(int(row["if_index"]))
            remote_device, basis = self._resolve_remote(
                None, None, row.get("address"), row.get("device_id")
            )
            entries.append(
                {
                    "local_port_key": f"cdp:{row['if_index']}",
                    "remote_key": _remote_key(row.get("device_id"), row.get("device_port")),
                    "local_port_label": interface.if_name if interface is not None else None,
                    "remote_chassis_id": row.get("device_id"),
                    "remote_chassis_id_subtype": "device_id",
                    "remote_port_id": row.get("device_port"),
                    "remote_port_id_subtype": "interface_name",
                    "remote_port_descr": None,
                    "remote_sys_name": row.get("device_id"),
                    "remote_sys_descr": None,
                    "remote_platform": row.get("platform"),
                    "remote_software": row.get("software"),
                    "remote_mgmt_address": row.get("address"),
                    "remote_capabilities": list(row.get("capabilities") or []),
                    "remote_native_vlan": row.get("native_vlan"),
                    "interface_id": interface.id if interface is not None else None,
                    "local_port_match": "if_index" if interface is not None else "unmatched",
                    "remote_device_id": remote_device,
                    "remote_match_basis": basis,
                }
            )
        self._upsert_neighbors("cdp", entries, authoritative)

    def _neighbor_counts(self) -> None:
        session, device = self._session, self._device
        counts = dict(
            session.execute(
                select(NetworkNeighbor.interface_id, func.count())
                .where(
                    NetworkNeighbor.device_id == device.id,
                    NetworkNeighbor.present,
                    NetworkNeighbor.interface_id.is_not(None),
                )
                .group_by(NetworkNeighbor.interface_id)
            ).all()
        )
        for interface in session.scalars(
            select(NetworkInterface).where(NetworkInterface.device_id == device.id)
        ):
            interface.neighbor_count = int(counts.get(interface.id, 0))

    def _reciprocity(self) -> None:
        """Marca como recíprocas las observaciones en las que ambos extremos se informan.

        Se recalcula en los dos sentidos: lo que este equipo informa del otro y lo que el otro
        informó (en su última consulta) de este.
        """
        session, device = self._session, self._device
        mine = session.scalars(
            select(NetworkNeighbor).where(
                (NetworkNeighbor.device_id == device.id)
                | (NetworkNeighbor.remote_device_id == device.id)
            )
        ).all()
        pairs = {
            (row.device_id, row.remote_device_id)
            for row in mine
            if row.present and row.remote_device_id is not None
        }
        for row in mine:
            row.reciprocal = (
                row.present
                and row.remote_device_id is not None
                and (row.remote_device_id, row.device_id) in pairs
            )
        session.flush()

    # --- MAC -------------------------------------------------------------------------------

    def _macs(
        self,
        rows: list[dict[str, Any]],
        port_map: dict[int, int],
        by_index: dict[int, NetworkInterface],
        fdb_vlan: dict[int, int],
    ) -> None:
        if not rows:
            return
        device = self._device
        values: dict[tuple[str, int], dict[str, Any]] = {}
        for row in rows:
            source = row["source"]
            fdb_key = int(row["fdb_id"]) if source == "dot1q" else 0
            vlan_id: int | None = None
            vlan_source = "none"
            if source == "dot1q":
                if fdb_key in fdb_vlan:
                    vlan_id, vlan_source = fdb_vlan[fdb_key], "fdb_vlan_map"
                elif 1 <= fdb_key <= 4094:
                    # Sin dot1qVlanFdbId se asume fdb id = VLAN (lo habitual en IVL), y se
                    # marca como supuesto para que la UI no lo presente como dato del equipo.
                    vlan_id, vlan_source = fdb_key, "fdb_id_assumed"
            port = int(row["port"]) or None
            interface = by_index.get(port_map.get(port, -1)) if port is not None else None
            values[(row["mac"], fdb_key)] = {
                "device_id": device.id,
                "site_id": device.site_id,
                "mac": row["mac"],
                "fdb_key": fdb_key,
                "bridge_port": port,
                "status": MAC_STATUS.get(int(row["status"]), "other"),
                "vlan_id": vlan_id,
                "vlan_source": vlan_source,
                "interface_id": interface.id if interface is not None else None,
                "present": True,
                "first_seen_at": self._now,
                "last_seen_at": self._now,
                "last_poll_id": self._poll.id,
            }
        # INSERT ... ON CONFLICT por bloques: una tabla CAM puede tener miles de filas y
        # PostgreSQL limita a 65535 parámetros por sentencia.
        items = list(values.values())
        for start in range(0, len(items), _INSERT_CHUNK):
            chunk = items[start : start + _INSERT_CHUNK]
            stmt = insert(NetworkMacEntry).values(chunk)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_network_mac_entries",
                set_={
                    name: stmt.excluded[name]
                    for name in (
                        "bridge_port",
                        "status",
                        "vlan_id",
                        "vlan_source",
                        "interface_id",
                        "present",
                        "last_seen_at",
                        "last_poll_id",
                    )
                },
            )
            self._session.execute(stmt)

    def _mac_counts_and_locations(self) -> None:
        """Cuántas MACs aprendidas ve cada puerto y dónde está (probablemente) cada MAC."""
        session, device = self._session, self._device
        counts = dict(
            session.execute(
                select(NetworkMacEntry.interface_id, func.count())
                .where(
                    NetworkMacEntry.device_id == device.id,
                    NetworkMacEntry.present,
                    NetworkMacEntry.status == "learned",
                    NetworkMacEntry.interface_id.is_not(None),
                )
                .group_by(NetworkMacEntry.interface_id)
            ).all()
        )
        interfaces = {
            row.id: row
            for row in session.scalars(
                select(NetworkInterface).where(NetworkInterface.device_id == device.id)
            )
        }
        for interface in interfaces.values():
            interface.mac_count = int(counts.get(interface.id, 0))
        groups: dict[tuple[str, str], list[int]] = defaultdict(list)
        for entry_id, interface_id, status in session.execute(
            select(NetworkMacEntry.id, NetworkMacEntry.interface_id, NetworkMacEntry.status).where(
                NetworkMacEntry.device_id == device.id, NetworkMacEntry.present
            )
        ):
            owner = interfaces.get(interface_id) if interface_id is not None else None
            groups[self._assess(owner, status)].append(int(entry_id))
        for (location, reason), ids in groups.items():
            for start in range(0, len(ids), _INSERT_CHUNK):
                session.execute(
                    update(NetworkMacEntry)
                    .where(NetworkMacEntry.id.in_(ids[start : start + _INSERT_CHUNK]))
                    .values(location=location, location_reason=reason)
                    .execution_options(synchronize_session=False)
                )

    def _assess(self, interface: NetworkInterface | None, status: str) -> tuple[str, str]:
        """Valoración de una MAC según la naturaleza del puerto (nunca "confirmada").

        Un uplink, un trunk, un LAG o un puerto con un vecino LLDP/CDP ve las MACs de todo lo
        que hay detrás; asignar esas MACs a un endpoint en ese puerto sería falso.
        """
        if status in ("self", "mgmt"):
            return "unknown", "device_own_address"
        if interface is None:
            return "unknown", "bridge_port_unmapped"
        if not interface.present:
            return "unknown", "interface_absent"
        if interface.port_kind == "lag" or interface.lag_parent_if_index is not None:
            return "uplink_or_shared", "lag_port"
        if interface.is_trunk:
            return "uplink_or_shared", "trunk_port"
        if interface.neighbor_count > 0:
            return "uplink_or_shared", "neighbor_on_port"
        if interface.port_kind not in ("physical", "wireless"):
            return "unknown", "logical_port"
        if interface.mac_count > self._settings.snmp_edge_port_max_macs:
            return "uplink_or_shared", "many_macs_on_port"
        return "edge_candidate", "access_port_few_macs"

    # --- equipo ----------------------------------------------------------------------------

    def _classify(self) -> None:
        session, device = self._session, self._device
        kinds = dict(
            session.execute(
                select(NetworkInterface.port_kind, func.count())
                .where(NetworkInterface.device_id == device.id, NetworkInterface.present)
                .group_by(NetworkInterface.port_kind)
            ).all()
        )
        result = classify(
            DeviceEvidence(
                sys_object_id=device.sys_object_id,
                sys_services=device.sys_services,
                ip_forwarding=device.ip_forwarding,
                lldp_capabilities=list(device.lldp_capabilities or []),
                bridge_ports=device.bridge_ports,
                physical_ports=int(kinds.get("physical", 0)),
                wireless_ports=int(kinds.get("wireless", 0)),
                entities=list(device.entities or []),
            )
        )
        if device.last_success_at is not None and result.classification != device.classification:
            self._changes["classification_changed"] = True
        device.classification = result.classification
        device.classification_confidence = result.confidence
        device.classification_evidence = result.evidence
        device.layer3 = result.layer3
        device.enterprise_number = result.enterprise_number
        device.vendor = result.vendor
        device.vendor_source = result.vendor_source
        device.model = result.model
        device.firmware = result.firmware
        device.serial_number = result.serial_number

    def _link_asset(self) -> None:
        link_device_asset(self._session, self._device)

    def _counts(self, records: int) -> dict[str, int]:
        session, device = self._session, self._device

        def count(model: Any) -> int:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(model)
                    .where(model.device_id == device.id, model.present)
                )
                or 0
            )

        return {
            "interfaces": count(NetworkInterface),
            "neighbors": count(NetworkNeighbor),
            "vlans": count(NetworkVlan),
            "mac_entries": count(NetworkMacEntry),
            "records": records,
        }


def link_device_asset(session: Session, device: NetworkDevice) -> None:
    """Liga el equipo al activo de su MISMO site con la misma IP, si existe y no hay otro.

    Nunca crea activos ni fusiona: solo enlaza para navegar entre el inventario de red y la
    ficha del activo descubierto (6A) o gestionado.
    """
    if device.asset_id is not None:
        return
    found = session.scalars(
        select(Asset.id)
        .where(
            Asset.site_id == device.site_id,
            Asset.primary_ip == device.management_address,
            Asset.archived_at.is_(None),
        )
        .limit(2)
    ).all()
    if len(found) == 1:
        device.asset_id = int(found[0])
