"""Persistencia compartida del inventario Wi-Fi (Fase 6C.3): upsert idempotente, historial
acotado y vinculaciones con evidencia. La usan el aplicador SNMP (wlan_apply.py) y la ingesta
de los agentes (services/wlan_ingest.py).

Idempotencia y concurrencia: cada entidad tiene una clave natural única por site. Las filas
se crean con INSERT ... ON CONFLICT DO NOTHING y después se leen bloqueadas en orden de id,
así dos ingestas simultáneas del mismo BSSID (dos agentes del site que ven la misma red) no
duplican la fila ni fallan con un 500, y repetir el mismo lote no crea nada nuevo.
"""

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.network import NetworkDevice
from app.models.wlan import WlanAccessPoint, WlanBss, WlanClient, WlanObservation
from app.network.wlan_catalog import mac_randomized

# Historial: una entidad y una fuente (y el mismo agente) generan una fila nueva solo si algo
# material cambió o si la última fila es más antigua que esto. Acota el volumen sin perder
# cuándo empezó y cuándo cambió cada cosa (el "visto por última vez" está en la entidad).
OBSERVATION_MIN_INTERVAL = timedelta(hours=1)
# Valores de una foto del historial: escalares cortos, nunca estructuras arbitrarias.
_MAX_TEXT = 255
_CHUNK = 1000

EntityKind = str  # "access_point" | "bss" | "client"
_ENTITY_COLUMN = {
    "access_point": WlanObservation.access_point_id,
    "bss": WlanObservation.bss_id,
    "client": WlanObservation.client_id,
}


def ensure_rows(
    session: Session,
    model: Any,
    constraint: str,
    site_id: int,
    key_column: str,
    defaults: Mapping[str, dict[str, Any]],
) -> tuple[dict[str, Any], set[str]]:
    """Garantiza una fila por clave natural (site, clave) y devuelve {clave: fila} y las
    claves creadas ahora. `defaults` da las columnas obligatorias de una fila nueva."""
    if not defaults:
        return {}, set()
    created: set[str] = set()
    items = sorted(defaults.items())
    for start in range(0, len(items), _CHUNK):
        chunk = items[start : start + _CHUNK]
        values = [
            {"site_id": site_id, key_column: key, "public_id": uuid.uuid4(), **extra}
            for key, extra in chunk
        ]
        stmt = (
            insert(model)
            .values(values)
            .on_conflict_do_nothing(constraint=constraint)
            .returning(getattr(model, key_column))
        )
        created.update(str(k) for k in session.scalars(stmt))
    rows: dict[str, Any] = {}
    keys = [key for key, _ in items]
    column = getattr(model, key_column)
    for start in range(0, len(keys), _CHUNK):
        found = session.scalars(
            select(model)
            .where(model.site_id == site_id, column.in_(keys[start : start + _CHUNK]))
            .order_by(model.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        for row in found:
            rows[str(getattr(row, key_column))] = row
    return rows, created


def _snapshot(data: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        if value is None or isinstance(value, bool | int | float):
            out[key] = value
        elif isinstance(value, str):
            out[key] = value[:_MAX_TEXT]
    return out


@dataclass
class Observations:
    """Acumula observaciones de una ingesta y escribe solo las que aportan historial."""

    session: Session
    site_id: int
    source: str
    confidence: str
    observed_at: datetime
    received_at: datetime
    poll_id: int | None = None
    sensor_id: int | None = None
    source_device_id: int | None = None
    agent_asset_id: int | None = None
    _pending: list[tuple[EntityKind, int, dict[str, Any], bool]] = field(default_factory=list)

    def add(self, kind: EntityKind, entity_id: int, data: Mapping[str, Any], changed: bool) -> None:
        self._pending.append((kind, entity_id, _snapshot(data), changed))

    def flush(self) -> int:
        if not self._pending:
            return 0
        last: dict[tuple[EntityKind, int], datetime] = {}
        for kind, column in _ENTITY_COLUMN.items():
            ids = sorted({eid for k, eid, _, changed in self._pending if k == kind and not changed})
            for start in range(0, len(ids), _CHUNK):
                stmt = (
                    select(column, func.max(WlanObservation.observed_at))
                    .where(column.in_(ids[start : start + _CHUNK]))
                    .where(WlanObservation.source == self.source)
                    .group_by(column)
                )
                if self.agent_asset_id is not None:
                    stmt = stmt.where(WlanObservation.agent_asset_id == self.agent_asset_id)
                for entity_id, observed in self.session.execute(stmt):
                    if entity_id is not None:
                        last[(kind, int(entity_id))] = observed
        written = 0
        seen: set[tuple[EntityKind, int]] = set()
        for kind, entity_id, data, changed in self._pending:
            if (kind, entity_id) in seen:
                continue
            seen.add((kind, entity_id))
            previous = last.get((kind, entity_id))
            recent = previous is not None and self.observed_at - previous < OBSERVATION_MIN_INTERVAL
            if not changed and recent:
                continue
            self.session.add(
                WlanObservation(
                    site_id=self.site_id,
                    access_point_id=entity_id if kind == "access_point" else None,
                    bss_id=entity_id if kind == "bss" else None,
                    client_id=entity_id if kind == "client" else None,
                    source=self.source,
                    confidence=self.confidence,
                    poll_id=self.poll_id,
                    sensor_id=self.sensor_id,
                    source_device_id=self.source_device_id,
                    agent_asset_id=self.agent_asset_id,
                    observed_at=self.observed_at,
                    received_at=self.received_at,
                    data=data,
                )
            )
            written += 1
        self._pending.clear()
        return written


def assign(row: Any, values: Mapping[str, Any]) -> bool:
    """Asigna valores y dice si alguno cambió (para decidir si hay historial nuevo)."""
    changed = False
    for name, value in values.items():
        if getattr(row, name) != value:
            setattr(row, name, value)
            changed = True
    return changed


def add_source(row: WlanBss, source: str) -> None:
    sources = list(row.sources or [])
    if source not in sources:
        # Lista nueva (no mutación en sitio) para que SQLAlchemy detecte el cambio del JSONB.
        row.sources = sorted([*sources, source])[:8]


# --- vinculación con evidencia ----------------------------------------------------------------


def _unique(ids: Iterable[int]) -> int | None:
    found = list(dict.fromkeys(ids))
    return found[0] if len(found) == 1 else None


def evidence_for_asset(
    session: Session, ap: WlanAccessPoint, asset: Asset
) -> dict[str, Any] | None:
    """Evidencia que justifica vincular el AP con el activo (mismo site, IP o MAC iguales)."""
    if asset.site_id != ap.site_id or asset.archived_at is not None:
        return None
    if ap.management_ip and asset.primary_ip == ap.management_ip:
        return {"basis": "management_ip", "value": ap.management_ip}
    mac = ap.ethernet_mac
    if mac and not mac_randomized(mac) and asset.mac_address == mac:
        return {"basis": "mac", "value": mac}
    return None


def evidence_for_device(
    session: Session, ap: WlanAccessPoint, device: NetworkDevice
) -> dict[str, Any] | None:
    """Evidencia para vincular el AP con un equipo de red 6B del mismo site."""
    if device.site_id != ap.site_id or device.status != "active":
        return None
    if ap.source_device_id == device.id and ap.ap_key == f"device:{device.public_id}":
        # AP autónomo consultado directamente: el AP ES el equipo que lo informa.
        return {"basis": "source_device", "value": str(device.public_id)}
    if ap.management_ip and device.management_address == ap.management_ip:
        return {"basis": "management_ip", "value": ap.management_ip}
    mac = ap.ethernet_mac
    if (
        mac
        and not mac_randomized(mac)
        and mac in (device.base_bridge_address, device.lldp_chassis_id)
    ):
        return {"basis": "mac", "value": mac}
    return None


def auto_link(session: Session, ap: WlanAccessPoint, now: datetime) -> None:
    """Vinculación automática solo con un candidato inequívoco del MISMO site.

    Nunca sustituye una vinculación existente ni actúa si un operador desvinculó a mano
    (link_suppressed). La evidencia queda guardada junto al enlace.
    """
    if ap.link_suppressed:
        return
    evidence = dict(ap.link_evidence or {})
    changed = False
    if ap.network_device_id is None:
        conditions = []
        if ap.management_ip:
            conditions.append(NetworkDevice.management_address == ap.management_ip)
        if ap.ethernet_mac and not mac_randomized(ap.ethernet_mac):
            conditions.append(NetworkDevice.base_bridge_address == ap.ethernet_mac)
            conditions.append(NetworkDevice.lldp_chassis_id == ap.ethernet_mac)
        if ap.ap_key.startswith("device:") and ap.source_device_id is not None:
            conditions.append(NetworkDevice.id == ap.source_device_id)
        if conditions:
            candidates = session.scalars(
                select(NetworkDevice).where(
                    NetworkDevice.site_id == ap.site_id,
                    NetworkDevice.status == "active",
                    or_(*conditions),
                )
            ).all()
            device_id = _unique(d.id for d in candidates)
            device = next((d for d in candidates if d.id == device_id), None)
            proof = evidence_for_device(session, ap, device) if device is not None else None
            if device is not None and proof is not None:
                ap.network_device_id = device.id
                evidence["network_device"] = {**proof, "method": "automatic", "at": now.isoformat()}
                changed = True
    if ap.asset_id is None:
        conditions = []
        if ap.management_ip:
            conditions.append(Asset.primary_ip == ap.management_ip)
        if ap.ethernet_mac and not mac_randomized(ap.ethernet_mac):
            conditions.append(Asset.mac_address == ap.ethernet_mac)
        if conditions:
            assets = session.scalars(
                select(Asset).where(
                    Asset.site_id == ap.site_id, Asset.archived_at.is_(None), or_(*conditions)
                )
            ).all()
            asset_id = _unique(a.id for a in assets)
            asset = next((a for a in assets if a.id == asset_id), None)
            proof = evidence_for_asset(session, ap, asset) if asset is not None else None
            if asset is not None and proof is not None:
                ap.asset_id = asset.id
                evidence["asset"] = {**proof, "method": "automatic", "at": now.isoformat()}
                changed = True
    if changed:
        ap.link_evidence = evidence


def correlate_client(
    session: Session, site_id: int, mac: str | None, cache: dict[str, int | None]
) -> int | None:
    """Activo del MISMO site con esa MAC, solo si la MAC es global y hay uno solo.

    Una MAC aleatoria nunca se correlaciona por coincidencia: puede repetirse entre equipos y
    cambiar por red, así que no identifica un dispositivo físico.
    """
    if mac is None or mac_randomized(mac):
        return None
    if mac not in cache:
        ids = session.scalars(
            select(Asset.id)
            .where(Asset.site_id == site_id, Asset.archived_at.is_(None), Asset.mac_address == mac)
            .limit(2)
        ).all()
        cache[mac] = int(ids[0]) if len(ids) == 1 else None
    return cache[mac]


def bss_by_bssid(session: Session, site_id: int, bssids: Iterable[str]) -> dict[str, WlanBss]:
    keys = sorted(set(bssids))
    if not keys:
        return {}
    return {
        row.bssid: row
        for row in session.scalars(
            select(WlanBss).where(WlanBss.site_id == site_id, WlanBss.bssid.in_(keys))
        )
    }


def clients_by_key(session: Session, site_id: int, keys: Iterable[str]) -> dict[str, WlanClient]:
    wanted = sorted(set(keys))
    if not wanted:
        return {}
    return {
        row.client_key: row
        for row in session.scalars(
            select(WlanClient).where(
                WlanClient.site_id == site_id, WlanClient.client_key.in_(wanted)
            )
        )
    }
