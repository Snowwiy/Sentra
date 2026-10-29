"""Consultas y gestión del inventario Wi-Fi (Fase 6C.3, docs/wlan-discovery.md).

Reglas que este servicio garantiza:
- Los filtros por site y las vinculaciones nunca cruzan sites: un AP solo se vincula con un
  activo o equipo de su mismo site y con evidencia (IP de gestión o MAC iguales).
- La frescura se deriva al leer: lo visto hace tiempo se presenta como "historical", nunca
  como activo. Lo que la infraestructura dejó de informar en una consulta completa es
  present=false, sin borrarse.
- La autorización (authorized / external / unknown) es una decisión de un operador
  (network:manage), auditada, y nunca se deduce: no existe un estado "rogue" automático.
- Las configuraciones inseguras (abierta, WEP, WPA1/TKIP) son observaciones técnicas que la
  API muestra; no contribuyen al Risk Engine.
"""

from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    NetworkDeviceNotFoundError,
    NotFoundError,
    SiteConflictError,
    WlanAccessPointNotFoundError,
    WlanBssNotFoundError,
    WlanClientNotFoundError,
)
from app.models.asset import Asset
from app.models.network import NetworkDevice, NetworkDevicePoll
from app.models.site import Sensor
from app.models.wlan import (
    WlanAccessPoint,
    WlanAgentReport,
    WlanBss,
    WlanClient,
    WlanConfiguredNetwork,
    WlanObservation,
)
from app.network import wlan_catalog as wc
from app.network.wlan_store import evidence_for_asset, evidence_for_device
from app.schemas.wlan import (
    WlanAccessPointDetail,
    WlanAccessPointList,
    WlanAccessPointRead,
    WlanApRef,
    WlanAssetRef,
    WlanAuthorizationUpdate,
    WlanBssList,
    WlanBssRead,
    WlanClientList,
    WlanClientRead,
    WlanConfigFinding,
    WlanDeviceRef,
    WlanLinkRequest,
    WlanObservationList,
    WlanObservationRead,
    WlanOverview,
    WlanSensorRef,
    WlanSourceStatus,
    WlanSsidList,
    WlanSsidRead,
    WlanUnlinkRequest,
)
from app.services import audit_service
from app.services.audit_service import Actor
from app.services.site_service import site_refs

# Ventanas de frescura. SNMP: como la Fase 6B (max(60 min, 3 intervalos del programador)).
# Agente: su inventario llega cada pocas horas como mucho; más de un día sin verlo es
# evidencia histórica.
SNMP_RECENT_MINIMUM = timedelta(minutes=60)
AGENT_RECENT = timedelta(hours=24)
DETAIL_OBSERVATIONS = 50
DETAIL_BSS = 200
# Tope de SSIDs agregados por petición (decenas en una red real).
MAX_SSIDS = 5000
_FINDING_DETAIL = {
    "open_network": "Network without encryption reported",
    "wep": "WEP encryption reported (broken)",
    "wpa1": "WPA (TKIP) reported (deprecated)",
    "wpa1_allowed": "Mixed WPA/WPA2 mode: WPA1/TKIP clients allowed",
    "legacy_privacy": "Privacy without RSN reported by the MIB (WEP or WPA1)",
    "tkip_allowed": "TKIP cipher reported",
}


def _device_name(device: NetworkDevice) -> str:
    return device.name or device.sys_name or device.management_address


def _ap_name(ap: WlanAccessPoint) -> str:
    return ap.name or ap.management_ip or ap.radio_mac or ap.ap_key


def finding(protection: str | None, reported: str | None) -> list[WlanConfigFinding]:
    code = wc.insecure_finding(protection, reported)
    if code is None:
        return []
    return [WlanConfigFinding(code=code, detail=_FINDING_DETAIL[code])]


@dataclass
class _Windows:
    snmp_cutoff: datetime
    agent_cutoff: datetime


class WlanService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- frescura --------------------------------------------------------------------------

    def _windows(self, now: datetime) -> _Windows:
        window = SNMP_RECENT_MINIMUM
        if self._settings.snmp_poll_interval_minutes:
            window = max(window, timedelta(minutes=3 * self._settings.snmp_poll_interval_minutes))
        return _Windows(now - window, now - AGENT_RECENT)

    @staticmethod
    def _bss_recent(w: _Windows) -> ColumnElement[bool]:
        return or_(
            WlanBss.last_snmp_seen_at >= w.snmp_cutoff, WlanBss.last_agent_seen_at >= w.agent_cutoff
        )

    @staticmethod
    def _client_recent(w: _Windows) -> ColumnElement[bool]:
        return or_(
            and_(WlanClient.source != wc.SOURCE_AGENT, WlanClient.last_seen_at >= w.snmp_cutoff),
            and_(WlanClient.source == wc.SOURCE_AGENT, WlanClient.last_seen_at >= w.agent_cutoff),
        )

    def _bss_is_recent(self, bss: WlanBss, w: _Windows) -> bool:
        return bool(
            (bss.last_snmp_seen_at and bss.last_snmp_seen_at >= w.snmp_cutoff)
            or (bss.last_agent_seen_at and bss.last_agent_seen_at >= w.agent_cutoff)
        )

    # --- referencias (sin N+1) -------------------------------------------------------------

    def _refs(
        self,
        *,
        devices: set[int] | None = None,
        sensors: set[int] | None = None,
        assets: set[int] | None = None,
        aps: set[int] | None = None,
    ) -> dict[str, dict[int, Any]]:
        session = self._session
        out: dict[str, dict[int, Any]] = {"devices": {}, "sensors": {}, "assets": {}, "aps": {}}
        if devices:
            out["devices"] = {
                d.id: WlanDeviceRef(device_id=d.public_id, display_name=_device_name(d))
                for d in session.scalars(select(NetworkDevice).where(NetworkDevice.id.in_(devices)))
            }
        if sensors:
            out["sensors"] = {
                s.id: WlanSensorRef(sensor_id=s.public_id, name=s.name)
                for s in session.scalars(select(Sensor).where(Sensor.id.in_(sensors)))
            }
        if assets:
            out["assets"] = {
                a.id: WlanAssetRef(asset_id=a.public_id, display_name=a.display_name)
                for a in session.scalars(select(Asset).where(Asset.id.in_(assets)))
            }
        if aps:
            out["aps"] = {
                a.id: WlanApRef(access_point_id=a.public_id, display_name=_ap_name(a))
                for a in session.scalars(select(WlanAccessPoint).where(WlanAccessPoint.id.in_(aps)))
            }
        return out

    # --- APs -------------------------------------------------------------------------------

    def _ap_query(
        self,
        site_id: int | None,
        ssid: str | None,
        band: str | None,
        status: str | None,
        authorization: str | None,
        freshness: str | None,
        present: bool | None,
        q: str | None,
        w: _Windows,
    ) -> Any:
        stmt = select(WlanAccessPoint)
        if site_id is not None:
            stmt = stmt.where(WlanAccessPoint.site_id == site_id)
        if status is not None:
            stmt = stmt.where(WlanAccessPoint.reported_status == status)
        if authorization is not None:
            stmt = stmt.where(WlanAccessPoint.authorization_status == authorization)
        if present is not None:
            stmt = stmt.where(WlanAccessPoint.present.is_(present))
        if freshness == "recent":
            stmt = stmt.where(WlanAccessPoint.last_seen_at >= w.snmp_cutoff)
        elif freshness == "historical":
            stmt = stmt.where(WlanAccessPoint.last_seen_at < w.snmp_cutoff)
        if ssid is not None or band is not None:
            bss = select(WlanBss.access_point_id).where(WlanBss.access_point_id.is_not(None))
            if ssid is not None:
                bss = bss.where(WlanBss.ssid == ssid)
            if band is not None:
                bss = bss.where(WlanBss.band == band)
            radio_filter = []
            if band is not None:
                radio_filter.append(WlanAccessPoint.radios.contains([{"band": band}]))
            if ssid is not None:
                radio_filter.append(WlanAccessPoint.radios.contains([{"ssid": ssid}]))
            stmt = stmt.where(or_(WlanAccessPoint.id.in_(bss), and_(*radio_filter)))
        if q is not None:
            pattern = f"%{q.replace('%', '').replace('_', '')}%"
            stmt = stmt.where(
                or_(
                    WlanAccessPoint.name.ilike(pattern),
                    WlanAccessPoint.management_ip.ilike(pattern),
                    WlanAccessPoint.radio_mac.ilike(pattern),
                    WlanAccessPoint.ethernet_mac.ilike(pattern),
                    WlanAccessPoint.model.ilike(pattern),
                )
            )
        return stmt

    def list_access_points(
        self,
        *,
        site_id: int | None,
        ssid: str | None = None,
        band: str | None = None,
        status: str | None = None,
        authorization: str | None = None,
        freshness: str | None = None,
        present: bool | None = None,
        q: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> WlanAccessPointList:
        now = datetime.now(UTC)
        w = self._windows(now)
        stmt = self._ap_query(site_id, ssid, band, status, authorization, freshness, present, q, w)
        total = int(self._session.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        rows = self._session.scalars(
            stmt.order_by(WlanAccessPoint.last_seen_at.desc(), WlanAccessPoint.id)
            .limit(limit)
            .offset(offset)
        ).all()
        return WlanAccessPointList(
            items=self._ap_reads(rows, w), total=total, limit=limit, offset=offset
        )

    def _ap_reads(self, rows: Sequence[WlanAccessPoint], w: _Windows) -> list[WlanAccessPointRead]:
        if not rows:
            return []
        session = self._session
        ids = [r.id for r in rows]
        sites = site_refs(session)
        refs = self._refs(
            devices={d for r in rows for d in (r.source_device_id, r.network_device_id) if d},
            sensors={r.sensor_id for r in rows if r.sensor_id},
            assets={r.asset_id for r in rows if r.asset_id},
        )
        bss_counts = {
            int(ap_id): int(n)
            for ap_id, n in session.execute(
                select(WlanBss.access_point_id, func.count())
                .where(WlanBss.access_point_id.in_(ids), WlanBss.present)
                .group_by(WlanBss.access_point_id)
            )
            if ap_id is not None
        }
        client_counts = {
            int(ap_id): int(n)
            for ap_id, n in session.execute(
                select(WlanClient.access_point_id, func.count())
                .where(WlanClient.access_point_id.in_(ids), WlanClient.present)
                .group_by(WlanClient.access_point_id)
            )
            if ap_id is not None
        }
        ssids: dict[int, set[str]] = defaultdict(set)
        for ap_id, value in session.execute(
            select(WlanBss.access_point_id, WlanBss.ssid)
            .where(WlanBss.access_point_id.in_(ids), WlanBss.ssid.is_not(None))
            .distinct()
        ):
            if ap_id is not None:
                ssids[int(ap_id)].add(str(value))
        out = []
        for ap in rows:
            site = sites[ap.site_id]
            radios = [dict(r) for r in (ap.radios or [])]
            for radio in radios:
                if radio.get("ssid"):
                    ssids[ap.id].add(str(radio["ssid"]))
            out.append(
                WlanAccessPointRead(
                    access_point_id=ap.public_id,
                    site_id=site.public_id,
                    site_name=site.name,
                    display_name=_ap_name(ap),
                    name=ap.name,
                    vendor=ap.vendor,
                    model=ap.model,
                    serial_number=ap.serial_number,
                    firmware=ap.firmware,
                    location=ap.location,
                    management_ip=ap.management_ip,
                    ethernet_mac=ap.ethernet_mac,
                    radio_mac=ap.radio_mac,
                    reported_status=ap.reported_status,
                    source=ap.source,
                    confidence=ap.confidence,
                    reported_by=refs["devices"].get(ap.source_device_id or 0),
                    sensor=refs["sensors"].get(ap.sensor_id or 0),
                    network_device=refs["devices"].get(ap.network_device_id or 0),
                    asset=refs["assets"].get(ap.asset_id or 0),
                    authorization_status=ap.authorization_status,
                    authorization_reason=ap.authorization_reason,
                    authorization_by=ap.authorization_by,
                    authorization_at=ap.authorization_at,
                    present=ap.present,
                    freshness="recent" if ap.last_seen_at >= w.snmp_cutoff else "historical",
                    first_seen_at=ap.first_seen_at,
                    last_seen_at=ap.last_seen_at,
                    radios=radios,
                    bss_count=int(bss_counts.get(ap.id, 0)),
                    client_count=int(client_counts.get(ap.id, 0)),
                    ssids=sorted(ssids.get(ap.id, set())),
                    version=ap.version,
                )
            )
        return out

    def _require_ap(self, public_id: UUID, lock: bool = False) -> WlanAccessPoint:
        stmt = select(WlanAccessPoint).where(WlanAccessPoint.public_id == public_id)
        if lock:
            stmt = stmt.with_for_update()
        ap = self._session.scalar(stmt)
        if ap is None:
            raise WlanAccessPointNotFoundError("Access point not found")
        return ap

    def _require_bss(self, public_id: UUID, lock: bool = False) -> WlanBss:
        stmt = select(WlanBss).where(WlanBss.public_id == public_id)
        if lock:
            stmt = stmt.with_for_update()
        bss = self._session.scalar(stmt)
        if bss is None:
            raise WlanBssNotFoundError("BSS not found")
        return bss

    def get_access_point(self, public_id: UUID) -> WlanAccessPointDetail:
        now = datetime.now(UTC)
        w = self._windows(now)
        ap = self._require_ap(public_id)
        (read,) = self._ap_reads([ap], w)
        bss_rows = self._session.scalars(
            select(WlanBss)
            .where(WlanBss.access_point_id == ap.id)
            .order_by(WlanBss.present.desc(), WlanBss.bssid)
            .limit(DETAIL_BSS)
        ).all()
        bss = self._bss_reads(bss_rows, w)
        findings: dict[str, WlanConfigFinding] = {}
        for item in bss:
            for f in item.findings:
                findings.setdefault(f.code, f)
        evidence: dict[str, Any] = {}
        for target, value in (ap.link_evidence or {}).items():
            if isinstance(value, dict) and value.get("basis") and value.get("at"):
                evidence[target] = value
        observations = self._observations(
            or_(
                WlanObservation.access_point_id == ap.id,
                WlanObservation.bss_id.in_(
                    select(WlanBss.id).where(WlanBss.access_point_id == ap.id)
                ),
            ),
            DETAIL_OBSERVATIONS,
            0,
        ).items
        return WlanAccessPointDetail(
            **read.model_dump(),
            link_suppressed=ap.link_suppressed,
            link_evidence=evidence,
            bss=bss,
            findings=list(findings.values()),
            observations=observations,
        )

    # --- historial -------------------------------------------------------------------------

    def _observations(
        self, condition: ColumnElement[bool], limit: int, offset: int
    ) -> WlanObservationList:
        session = self._session
        total = int(
            session.scalar(select(func.count()).select_from(WlanObservation).where(condition)) or 0
        )
        rows = session.scalars(
            select(WlanObservation)
            .where(condition)
            .order_by(WlanObservation.observed_at.desc(), WlanObservation.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        refs = self._refs(
            devices={r.source_device_id for r in rows if r.source_device_id},
            sensors={r.sensor_id for r in rows if r.sensor_id},
            assets={r.agent_asset_id for r in rows if r.agent_asset_id},
        )
        polls = dict(
            session.execute(
                select(NetworkDevicePoll.id, NetworkDevicePoll.public_id).where(
                    NetworkDevicePoll.id.in_({r.poll_id for r in rows if r.poll_id})
                )
            ).all()
        )
        entity_ids: dict[tuple[str, int], UUID] = {}
        for kind, model, column in (
            ("access_point", WlanAccessPoint, "access_point_id"),
            ("bss", WlanBss, "bss_id"),
            ("client", WlanClient, "client_id"),
        ):
            wanted = {getattr(r, column) for r in rows if getattr(r, column)}
            if wanted:
                for row_id, public in session.execute(
                    select(model.id, model.public_id).where(model.id.in_(wanted))
                ):
                    entity_ids[(kind, int(row_id))] = public
        items = []
        for row in rows:
            if row.access_point_id:
                kind, entity = "access_point", row.access_point_id
            elif row.bss_id:
                kind, entity = "bss", row.bss_id
            else:
                kind, entity = "client", row.client_id or 0
            items.append(
                WlanObservationRead(
                    observation_id=row.id,
                    entity=kind,
                    entity_id=entity_ids[(kind, entity)],
                    source=row.source,
                    confidence=row.confidence,
                    observed_at=row.observed_at,
                    received_at=row.received_at,
                    poll_id=polls.get(row.poll_id) if row.poll_id else None,
                    sensor=refs["sensors"].get(row.sensor_id or 0),
                    reported_by=refs["devices"].get(row.source_device_id or 0),
                    agent_asset=refs["assets"].get(row.agent_asset_id or 0),
                    data={
                        k: v
                        for k, v in (row.data or {}).items()
                        if v is None or isinstance(v, str | int | float | bool)
                    },
                )
            )
        return WlanObservationList(items=items, total=total, limit=limit, offset=offset)

    def access_point_observations(
        self, public_id: UUID, limit: int, offset: int
    ) -> WlanObservationList:
        ap = self._require_ap(public_id)
        return self._observations(
            or_(
                WlanObservation.access_point_id == ap.id,
                WlanObservation.bss_id.in_(
                    select(WlanBss.id).where(WlanBss.access_point_id == ap.id)
                ),
            ),
            limit,
            offset,
        )

    def bss_observations(self, public_id: UUID, limit: int, offset: int) -> WlanObservationList:
        bss = self._require_bss(public_id)
        return self._observations(WlanObservation.bss_id == bss.id, limit, offset)

    # --- BSS -------------------------------------------------------------------------------

    def _bss_reads(self, rows: Sequence[WlanBss], w: _Windows) -> list[WlanBssRead]:
        if not rows:
            return []
        sites = site_refs(self._session)
        refs = self._refs(
            devices={r.source_device_id for r in rows if r.source_device_id},
            assets={r.last_agent_asset_id for r in rows if r.last_agent_asset_id},
            aps={r.access_point_id for r in rows if r.access_point_id},
        )
        out = []
        for bss in rows:
            site = sites[bss.site_id]
            out.append(
                WlanBssRead(
                    bss_id=bss.public_id,
                    site_id=site.public_id,
                    site_name=site.name,
                    bssid=bss.bssid,
                    bssid_randomized=wc.mac_randomized(bss.bssid),
                    ssid=bss.ssid,
                    band=bss.band,
                    channel=bss.channel,
                    frequency_mhz=bss.frequency_mhz,
                    protection=bss.protection,
                    protection_reported=bss.protection_reported,
                    standard=bss.standard,
                    signal_dbm=bss.signal_dbm,
                    signal_quality=bss.signal_quality,
                    client_count=bss.client_count,
                    vlan_id=bss.vlan_id,
                    access_point=refs["aps"].get(bss.access_point_id or 0),
                    source=bss.source,
                    sources=[s for s in (bss.sources or []) if s in wc.ALL_SOURCES],
                    confidence=bss.confidence,
                    reported_by=refs["devices"].get(bss.source_device_id or 0),
                    last_agent=refs["assets"].get(bss.last_agent_asset_id or 0),
                    authorization_status=bss.authorization_status,
                    authorization_reason=bss.authorization_reason,
                    authorization_by=bss.authorization_by,
                    authorization_at=bss.authorization_at,
                    findings=finding(bss.protection, bss.protection_reported),
                    present=bss.present,
                    freshness="recent" if self._bss_is_recent(bss, w) else "historical",
                    first_seen_at=bss.first_seen_at,
                    last_seen_at=bss.last_seen_at,
                    last_snmp_seen_at=bss.last_snmp_seen_at,
                    last_agent_seen_at=bss.last_agent_seen_at,
                    version=bss.version,
                )
            )
        return out

    def list_bss(
        self,
        *,
        site_id: int | None,
        ssid: str | None = None,
        band: str | None = None,
        authorization: str | None = None,
        source: str | None = None,
        confidence: str | None = None,
        protection: str | None = None,
        access_point_id: UUID | None = None,
        freshness: str | None = None,
        insecure: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> WlanBssList:
        w = self._windows(datetime.now(UTC))
        stmt = select(WlanBss)
        if site_id is not None:
            stmt = stmt.where(WlanBss.site_id == site_id)
        if ssid is not None:
            stmt = stmt.where(WlanBss.ssid == ssid)
        if band is not None:
            stmt = stmt.where(WlanBss.band == band)
        if authorization is not None:
            stmt = stmt.where(WlanBss.authorization_status == authorization)
        if source is not None:
            stmt = stmt.where(WlanBss.sources.contains([source]))
        if confidence is not None:
            stmt = stmt.where(WlanBss.confidence == confidence)
        if protection is not None:
            stmt = stmt.where(WlanBss.protection == protection)
        if access_point_id is not None:
            ap = self._require_ap(access_point_id)
            stmt = stmt.where(WlanBss.access_point_id == ap.id)
        if freshness == "recent":
            stmt = stmt.where(self._bss_recent(w))
        elif freshness == "historical":
            stmt = stmt.where(~self._bss_recent(w))
        if insecure is not None:
            condition = or_(
                WlanBss.protection.in_(list(wc.INSECURE_PROTECTIONS)),
                WlanBss.protection_reported.ilike("%tkip%"),
            )
            stmt = stmt.where(condition if insecure else ~func.coalesce(condition, False))
        total = int(self._session.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        rows = self._session.scalars(
            stmt.order_by(WlanBss.last_seen_at.desc(), WlanBss.id).limit(limit).offset(offset)
        ).all()
        return WlanBssList(items=self._bss_reads(rows, w), total=total, limit=limit, offset=offset)

    def get_bss(self, public_id: UUID) -> WlanBssRead:
        bss = self._require_bss(public_id)
        return self._bss_reads([bss], self._windows(datetime.now(UTC)))[0]

    # --- agregado por SSID ------------------------------------------------------------------

    def list_ssids(
        self,
        *,
        site_id: int | None,
        band: str | None = None,
        q: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> WlanSsidList:
        session = self._session
        w = self._windows(datetime.now(UTC))
        stmt = select(WlanBss)
        if site_id is not None:
            stmt = stmt.where(WlanBss.site_id == site_id)
        if band is not None:
            stmt = stmt.where(WlanBss.band == band)
        if q is not None:
            stmt = stmt.where(WlanBss.ssid.ilike(f"%{q.replace('%', '').replace('_', '')}%"))
        groups: dict[tuple[int, str | None], dict[str, Any]] = {}

        def group(site: int, ssid: str | None) -> dict[str, Any]:
            return groups.setdefault(
                (site, ssid),
                {
                    "bss": 0,
                    "recent": 0,
                    "aps": set(),
                    "bands": set(),
                    "protections": set(),
                    "sources": set(),
                    "configured": 0,
                    "controller_clients": None,
                    "clients": None,
                    "auth": Counter(),
                    "findings": set(),
                    "last": None,
                },
            )

        for bss in session.scalars(stmt.limit(MAX_SSIDS * 20)):
            g = group(bss.site_id, bss.ssid)
            g["bss"] += 1
            g["recent"] += int(self._bss_is_recent(bss, w))
            if bss.access_point_id:
                g["aps"].add(bss.access_point_id)
            if bss.band:
                g["bands"].add(bss.band)
            if bss.protection:
                g["protections"].add(bss.protection)
            g["sources"].update(s for s in (bss.sources or []) if s in wc.ALL_SOURCES)
            if bss.client_count is not None:
                g["clients"] = (g["clients"] or 0) + bss.client_count
            g["auth"][bss.authorization_status] += 1
            code = wc.insecure_finding(bss.protection, bss.protection_reported)
            if code:
                g["findings"].add(code)
            g["last"] = max(g["last"] or bss.last_seen_at, bss.last_seen_at)
        if band is None:
            configured = select(WlanConfiguredNetwork).where(WlanConfiguredNetwork.present)
            if site_id is not None:
                configured = configured.where(WlanConfiguredNetwork.site_id == site_id)
            if q is not None:
                configured = configured.where(
                    WlanConfiguredNetwork.ssid.ilike(f"%{q.replace('%', '').replace('_', '')}%")
                )
            for network in session.scalars(configured.limit(MAX_SSIDS)):
                g = group(network.site_id, network.ssid)
                g["configured"] += 1
                g["sources"].add(network.source)
                if network.client_count is not None:
                    g["controller_clients"] = (g["controller_clients"] or 0) + network.client_count
                g["last"] = max(g["last"] or network.last_seen_at, network.last_seen_at)
        sites = site_refs(session)
        ordered = sorted(
            groups.items(), key=lambda item: (sites[item[0][0]].name, item[0][1] or "")
        )
        total = len(ordered)
        items = []
        for (site, ssid), g in ordered[offset : offset + limit]:
            ref = sites[site]
            items.append(
                WlanSsidRead(
                    site_id=ref.public_id,
                    site_name=ref.name,
                    ssid=ssid,
                    bss_count=g["bss"],
                    bss_recent=g["recent"],
                    access_point_count=len(g["aps"]),
                    bands=sorted(g["bands"]),
                    protections=sorted(g["protections"]),
                    sources=sorted(g["sources"]),
                    configured_on_controllers=g["configured"],
                    controller_client_count=g["controller_clients"],
                    client_count=g["clients"],
                    authorized_bss=g["auth"]["authorized"],
                    external_bss=g["auth"]["external"],
                    unknown_bss=g["auth"]["unknown"],
                    findings=sorted(g["findings"]),
                    last_seen_at=g["last"],
                )
            )
        return WlanSsidList(items=items, total=total, limit=limit, offset=offset)

    # --- clientes --------------------------------------------------------------------------

    def _client_reads(self, rows: Sequence[WlanClient], w: _Windows) -> list[WlanClientRead]:
        sites = site_refs(self._session)
        refs = self._refs(
            devices={r.source_device_id for r in rows if r.source_device_id},
            assets={r.asset_id for r in rows if r.asset_id},
            aps={r.access_point_id for r in rows if r.access_point_id},
        )
        items = []
        for client in rows:
            site = sites[client.site_id]
            cutoff = w.agent_cutoff if client.source == wc.SOURCE_AGENT else w.snmp_cutoff
            items.append(
                WlanClientRead(
                    client_id=client.public_id,
                    site_id=site.public_id,
                    site_name=site.name,
                    mac=client.mac,
                    mac_randomized=client.mac_randomized,
                    bssid=client.bssid,
                    ssid=client.ssid,
                    access_point=refs["aps"].get(client.access_point_id or 0),
                    radio_slot=client.radio_slot,
                    band=client.band,
                    standard=client.standard,
                    state=client.state,
                    source=client.source,
                    identity_confidence=client.identity_confidence,
                    asset=refs["assets"].get(client.asset_id or 0),
                    correlation_basis=client.correlation_basis,
                    reported_by=refs["devices"].get(client.source_device_id or 0),
                    present=client.present,
                    freshness="recent" if client.last_seen_at >= cutoff else "historical",
                    first_seen_at=client.first_seen_at,
                    last_seen_at=client.last_seen_at,
                )
            )
        return items

    def _require_client(self, public_id: UUID) -> WlanClient:
        client = self._session.scalar(select(WlanClient).where(WlanClient.public_id == public_id))
        if client is None:
            raise WlanClientNotFoundError("Wireless client not found")
        return client

    def get_client(self, public_id: UUID) -> WlanClientRead:
        """Ficha de un cliente (Fase 7B.2): base de la asociación manual desde la UI."""
        client = self._require_client(public_id)
        (read,) = self._client_reads([client], self._windows(datetime.now(UTC)))
        return read

    def client_observations(self, public_id: UUID, limit: int, offset: int) -> WlanObservationList:
        client = self._require_client(public_id)
        return self._observations(WlanObservation.client_id == client.id, limit, offset)

    def list_clients(
        self,
        *,
        site_id: int | None,
        ssid: str | None = None,
        bssid: str | None = None,
        access_point_id: UUID | None = None,
        identity: str | None = None,
        state: str | None = None,
        present: bool | None = None,
        freshness: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> WlanClientList:
        session = self._session
        w = self._windows(datetime.now(UTC))
        stmt = select(WlanClient)
        if site_id is not None:
            stmt = stmt.where(WlanClient.site_id == site_id)
        if ssid is not None:
            stmt = stmt.where(WlanClient.ssid == ssid)
        if bssid is not None:
            stmt = stmt.where(WlanClient.bssid == bssid)
        if access_point_id is not None:
            ap = self._require_ap(access_point_id)
            stmt = stmt.where(WlanClient.access_point_id == ap.id)
        if identity is not None:
            stmt = stmt.where(WlanClient.identity_confidence == identity)
        if state is not None:
            stmt = stmt.where(WlanClient.state == state)
        if present is not None:
            stmt = stmt.where(WlanClient.present.is_(present))
        if freshness == "recent":
            stmt = stmt.where(self._client_recent(w))
        elif freshness == "historical":
            stmt = stmt.where(~self._client_recent(w))
        total = int(session.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        rows = session.scalars(
            stmt.order_by(WlanClient.last_seen_at.desc(), WlanClient.id).limit(limit).offset(offset)
        ).all()
        items = self._client_reads(rows, w)
        return WlanClientList(items=items, total=total, limit=limit, offset=offset)

    # --- vista general ---------------------------------------------------------------------

    def overview(self, site_id: int | None, site_public_id: UUID | None) -> WlanOverview:
        session = self._session
        w = self._windows(datetime.now(UTC))

        def scoped(model: Any) -> Any:
            stmt = select(model)
            return stmt.where(model.site_id == site_id) if site_id is not None else stmt

        def grouped(model: Any, column: Any, *where: Any) -> dict[str, int]:
            stmt = select(column, func.count()).select_from(model).group_by(column)
            if site_id is not None:
                stmt = stmt.where(model.site_id == site_id)
            for condition in where:
                stmt = stmt.where(condition)
            return {str(k): int(v) for k, v in session.execute(stmt).all() if k is not None}

        def count(model: Any, *where: Any) -> int:
            stmt = select(func.count()).select_from(model)
            if site_id is not None:
                stmt = stmt.where(model.site_id == site_id)
            for condition in where:
                stmt = stmt.where(condition)
            return int(session.scalar(stmt) or 0)

        insecure_condition = or_(
            WlanBss.protection.in_(list(wc.INSECURE_PROTECTIONS)),
            WlanBss.protection_reported.ilike("%tkip%"),
        )
        findings: Counter[str] = Counter()
        for protection, reported in session.execute(
            scoped(WlanBss)
            .with_only_columns(WlanBss.protection, WlanBss.protection_reported)
            .where(insecure_condition)
        ):
            code = wc.insecure_finding(protection, reported)
            if code:
                findings[code] += 1
        ssid_stmt = select(func.count(func.distinct(WlanBss.ssid))).where(WlanBss.ssid.is_not(None))
        if site_id is not None:
            ssid_stmt = ssid_stmt.where(WlanBss.site_id == site_id)
        return WlanOverview(
            site_id=site_public_id,
            access_points=count(WlanAccessPoint),
            access_points_recent=count(
                WlanAccessPoint, WlanAccessPoint.last_seen_at >= w.snmp_cutoff
            ),
            access_points_by_authorization=grouped(
                WlanAccessPoint, WlanAccessPoint.authorization_status
            ),
            access_points_by_status=grouped(WlanAccessPoint, WlanAccessPoint.reported_status),
            bss=count(WlanBss),
            bss_recent=count(WlanBss, self._bss_recent(w)),
            bss_observed_only=count(WlanBss, WlanBss.confidence == wc.OBSERVED),
            bss_by_band=grouped(WlanBss, WlanBss.band),
            ssids=int(session.scalar(ssid_stmt) or 0),
            clients=count(WlanClient),
            clients_recent=count(WlanClient, self._client_recent(w)),
            clients_by_identity=grouped(WlanClient, WlanClient.identity_confidence),
            insecure_bss=count(WlanBss, insecure_condition),
            findings_by_code=dict(findings),
            sources=[self._snmp_status(site_id), self._agent_status(site_id)],
        )

    def _snmp_status(self, site_id: int | None) -> WlanSourceStatus:
        session = self._session
        sensors_stmt = select(Sensor).where(Sensor.status.not_in(("revoked",)))
        devices_stmt = select(NetworkDevice).where(NetworkDevice.status == "active")
        if site_id is not None:
            sensors_stmt = sensors_stmt.where(Sensor.site_id == site_id)
            devices_stmt = devices_stmt.where(NetworkDevice.site_id == site_id)
        sensors = [
            s for s in session.scalars(sensors_stmt) if "snmp.wlan" in (s.capabilities or [])
        ]
        by_status: Counter[str] = Counter()
        for device in session.scalars(devices_stmt):
            status = (device.last_modules or {}).get("wlan")
            if status is not None:
                by_status[str(status)] += 1
        last_stmt = select(func.max(WlanAccessPoint.last_seen_at))
        if site_id is not None:
            last_stmt = last_stmt.where(WlanAccessPoint.site_id == site_id)
        last = session.scalar(last_stmt)
        if by_status["complete"]:
            availability, detail = "available", "SNMP wlan data from at least one device"
        elif by_status["partial"]:
            availability, detail = "partial", "SNMP wlan module only partially collected"
        elif by_status:
            availability, detail = (
                "unavailable",
                "Polled devices do not expose a supported WLAN MIB",
            )
        elif sensors:
            availability, detail = "unavailable", "Sensors support snmp.wlan but no poll has run"
        else:
            availability, detail = "not_configured", "No sensor declares snmp.wlan (needs 0.4.0+)"
        return WlanSourceStatus(
            source="snmp",
            availability=availability,
            reporters=len(sensors),
            by_status=dict(by_status),
            last_seen_at=last,
            detail=detail,
        )

    def _agent_status(self, site_id: int | None) -> WlanSourceStatus:
        session = self._session
        stmt = select(WlanAgentReport.status, func.count(), func.max(WlanAgentReport.collected_at))
        if site_id is not None:
            stmt = stmt.where(WlanAgentReport.site_id == site_id)
        rows = session.execute(stmt.group_by(WlanAgentReport.status)).all()
        by_status = {str(status): int(n) for status, n, _ in rows}
        last = max((m for _, _, m in rows if m is not None), default=None)
        if by_status.get("ok"):
            availability, detail = "available", "At least one agent reports Wi-Fi observations"
        elif by_status.get("permission_limited"):
            availability, detail = "partial", "Agents report Wi-Fi with limited OS permissions"
        elif by_status:
            availability, detail = "unavailable", "Agents report no usable Wi-Fi adapter or data"
        else:
            availability, detail = "not_configured", "No agent has sent a wireless report"
        return WlanSourceStatus(
            source="agent",
            availability=availability,
            reporters=sum(by_status.values()),
            by_status=by_status,
            last_seen_at=last,
            detail=detail,
        )

    # --- gestión ---------------------------------------------------------------------------

    def _authorize(
        self, row: WlanAccessPoint | WlanBss, body: WlanAuthorizationUpdate, actor: Actor, kind: str
    ) -> None:
        if body.version is not None and body.version != row.version:
            raise SiteConflictError(
                "wlan_version_conflict",
                "The item changed since it was read",
                [{"version": row.version}],
            )
        previous = row.authorization_status
        row.authorization_status = body.status
        row.authorization_reason = body.reason
        row.authorization_by = actor.name
        row.authorization_at = datetime.now(UTC)
        row.version += 1
        audit_service.record(
            self._session,
            actor,
            "wlan_authorization_changed",
            target_type=kind,
            target_id=row.public_id,
            details={"from": previous, "to": body.status, "reason": body.reason},
            commit=False,
        )
        self._session.commit()

    def set_ap_authorization(
        self, public_id: UUID, body: WlanAuthorizationUpdate, actor: Actor
    ) -> WlanAccessPointDetail:
        ap = self._require_ap(public_id, lock=True)
        self._authorize(ap, body, actor, "wlan_access_point")
        return self.get_access_point(public_id)

    def set_bss_authorization(
        self, public_id: UUID, body: WlanAuthorizationUpdate, actor: Actor
    ) -> WlanBssRead:
        bss = self._require_bss(public_id, lock=True)
        self._authorize(bss, body, actor, "wlan_bss")
        return self.get_bss(public_id)

    def link(self, public_id: UUID, body: WlanLinkRequest, actor: Actor) -> WlanAccessPointDetail:
        """Vinculación manual: exige el mismo site Y evidencia (IP de gestión o MAC iguales).

        Sin evidencia no se vincula aunque lo pida un operador: un enlace sin evidencia
        mezclaría el historial de dos equipos distintos.
        """
        session = self._session
        ap = self._require_ap(public_id, lock=True)
        now = datetime.now(UTC)
        evidence = dict(ap.link_evidence or {})
        details: dict[str, Any] = {}
        if body.asset_id is not None:
            asset = session.scalar(select(Asset).where(Asset.public_id == body.asset_id))
            if asset is None:
                raise NotFoundError("Asset not found")
            if asset.site_id != ap.site_id:
                raise SiteConflictError(
                    "wlan_link_site_mismatch", "The asset belongs to another site"
                )
            proof = evidence_for_asset(session, ap, asset)
            if proof is None:
                raise SiteConflictError(
                    "wlan_link_evidence_insufficient",
                    "No matching management IP or MAC between the access point and the asset",
                )
            ap.asset_id = asset.id
            evidence["asset"] = {
                **proof,
                "method": "manual",
                "at": now.isoformat(),
                "by": actor.name,
            }
            details["asset_id"] = str(asset.public_id)
            details["asset_basis"] = proof["basis"]
        if body.network_device_id is not None:
            device = session.scalar(
                select(NetworkDevice).where(NetworkDevice.public_id == body.network_device_id)
            )
            if device is None:
                raise NetworkDeviceNotFoundError("Network device not found")
            if device.site_id != ap.site_id:
                raise SiteConflictError(
                    "wlan_link_site_mismatch", "The network device belongs to another site"
                )
            proof = evidence_for_device(session, ap, device)
            if proof is None:
                raise SiteConflictError(
                    "wlan_link_evidence_insufficient",
                    "No matching management IP or MAC between the access point and the device",
                )
            ap.network_device_id = device.id
            evidence["network_device"] = {
                **proof,
                "method": "manual",
                "at": now.isoformat(),
                "by": actor.name,
            }
            details["network_device_id"] = str(device.public_id)
            details["network_device_basis"] = proof["basis"]
        ap.link_evidence = evidence
        ap.link_suppressed = False
        ap.version += 1
        audit_service.record(
            session,
            actor,
            "wlan_access_point_linked",
            target_type="wlan_access_point",
            target_id=ap.public_id,
            details=details,
            commit=False,
        )
        session.commit()
        return self.get_access_point(public_id)

    def unlink(
        self, public_id: UUID, body: WlanUnlinkRequest, actor: Actor
    ) -> WlanAccessPointDetail:
        """Desvincula conservando identidad e historial del AP; la vinculación automática no
        vuelve a enlazar sola hasta un enlace manual."""
        session = self._session
        ap = self._require_ap(public_id, lock=True)
        evidence = dict(ap.link_evidence or {})
        removed: list[str] = []
        if body.target in ("asset", "all") and ap.asset_id is not None:
            ap.asset_id = None
            evidence.pop("asset", None)
            removed.append("asset")
        if body.target in ("network_device", "all") and ap.network_device_id is not None:
            ap.network_device_id = None
            evidence.pop("network_device", None)
            removed.append("network_device")
        ap.link_evidence = evidence or None
        ap.link_suppressed = True
        ap.version += 1
        audit_service.record(
            session,
            actor,
            "wlan_access_point_unlinked",
            target_type="wlan_access_point",
            target_id=ap.public_id,
            details={"removed": removed, "reason": body.reason},
            commit=False,
        )
        session.commit()
        return self.get_access_point(public_id)


def purge_wlan_history(session: Session, days: int, now: datetime | None = None) -> dict[str, int]:
    """Retención opt-in (WLAN_HISTORY_RETENTION_DAYS): historial más antiguo que el plazo,
    clientes no vistos desde entonces, BSS solo observados (sin AP ni decisión de un operador)
    y WLANs configuradas ausentes. Los APs y lo autorizado o marcado como externo se conservan:
    son decisiones de un operador."""
    from sqlalchemy import delete

    cutoff = (now or datetime.now(UTC)) - timedelta(days=days)
    statements = {
        "wlan_observations": delete(WlanObservation).where(WlanObservation.observed_at < cutoff),
        "wlan_clients": delete(WlanClient).where(WlanClient.last_seen_at < cutoff),
        "wlan_bss": delete(WlanBss).where(
            WlanBss.last_seen_at < cutoff,
            WlanBss.access_point_id.is_(None),
            WlanBss.authorization_status == "unknown",
        ),
        "wlan_configured_networks": delete(WlanConfiguredNetwork).where(
            WlanConfiguredNetwork.present.is_(False), WlanConfiguredNetwork.last_seen_at < cutoff
        ),
    }
    counts: dict[str, int] = {}
    for name, stmt in statements.items():
        result = session.execute(stmt.execution_options(synchronize_session=False))
        counts[name] = int(getattr(result, "rowcount", 0) or 0)
    session.commit()
    return counts
