"""Consultas y administración de NDR para el dashboard (Fase 7E.1).

Permisos (app/core/permissions.py): ndr:read ve estado de captura y agregados; ndr:evidence
ve flujos y metadatos individuales; ndr:manage aprueba la captura de un sensor (auditado).
"""

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, and_, cast, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    NdrConflictError,
    NdrValidationError,
    SensorNotFoundError,
    SiteValidationError,
)
from app.models.ndr import NdrBatch, NdrCaptureConfig, NdrFlow, NdrProtocolObservation
from app.models.site import Sensor, Site
from app.ndr.config import capture_config, is_capable
from app.schemas.ndr import (
    NdrCaptureConfigRead,
    NdrCaptureConfigUpdate,
    NdrFlowList,
    NdrFlowRead,
    NdrInterfaceHealth,
    NdrObservationList,
    NdrObservationRead,
    NdrOverview,
    NdrProtocolCount,
    NdrSensorList,
    NdrSensorRead,
    NdrTalker,
)
from app.services import audit_service
from app.services.audit_service import Actor

# Servicios conocidos para el resumen por puerto (solo etiquetas de presentación).
SERVICE_NAMES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    514: "syslog",
    636: "ldaps",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-tls",
    8080: "http-alt",
    8443: "https-alt",
}
OVERVIEW_TOP = 10


def _ip_filter(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        raise SiteValidationError("invalid_ip", "Invalid IP address") from exc


def _health_interfaces(health: dict[str, Any]) -> list[NdrInterfaceHealth]:
    out: list[NdrInterfaceHealth] = []
    for item in health.get("interfaces") or []:
        if not isinstance(item, dict):
            continue
        out.append(
            NdrInterfaceHealth(
                name=str(item.get("name")),
                state=item.get("state") or "error",
                error_code=item.get("error_code"),
                backend=item.get("backend"),
                packets_seen=item.get("packets_seen"),
                packets_processed=item.get("packets_processed"),
                budget_dropped=item.get("budget_dropped"),
                malformed=item.get("malformed"),
                cpu_percent=item.get("cpu_percent"),
                pps_budget=item.get("pps_budget"),
                last_packet_at=item.get("last_packet_at"),
                last_export_at=item.get("last_export_at"),
                degraded_reasons=list(item.get("degraded_reasons") or []),
            )
        )
    return out


def _stat(name: str) -> Any:
    return func.coalesce(func.sum(cast(NdrBatch.stats[name].astext, BigInteger)), 0)


class NdrService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- sensores y configuración -------------------------------------------------------

    def _require_sensor(self, public_id: UUID, lock: bool = False) -> Sensor:
        query = select(Sensor).where(Sensor.public_id == public_id)
        if lock:
            query = query.with_for_update()
        sensor = self._session.scalar(query)
        if sensor is None:
            raise SensorNotFoundError("Sensor not found")
        return sensor

    def list_sensors(self, site_id: int | None) -> NdrSensorList:
        since = datetime.now(UTC) - timedelta(hours=24)
        query = (
            select(Sensor, Site, NdrCaptureConfig)
            .join(Site, Site.id == Sensor.site_id)
            .outerjoin(NdrCaptureConfig, NdrCaptureConfig.sensor_id == Sensor.id)
            .where(Sensor.status != "revoked")
            .order_by(Site.name, Sensor.name)
        )
        if site_id is not None:
            query = query.where(Sensor.site_id == site_id)
        rows = [
            row
            for row in self._session.execute(query).all()
            if is_capable(row[0]) or row[2] is not None
        ]
        stats = {
            row.sensor_id: row
            for row in self._session.execute(
                select(
                    NdrBatch.sensor_id,
                    func.max(NdrBatch.received_at).label("last_batch_at"),
                    _stat("packets_seen").label("packets"),
                    (
                        _stat("kernel_dropped")
                        + _stat("interface_dropped")
                        + _stat("budget_dropped")
                    ).label("dropped"),
                )
                .where(
                    NdrBatch.sensor_id.in_([r[0].id for r in rows]),
                    NdrBatch.received_at >= since,
                )
                .group_by(NdrBatch.sensor_id)
            ).all()
        }
        items = []
        for sensor, site, config in rows:
            health = (sensor.health or {}).get("ndr") or {}
            stat = stats.get(sensor.id)
            items.append(
                NdrSensorRead(
                    sensor_id=sensor.public_id,
                    name=sensor.name,
                    site_id=site.public_id,
                    site_name=site.name,
                    status=sensor.status,
                    sensor_version=sensor.sensor_version,
                    last_seen_at=sensor.last_seen_at,
                    capable=is_capable(sensor),
                    capture_state=health.get("state"),
                    reported_revision=health.get("config_revision"),
                    interfaces=_health_interfaces(health),
                    spool_items=health.get("spool_items"),
                    spool_dropped=health.get("spool_dropped"),
                    config=NdrCaptureConfigRead.model_validate(config) if config else None,
                    last_batch_at=stat.last_batch_at if stat else None,
                    packets_24h=int(stat.packets) if stat else 0,
                    dropped_24h=int(stat.dropped) if stat else 0,
                )
            )
        return NdrSensorList(items=items)

    def update_config(
        self, sensor_id: UUID, body: NdrCaptureConfigUpdate, actor: Actor
    ) -> NdrCaptureConfigRead:
        sensor = self._require_sensor(sensor_id, lock=True)
        if sensor.status == "revoked":
            raise NdrConflictError("ndr_sensor_revoked", "The sensor has been revoked")
        if body.enabled:
            if not body.interfaces:
                raise NdrValidationError(
                    "ndr_interfaces_required", "Approve at least one interface alias"
                )
            if not body.observation_point:
                raise NdrValidationError(
                    "ndr_observation_point_required",
                    "Describe where the interface is connected (SPAN port, TAP, segment)",
                )
            if not body.confirm_passive_authorized:
                raise NdrValidationError(
                    "ndr_confirmation_required",
                    "Confirm that passive capture is authorized on that segment",
                )
        row = capture_config(self._session, sensor.id)
        current = row.revision if row is not None else 0
        if body.expected_revision != current:
            raise NdrConflictError(
                "ndr_config_changed",
                "The capture configuration changed since it was read",
                [{"revision": current}],
            )
        before = _config_summary(row) if row is not None else None
        if row is None:
            row = NdrCaptureConfig(sensor_id=sensor.id, site_id=sensor.site_id, revision=0)
            self._session.add(row)
        values = body.model_dump(exclude={"confirm_passive_authorized", "expected_revision"})
        for key, value in values.items():
            setattr(row, key, value)
        row.site_id = sensor.site_id
        row.revision = current + 1
        row.updated_by = actor.name[:64]
        row.updated_at = datetime.now(UTC)
        audit_service.record(
            self._session,
            actor,
            "ndr_capture_config_changed",
            target_type="sensor",
            target_id=sensor.public_id,
            details={
                "from": before,
                "to": _config_summary(row),
                "confirmed_passive": body.confirm_passive_authorized,
            },
            commit=False,
        )
        self._session.commit()
        self._session.refresh(row)
        return NdrCaptureConfigRead.model_validate(row)

    # --- agregados ----------------------------------------------------------------------

    def overview(self, site_id: int | None, hours: int) -> NdrOverview:
        since = datetime.now(UTC) - timedelta(hours=hours)
        sensors = self.list_sensors(site_id).items
        flow_scope = [NdrFlow.last_seen >= since]
        if site_id is not None:
            flow_scope.append(NdrFlow.site_id == site_id)
        volume = NdrFlow.bytes_out + NdrFlow.bytes_in
        totals = self._session.execute(
            select(func.count(), func.coalesce(func.sum(volume), 0)).where(*flow_scope)
        ).one()
        transports = self._session.execute(
            select(NdrFlow.transport, func.count(), func.coalesce(func.sum(volume), 0))
            .where(*flow_scope)
            .group_by(NdrFlow.transport)
            .order_by(func.count().desc())
            .limit(OVERVIEW_TOP)
        ).all()
        services = self._session.execute(
            select(NdrFlow.dst_port, func.count(), func.coalesce(func.sum(volume), 0))
            .where(*flow_scope, NdrFlow.dst_port.is_not(None))
            .group_by(NdrFlow.dst_port)
            .order_by(func.coalesce(func.sum(volume), 0).desc())
            .limit(OVERVIEW_TOP)
        ).all()
        talkers = self._session.execute(
            select(NdrFlow.src_ip, func.count(), func.coalesce(func.sum(volume), 0))
            .where(*flow_scope)
            .group_by(NdrFlow.src_ip)
            .order_by(func.coalesce(func.sum(volume), 0).desc())
            .limit(OVERVIEW_TOP)
        ).all()
        obs_scope = [NdrProtocolObservation.last_seen >= since]
        if site_id is not None:
            obs_scope.append(NdrProtocolObservation.site_id == site_id)
        observations = {kind: 0 for kind in ("arp", "dns", "dhcp", "tls")}
        for kind, count in self._session.execute(
            select(NdrProtocolObservation.kind, func.count())
            .where(*obs_scope)
            .group_by(NdrProtocolObservation.kind)
        ).all():
            observations[kind] = int(count)
        batch_scope = [NdrBatch.received_at >= since]
        if site_id is not None:
            batch_scope.append(NdrBatch.site_id == site_id)
        packets = self._session.execute(
            select(
                _stat("packets_seen"),
                _stat("kernel_dropped") + _stat("interface_dropped") + _stat("budget_dropped"),
                func.max(NdrBatch.received_at),
            ).where(*batch_scope)
        ).one()
        return NdrOverview(
            window_hours=hours,
            sensors_capable=sum(1 for s in sensors if s.capable),
            sensors_enabled=sum(1 for s in sensors if s.config is not None and s.config.enabled),
            sensors_capturing=sum(1 for s in sensors if s.capture_state == "running"),
            sensors_degraded=sum(1 for s in sensors if s.capture_state in ("degraded", "error")),
            flows=int(totals[0]),
            bytes=int(totals[1]),
            packets_seen=int(packets[0]),
            packets_dropped=int(packets[1]),
            observations=observations,
            transports=[
                NdrProtocolCount(key=str(t), flows=int(c), bytes=int(b)) for t, c, b in transports
            ],
            services=[
                NdrProtocolCount(
                    key=f"{port}/{SERVICE_NAMES.get(int(port or 0), 'other')}",
                    flows=int(c),
                    bytes=int(b),
                )
                for port, c, b in services
            ],
            top_talkers=[NdrTalker(ip=str(ip), flows=int(c), bytes=int(b)) for ip, c, b in talkers],
            last_batch_at=packets[2],
        )

    # --- evidencia ----------------------------------------------------------------------

    def list_flows(
        self,
        *,
        site_id: int | None,
        sensor_id: UUID | None,
        ip: str | None,
        port: int | None,
        transport: str | None,
        flag: str | None,
        since: datetime | None,
        until: datetime | None,
        limit: int,
        offset: int,
    ) -> NdrFlowList:
        query = (
            select(NdrFlow, Sensor.public_id, Sensor.name, Site.public_id)
            .join(Sensor, Sensor.id == NdrFlow.sensor_id)
            .join(Site, Site.id == NdrFlow.site_id)
        )
        conditions = []
        if site_id is not None:
            conditions.append(NdrFlow.site_id == site_id)
        if sensor_id is not None:
            conditions.append(Sensor.public_id == sensor_id)
        if ip is not None:
            address = _ip_filter(ip)
            conditions.append(or_(NdrFlow.src_ip == address, NdrFlow.dst_ip == address))
        if port is not None:
            conditions.append(or_(NdrFlow.dst_port == port, NdrFlow.src_port == port))
        if transport is not None:
            conditions.append(NdrFlow.transport == transport)
        if flag is not None:
            conditions.append(NdrFlow.flags.contains([flag]))
        if since is not None:
            conditions.append(NdrFlow.last_seen >= since)
        if until is not None:
            conditions.append(NdrFlow.first_seen <= until)
        where = and_(*conditions) if conditions else None
        count_query = (
            select(func.count()).select_from(NdrFlow).join(Sensor, Sensor.id == NdrFlow.sensor_id)
        )
        if where is not None:
            query = query.where(where)
            count_query = count_query.where(where)
        total = int(self._session.scalar(count_query) or 0)
        rows = self._session.execute(
            query.order_by(NdrFlow.last_seen.desc(), NdrFlow.id.desc()).limit(limit).offset(offset)
        ).all()
        items = [
            NdrFlowRead.model_validate(
                {
                    **{c.key: getattr(flow, c.key) for c in NdrFlow.__table__.columns},
                    "sensor_id": sensor_public,
                    "sensor_name": sensor_name,
                    "site_id": site_public,
                }
            )
            for flow, sensor_public, sensor_name, site_public in rows
        ]
        return NdrFlowList(items=items, total=total)

    def list_observations(
        self,
        *,
        kind: str | None,
        site_id: int | None,
        sensor_id: UUID | None,
        ip: str | None,
        mac: str | None,
        name: str | None,
        since: datetime | None,
        limit: int,
        offset: int,
    ) -> NdrObservationList:
        model = NdrProtocolObservation
        conditions = []
        if kind is not None:
            conditions.append(model.kind == kind)
        if site_id is not None:
            conditions.append(model.site_id == site_id)
        if sensor_id is not None:
            conditions.append(Sensor.public_id == sensor_id)
        if ip is not None:
            address = _ip_filter(ip)
            conditions.append(or_(model.ip == address, model.peer_ip == address))
        if mac is not None:
            conditions.append(model.mac == mac)
        if name is not None:
            # Búsqueda por sufijo o subcadena literal: los comodines de LIKE se escapan.
            escaped = name.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conditions.append(model.name.like(f"%{escaped}%", escape="\\"))
        if since is not None:
            conditions.append(model.last_seen >= since)
        base = (
            select(model, Sensor.public_id, Sensor.name, Site.public_id)
            .join(Sensor, Sensor.id == model.sensor_id)
            .join(Site, Site.id == model.site_id)
        )
        count_query = (
            select(func.count()).select_from(model).join(Sensor, Sensor.id == model.sensor_id)
        )
        if conditions:
            base = base.where(*conditions)
            count_query = count_query.where(*conditions)
        total = int(self._session.scalar(count_query) or 0)
        rows = self._session.execute(
            base.order_by(model.last_seen.desc(), model.id.desc()).limit(limit).offset(offset)
        ).all()
        return NdrObservationList(
            items=[
                NdrObservationRead(
                    id=row.id,
                    sensor_id=sensor_public,
                    sensor_name=sensor_name,
                    site_id=site_public,
                    interface=row.interface,
                    kind=row.kind,
                    ip=row.ip,
                    peer_ip=row.peer_ip,
                    mac=row.mac,
                    name=row.name,
                    vlan=row.vlan,
                    count=row.count,
                    first_seen=row.first_seen,
                    last_seen=row.last_seen,
                    data=dict(row.data or {}),
                )
                for row, sensor_public, sensor_name, site_public in rows
            ],
            total=total,
        )


def _config_summary(row: NdrCaptureConfig) -> dict[str, Any]:
    return {
        "enabled": row.enabled,
        "revision": row.revision,
        "interfaces": list(row.interfaces or []),
        "observation_point": row.observation_point,
        "promiscuous": row.promiscuous,
        "dns_metadata": row.dns_metadata,
        "tls_metadata": row.tls_metadata,
        "arp_metadata": row.arp_metadata,
        "dhcp_metadata": row.dhcp_metadata,
    }
