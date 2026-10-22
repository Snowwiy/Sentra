"""Equipos de red administrables y su inventario SNMP (Fase 6B, docs/snmp-network-intelligence.md).

Reglas que este servicio garantiza:
- Un equipo pertenece a UN site. Perfil, sensor y activo enlazado deben ser de ese mismo site,
  y la dirección de gestión debe caer dentro de una red habilitada del site. La misma IP
  privada en dos sites son dos equipos distintos (rangos solapados permitidos).
- El estado de monitorización se deriva al leer (nunca se guarda): un equipo cuya última
  consulta correcta es antigua se presenta con evidencia "historical", nunca como disponible.
- Sin perfil o sin sensor es "configuración pendiente", no un error.
- Las lecturas de inventario nunca cruzan sites: una MAC o un vecino solo se relacionan con
  activos y equipos del mismo site.
"""

import ipaddress
import uuid
from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    NetworkDeviceNotFoundError,
    NetworkPollNotFoundError,
    SiteConflictError,
    SiteValidationError,
)
from app.discovery.probes import normalize_mac
from app.models.asset import Asset
from app.models.network import (
    OPEN_POLL_STATUSES,
    NetworkDevice,
    NetworkDevicePoll,
    NetworkInterface,
    NetworkMacEntry,
    NetworkNeighbor,
    NetworkVlan,
    NetworkVlanMembership,
    SnmpCredentialProfile,
)
from app.models.site import Sensor, SensorJob, Site
from app.network.apply import link_device_asset
from app.network.catalog import evidence_source
from app.schemas.network import (
    AssetRef,
    DeviceProfileRef,
    DeviceRef,
    DeviceSensorRef,
    EntityRead,
    InterfaceRef,
    LldpLocalRead,
    MacLocationList,
    MacLocationRead,
    NetworkCandidate,
    NetworkCandidateList,
    NetworkDeviceArchive,
    NetworkDeviceCounts,
    NetworkDeviceCreate,
    NetworkDeviceDetail,
    NetworkDeviceList,
    NetworkDeviceRead,
    NetworkDeviceResume,
    NetworkDeviceUpdate,
    NetworkInterfaceList,
    NetworkInterfaceRead,
    NetworkMacEntryList,
    NetworkMacEntryRead,
    NetworkNeighborList,
    NetworkNeighborRead,
    NetworkPollList,
    NetworkPollRead,
    NetworkVlanList,
    NetworkVlanRead,
    PollChanges,
    PollCounts,
)
from app.services import audit_service, network_jobs
from app.services.audit_service import Actor
from app.services.site_service import enabled_networks, site_refs

# Tipos de activo (clasificación de 6A) que suelen ser equipos administrables por SNMP.
CANDIDATE_DEVICE_TYPES = ("router", "network_switch", "access_point", "firewall")
# Tope de equipos que se evalúan para filtrar por estado derivado. Muy por encima de una red
# de una pyme; si se alcanza, el filtro por estado se aplica sobre los primeros.
MAX_DEVICES_SCAN = 10_000
# La evidencia es "reciente" si la última consulta correcta está dentro de este margen
# (o de 3 intervalos del programador, si es mayor).
RECENT_MINIMUM = timedelta(minutes=60)
_PHYS_CLASS = {3: "chassis", 11: "stack"}
_SENSOR_DOWN = ("offline", "stale", "pending")


def _display_name(device: NetworkDevice) -> str:
    return device.name or device.sys_name or device.management_address


def _interface_name(interface: NetworkInterface) -> str:
    return interface.if_name or interface.if_descr or f"ifIndex {interface.if_index}"


def _interface_ref(interface: NetworkInterface | None) -> InterfaceRef | None:
    if interface is None:
        return None
    return InterfaceRef(
        interface_id=interface.public_id,
        name=_interface_name(interface),
        port_kind=interface.port_kind,
    )


def freshness(device: NetworkDevice, settings: Settings, now: datetime) -> str:
    if device.last_success_at is None:
        return "none"
    window = RECENT_MINIMUM
    if settings.snmp_poll_interval_minutes:
        window = max(window, timedelta(minutes=3 * settings.snmp_poll_interval_minutes))
    return "recent" if now - device.last_success_at <= window else "historical"


def monitoring_status(
    device: NetworkDevice,
    profile: SnmpCredentialProfile | None,
    has_sensor: bool,
    polling: bool,
) -> str:
    """Estado derivado (orden fijo: lo administrativo antes que la salud de la consulta)."""
    if device.status != "active":
        return "archived"
    if profile is None or profile.status != "active":
        return "credentials_pending"
    if not has_sensor:
        return "sensor_pending"
    if polling:
        return "polling"
    if device.monitoring_paused_at is not None:
        return "paused"
    failing = device.consecutive_failures > 0 and (
        device.last_success_at is None
        or (device.last_error_at is not None and device.last_error_at > device.last_success_at)
    )
    if failing:
        return "failing"
    if device.last_success_at is not None:
        return "partial" if device.last_error_code else "ok"
    return "never_polled" if device.monitoring_enabled else "disabled"


class NetworkDeviceService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- lecturas de equipos ---------------------------------------------------------------

    def _context(self, devices: Sequence[NetworkDevice]) -> dict[str, Any]:
        """Todo lo que necesitan las filas en pocas consultas (sin N+1)."""
        from app.services.sensor_service import effective_status

        session = self._session
        ids = [d.id for d in devices]
        profiles = {
            p.id: p
            for p in session.scalars(
                select(SnmpCredentialProfile).where(
                    SnmpCredentialProfile.id.in_({d.profile_id for d in devices if d.profile_id})
                )
            )
        }
        now = datetime.now(UTC)
        sensors = {
            s.id: (s, effective_status(s, now, self._settings))
            for s in session.scalars(
                select(Sensor).where(Sensor.id.in_({d.sensor_id for d in devices if d.sensor_id}))
            )
        }
        assets = dict(
            session.execute(
                select(Asset.id, Asset.public_id).where(
                    Asset.id.in_({d.asset_id for d in devices if d.asset_id})
                )
            ).all()
        )
        open_polls = set(
            session.scalars(
                select(NetworkDevicePoll.device_id).where(
                    NetworkDevicePoll.device_id.in_(ids),
                    NetworkDevicePoll.status.in_(OPEN_POLL_STATUSES),
                )
            )
        )
        return {
            "now": now,
            "sites": site_refs(session),
            "profiles": profiles,
            "sensors": sensors,
            "assets": assets,
            "open": open_polls,
        }

    def _status_of(self, device: NetworkDevice, ctx: dict[str, Any]) -> str:
        profile = ctx["profiles"].get(device.profile_id)
        return monitoring_status(
            device, profile, device.sensor_id in ctx["sensors"], device.id in ctx["open"]
        )

    def _counts(self, ids: list[int]) -> dict[int, dict[str, int]]:
        session = self._session
        out: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        if not ids:
            return out
        for device_id, total, up in session.execute(
            select(
                NetworkInterface.device_id,
                func.count(),
                func.count().filter(NetworkInterface.oper_status == "up"),
            )
            .where(NetworkInterface.device_id.in_(ids), NetworkInterface.present)
            .group_by(NetworkInterface.device_id)
        ):
            out[device_id]["interfaces_total"] = int(total)
            out[device_id]["interfaces_up"] = int(up)
        for model, key in (
            (NetworkNeighbor, "neighbors_total"),
            (NetworkVlan, "vlans_total"),
            (NetworkMacEntry, "mac_entries_total"),
        ):
            for device_id, total in session.execute(
                select(model.device_id, func.count())
                .where(model.device_id.in_(ids), model.present)
                .group_by(model.device_id)
            ):
                out[device_id][key] = int(total)
        return out

    def _read(
        self,
        device: NetworkDevice,
        ctx: dict[str, Any],
        counts: dict[str, int],
        cls: type[NetworkDeviceRead] = NetworkDeviceRead,
        **extra: Any,
    ) -> Any:
        site = ctx["sites"][device.site_id]
        profile = ctx["profiles"].get(device.profile_id)
        sensor_entry = ctx["sensors"].get(device.sensor_id)
        return cls(
            device_id=device.public_id,
            site_id=site.public_id,
            site_name=site.name,
            display_name=_display_name(device),
            name=device.name,
            management_address=device.management_address,
            snmp_port=device.snmp_port,
            asset_id=ctx["assets"].get(device.asset_id),
            status=device.status,
            monitoring_enabled=device.monitoring_enabled,
            monitoring_status=self._status_of(device, ctx),
            freshness=freshness(device, self._settings, ctx["now"]),
            sys_name=device.sys_name,
            sys_descr=device.sys_descr,
            sys_object_id=device.sys_object_id,
            sys_location=device.sys_location,
            sys_uptime_seconds=device.sys_uptime_seconds,
            vendor=device.vendor,
            vendor_source=device.vendor_source,
            enterprise_number=device.enterprise_number,
            model=device.model,
            firmware=device.firmware,
            serial_number=device.serial_number,
            classification=device.classification,
            classification_confidence=device.classification_confidence,
            classification_evidence=list(device.classification_evidence or []),
            layer3=device.layer3,
            profile=(
                DeviceProfileRef(
                    profile_id=profile.public_id,
                    name=profile.name,
                    snmp_version=profile.snmp_version,
                    status=profile.status,
                )
                if profile is not None
                else None
            ),
            sensor=(
                DeviceSensorRef(
                    sensor_id=sensor_entry[0].public_id,
                    name=sensor_entry[0].name,
                    status=sensor_entry[1],
                )
                if sensor_entry is not None
                else None
            ),
            last_poll_at=device.last_poll_at,
            last_success_at=device.last_success_at,
            last_error_code=device.last_error_code,
            last_error_at=device.last_error_at,
            consecutive_failures=device.consecutive_failures,
            snmp_status=device.snmp_status,
            monitoring_paused_at=device.monitoring_paused_at,
            monitoring_pause_reason=device.monitoring_pause_reason,
            interfaces_total=counts.get("interfaces_total", 0),
            interfaces_up=counts.get("interfaces_up", 0),
            neighbors_total=counts.get("neighbors_total", 0),
            vlans_total=counts.get("vlans_total", 0),
            mac_entries_total=counts.get("mac_entries_total", 0),
            created_at=device.created_at,
            updated_at=device.updated_at,
            version=device.version,
            **extra,
        )

    def list_devices(
        self,
        *,
        site_id: int | None,
        classification: str | None,
        status: str | None,
        q: str | None,
        include_archived: bool,
        limit: int,
        offset: int,
    ) -> NetworkDeviceList:
        query = select(NetworkDevice)
        if site_id is not None:
            query = query.where(NetworkDevice.site_id == site_id)
        if not include_archived:
            query = query.where(NetworkDevice.status == "active")
        if classification is not None:
            query = query.where(NetworkDevice.classification == classification)
        if q:
            pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            query = query.where(
                or_(
                    NetworkDevice.name.ilike(pattern, escape="\\"),
                    NetworkDevice.sys_name.ilike(pattern, escape="\\"),
                    NetworkDevice.management_address.ilike(pattern, escape="\\"),
                )
            )
        devices = self._session.scalars(
            query.order_by(
                func.lower(
                    func.coalesce(
                        NetworkDevice.name, NetworkDevice.sys_name, NetworkDevice.management_address
                    )
                ),
                NetworkDevice.id,
            ).limit(MAX_DEVICES_SCAN)
        ).all()
        ctx = self._context(devices)
        statuses = {d.id: self._status_of(d, ctx) for d in devices}
        by_class: dict[str, int] = defaultdict(int)
        by_status: dict[str, int] = defaultdict(int)
        for device in devices:
            by_class[device.classification] += 1
            by_status[statuses[device.id]] += 1
        selected = [d for d in devices if status is None or statuses[d.id] == status]
        page = selected[offset : offset + limit]
        counts = self._counts([d.id for d in page])
        return NetworkDeviceList(
            items=[self._read(d, ctx, counts.get(d.id, {})) for d in page],
            total=len(selected),
            limit=limit,
            offset=offset,
            counts=NetworkDeviceCounts(
                total=len(devices),
                by_classification=dict(by_class),
                by_monitoring_status=dict(by_status),
            ),
        )

    def row(self, public_id: uuid.UUID, *, lock: bool = False) -> NetworkDevice:
        query = select(NetworkDevice).where(NetworkDevice.public_id == public_id)
        if lock:
            query = query.with_for_update()
        device = self._session.scalar(query)
        if device is None:
            raise NetworkDeviceNotFoundError("Network device not found")
        return device

    def get(self, public_id: uuid.UUID) -> NetworkDeviceDetail:
        device = self.row(public_id)
        ctx = self._context([device])
        counts = self._counts([device.id])
        blockers, _ = network_jobs.poll_blockers(self._session, self._settings, device)
        if device.id in ctx["open"]:
            blockers.append("poll_in_progress")
        entities = []
        for item in device.entities or []:
            entities.append(
                EntityRead(
                    index=int(item.get("index", 0)),
                    phys_class=_PHYS_CLASS.get(int(item.get("phys_class", 0)), "other"),
                    description=item.get("descr"),
                    name=item.get("name"),
                    model_name=item.get("model_name"),
                    serial_number=item.get("serial"),
                    hardware_rev=item.get("hardware_rev"),
                    firmware_rev=item.get("firmware_rev"),
                    software_rev=item.get("software_rev"),
                    mfg_name=item.get("mfg_name"),
                )
            )
        lldp = None
        if device.lldp_chassis_id or device.lldp_sys_name or device.lldp_capabilities:
            lldp = LldpLocalRead(
                chassis_id=device.lldp_chassis_id,
                chassis_id_subtype=device.lldp_chassis_id_subtype,
                sys_name=device.lldp_sys_name,
                capabilities_enabled=list(device.lldp_capabilities or []),
            )
        return self._read(  # type: ignore[no-any-return]
            device,
            ctx,
            counts.get(device.id, {}),
            NetworkDeviceDetail,
            lldp_local=lldp,
            entities=entities,
            base_bridge_address=device.base_bridge_address,
            bridge_ports=device.bridge_ports,
            last_modules=dict(device.last_modules or {}),
            can_poll=not blockers,
            poll_blockers=blockers,
        )

    # --- escritura ---------------------------------------------------------------------------

    def _site(self, public_id: uuid.UUID) -> Site:
        site = self._session.scalar(select(Site).where(Site.public_id == public_id))
        if site is None:
            from app.core.exceptions import SiteNotFoundError

            raise SiteNotFoundError("Site not found")
        return site

    def _check_address(self, site: Site, address: str) -> None:
        from app.services.sensor_service import inside_site_networks

        parsed = ipaddress.ip_address(address)
        if parsed.is_global and not self._settings.discovery_allow_public_networks:
            raise SiteValidationError(
                "network_address_public",
                "Public management addresses need DISCOVERY_ALLOW_PUBLIC_NETWORKS=true",
            )
        if not inside_site_networks(address, enabled_networks(self._session, site.id)):
            raise SiteValidationError(
                "network_address_out_of_scope",
                "The management address is outside the enabled networks of the site",
                [{"management_address": address}],
            )

    def _profile(self, public_id: uuid.UUID, site: Site) -> SnmpCredentialProfile:
        profile = self._session.scalar(
            select(SnmpCredentialProfile).where(SnmpCredentialProfile.public_id == public_id)
        )
        # El perfil de otro site responde igual que uno inexistente: no se confirma que exista.
        if profile is None or profile.site_id != site.id:
            raise SiteValidationError(
                "snmp_profile_invalid", "The SNMP profile does not exist in this site"
            )
        if profile.status != "active":
            raise SiteConflictError("snmp_profile_revoked", "The SNMP profile is revoked")
        return profile

    def _sensor(self, public_id: uuid.UUID, site: Site) -> Sensor:
        sensor = self._session.scalar(select(Sensor).where(Sensor.public_id == public_id))
        if sensor is None or sensor.site_id != site.id:
            raise SiteValidationError("sensor_invalid", "The sensor does not exist in this site")
        if sensor.status == "revoked":
            raise SiteConflictError("sensor_revoked", "The sensor is revoked")
        return sensor

    def create(self, body: NetworkDeviceCreate, actor: Actor) -> NetworkDeviceDetail:
        session = self._session
        site = self._site(body.site_id)
        if site.status != "active":
            raise SiteConflictError("site_not_active", "The site is not active")
        self._check_address(site, body.management_address)
        profile = self._profile(body.profile_id, site) if body.profile_id else None
        sensor = self._sensor(body.sensor_id, site) if body.sensor_id else None
        asset_id = None
        if body.asset_id is not None:
            asset = session.scalar(select(Asset).where(Asset.public_id == body.asset_id))
            if asset is None or asset.site_id != site.id:
                raise SiteValidationError("asset_invalid", "The asset does not exist in this site")
            asset_id = asset.id
        device = NetworkDevice(
            public_id=uuid.uuid4(),
            site_id=site.id,
            name=body.name,
            management_address=body.management_address,
            snmp_port=body.snmp_port,
            profile_id=profile.id if profile else None,
            sensor_id=sensor.id if sensor else None,
            asset_id=asset_id,
            monitoring_enabled=body.monitoring_enabled,
            created_by=actor.name,
        )
        try:
            with session.begin_nested():
                session.add(device)
                session.flush()
        except IntegrityError as exc:
            raise SiteConflictError(
                "network_device_exists",
                "A device with this management address already exists in the site",
            ) from exc
        link_device_asset(session, device)
        audit_service.record(
            session,
            actor,
            "network_device_created",
            target_type="network_device",
            target_id=device.public_id,
            details={
                "site_id": str(site.public_id),
                "management_address": device.management_address,
                "profile_id": str(profile.public_id) if profile else None,
                "sensor_id": str(sensor.public_id) if sensor else None,
                "monitoring_enabled": device.monitoring_enabled,
            },
            commit=False,
        )
        session.commit()
        return self.get(device.public_id)

    def _locked(self, public_id: uuid.UUID, version: int) -> NetworkDevice:
        device = self.row(public_id, lock=True)
        if device.status != "active":
            raise SiteConflictError("network_device_archived", "The device is archived")
        if device.version != version:
            raise SiteConflictError(
                "network_device_conflict",
                "The device changed since it was read",
                [{"current_version": device.version}],
            )
        return device

    def update(
        self, public_id: uuid.UUID, body: NetworkDeviceUpdate, actor: Actor
    ) -> NetworkDeviceDetail:
        session = self._session
        device = self._locked(public_id, body.version)
        site = session.get(Site, device.site_id)
        assert site is not None  # noqa: S101  (FK RESTRICT)
        changed: list[str] = []
        reassigned = False
        if body.name is not None and body.name != device.name:
            device.name = body.name
            changed.append("name")
        if body.snmp_port is not None and body.snmp_port != device.snmp_port:
            device.snmp_port = body.snmp_port
            changed.append("snmp_port")
            reassigned = True
        if body.clear_profile and body.profile_id is not None:
            raise SiteValidationError(
                "network_device_invalid", "profile_id and clear_profile are exclusive"
            )
        if body.clear_sensor and body.sensor_id is not None:
            raise SiteValidationError(
                "network_device_invalid", "sensor_id and clear_sensor are exclusive"
            )
        if body.clear_profile and device.profile_id is not None:
            device.profile_id = None
            changed.append("profile")
            reassigned = True
        elif body.profile_id is not None:
            profile = self._profile(body.profile_id, site)
            if profile.id != device.profile_id:
                device.profile_id = profile.id
                changed.append("profile")
                reassigned = True
        if body.clear_sensor and device.sensor_id is not None:
            device.sensor_id = None
            changed.append("sensor")
            reassigned = True
        elif body.sensor_id is not None:
            sensor = self._sensor(body.sensor_id, site)
            if sensor.id != device.sensor_id:
                device.sensor_id = sensor.id
                changed.append("sensor")
                reassigned = True
        if body.monitoring_enabled is not None and (
            body.monitoring_enabled != device.monitoring_enabled
        ):
            device.monitoring_enabled = body.monitoring_enabled
            changed.append("monitoring_enabled")
            if body.monitoring_enabled:
                # Reactivar la monitorización es una decisión explícita del admin: levanta la
                # pausa automática y da al equipo una oportunidad completa de nuevo.
                network_jobs.clear_pause(device)
        if not changed:
            return self.get(public_id)
        if reassigned:
            # Una consulta abierta se creó con el perfil, sensor o puerto anteriores: se
            # cancela para no entregar la credencial antigua ni consultar con datos viejos.
            network_jobs.cancel_device_polls(session, device.id, "reassigned")
        device.version += 1
        audit_service.record(
            session,
            actor,
            "network_device_updated",
            target_type="network_device",
            target_id=device.public_id,
            details={"changed": changed},
            commit=False,
        )
        session.commit()
        return self.get(public_id)

    def archive(
        self, public_id: uuid.UUID, body: NetworkDeviceArchive, actor: Actor
    ) -> NetworkDeviceDetail:
        session = self._session
        device = self._locked(public_id, body.version)
        network_jobs.cancel_device_polls(session, device.id, "archived")
        now = datetime.now(UTC)
        device.status = "archived"
        device.monitoring_enabled = False
        device.archived_at = now
        device.archived_by = actor.name
        device.archive_reason = body.reason
        device.version += 1
        audit_service.record(
            session,
            actor,
            "network_device_archived",
            target_type="network_device",
            target_id=device.public_id,
            details={"reason": body.reason},
            commit=False,
        )
        session.commit()
        return self.get(public_id)

    # --- consultas -----------------------------------------------------------------------------

    def _poll_read(self, poll: NetworkDevicePoll, device: NetworkDevice) -> NetworkPollRead:
        session = self._session
        site = session.get(Site, poll.site_id)
        sensor = session.get(Sensor, poll.sensor_id) if poll.sensor_id else None
        job_public = (
            session.scalar(select(SensorJob.public_id).where(SensorJob.id == poll.sensor_job_id))
            if poll.sensor_job_id
            else None
        )
        assert site is not None  # noqa: S101
        counts = dict(poll.counts or {})
        counts.setdefault("records", poll.records_received)
        return NetworkPollRead(
            poll_id=poll.public_id,
            device_id=device.public_id,
            site_id=site.public_id,
            sensor_id=sensor.public_id if sensor else None,
            sensor_name=sensor.name if sensor else None,
            sensor_job_id=job_public,
            status=poll.status,
            trigger=poll.trigger,
            requested_by=poll.requested_by,
            snmp_version=poll.snmp_version,
            modules_requested=list(poll.modules_requested or []),
            modules=dict(poll.modules or {}),
            error_code=poll.error_code,
            error_message=network_jobs.safe_error_message(poll.error_code, poll.error_message),
            counts=PollCounts(**counts),
            changes=PollChanges(**(poll.changes or {})),
            created_at=poll.created_at,
            started_at=poll.started_at,
            finished_at=poll.finished_at,
        )

    def polls(self, public_id: uuid.UUID, limit: int, offset: int) -> NetworkPollList:
        device = self.row(public_id)
        base = select(NetworkDevicePoll).where(NetworkDevicePoll.device_id == device.id)
        total = int(self._session.scalar(select(func.count()).select_from(base.subquery())) or 0)
        rows = self._session.scalars(
            base.order_by(NetworkDevicePoll.created_at.desc(), NetworkDevicePoll.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return NetworkPollList(
            items=[self._poll_read(p, device) for p in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def request_poll(self, public_id: uuid.UUID, actor: Actor) -> NetworkPollRead:
        device = self.row(public_id, lock=True)
        poll = network_jobs.create_poll(self._session, self._settings, device, actor)
        return self._poll_read(poll, device)

    def compatibility_check(self, public_id: uuid.UUID, actor: Actor) -> NetworkPollRead:
        """Consulta mínima (solo el grupo system) para verificar que el equipo tiene SNMP
        utilizable con el perfil asignado, sin recorrer tablas grandes. Su resultado fija
        snmp_status como cualquier consulta."""
        device = self.row(public_id, lock=True)
        poll = network_jobs.create_poll(
            self._session, self._settings, device, actor, trigger="check", modules=["system"]
        )
        return self._poll_read(poll, device)

    def resume_monitoring(
        self, public_id: uuid.UUID, body: NetworkDeviceResume, actor: Actor
    ) -> NetworkDeviceDetail:
        session = self._session
        device = self._locked(public_id, body.version)
        if device.monitoring_paused_at is None:
            return self.get(public_id)
        reason = device.monitoring_pause_reason
        network_jobs.clear_pause(device)
        device.version += 1
        audit_service.record(
            session,
            actor,
            "network_monitoring_resumed",
            target_type="network_device",
            target_id=device.public_id,
            details={"reason": "manual", "paused_reason": reason},
            commit=False,
        )
        session.commit()
        return self.get(public_id)

    def cancel_poll(self, poll_public: uuid.UUID, actor: Actor) -> NetworkPollRead:
        session = self._session
        poll = session.scalar(
            select(NetworkDevicePoll)
            .where(NetworkDevicePoll.public_id == poll_public)
            .with_for_update()
        )
        if poll is None:
            raise NetworkPollNotFoundError("Network poll not found")
        network_jobs.request_poll_cancel(session, poll, actor)
        session.refresh(poll)
        device = session.get(NetworkDevice, poll.device_id)
        assert device is not None  # noqa: S101
        return self._poll_read(poll, device)

    # --- inventario --------------------------------------------------------------------------

    def interfaces(
        self,
        public_id: uuid.UUID,
        *,
        oper_status: str | None,
        port_kind: str | None,
        q: str | None,
        include_absent: bool,
        limit: int,
        offset: int,
    ) -> NetworkInterfaceList:
        session = self._session
        device = self.row(public_id)
        query = select(NetworkInterface).where(NetworkInterface.device_id == device.id)
        if not include_absent:
            query = query.where(NetworkInterface.present)
        if oper_status is not None:
            query = query.where(NetworkInterface.oper_status == oper_status)
        if port_kind is not None:
            query = query.where(NetworkInterface.port_kind == port_kind)
        if q:
            pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            query = query.where(
                or_(
                    NetworkInterface.if_name.ilike(pattern, escape="\\"),
                    NetworkInterface.if_descr.ilike(pattern, escape="\\"),
                    NetworkInterface.if_alias.ilike(pattern, escape="\\"),
                )
            )
        total = int(session.scalar(select(func.count()).select_from(query.subquery())) or 0)
        rows = session.scalars(
            query.order_by(NetworkInterface.if_index, NetworkInterface.id)
            .limit(limit)
            .offset(offset)
        ).all()
        present = {
            i.if_index: i
            for i in session.scalars(
                select(NetworkInterface).where(
                    NetworkInterface.device_id == device.id, NetworkInterface.present
                )
            )
        }
        members: dict[int, int] = defaultdict(int)
        for interface in present.values():
            if interface.lag_parent_if_index is not None:
                members[interface.lag_parent_if_index] += 1
        vlans: dict[int, tuple[list[int], list[int]]] = defaultdict(lambda: ([], []))
        for interface_id, vlan_id, tagged in session.execute(
            select(
                NetworkVlanMembership.interface_id,
                NetworkVlanMembership.vlan_id,
                NetworkVlanMembership.tagged,
            )
            .where(
                NetworkVlanMembership.interface_id.in_([r.id for r in rows]),
                NetworkVlanMembership.present,
            )
            .order_by(NetworkVlanMembership.vlan_id)
        ):
            vlans[interface_id][1 if tagged else 0].append(int(vlan_id))
        source = evidence_source("interfaces")
        items = []
        for row in rows:
            untagged, tagged_list = vlans.get(row.id, ([], []))
            parent = (
                present.get(row.lag_parent_if_index)
                if row.lag_parent_if_index is not None
                else None
            )
            items.append(
                NetworkInterfaceRead(
                    interface_id=row.public_id,
                    if_index=row.if_index,
                    name=_interface_name(row),
                    if_name=row.if_name,
                    if_descr=row.if_descr,
                    if_alias=row.if_alias,
                    if_type=row.if_type,
                    port_kind=row.port_kind,
                    mac=row.mac,
                    admin_status=row.admin_status,
                    oper_status=row.oper_status,
                    speed_mbps=row.speed_mbps,
                    mtu=row.mtu,
                    in_octets=row.in_octets,
                    out_octets=row.out_octets,
                    counters_hc=row.counters_hc,
                    in_errors=row.in_errors,
                    out_errors=row.out_errors,
                    in_discards=row.in_discards,
                    out_discards=row.out_discards,
                    counters_at=row.counters_at,
                    bridge_port=row.bridge_port,
                    pvid=row.pvid,
                    untagged_vlans=untagged,
                    tagged_vlans=tagged_list,
                    is_trunk=row.is_trunk,
                    lag_parent=_interface_ref(parent),
                    lag_members=members.get(row.if_index, 0) if row.present else 0,
                    mac_count=row.mac_count,
                    neighbor_count=row.neighbor_count,
                    present=row.present,
                    first_seen_at=row.first_seen_at,
                    last_seen_at=row.last_seen_at,
                    evidence_source=source,
                )
            )
        return NetworkInterfaceList(items=items, total=total, limit=limit, offset=offset)

    def neighbors(
        self,
        public_id: uuid.UUID,
        *,
        protocol: str | None,
        include_absent: bool,
        limit: int,
        offset: int,
    ) -> NetworkNeighborList:
        session = self._session
        device = self.row(public_id)
        query = select(NetworkNeighbor).where(NetworkNeighbor.device_id == device.id)
        if not include_absent:
            query = query.where(NetworkNeighbor.present)
        if protocol is not None:
            query = query.where(NetworkNeighbor.protocol == protocol)
        total = int(session.scalar(select(func.count()).select_from(query.subquery())) or 0)
        rows = session.scalars(
            query.order_by(
                NetworkNeighbor.protocol,
                NetworkNeighbor.local_port_label,
                NetworkNeighbor.id,
            )
            .limit(limit)
            .offset(offset)
        ).all()
        interfaces = {
            i.id: i
            for i in session.scalars(
                select(NetworkInterface).where(
                    NetworkInterface.id.in_({r.interface_id for r in rows if r.interface_id})
                )
            )
        }
        # Solo equipos del MISMO site (apply.py ya lo garantiza; aquí se vuelve a filtrar).
        remotes = {
            d.id: d
            for d in session.scalars(
                select(NetworkDevice).where(
                    NetworkDevice.id.in_({r.remote_device_id for r in rows if r.remote_device_id}),
                    NetworkDevice.site_id == device.site_id,
                )
            )
        }
        sensors = dict(
            session.execute(
                select(Sensor.id, Sensor.public_id).where(
                    Sensor.id.in_({r.sensor_id for r in rows if r.sensor_id})
                )
            ).all()
        )
        items = []
        for row in rows:
            remote = remotes.get(row.remote_device_id) if row.remote_device_id else None
            items.append(
                NetworkNeighborRead(
                    neighbor_id=row.public_id,
                    protocol=row.protocol,
                    local_interface=_interface_ref(
                        interfaces.get(row.interface_id) if row.interface_id else None
                    ),
                    local_port_label=row.local_port_label,
                    local_port_match=row.local_port_match,
                    remote_chassis_id=row.remote_chassis_id,
                    remote_chassis_id_subtype=row.remote_chassis_id_subtype,
                    remote_port_id=row.remote_port_id,
                    remote_port_id_subtype=row.remote_port_id_subtype,
                    remote_port_descr=row.remote_port_descr,
                    remote_sys_name=row.remote_sys_name,
                    remote_sys_descr=row.remote_sys_descr,
                    remote_platform=row.remote_platform,
                    remote_software=row.remote_software,
                    remote_mgmt_address=row.remote_mgmt_address,
                    remote_capabilities=list(row.remote_capabilities or []),
                    remote_native_vlan=row.remote_native_vlan,
                    remote_device=(
                        DeviceRef(device_id=remote.public_id, display_name=_display_name(remote))
                        if remote is not None
                        else None
                    ),
                    remote_match_basis=(row.remote_match_basis if remote is not None else None),
                    reciprocal=row.reciprocal,
                    assessment="reported_by_device",
                    present=row.present,
                    first_seen_at=row.first_seen_at,
                    last_seen_at=row.last_seen_at,
                    sensor_id=sensors.get(row.sensor_id) if row.sensor_id else None,
                    evidence_source=evidence_source(row.protocol),
                )
            )
        return NetworkNeighborList(items=items, total=total, limit=limit, offset=offset)

    def vlans(self, public_id: uuid.UUID, include_absent: bool) -> NetworkVlanList:
        session = self._session
        device = self.row(public_id)
        query = select(NetworkVlan).where(NetworkVlan.device_id == device.id)
        if not include_absent:
            query = query.where(NetworkVlan.present)
        rows = session.scalars(query.order_by(NetworkVlan.vlan_id)).all()
        ports: dict[tuple[int, bool], int] = {}
        for vlan_id, tagged, total in session.execute(
            select(NetworkVlanMembership.vlan_id, NetworkVlanMembership.tagged, func.count())
            .where(NetworkVlanMembership.device_id == device.id, NetworkVlanMembership.present)
            .group_by(NetworkVlanMembership.vlan_id, NetworkVlanMembership.tagged)
        ):
            ports[(int(vlan_id), bool(tagged))] = int(total)
        return NetworkVlanList(
            items=[
                NetworkVlanRead(
                    vlan_id=row.vlan_id,
                    name=row.name,
                    source=row.source,
                    untagged_ports=ports.get((row.vlan_id, False), 0),
                    tagged_ports=ports.get((row.vlan_id, True), 0),
                    present=row.present,
                    first_seen_at=row.first_seen_at,
                    last_seen_at=row.last_seen_at,
                )
                for row in rows
            ]
        )

    def _mac_reads(
        self, rows: Sequence[NetworkMacEntry]
    ) -> list[tuple[NetworkMacEntry, NetworkMacEntryRead]]:
        session = self._session
        interfaces = {
            i.id: i
            for i in session.scalars(
                select(NetworkInterface).where(
                    NetworkInterface.id.in_({r.interface_id for r in rows if r.interface_id})
                )
            )
        }
        # Activo con esa MAC en el MISMO site de la entrada; si hay varios no se elige ninguno.
        assets: dict[tuple[int, str], list[Asset]] = defaultdict(list)
        macs = {r.mac for r in rows}
        if macs:
            for asset in session.scalars(
                select(Asset).where(Asset.mac_address.in_(macs), Asset.archived_at.is_(None))
            ):
                if asset.mac_address:
                    assets[(asset.site_id, asset.mac_address)].append(asset)
        out = []
        for row in rows:
            interface = interfaces.get(row.interface_id) if row.interface_id else None
            matches = assets.get((row.site_id, row.mac), [])
            linked = matches[0] if len(matches) == 1 else None
            out.append(
                (
                    row,
                    NetworkMacEntryRead(
                        entry_id=row.public_id,
                        mac=row.mac,
                        vlan_id=row.vlan_id,
                        vlan_source=row.vlan_source,
                        bridge_port=row.bridge_port,
                        interface=_interface_ref(interface),
                        status=row.status,
                        location=row.location,
                        location_reason=row.location_reason,
                        port_mac_count=interface.mac_count if interface is not None else 0,
                        asset=(
                            AssetRef(asset_id=linked.public_id, display_name=linked.display_name)
                            if linked is not None
                            else None
                        ),
                        present=row.present,
                        first_seen_at=row.first_seen_at,
                        last_seen_at=row.last_seen_at,
                    ),
                )
            )
        return out

    def mac_entries(
        self,
        public_id: uuid.UUID,
        *,
        vlan_id: int | None,
        interface_id: uuid.UUID | None,
        mac: str | None,
        include_absent: bool,
        limit: int,
        offset: int,
    ) -> NetworkMacEntryList:
        session = self._session
        device = self.row(public_id)
        query = select(NetworkMacEntry).where(NetworkMacEntry.device_id == device.id)
        if not include_absent:
            query = query.where(NetworkMacEntry.present)
        if vlan_id is not None:
            query = query.where(NetworkMacEntry.vlan_id == vlan_id)
        if interface_id is not None:
            internal = session.scalar(
                select(NetworkInterface.id).where(
                    NetworkInterface.public_id == interface_id,
                    NetworkInterface.device_id == device.id,
                )
            )
            query = query.where(NetworkMacEntry.interface_id == (internal or -1))
        if mac is not None:
            normalized = normalize_mac(mac)
            if normalized is None:
                raise SiteValidationError("mac_invalid", "Invalid MAC address")
            query = query.where(NetworkMacEntry.mac == normalized)
        total = int(session.scalar(select(func.count()).select_from(query.subquery())) or 0)
        rows = session.scalars(
            query.order_by(NetworkMacEntry.mac, NetworkMacEntry.fdb_key, NetworkMacEntry.id)
            .limit(limit)
            .offset(offset)
        ).all()
        modules = device.last_modules or {}
        return NetworkMacEntryList(
            items=[read for _, read in self._mac_reads(rows)],
            total=total,
            limit=limit,
            offset=offset,
            # El sensor recortó la tabla (SNMP_MAX_ROWS_PER_TABLE) o la consulta fue parcial.
            truncated=modules.get("bridge") == "partial",
        )

    def mac_locations(self, mac: str, site_id: int | None) -> MacLocationList:
        """Dónde informan los switches haber aprendido una MAC, por site y sin fusionar."""
        session = self._session
        normalized = normalize_mac(mac)
        if normalized is None:
            raise SiteValidationError("mac_invalid", "Invalid MAC address")
        query = select(NetworkMacEntry).where(
            NetworkMacEntry.mac == normalized, NetworkMacEntry.present
        )
        if site_id is not None:
            query = query.where(NetworkMacEntry.site_id == site_id)
        rows = session.scalars(query.order_by(NetworkMacEntry.id).limit(200)).all()
        devices = {
            d.id: d
            for d in session.scalars(
                select(NetworkDevice).where(NetworkDevice.id.in_({r.device_id for r in rows}))
            )
        }
        sites = site_refs(session)
        rank = {"edge_candidate": 0, "unknown": 1, "uplink_or_shared": 2}
        items = []
        for row, read in self._mac_reads(rows):
            device = devices[row.device_id]
            site = sites[row.site_id]
            items.append(
                MacLocationRead(
                    **read.model_dump(),
                    device=DeviceRef(
                        device_id=device.public_id, display_name=_display_name(device)
                    ),
                    site_id=site.public_id,
                    site_name=site.name,
                )
            )
        items.sort(key=lambda item: (rank.get(item.location, 3), item.port_mac_count))
        return MacLocationList(mac=normalized, items=items)

    def candidates(self, site_id: int | None, limit: int) -> NetworkCandidateList:
        """Activos descubiertos (6A) que parecen infraestructura y aún no están registrados.

        Solo una sugerencia: registrar el equipo y asignarle un perfil sigue siendo una
        decisión del admin (no hay credenciales automáticas ni pruebas de contraseñas).
        """
        session = self._session
        registered = select(NetworkDevice.id).where(
            NetworkDevice.site_id == Asset.site_id,
            NetworkDevice.management_address == Asset.primary_ip,
        )
        query = select(Asset).where(
            Asset.device_type.in_(CANDIDATE_DEVICE_TYPES),
            Asset.archived_at.is_(None),
            ~registered.exists(),
        )
        if site_id is not None:
            query = query.where(Asset.site_id == site_id)
        rows = session.scalars(
            query.order_by(Asset.last_network_seen_at.desc().nullslast(), Asset.id).limit(limit)
        ).all()
        sites = site_refs(session)
        return NetworkCandidateList(
            items=[
                NetworkCandidate(
                    asset_id=row.public_id,
                    site_id=sites[row.site_id].public_id,
                    site_name=sites[row.site_id].name,
                    address=row.primary_ip,
                    hostname=row.device_name or row.hostname or row.reverse_dns,
                    device_type=row.device_type,
                    device_type_reason=row.device_type_reason,
                    mac_address=row.mac_address,
                    last_seen_at=row.last_network_seen_at,
                )
                for row in rows
            ]
        )
