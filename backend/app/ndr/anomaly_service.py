"""Anomalías NDR en el dashboard (Fase 7E.2): consulta, triaje y asociaciones IP-MAC.

Fase 7E.4: cada anomalía lleva el activo atribuido y, en el detalle, su correlación: dónde
ve un switch la MAC del sujeto (FDB por SNMP), la detección NET-NDR-001 que generó y los
incidentes que la incluyen. Todo se lee en el momento: no se copia nada a la anomalía.
"""

import ipaddress
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, aliased

from app.core.exceptions import (
    NdrAnomalyNotFoundError,
    NdrConflictError,
    NdrValidationError,
    NotFoundError,
    SiteValidationError,
)
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.incident import Incident, IncidentDetection
from app.models.ndr import ACTIVE_ANOMALY_STATUSES, NdrAnomaly, NdrIpMacBinding
from app.models.network import NetworkDevice, NetworkInterface, NetworkMacEntry
from app.models.site import Sensor, Site
from app.ndr.response import suggestions
from app.ndr.rules import RULES, NdrRule, rules_by_id
from app.schemas.case_operations import (
    ControlType,
    Direction,
    NetworkControlCreate,
    NetworkControlRead,
)
from app.schemas.ndr import (
    NdrAnomalyContext,
    NdrAnomalyList,
    NdrAnomalyRead,
    NdrAnomalyStatusUpdate,
    NdrAssetRef,
    NdrBindingList,
    NdrBindingRead,
    NdrControlRequest,
    NdrDetectionRef,
    NdrIncidentRef,
    NdrMitreRead,
    NdrResponsePlan,
    NdrResponseSuggestion,
    NdrRuleList,
    NdrRuleRead,
    NdrSwitchLocation,
)
from app.services import audit_service
from app.services.audit_service import Actor
from app.services.case_operations_service import CaseOperationsService, get_control
from app.services.incident_service import Operator

DETECTION_RULE_ID = "NET-NDR-001"
MAX_CONTEXT_ITEMS = 10


def _address(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        raise SiteValidationError("invalid_ip", "Invalid IP address") from exc


def resolve_asset(session: Session, public_id: UUID | None) -> int | None:
    """Filtro `asset_id` de la API → id interno. 404 si el activo no existe."""
    if public_id is None:
        return None
    found = session.scalar(select(Asset.id).where(Asset.public_id == public_id))
    if found is None:
        raise NotFoundError("Asset not found")
    return int(found)


def mitre_of(rule: NdrRule | None) -> NdrMitreRead | None:
    if rule is None or rule.mitre is None:
        return None
    return NdrMitreRead(
        tactic=rule.mitre.tactic,
        technique=rule.mitre.technique,
        subtechnique=rule.mitre.subtechnique,
    )


_RULES = rules_by_id()


def rule_list() -> NdrRuleList:
    return NdrRuleList(
        items=[
            NdrRuleRead(
                id=rule.id,
                version=rule.version,
                category=rule.category,
                title=rule.title,
                description=rule.description,
                why=rule.why,
                recommendations=list(rule.recommendations),
                verdicts=dict(rule.verdicts),
                mitre=mitre_of(rule),
            )
            for rule in RULES
        ]
    )


class NdrAnomalyService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def _read(
        self, row: NdrAnomaly, site: Site, sensor: Sensor | None, asset: Asset | None = None
    ) -> NdrAnomalyRead:
        return NdrAnomalyRead(
            anomaly_id=row.public_id,
            site_id=site.public_id,
            site_name=site.name,
            sensor_id=sensor.public_id if sensor else None,
            sensor_name=sensor.name if sensor else None,
            rule_id=row.rule_id,
            rule_version=row.rule_version,
            category=row.category,
            title=row.title,
            verdict=row.verdict,
            severity=row.severity,
            status=row.status,
            subject_ip=row.subject_ip,
            subject_mac=row.subject_mac,
            summary=row.summary,
            evidence=dict(row.evidence or {}),
            occurrences=row.occurrences,
            first_seen=row.first_seen,
            last_seen=row.last_seen,
            status_by=row.status_by,
            status_at=row.status_at,
            status_note=row.status_note,
            asset_id=asset.public_id if asset else None,
            asset_name=asset.display_name if asset else None,
            mitre=mitre_of(_RULES.get(row.rule_id)),
        )

    def list(
        self,
        *,
        site_id: int | None,
        status: str | None,
        active: bool | None,
        verdict: str | None,
        category: str | None,
        rule_id: str | None,
        ip: str | None,
        limit: int,
        offset: int,
        asset_id: int | None = None,
    ) -> NdrAnomalyList:
        sensor = aliased(Sensor)
        conditions: list[Any] = []
        if site_id is not None:
            conditions.append(NdrAnomaly.site_id == site_id)
        if status is not None:
            conditions.append(NdrAnomaly.status == status)
        if active is not None:
            in_active = NdrAnomaly.status.in_(ACTIVE_ANOMALY_STATUSES)
            conditions.append(in_active if active else ~in_active)
        if verdict is not None:
            conditions.append(NdrAnomaly.verdict == verdict)
        if category is not None:
            conditions.append(NdrAnomaly.category == category)
        if rule_id is not None:
            conditions.append(NdrAnomaly.rule_id == rule_id)
        if asset_id is not None:
            conditions.append(NdrAnomaly.asset_id == asset_id)
        if ip is not None:
            address = _address(ip)
            conditions.append(
                or_(
                    NdrAnomaly.subject_ip == address,
                    NdrAnomaly.evidence.contains({"ip": address}),
                )
            )
        total = int(
            self._session.scalar(select(func.count()).select_from(NdrAnomaly).where(*conditions))
            or 0
        )
        rows = self._session.execute(
            select(NdrAnomaly, Site, sensor, Asset)
            .join(Site, Site.id == NdrAnomaly.site_id)
            .outerjoin(sensor, sensor.id == NdrAnomaly.sensor_id)
            .outerjoin(Asset, Asset.id == NdrAnomaly.asset_id)
            .where(*conditions)
            .order_by(NdrAnomaly.last_seen.desc(), NdrAnomaly.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return NdrAnomalyList(items=[self._read(*row) for row in rows], total=total)

    def _require(self, public_id: UUID, lock: bool = False) -> NdrAnomaly:
        query = select(NdrAnomaly).where(NdrAnomaly.public_id == public_id)
        if lock:
            query = query.with_for_update()
        row = self._session.scalar(query)
        if row is None:
            raise NdrAnomalyNotFoundError("NDR anomaly not found")
        return row

    def get(self, public_id: UUID) -> NdrAnomalyRead:
        row = self._require(public_id)
        site = self._session.get(Site, row.site_id)
        assert site is not None  # noqa: S101  (FK RESTRICT)
        sensor = self._session.get(Sensor, row.sensor_id) if row.sensor_id else None
        asset = self._session.get(Asset, row.asset_id) if row.asset_id else None
        result = self._read(row, site, sensor, asset)
        result.context = self._context(row, asset)
        return result

    def _context(self, row: NdrAnomaly, asset: Asset | None) -> NdrAnomalyContext:
        mac = row.subject_mac or (asset.mac_address if asset else None)
        locations: list[NdrSwitchLocation] = []
        if mac:
            entries = self._session.execute(
                select(NetworkMacEntry, NetworkDevice, NetworkInterface)
                .join(NetworkDevice, NetworkDevice.id == NetworkMacEntry.device_id)
                .outerjoin(NetworkInterface, NetworkInterface.id == NetworkMacEntry.interface_id)
                .where(
                    NetworkMacEntry.site_id == row.site_id,
                    NetworkMacEntry.mac == mac,
                    NetworkMacEntry.present.is_(True),
                )
                .order_by(NetworkMacEntry.last_seen_at.desc())
                .limit(MAX_CONTEXT_ITEMS)
            ).all()
            locations = [
                NdrSwitchLocation(
                    device_id=device.public_id,
                    device_name=device.name or device.sys_name or device.management_address,
                    interface=(iface.if_name or iface.if_descr) if iface else None,
                    vlan=entry.vlan_id,
                    location=entry.location,
                    last_seen=entry.last_seen_at,
                )
                for entry, device, iface in entries
            ]
        detections: list[Detection] = []
        if row.asset_id is not None:
            detections = list(
                self._session.scalars(
                    select(Detection)
                    .where(
                        Detection.asset_id == row.asset_id,
                        Detection.rule_id == DETECTION_RULE_ID,
                        Detection.dedup_key == f"ndr:{row.public_id}",
                    )
                    .order_by(Detection.id.desc())
                    .limit(MAX_CONTEXT_ITEMS)
                )
            )
        incidents: list[Incident] = []
        if detections:
            incidents = list(
                self._session.scalars(
                    select(Incident)
                    .join(IncidentDetection, IncidentDetection.incident_id == Incident.id)
                    .where(IncidentDetection.detection_id.in_([d.id for d in detections]))
                    .distinct()
                    .order_by(Incident.id.desc())
                    .limit(MAX_CONTEXT_ITEMS)
                )
            )
        return NdrAnomalyContext(
            asset=(
                NdrAssetRef(
                    asset_id=asset.public_id,
                    name=asset.display_name,
                    primary_ip=asset.primary_ip,
                    mac_address=asset.mac_address,
                )
                if asset
                else None
            ),
            switch_locations=locations,
            detections=[
                NdrDetectionRef(
                    detection_id=d.public_id,
                    rule_id=d.rule_id,
                    severity=str(d.severity),
                    confidence=str(d.confidence),
                    status=str(d.status),
                )
                for d in detections
            ],
            incidents=[
                NdrIncidentRef(
                    incident_id=i.public_id, number=i.number, title=i.title, status=str(i.status)
                )
                for i in incidents
            ],
        )

    def response_plan(self, public_id: UUID) -> NdrResponsePlan:
        """Fase 7E.7: sugerencias derivadas de la evidencia. No crea ni ejecuta nada."""
        row = self._require(public_id)
        context = self._context(row, None)
        return NdrResponsePlan(
            anomaly_id=row.public_id,
            applied_by_sentra=False,
            note=(
                "Sentra no aplica cambios en la red: cada control se registra como solicitud en"
                " un incidente, un admin la aprueba o rechaza y se aplica fuera de Sentra"
                " siguiendo las instrucciones."
            ),
            incidents=context.incidents,
            suggestions=[
                NdrResponseSuggestion(
                    suggestion_id=s.suggestion_id,
                    kind=s.kind,
                    title=s.title,
                    rationale=s.rationale,
                    instructions=s.instructions,
                    control_type=s.control_type,
                    target=s.target,
                    direction=s.direction,
                    playbook_key=s.playbook_key,
                )
                for s in suggestions(row, row.asset_id is not None)
            ],
        )

    def request_control(
        self, public_id: UUID, body: NdrControlRequest, operator: Operator
    ) -> NetworkControlRead:
        """Fase 7E.7: registra en el incidente la solicitud de una sugerencia del plan.

        Reutiliza el flujo de la Fase 7A.6 (pendiente de aprobación, auditado, visible en el
        incidente). El alcance es el site de la anomalía: el control se pediría en su red.
        """
        row = self._require(public_id)
        plan = {s.suggestion_id: s for s in suggestions(row, row.asset_id is not None)}
        chosen = plan.get(body.suggestion_id)
        if chosen is None or chosen.kind != "network_control" or chosen.control_type is None:
            raise NdrValidationError(
                "ndr_suggestion_invalid", "The suggestion is not a network control of this plan"
            )
        site = self._session.get(Site, row.site_id)
        assert site is not None  # noqa: S101  (FK RESTRICT)
        payload = NetworkControlCreate(
            control_type=cast(ControlType, chosen.control_type),
            target=dict(chosen.target or {}),
            direction=cast(Direction | None, chosen.direction),
            site_id=site.public_id,
            justification=(
                f"{body.justification.strip()}\n\nOrigen: anomalía NDR {row.rule_id}"
                f" ({row.public_id}), sugerencia {chosen.suggestion_id}."
            )[:5000],
            expires_at=body.expires_at,
        )
        control = CaseOperationsService(self._session, operator).request_control(
            body.incident_id, payload
        )
        return get_control(self._session, control.public_id)

    def set_status(
        self, public_id: UUID, body: NdrAnomalyStatusUpdate, actor: Actor
    ) -> NdrAnomalyRead:
        row = self._require(public_id, lock=True)
        if row.status in ("resolved", "false_positive"):
            raise NdrConflictError("ndr_anomaly_closed", "The anomaly is already closed")
        if body.status in ("resolved", "false_positive") and not body.note:
            raise NdrConflictError(
                "ndr_note_required", "Closing an anomaly requires a note explaining why"
            )
        previous = row.status
        row.status = body.status
        row.status_by = actor.name[:64]
        row.status_at = datetime.now(UTC)
        row.status_note = body.note
        audit_service.record(
            self._session,
            actor,
            "ndr_anomaly_status_changed",
            target_type="ndr_anomaly",
            target_id=row.public_id,
            details={
                "rule_id": row.rule_id,
                "from": previous,
                "to": body.status,
                "note": body.note,
            },
            commit=False,
        )
        self._session.commit()
        return self.get(public_id)

    def bindings(
        self,
        *,
        site_id: int | None,
        ip: str | None,
        mac: str | None,
        gateway: bool | None,
        limit: int,
        offset: int,
    ) -> NdrBindingList:
        conditions: list[Any] = []
        if site_id is not None:
            conditions.append(NdrIpMacBinding.site_id == site_id)
        if ip is not None:
            conditions.append(NdrIpMacBinding.ip == _address(ip))
        if mac is not None:
            conditions.append(NdrIpMacBinding.mac == mac)
        if gateway is not None:
            conditions.append(NdrIpMacBinding.gateway.is_(gateway))
        total = int(
            self._session.scalar(
                select(func.count()).select_from(NdrIpMacBinding).where(*conditions)
            )
            or 0
        )
        rows = self._session.execute(
            select(NdrIpMacBinding, Site.public_id)
            .join(Site, Site.id == NdrIpMacBinding.site_id)
            .where(*conditions)
            .order_by(NdrIpMacBinding.last_seen.desc(), NdrIpMacBinding.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return NdrBindingList(
            items=[
                NdrBindingRead(
                    site_id=site_public,
                    vlan=row.vlan_key or None,
                    ip=row.ip,
                    mac=row.mac,
                    source=row.source,
                    gateway=row.gateway,
                    count=row.count,
                    first_seen=row.first_seen,
                    last_seen=row.last_seen,
                )
                for row, site_public in rows
            ],
            total=total,
        )
