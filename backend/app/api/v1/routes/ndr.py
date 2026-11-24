"""Network Detection & Response en el dashboard (Fase 7E, docs/fase-7e.md).

Permisos propios, distintos de monitoring:read:
- ndr:read (todos los roles): estado de la captura por sensor y agregados;
- ndr:evidence (analyst y admin): flujos y metadatos individuales (DNS, SNI, ARP, DHCP);
- ndr:triage (analyst y admin): reconocer, resolver o marcar como falso positivo una
  anomalía (Fase 7E.2). Auditado; cerrar exige una nota.
- ndr:manage (admin): aprobar qué interfaces captura un sensor. Auditado.

Nada aquí actúa sobre la red: no hay inyección, bloqueo ni escaneo; solo lectura de lo que
los sensores observaron de forma pasiva.
"""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.exceptions import SentraError, SiteValidationError
from app.core.permissions import Permission
from app.discovery.probes import normalize_mac
from app.ndr.anomaly_service import NdrAnomalyService, resolve_asset, rule_list
from app.ndr.service import NdrService
from app.schemas.case_operations import NetworkControlRead
from app.schemas.ndr import (
    AnomalyStatus,
    AnomalyVerdict,
    NdrAnomalyList,
    NdrAnomalyRead,
    NdrAnomalyStatusUpdate,
    NdrBindingList,
    NdrCaptureConfigRead,
    NdrCaptureConfigUpdate,
    NdrControlRequest,
    NdrFlowList,
    NdrObservationList,
    NdrOverview,
    NdrResponsePlan,
    NdrRuleList,
    NdrSensorList,
)
from app.services import audit_service
from app.services.auth_service import AuthContext
from app.services.incident_service import Operator
from app.services.site_service import resolve_site

router = APIRouter(prefix="/ndr", tags=["ndr"], responses=error_responses(401, 403))

NDR_READ = Depends(require_permission(Permission.NDR_READ))
NDR_EVIDENCE = Depends(require_permission(Permission.NDR_EVIDENCE))
Manager = Annotated[AuthContext, Depends(require_permission(Permission.NDR_MANAGE))]
Triage = Annotated[AuthContext, Depends(require_permission(Permission.NDR_TRIAGE))]
CaseManager = Annotated[AuthContext, Depends(require_permission(Permission.INCIDENTS_MANAGE))]


def get_ndr_service(session: DbSession, settings: AppSettings) -> NdrService:
    return NdrService(session, settings)


Ndr = Annotated[NdrService, Depends(get_ndr_service)]


def get_anomaly_service(session: DbSession) -> NdrAnomalyService:
    return NdrAnomalyService(session)


Anomalies = Annotated[NdrAnomalyService, Depends(get_anomaly_service)]
SiteFilter = Annotated[UUID | None, Query()]
Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
IpFilter = Annotated[str | None, Query(min_length=2, max_length=45)]


def _mac(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = normalize_mac(value)
    if normalized is None:
        raise SiteValidationError("invalid_mac", "Invalid MAC address")
    return normalized


@router.get(
    "/overview", response_model=NdrOverview, dependencies=[NDR_READ], responses=error_responses(404)
)
def overview(
    service: Ndr,
    session: DbSession,
    site_id: SiteFilter = None,
    hours: Annotated[int, Query(ge=1, le=168)] = 24,
) -> NdrOverview:
    return service.overview(resolve_site(session, site_id), hours)


@router.get(
    "/sensors",
    response_model=NdrSensorList,
    dependencies=[NDR_READ],
    responses=error_responses(404),
)
def list_sensors(service: Ndr, session: DbSession, site_id: SiteFilter = None) -> NdrSensorList:
    return service.list_sensors(resolve_site(session, site_id))


@router.put(
    "/sensors/{sensor_id}/config",
    response_model=NdrCaptureConfigRead,
    responses=error_responses(404, 409, 422),
)
def update_config(
    sensor_id: UUID, body: NdrCaptureConfigUpdate, service: Ndr, ctx: Manager
) -> NdrCaptureConfigRead:
    """Aprueba (o retira) la captura pasiva de un sensor. Habilitar exige el punto de
    observación y la confirmación expresa; el sensor la aplica en su siguiente heartbeat."""
    return service.update_config(sensor_id, body, actor(ctx))


@router.get(
    "/flows",
    response_model=NdrFlowList,
    dependencies=[NDR_EVIDENCE],
    responses=error_responses(404, 422),
)
def list_flows(
    service: Ndr,
    session: DbSession,
    site_id: SiteFilter = None,
    sensor_id: UUID | None = None,
    ip: IpFilter = None,
    port: Annotated[int | None, Query(ge=0, le=65_535)] = None,
    transport: Annotated[str | None, Query(pattern=r"^[a-z0-9]{1,8}$")] = None,
    flag: Literal["midstream", "asymmetric", "fragmented", "retransmissions", "no_handshake_reply"]
    | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> NdrFlowList:
    return service.list_flows(
        site_id=resolve_site(session, site_id),
        sensor_id=sensor_id,
        ip=ip,
        port=port,
        transport=transport,
        flag=flag,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/observations",
    response_model=NdrObservationList,
    dependencies=[NDR_EVIDENCE],
    responses=error_responses(404, 422),
)
def list_observations(
    service: Ndr,
    session: DbSession,
    kind: Literal["arp", "dns", "dhcp", "tls"] | None = None,
    site_id: SiteFilter = None,
    sensor_id: UUID | None = None,
    ip: IpFilter = None,
    mac: Annotated[str | None, Query(min_length=12, max_length=17)] = None,
    name: Annotated[str | None, Query(min_length=1, max_length=253)] = None,
    since: datetime | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> NdrObservationList:
    return service.list_observations(
        kind=kind,
        site_id=resolve_site(session, site_id),
        sensor_id=sensor_id,
        ip=ip,
        mac=_mac(mac),
        name=name,
        since=since,
        limit=limit,
        offset=offset,
    )


# --- Fase 7E.2: reglas, anomalías y asociaciones IP-MAC ------------------------------------


@router.get("/rules", response_model=NdrRuleList, dependencies=[NDR_READ])
def list_rules() -> NdrRuleList:
    """Catálogo de reglas NDR con los criterios de cada veredicto."""
    return rule_list()


@router.get(
    "/anomalies",
    response_model=NdrAnomalyList,
    dependencies=[NDR_READ],
    responses=error_responses(404, 422),
)
def list_anomalies(
    anomalies: Anomalies,
    session: DbSession,
    site_id: SiteFilter = None,
    status: AnomalyStatus | None = None,
    active: bool | None = None,
    verdict: AnomalyVerdict | None = None,
    category: Annotated[str | None, Query(pattern=r"^[a-z0-9_]{1,16}$")] = None,
    rule_id: Annotated[str | None, Query(pattern=r"^NDR-[A-Z0-9-]{1,20}$")] = None,
    ip: IpFilter = None,
    asset_id: UUID | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> NdrAnomalyList:
    return anomalies.list(
        asset_id=resolve_asset(session, asset_id),
        site_id=resolve_site(session, site_id),
        status=status,
        active=active,
        verdict=verdict,
        category=category,
        rule_id=rule_id,
        ip=ip,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/anomalies/{anomaly_id}",
    response_model=NdrAnomalyRead,
    dependencies=[NDR_READ],
    responses=error_responses(404),
)
def get_anomaly(anomaly_id: UUID, anomalies: Anomalies) -> NdrAnomalyRead:
    return anomalies.get(anomaly_id)


@router.post(
    "/anomalies/{anomaly_id}/status",
    response_model=NdrAnomalyRead,
    responses=error_responses(404, 409, 422),
)
def set_anomaly_status(
    anomaly_id: UUID, body: NdrAnomalyStatusUpdate, anomalies: Anomalies, ctx: Triage
) -> NdrAnomalyRead:
    return anomalies.set_status(anomaly_id, body, actor(ctx))


# --- Fase 7E.7: respuesta (sugerencias y solicitudes registradas, nunca acción en la red) ----


@router.get(
    "/anomalies/{anomaly_id}/response-plan",
    response_model=NdrResponsePlan,
    dependencies=[NDR_READ],
    responses=error_responses(404),
)
def anomaly_response_plan(anomaly_id: UUID, anomalies: Anomalies) -> NdrResponsePlan:
    """Controles y pasos sugeridos según la evidencia. Solo lectura: no crea nada."""
    return anomalies.response_plan(anomaly_id)


@router.post(
    "/anomalies/{anomaly_id}/network-controls",
    response_model=NetworkControlRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[NDR_READ],
    responses=error_responses(404, 409, 422),
)
def request_anomaly_control(
    anomaly_id: UUID,
    body: NdrControlRequest,
    anomalies: Anomalies,
    session: DbSession,
    ctx: CaseManager,
) -> NetworkControlRead:
    """Registra en un incidente la solicitud de control de una sugerencia del plan (queda
    pendiente de aprobación de un admin y se aplica FUERA de Sentra). Mismo permiso que pedir
    un control desde el incidente (incidents:manage)."""
    operator = Operator.from_context(ctx.user, ctx.client_ip, ctx.permissions)
    try:
        return anomalies.request_control(anomaly_id, body, operator)
    except SentraError as exc:
        session.rollback()
        audit_service.record(
            session,
            actor(ctx),
            "network_control_requested",
            audit_service.FAILURE,
            "ndr_anomaly",
            anomaly_id,
            details={"error": exc.code, "suggestion_id": body.suggestion_id},
        )
        raise


@router.get(
    "/bindings",
    response_model=NdrBindingList,
    dependencies=[NDR_EVIDENCE],
    responses=error_responses(404, 422),
)
def list_bindings(
    anomalies: Anomalies,
    session: DbSession,
    site_id: SiteFilter = None,
    ip: IpFilter = None,
    mac: Annotated[str | None, Query(min_length=12, max_length=17)] = None,
    gateway: bool | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> NdrBindingList:
    return anomalies.bindings(
        site_id=resolve_site(session, site_id),
        ip=ip,
        mac=_mac(mac),
        gateway=gateway,
        limit=limit,
        offset=offset,
    )
