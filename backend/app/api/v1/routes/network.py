"""Infraestructura de red: SNMP, LLDP, CDP y switches (Fase 6B, docs/snmp-network-intelligence.md).

Permisos:
- perfiles de credenciales SNMP: snmp_credentials:manage (solo admin). Los secretos son de
  solo escritura: entran en el cuerpo de create/rotate y ninguna respuesta los devuelve;
- leer equipos, inventario e historial: monitoring:read;
- registrar, editar y archivar equipos: network:manage (solo admin);
- pedir o cancelar una consulta SNMP: network:poll (analista y admin).

Los intentos de escritura sin permiso quedan auditados (require_permission).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from app.api.auth import READ, actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.network import (
    DeviceClassification,
    MacLocationList,
    MonitoringStatus,
    NeighborProtocol,
    NetworkCandidateList,
    NetworkDeviceArchive,
    NetworkDeviceCreate,
    NetworkDeviceDetail,
    NetworkDeviceList,
    NetworkDeviceResume,
    NetworkDeviceUpdate,
    NetworkInterfaceList,
    NetworkMacEntryList,
    NetworkNeighborList,
    NetworkPollList,
    NetworkPollRead,
    NetworkVlanList,
    OperStatus,
    PortKind,
    SnmpProfileCreate,
    SnmpProfileList,
    SnmpProfileRead,
    SnmpProfileRevoke,
    SnmpProfileRotate,
    SnmpProfileUpdate,
)
from app.services.auth_service import AuthContext
from app.services.network_device_service import NetworkDeviceService
from app.services.site_service import resolve_site
from app.services.snmp_profile_service import SnmpProfileService

router = APIRouter(prefix="/network", tags=["network"], responses=error_responses(401, 403))
CredentialManager = Annotated[
    AuthContext, Depends(require_permission(Permission.SNMP_CREDENTIALS_MANAGE))
]
Manager = Annotated[AuthContext, Depends(require_permission(Permission.NETWORK_MANAGE))]
Poller = Annotated[AuthContext, Depends(require_permission(Permission.NETWORK_POLL))]


def get_profile_service(session: DbSession, settings: AppSettings) -> SnmpProfileService:
    return SnmpProfileService(session, settings)


def get_device_service(session: DbSession, settings: AppSettings) -> NetworkDeviceService:
    return NetworkDeviceService(session, settings)


Profiles = Annotated[SnmpProfileService, Depends(get_profile_service)]
Devices = Annotated[NetworkDeviceService, Depends(get_device_service)]
SiteFilter = Annotated[UUID | None, Query()]
Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Search = Annotated[str | None, Query(min_length=1, max_length=100)]


# --- perfiles de credenciales SNMP ----------------------------------------------------------


@router.get("/snmp-profiles", response_model=SnmpProfileList, responses=error_responses(404))
def list_profiles(
    service: Profiles,
    session: DbSession,
    _: CredentialManager,
    site_id: SiteFilter = None,
    include_revoked: bool = False,
) -> SnmpProfileList:
    return service.list(resolve_site(session, site_id), include_revoked)


@router.post(
    "/snmp-profiles",
    response_model=SnmpProfileRead,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(404, 409),
)
def create_profile(
    body: SnmpProfileCreate, service: Profiles, ctx: CredentialManager
) -> SnmpProfileRead:
    """Los secretos se cifran antes de guardarse y nunca vuelven a salir por la API."""
    return service.create(body, actor(ctx))


@router.get(
    "/snmp-profiles/{profile_id}", response_model=SnmpProfileRead, responses=error_responses(404)
)
def get_profile(profile_id: UUID, service: Profiles, _: CredentialManager) -> SnmpProfileRead:
    return service.get(profile_id)


@router.patch(
    "/snmp-profiles/{profile_id}",
    response_model=SnmpProfileRead,
    responses=error_responses(404, 409),
)
def update_profile(
    profile_id: UUID, body: SnmpProfileUpdate, service: Profiles, ctx: CredentialManager
) -> SnmpProfileRead:
    return service.update(profile_id, body, actor(ctx))


@router.post(
    "/snmp-profiles/{profile_id}/rotate",
    response_model=SnmpProfileRead,
    responses=error_responses(404, 409),
)
def rotate_profile(
    profile_id: UUID, body: SnmpProfileRotate, service: Profiles, ctx: CredentialManager
) -> SnmpProfileRead:
    return service.rotate(profile_id, body, actor(ctx))


@router.post(
    "/snmp-profiles/{profile_id}/revoke",
    response_model=SnmpProfileRead,
    responses=error_responses(404, 409),
)
def revoke_profile(
    profile_id: UUID, body: SnmpProfileRevoke, service: Profiles, ctx: CredentialManager
) -> SnmpProfileRead:
    """Destruye el secreto cifrado y cancela las consultas abiertas que lo usaban."""
    return service.revoke(profile_id, body, actor(ctx))


# --- equipos ------------------------------------------------------------------------------


@router.get(
    "/devices",
    response_model=NetworkDeviceList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_devices(
    service: Devices,
    session: DbSession,
    site_id: SiteFilter = None,
    classification: DeviceClassification | None = None,
    monitoring_status: MonitoringStatus | None = None,
    q: Search = None,
    include_archived: bool = False,
    limit: Limit = 50,
    offset: Offset = 0,
) -> NetworkDeviceList:
    return service.list_devices(
        site_id=resolve_site(session, site_id),
        classification=classification,
        status=monitoring_status,
        q=q,
        include_archived=include_archived,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/devices",
    response_model=NetworkDeviceDetail,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(404, 409),
)
def create_device(body: NetworkDeviceCreate, service: Devices, ctx: Manager) -> NetworkDeviceDetail:
    return service.create(body, actor(ctx))


@router.get(
    "/candidates",
    response_model=NetworkCandidateList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_candidates(
    service: Devices, session: DbSession, site_id: SiteFilter = None, limit: Limit = 50
) -> NetworkCandidateList:
    return service.candidates(resolve_site(session, site_id), limit)


@router.get(
    "/mac-locations",
    response_model=MacLocationList,
    dependencies=[READ],
    responses=error_responses(404),
)
def mac_locations(
    service: Devices,
    session: DbSession,
    mac: Annotated[str, Query(min_length=12, max_length=17)],
    site_id: SiteFilter = None,
) -> MacLocationList:
    return service.mac_locations(mac, resolve_site(session, site_id))


@router.get(
    "/devices/{device_id}",
    response_model=NetworkDeviceDetail,
    dependencies=[READ],
    responses=error_responses(404),
)
def get_device(device_id: UUID, service: Devices) -> NetworkDeviceDetail:
    return service.get(device_id)


@router.patch(
    "/devices/{device_id}", response_model=NetworkDeviceDetail, responses=error_responses(404, 409)
)
def update_device(
    device_id: UUID, body: NetworkDeviceUpdate, service: Devices, ctx: Manager
) -> NetworkDeviceDetail:
    return service.update(device_id, body, actor(ctx))


@router.post(
    "/devices/{device_id}/archive",
    response_model=NetworkDeviceDetail,
    responses=error_responses(404, 409),
)
def archive_device(
    device_id: UUID, body: NetworkDeviceArchive, service: Devices, ctx: Manager
) -> NetworkDeviceDetail:
    return service.archive(device_id, body, actor(ctx))


@router.get(
    "/devices/{device_id}/interfaces",
    response_model=NetworkInterfaceList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_interfaces(
    device_id: UUID,
    service: Devices,
    oper_status: OperStatus | None = None,
    port_kind: PortKind | None = None,
    q: Search = None,
    include_absent: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Offset = 0,
) -> NetworkInterfaceList:
    return service.interfaces(
        device_id,
        oper_status=oper_status,
        port_kind=port_kind,
        q=q,
        include_absent=include_absent,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/devices/{device_id}/neighbors",
    response_model=NetworkNeighborList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_neighbors(
    device_id: UUID,
    service: Devices,
    protocol: NeighborProtocol | None = None,
    include_absent: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Offset = 0,
) -> NetworkNeighborList:
    return service.neighbors(
        device_id, protocol=protocol, include_absent=include_absent, limit=limit, offset=offset
    )


@router.get(
    "/devices/{device_id}/vlans",
    response_model=NetworkVlanList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_vlans(device_id: UUID, service: Devices, include_absent: bool = False) -> NetworkVlanList:
    return service.vlans(device_id, include_absent)


@router.get(
    "/devices/{device_id}/mac-entries",
    response_model=NetworkMacEntryList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_mac_entries(
    device_id: UUID,
    service: Devices,
    vlan_id: Annotated[int | None, Query(ge=1, le=4094)] = None,
    interface_id: UUID | None = None,
    mac: Annotated[str | None, Query(min_length=12, max_length=17)] = None,
    include_absent: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Offset = 0,
) -> NetworkMacEntryList:
    return service.mac_entries(
        device_id,
        vlan_id=vlan_id,
        interface_id=interface_id,
        mac=mac,
        include_absent=include_absent,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/devices/{device_id}/polls",
    response_model=NetworkPollList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_polls(
    device_id: UUID, service: Devices, limit: Limit = 50, offset: Offset = 0
) -> NetworkPollList:
    return service.polls(device_id, limit, offset)


@router.post(
    "/devices/{device_id}/polls",
    response_model=NetworkPollRead,
    status_code=status.HTTP_202_ACCEPTED,
    responses=error_responses(404, 409),
)
def request_poll(device_id: UUID, service: Devices, ctx: Poller) -> NetworkPollRead:
    """Encola una consulta SNMP de solo lectura que ejecutará el sensor del equipo.

    409 network_poll_unavailable lista los bloqueos (sin perfil, sensor offline...) y 409
    network_poll_busy indica que ya hay una consulta en cola o en curso.
    """
    return service.request_poll(device_id, actor(ctx))


@router.post(
    "/devices/{device_id}/compatibility-check",
    response_model=NetworkPollRead,
    status_code=status.HTTP_202_ACCEPTED,
    responses=error_responses(404, 409),
)
def compatibility_check(device_id: UUID, service: Devices, ctx: Poller) -> NetworkPollRead:
    """Fase 6D: verifica si el equipo tiene SNMP utilizable con su perfil (solo el grupo
    system). El resultado fija `snmp_status`; mismos errores 409 que una consulta."""
    return service.compatibility_check(device_id, actor(ctx))


@router.post(
    "/devices/{device_id}/monitoring/resume",
    response_model=NetworkDeviceDetail,
    responses=error_responses(404, 409),
)
def resume_monitoring(
    device_id: UUID, body: NetworkDeviceResume, service: Devices, ctx: Manager
) -> NetworkDeviceDetail:
    """Fase 6D: levanta la pausa automática de las consultas periódicas (auditado)."""
    return service.resume_monitoring(device_id, body, actor(ctx))


@router.post(
    "/polls/{poll_id}/cancel",
    response_model=NetworkPollRead,
    responses=error_responses(404, 409),
)
def cancel_poll(poll_id: UUID, service: Devices, ctx: Poller) -> NetworkPollRead:
    return service.cancel_poll(poll_id, actor(ctx))
