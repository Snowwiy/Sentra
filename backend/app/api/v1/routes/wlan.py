"""Inventario Wi-Fi / AP / WLAN (Fase 6C.3, docs/wlan-discovery.md).

Bajo el mismo prefijo que la infraestructura de la Fase 6B (/api/v1/network) y con sus
mismos permisos, sin roles nuevos:
- leer vista general, APs, BSS, SSIDs, clientes e historial: monitoring:read;
- cambiar la autorización de un AP o BSS y vincular o desvincular un AP: network:manage
  (solo admin). Cada cambio se audita; los intentos sin permiso también (require_permission).

Nada aquí ejecuta acciones sobre la red: no hay escaneo, desautenticación, SET ni comandos.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.auth import READ, actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.exceptions import SiteValidationError
from app.core.permissions import Permission
from app.discovery.probes import normalize_mac
from app.schemas.wlan import (
    ApReportedStatus,
    AuthorizationStatus,
    Band,
    ClientState,
    IdentityConfidence,
    Protection,
    WlanAccessPointDetail,
    WlanAccessPointList,
    WlanAuthorizationUpdate,
    WlanBssList,
    WlanBssRead,
    WlanClientList,
    WlanClientRead,
    WlanConfidence,
    WlanFreshness,
    WlanLinkRequest,
    WlanObservationList,
    WlanOverview,
    WlanSource,
    WlanSsidList,
    WlanUnlinkRequest,
)
from app.services.auth_service import AuthContext
from app.services.site_service import resolve_site
from app.services.wlan_service import WlanService

router = APIRouter(prefix="/network/wlan", tags=["network"], responses=error_responses(401, 403))
Manager = Annotated[AuthContext, Depends(require_permission(Permission.NETWORK_MANAGE))]


def get_wlan_service(session: DbSession, settings: AppSettings) -> WlanService:
    return WlanService(session, settings)


Wlan = Annotated[WlanService, Depends(get_wlan_service)]
SiteFilter = Annotated[UUID | None, Query()]
Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Search = Annotated[str | None, Query(min_length=1, max_length=100)]
Ssid = Annotated[str | None, Query(min_length=1, max_length=64)]
Mac = Annotated[str | None, Query(min_length=12, max_length=17)]


def _mac(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = normalize_mac(value)
    if normalized is None:
        raise SiteValidationError("invalid_mac", "Invalid MAC address")
    return normalized


@router.get(
    "/overview", response_model=WlanOverview, dependencies=[READ], responses=error_responses(404)
)
def overview(service: Wlan, session: DbSession, site_id: SiteFilter = None) -> WlanOverview:
    """Resumen con indicadores de disponibilidad de datos por fuente (SNMP y agentes)."""
    return service.overview(resolve_site(session, site_id), site_id)


@router.get(
    "/access-points",
    response_model=WlanAccessPointList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_access_points(
    service: Wlan,
    session: DbSession,
    site_id: SiteFilter = None,
    ssid: Ssid = None,
    band: Band | None = None,
    status: ApReportedStatus | None = None,
    authorization: AuthorizationStatus | None = None,
    freshness: WlanFreshness | None = None,
    present: bool | None = None,
    q: Search = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> WlanAccessPointList:
    return service.list_access_points(
        site_id=resolve_site(session, site_id),
        ssid=ssid,
        band=band,
        status=status,
        authorization=authorization,
        freshness=freshness,
        present=present,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/access-points/{access_point_id}",
    response_model=WlanAccessPointDetail,
    dependencies=[READ],
    responses=error_responses(404),
)
def get_access_point(access_point_id: UUID, service: Wlan) -> WlanAccessPointDetail:
    return service.get_access_point(access_point_id)


@router.get(
    "/access-points/{access_point_id}/observations",
    response_model=WlanObservationList,
    dependencies=[READ],
    responses=error_responses(404),
)
def access_point_observations(
    access_point_id: UUID, service: Wlan, limit: Limit = 50, offset: Offset = 0
) -> WlanObservationList:
    return service.access_point_observations(access_point_id, limit, offset)


@router.post(
    "/access-points/{access_point_id}/authorization",
    response_model=WlanAccessPointDetail,
    responses=error_responses(404, 409),
)
def set_access_point_authorization(
    access_point_id: UUID, body: WlanAuthorizationUpdate, service: Wlan, ctx: Manager
) -> WlanAccessPointDetail:
    """authorized / external (vecino) / unknown. Nunca se marca "rogue" automáticamente."""
    return service.set_ap_authorization(access_point_id, body, actor(ctx))


@router.post(
    "/access-points/{access_point_id}/link",
    response_model=WlanAccessPointDetail,
    responses=error_responses(404, 409),
)
def link_access_point(
    access_point_id: UUID, body: WlanLinkRequest, service: Wlan, ctx: Manager
) -> WlanAccessPointDetail:
    """Solo con evidencia (IP de gestión o MAC iguales) y dentro del mismo site."""
    return service.link(access_point_id, body, actor(ctx))


@router.post(
    "/access-points/{access_point_id}/unlink",
    response_model=WlanAccessPointDetail,
    responses=error_responses(404),
)
def unlink_access_point(
    access_point_id: UUID, body: WlanUnlinkRequest, service: Wlan, ctx: Manager
) -> WlanAccessPointDetail:
    return service.unlink(access_point_id, body, actor(ctx))


@router.get("/bss", response_model=WlanBssList, dependencies=[READ], responses=error_responses(404))
def list_bss(
    service: Wlan,
    session: DbSession,
    site_id: SiteFilter = None,
    ssid: Ssid = None,
    band: Band | None = None,
    authorization: AuthorizationStatus | None = None,
    source: WlanSource | None = None,
    confidence: WlanConfidence | None = None,
    protection: Protection | None = None,
    access_point_id: UUID | None = None,
    freshness: WlanFreshness | None = None,
    insecure: bool | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> WlanBssList:
    return service.list_bss(
        site_id=resolve_site(session, site_id),
        ssid=ssid,
        band=band,
        authorization=authorization,
        source=source,
        confidence=confidence,
        protection=protection,
        access_point_id=access_point_id,
        freshness=freshness,
        insecure=insecure,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/bss/{bss_id}", response_model=WlanBssRead, dependencies=[READ], responses=error_responses(404)
)
def get_bss(bss_id: UUID, service: Wlan) -> WlanBssRead:
    return service.get_bss(bss_id)


@router.get(
    "/bss/{bss_id}/observations",
    response_model=WlanObservationList,
    dependencies=[READ],
    responses=error_responses(404),
)
def bss_observations(
    bss_id: UUID, service: Wlan, limit: Limit = 50, offset: Offset = 0
) -> WlanObservationList:
    return service.bss_observations(bss_id, limit, offset)


@router.post(
    "/bss/{bss_id}/authorization",
    response_model=WlanBssRead,
    responses=error_responses(404, 409),
)
def set_bss_authorization(
    bss_id: UUID, body: WlanAuthorizationUpdate, service: Wlan, ctx: Manager
) -> WlanBssRead:
    return service.set_bss_authorization(bss_id, body, actor(ctx))


@router.get(
    "/ssids", response_model=WlanSsidList, dependencies=[READ], responses=error_responses(404)
)
def list_ssids(
    service: Wlan,
    session: DbSession,
    site_id: SiteFilter = None,
    band: Band | None = None,
    q: Search = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> WlanSsidList:
    return service.list_ssids(
        site_id=resolve_site(session, site_id), band=band, q=q, limit=limit, offset=offset
    )


@router.get(
    "/clients", response_model=WlanClientList, dependencies=[READ], responses=error_responses(404)
)
def list_clients(
    service: Wlan,
    session: DbSession,
    site_id: SiteFilter = None,
    ssid: Ssid = None,
    bssid: Mac = None,
    access_point_id: UUID | None = None,
    identity: IdentityConfidence | None = None,
    state: ClientState | None = None,
    present: bool | None = None,
    freshness: WlanFreshness | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> WlanClientList:
    return service.list_clients(
        site_id=resolve_site(session, site_id),
        ssid=ssid,
        bssid=_mac(bssid),
        access_point_id=access_point_id,
        identity=identity,
        state=state,
        present=present,
        freshness=freshness,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/clients/{client_id}",
    response_model=WlanClientRead,
    dependencies=[READ],
    responses=error_responses(404),
)
def get_client(client_id: UUID, service: Wlan) -> WlanClientRead:
    return service.get_client(client_id)


@router.get(
    "/clients/{client_id}/observations",
    response_model=WlanObservationList,
    dependencies=[READ],
    responses=error_responses(404),
)
def client_observations(
    client_id: UUID, service: Wlan, limit: Limit = 50, offset: Offset = 0
) -> WlanObservationList:
    """Historial del cliente: dónde y con qué fuente se vio (MAC privada incluida)."""
    return service.client_observations(client_id, limit, offset)
