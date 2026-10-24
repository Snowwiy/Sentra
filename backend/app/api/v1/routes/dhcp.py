"""Fuentes DHCP, leases e identidad de activos (Fase 6E.2, docs/dhcp-identity.md).

Lectura (fuentes, leases, identidad e historial de identidad): monitoring:read, como el resto
del inventario. Declarar, cambiar o borrar fuentes, importar leases y pedir una lectura a un
sensor: dhcp:manage, solo admin, auditado. Ningún endpoint acepta ni devuelve rutas de fichero.
"""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from app.api.auth import READ, actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.dhcp.service import DhcpService
from app.schemas.dhcp import (
    AssetIdentityHistory,
    AssetIdentityRead,
    DhcpImportIn,
    DhcpImportResult,
    DhcpLeaseList,
    DhcpReadRequested,
    DhcpSourceCreate,
    DhcpSourceList,
    DhcpSourceRead,
    DhcpSourceUpdate,
    LeaseMatch,
)
from app.services.auth_service import AuthContext

router = APIRouter(prefix="/dhcp", tags=["dhcp"], responses=error_responses(401, 403))
identity_router = APIRouter(prefix="/assets", tags=["assets"], responses=error_responses(401, 403))
Manager = Annotated[AuthContext, Depends(require_permission(Permission.DHCP_MANAGE))]
SiteFilter = Annotated[UUID | None, Query(description="Site filter")]


def get_service(session: DbSession, settings: AppSettings) -> DhcpService:
    return DhcpService(session, settings)


Service = Annotated[DhcpService, Depends(get_service)]


@router.get("/sources", response_model=DhcpSourceList, dependencies=[READ])
def list_sources(service: Service, site_id: SiteFilter = None) -> DhcpSourceList:
    """Fuentes DHCP declaradas (todas o las de un site) con su último estado."""
    return service.list_sources(site_id)


@router.post(
    "/sources",
    response_model=DhcpSourceRead,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(404, 409, 422),
)
def create_source(body: DhcpSourceCreate, service: Service, ctx: Manager) -> DhcpSourceRead:
    """Declara una fuente: `lease_import` (fichero que sube un admin) o `sensor_file` (nombre
    de una entrada `[[dhcp_lease_files]]` del sensor.toml de un sensor del mismo site)."""
    return service.create_source(body, actor(ctx))


@router.get(
    "/sources/{dhcp_source_id}",
    response_model=DhcpSourceRead,
    dependencies=[READ],
    responses=error_responses(404),
)
def get_source(dhcp_source_id: UUID, service: Service) -> DhcpSourceRead:
    return service.get_source(dhcp_source_id)


@router.patch(
    "/sources/{dhcp_source_id}",
    response_model=DhcpSourceRead,
    responses=error_responses(404, 409, 422),
)
def update_source(
    dhcp_source_id: UUID, body: DhcpSourceUpdate, service: Service, ctx: Manager
) -> DhcpSourceRead:
    """Habilitar/deshabilitar, formato e intervalo de lectura. 409 dhcp_source_conflict con
    versión obsoleta."""
    return service.update_source(dhcp_source_id, body, actor(ctx))


@router.delete(
    "/sources/{dhcp_source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=error_responses(404, 409),
)
def delete_source(
    dhcp_source_id: UUID,
    service: Service,
    ctx: Manager,
    version: Annotated[int, Query(ge=1)],
) -> None:
    """Borra la fuente y sus leases; los activos que tomaban nombre de ella se reidentifican
    sin él. Auditado (dhcp_source_deleted)."""
    service.delete_source(dhcp_source_id, version, actor(ctx))


@router.post(
    "/sources/{dhcp_source_id}/import",
    response_model=DhcpImportResult,
    responses=error_responses(404, 409, 413, 422),
)
def import_leases(
    dhcp_source_id: UUID, body: DhcpImportIn, service: Service, ctx: Manager
) -> DhcpImportResult:
    """Importa el texto de un fichero de leases en una fuente `lease_import`. 422
    dhcp_file_too_large por encima de DHCP_IMPORT_MAX_KB y dhcp_format_invalid si no se puede
    leer con el formato de la fuente."""
    return service.import_leases(dhcp_source_id, body, actor(ctx))


@router.post(
    "/sources/{dhcp_source_id}/read",
    response_model=DhcpReadRequested,
    status_code=status.HTTP_202_ACCEPTED,
    responses=error_responses(404, 409),
)
def request_read(dhcp_source_id: UUID, service: Service, ctx: Manager) -> DhcpReadRequested:
    """Pide al sensor que lea ahora el fichero de una fuente `sensor_file` (job
    dhcp_leases). 409 dhcp_sensor_unavailable si el sensor no está activo o es < 0.6.0."""
    return service.request_read(dhcp_source_id, actor(ctx))


@router.get(
    "/leases",
    response_model=DhcpLeaseList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_leases(
    service: Service,
    site_id: SiteFilter = None,
    source_id: UUID | None = None,
    match: LeaseMatch | None = None,
    search: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> DhcpLeaseList:
    """Leases guardados con su asociación (`match`) a un activo. `search`: IP o MAC exactas
    o parte del hostname."""
    return service.list_leases(site_id, source_id, match, search, limit, offset)


@identity_router.get(
    "/{asset_id}/identity",
    response_model=AssetIdentityRead,
    dependencies=[READ],
    responses=error_responses(404),
)
def asset_identity(asset_id: UUID, service: Service) -> AssetIdentityRead:
    """Identidad del activo con su evidencia: nombres observados, leases, Wi-Fi y, si no
    tiene nombre, los motivos (`unidentified_reasons`)."""
    return service.asset_identity(asset_id)


@identity_router.get(
    "/{asset_id}/identity/history",
    response_model=AssetIdentityHistory,
    dependencies=[READ],
    responses=error_responses(404),
)
def asset_identity_history(
    asset_id: UUID,
    service: Service,
    before_id: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    field: Literal["name", "label", "ip", "mac", "vendor", "device_type"] | None = None,
) -> AssetIdentityHistory:
    """Cambios de nombre, etiqueta, IP, MAC, fabricante y tipo, del más reciente al más
    antiguo. Paginación por cursor (`before_id` = `next_before_id`)."""
    return service.identity_history(asset_id, before_id, limit, field)
