"""Sites y sus redes autorizadas (Fase 5F, docs/sites.md).

Leer es monitoring:read (sin secretos). Crear, editar, deshabilitar, archivar, borrar y
gestionar redes exige sites:manage (solo admin): las redes de un site son exactamente lo que
sus sensores pueden escanear.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.auth import READ, actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.site import (
    SiteArchive,
    SiteCreate,
    SiteList,
    SiteNetworkCreate,
    SiteNetworkList,
    SiteNetworkRead,
    SiteNetworkUpdate,
    SiteRead,
    SiteUpdate,
    SiteVersion,
)
from app.services.auth_service import AuthContext
from app.services.site_service import SiteService

router = APIRouter(prefix="/sites", tags=["sites"], responses=error_responses(401, 403))
Manager = Annotated[AuthContext, Depends(require_permission(Permission.SITES_MANAGE))]


def get_site_service(session: DbSession, settings: AppSettings) -> SiteService:
    return SiteService(session, settings)


Service = Annotated[SiteService, Depends(get_site_service)]


@router.get("", response_model=SiteList, dependencies=[READ])
def list_sites(service: Service) -> SiteList:
    return service.list()


@router.post(
    "",
    response_model=SiteRead,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(409),
)
def create_site(body: SiteCreate, service: Service, ctx: Manager) -> SiteRead:
    return service.create(body, actor(ctx))


@router.get(
    "/{site_id}", response_model=SiteRead, dependencies=[READ], responses=error_responses(404)
)
def get_site(site_id: UUID, service: Service) -> SiteRead:
    return service.get(site_id)


@router.patch("/{site_id}", response_model=SiteRead, responses=error_responses(404, 409))
def update_site(site_id: UUID, body: SiteUpdate, service: Service, ctx: Manager) -> SiteRead:
    return service.update(site_id, body, actor(ctx))


@router.post("/{site_id}/archive", response_model=SiteRead, responses=error_responses(404, 409))
def archive_site(site_id: UUID, body: SiteArchive, service: Service, ctx: Manager) -> SiteRead:
    """Retira el site sin borrar nada: sus activos, alertas e incidentes siguen consultables y
    sus sensores dejan de recibir trabajo."""
    return service.archive(site_id, body, actor(ctx))


@router.post("/{site_id}/restore", response_model=SiteRead, responses=error_responses(404, 409))
def restore_site(site_id: UUID, body: SiteVersion, service: Service, ctx: Manager) -> SiteRead:
    return service.restore(site_id, body.version, actor(ctx))


@router.delete(
    "/{site_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses=error_responses(404, 409),
)
def delete_site(
    site_id: UUID, version: Annotated[int, Query(ge=1)], service: Service, ctx: Manager
) -> Response:
    """Solo un site sin ningún dato asociado (409 site_has_data con los recuentos si no)."""
    service.delete(site_id, version, actor(ctx))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{site_id}/networks",
    response_model=SiteNetworkList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_networks(site_id: UUID, service: Service) -> SiteNetworkList:
    return service.networks(site_id)


@router.post(
    "/{site_id}/networks",
    response_model=SiteNetworkRead,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(404, 409),
)
def add_network(
    site_id: UUID, body: SiteNetworkCreate, service: Service, ctx: Manager
) -> SiteNetworkRead:
    return service.add_network(site_id, body, actor(ctx))


@router.patch(
    "/{site_id}/networks/{network_id}",
    response_model=SiteNetworkRead,
    responses=error_responses(404, 409),
)
def update_network(
    site_id: UUID, network_id: UUID, body: SiteNetworkUpdate, service: Service, ctx: Manager
) -> SiteNetworkRead:
    return service.update_network(site_id, network_id, body, actor(ctx))


@router.delete(
    "/{site_id}/networks/{network_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses=error_responses(404),
)
def remove_network(site_id: UUID, network_id: UUID, service: Service, ctx: Manager) -> Response:
    service.remove_network(site_id, network_id, actor(ctx))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
