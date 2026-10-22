"""Motor de topología de red (Fase 6D, docs/topology-engine.md).

Lectura del grafo, enlaces, nodos y estado: monitoring:read (todos los roles). Reconstruir a
demanda y revisar enlaces: topology:manage (solo admin); los intentos sin permiso quedan
auditados por require_permission. Nada aquí consulta la red: el grafo se deriva de la
evidencia ya guardada (LLDP/CDP, tablas MAC, WLAN, gateways de agentes).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.auth import READ, actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.exceptions import SiteValidationError
from app.core.permissions import Permission
from app.models.topology import LINK_KINDS
from app.schemas.topology import (
    LinkConfidence,
    LinkKind,
    ReviewState,
    TopologyBuild,
    TopologyGraph,
    TopologyLinkDetail,
    TopologyLinkList,
    TopologyNodeDetail,
    TopologyRebuildRequest,
    TopologyReviewUpdate,
    TopologyStatus,
)
from app.services.auth_service import AuthContext
from app.topology.service import TopologyService

router = APIRouter(prefix="/topology", tags=["topology"], responses=error_responses(401, 403))
Manager = Annotated[AuthContext, Depends(require_permission(Permission.TOPOLOGY_MANAGE))]


def get_topology_service(session: DbSession, settings: AppSettings) -> TopologyService:
    return TopologyService(session, settings)


Topology = Annotated[TopologyService, Depends(get_topology_service)]
SiteFilter = Annotated[UUID | None, Query(description="Site; without it, the default site")]
Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]


def _kinds(value: str | None) -> set[str] | None:
    if value is None:
        return None
    kinds = {part.strip() for part in value.split(",") if part.strip()}
    unknown = kinds - set(LINK_KINDS)
    if unknown:
        raise SiteValidationError(
            "topology_invalid_kind",
            "Unknown link kind",
            [{"allowed": ",".join(LINK_KINDS)}],
        )
    return kinds or None


@router.get(
    "/graph", response_model=TopologyGraph, dependencies=[READ], responses=error_responses(404)
)
def graph(
    service: Topology,
    site_id: SiteFilter = None,
    kinds: Annotated[
        str | None,
        Query(max_length=100, description="Comma separated link kinds; all by default"),
    ] = None,
    include_absent: bool = False,
    include_rejected: bool = False,
    device_type: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    q: Annotated[
        str | None, Query(min_length=1, max_length=100, description="IP, name, label or MAC")
    ] = None,
) -> TopologyGraph:
    """Grafo del site: nodos compuestos desde el inventario, enlaces derivados y grupos por
    red autorizada. Con `q` o `device_type` se devuelven los nodos que coinciden, sus enlaces
    y los extremos de esos enlaces. Por encima de TOPOLOGY_MAX_NODES / TOPOLOGY_MAX_LINKS se
    recorta (`truncated=true`) priorizando nodos con enlaces e infraestructura."""
    parsed = _kinds(kinds)
    return service.graph(
        service.site(site_id),
        kinds=parsed,
        include_absent=include_absent,
        include_rejected=include_rejected,
        device_type=device_type,
        q=q,
    )


@router.get(
    "/links", response_model=TopologyLinkList, dependencies=[READ], responses=error_responses(404)
)
def list_links(
    service: Topology,
    site_id: SiteFilter = None,
    kind: LinkKind | None = None,
    confidence: LinkConfidence | None = None,
    node: Annotated[str | None, Query(min_length=1, max_length=96)] = None,
    present: bool = True,
    review_state: ReviewState | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> TopologyLinkList:
    return service.list_links(
        service.site(site_id),
        kind=kind,
        confidence=confidence,
        node=node,
        present=present,
        review_state=review_state,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/links/{link_id}",
    response_model=TopologyLinkDetail,
    dependencies=[READ],
    responses=error_responses(404),
)
def get_link(link_id: str, service: Topology, site_id: SiteFilter = None) -> TopologyLinkDetail:
    """Detalle con evidencia acotada. Con `site_id`, un enlace de otro site es 404.

    `link_id` es texto y no UUID a propósito: uno mal formado responde el mismo 404 que uno
    inexistente o de otro site (anti-IDOR), no un 422 que confirme el formato."""
    site = service.site(site_id).id if site_id is not None else None
    return service.get_link(link_id[:64], site)


@router.patch(
    "/links/{link_id}/review",
    response_model=TopologyLinkDetail,
    responses=error_responses(404, 409),
)
def review_link(
    link_id: str,
    body: TopologyReviewUpdate,
    service: Topology,
    ctx: Manager,
    site_id: SiteFilter = None,
) -> TopologyLinkDetail:
    """Aceptar, rechazar o volver a sin revisar. No cambia kind ni confidence. 409
    topology_link_conflict si `version` no es la actual. Auditado (topology_link_reviewed)."""
    site = service.site(site_id).id if site_id is not None else None
    return service.review(link_id[:64], site, body, actor(ctx))


@router.get(
    "/nodes/{node_id}",
    response_model=TopologyNodeDetail,
    dependencies=[READ],
    responses=error_responses(404),
)
def get_node(node_id: str, service: Topology, site_id: SiteFilter = None) -> TopologyNodeDetail:
    """Nodo del site con sus enlaces presentes (máx. 200). Una clave mal formada, de otro
    site o de algo archivado responde el mismo 404 (topology_node_not_found)."""
    return service.node_detail(service.site(site_id), node_id)


@router.post("/rebuild", response_model=TopologyBuild, responses=error_responses(404, 409))
def rebuild(body: TopologyRebuildRequest, service: Topology, ctx: Manager) -> TopologyBuild:
    """Reconstruye en la petición (acotado por TOPOLOGY_MAX_LINKS). 409
    topology_build_running si ya hay una en curso para el site. Auditado (topology_rebuilt)."""
    return service.rebuild(service.site(body.site_id), "manual", actor(ctx))


@router.get(
    "/status", response_model=TopologyStatus, dependencies=[READ], responses=error_responses(404)
)
def status(service: Topology, site_id: SiteFilter = None) -> TopologyStatus:
    """Última reconstrucción, enlaces presentes por clase y qué evidencia hay disponible, para
    que la UI pueda explicar por qué el grafo está vacío."""
    return service.status(service.site(site_id))
