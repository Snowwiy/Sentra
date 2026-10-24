"""Historial de topología y cambios de red (Fase 6E.1, docs/topology-history.md).

Lectura (snapshots, diff, cambios, historial, export): monitoring:read, como el grafo de 6D.
Revisar un cambio (confirmar o descartar): topology:manage, solo admin, auditado. Nada aquí
consulta la red: todo sale de los snapshots que guarda cada reconstrucción.
"""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

from app.api.auth import READ, actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.topology_history import (
    ChangeStatus,
    ChangeType,
    NetworkChangeList,
    NetworkChangeRead,
    NetworkChangeReview,
    TopologyDiff,
    TopologyHistory,
    TopologySnapshotDetail,
    TopologySnapshotList,
)
from app.services.auth_service import AuthContext
from app.topology.errors import TopologyHistoryNotFoundError
from app.topology.history_service import TopologyHistoryService
from app.topology.service import TopologyService, parse_node_id

router = APIRouter(prefix="/topology", tags=["topology"], responses=error_responses(401, 403))
Manager = Annotated[AuthContext, Depends(require_permission(Permission.TOPOLOGY_MANAGE))]
SiteFilter = Annotated[UUID | None, Query(description="Site; without it, the default site")]
Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Subnet = Annotated[str | None, Query(min_length=3, max_length=49, description="CIDR filter")]


def get_services(
    session: DbSession, settings: AppSettings
) -> tuple[TopologyService, TopologyHistoryService]:
    return TopologyService(session, settings), TopologyHistoryService(session, settings)


Services = Annotated[tuple[TopologyService, TopologyHistoryService], Depends(get_services)]


@router.get(
    "/snapshots",
    response_model=TopologySnapshotList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_snapshots(
    services: Services,
    site_id: SiteFilter = None,
    start: datetime | None = None,
    end: datetime | None = None,
    before_sequence: Annotated[int | None, Query(ge=1, le=2**31 - 1)] = None,
    limit: Limit = 50,
) -> TopologySnapshotList:
    """Estados distintos del grafo, del más reciente al más antiguo. Paginación por cursor
    (`before_sequence` = `next_before_sequence` de la página anterior)."""
    topology, history = services
    return history.list_snapshots(
        topology.site(site_id), start=start, end=end, limit=limit, before_sequence=before_sequence
    )


@router.get(
    "/snapshots/{snapshot_id}",
    response_model=TopologySnapshotDetail,
    dependencies=[READ],
    responses=error_responses(404),
)
def get_snapshot(
    snapshot_id: UUID, services: Services, site_id: SiteFilter = None
) -> TopologySnapshotDetail:
    topology, history = services
    return history.get_snapshot(topology.site(site_id), snapshot_id)


@router.get(
    "/diff", response_model=TopologyDiff, dependencies=[READ], responses=error_responses(404)
)
def diff(
    services: Services,
    site_id: SiteFilter = None,
    from_snapshot: UUID | None = None,
    to_snapshot: UUID | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    subnet: Subnet = None,
) -> TopologyDiff:
    """Diferencias entre dos estados (por id o por instante; sin destino, el estado actual).
    422 topology_diff_missing_from si falta el origen."""
    topology, history = services
    return history.diff(
        topology.site(site_id),
        from_snapshot=from_snapshot,
        to_snapshot=to_snapshot,
        from_time=from_time,
        to_time=to_time,
        subnet=subnet,
    )


@router.get(
    "/diff/export",
    dependencies=[READ],
    responses={
        **error_responses(404),
        200: {"content": {"application/json": {}, "text/csv": {}}},
    },
    response_class=Response,
)
def export_diff(
    services: Services,
    site_id: SiteFilter = None,
    from_snapshot: UUID | None = None,
    to_snapshot: UUID | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    subnet: Subnet = None,
    format: Literal["json", "csv"] = "json",
) -> Response:
    """Export del diff con su SHA-256 en X-Sentra-SHA256 (integridad verificable)."""
    topology, history = services
    result = history.diff(
        topology.site(site_id),
        from_snapshot=from_snapshot,
        to_snapshot=to_snapshot,
        from_time=from_time,
        to_time=to_time,
        subnet=subnet,
    )
    body, media, digest = history.export_diff(result, format)
    name = f"topology-diff-{result.from_snapshot.sequence}-{result.to_snapshot.sequence}.{format}"
    return Response(
        content=body,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Sentra-SHA256": digest,
            "Cache-Control": "no-store",
        },
    )


@router.get(
    "/changes",
    response_model=NetworkChangeList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_changes(
    services: Services,
    site_id: SiteFilter = None,
    change_type: ChangeType | None = None,
    status: ChangeStatus | None = None,
    subject: Annotated[str | None, Query(min_length=1, max_length=96)] = None,
    asset_id: UUID | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    subnet: Subnet = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> NetworkChangeList:
    topology, history = services
    return history.list_changes(
        topology.site(site_id),
        change_type=change_type,
        status=status,
        subject=subject,
        asset=asset_id,
        start=start,
        end=end,
        subnet=subnet,
        limit=limit,
        offset=offset,
    )


@router.patch(
    "/changes/{change_id}/review",
    response_model=NetworkChangeRead,
    responses=error_responses(404, 409),
)
def review_change(
    change_id: UUID,
    body: NetworkChangeReview,
    services: Services,
    ctx: Manager,
    site_id: SiteFilter = None,
) -> NetworkChangeRead:
    """Confirmar, descartar o volver a detectado. 409 network_change_conflict con versión
    obsoleta. Auditado (network_change_reviewed)."""
    topology, history = services
    return history.review(topology.site(site_id), change_id, body, actor(ctx))


@router.get(
    "/history/nodes/{node_id}",
    response_model=TopologyHistory,
    dependencies=[READ],
    responses=error_responses(404),
)
def node_history(
    node_id: str, services: Services, site_id: SiteFilter = None, limit: Limit = 100
) -> TopologyHistory:
    """Periodos del nodo con los mismos valores (nombre, IP, MAC, estado, Wi-Fi...). Una clave
    mal formada o de otro site responde el mismo 404 (topology_history_not_found)."""
    topology, history = services
    site = topology.site(site_id)
    key = parse_node_id(node_id)
    if key is None:
        raise TopologyHistoryNotFoundError("No history for this subject")
    entries = history.history(site, subject_type="node", key=key, limit=limit)
    return TopologyHistory(
        site_id=site.public_id, subject_type="node", subject_key=key, entries=entries
    )


@router.get(
    "/history/links/{link_id}",
    response_model=TopologyHistory,
    dependencies=[READ],
    responses=error_responses(404),
)
def link_history(
    link_id: str, services: Services, site_id: SiteFilter = None, limit: Limit = 100
) -> TopologyHistory:
    """Periodos de un enlace (por su id de 6D). Texto y no UUID por la misma razón anti-IDOR
    que el detalle de enlace."""
    topology, history = services
    site = topology.site(site_id)
    key = history.link_key(site, link_id[:64])
    if key is None:
        raise TopologyHistoryNotFoundError("No history for this subject")
    entries = history.history(site, subject_type="link", key=key, limit=limit)
    return TopologyHistory(
        site_id=site.public_id, subject_type="link", subject_key=key, entries=entries
    )
