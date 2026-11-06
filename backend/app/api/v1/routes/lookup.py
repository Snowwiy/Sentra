"""Selectores contextuales (Fase 7C.3): GET /lookup/{kind}.

Permisos: activos y detecciones con monitoring:read (lo mismo que listarlos); incidentes con
incidents:read. Respeta el site elegido. Solo lectura y sin efectos: no audita (igual que los
listados y la búsqueda global).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from app.api.auth import READ, CurrentAuth
from app.api.deps import DbSession
from app.api.responses import error_responses
from app.core.exceptions import PermissionDeniedError
from app.core.permissions import Permission
from app.schemas.lookup import LookupKind, LookupResult
from app.services.lookup_service import MAX_LIMIT, LookupService
from app.services.site_service import resolve_site

router = APIRouter(prefix="/lookup", tags=["console"], responses=error_responses(401, 403))


@router.get("/{kind}", response_model=LookupResult, dependencies=[READ])
def lookup(
    kind: LookupKind,
    ctx: CurrentAuth,
    session: DbSession,
    q: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    ids: Annotated[list[UUID] | None, Query(max_length=MAX_LIMIT)] = None,
    site_id: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 8,
    include_archived: bool = False,
) -> LookupResult:
    """Candidatos por nombre, etiqueta, IP, MAC, regla o número de caso (`q`), o etiquetas
    de ids ya conocidos (`ids`). La respuesta dice si la coincidencia es única o ambigua."""
    if kind == "incident" and not ctx.has(Permission.INCIDENTS_READ):
        raise PermissionDeniedError("Missing permission: incidents:read")
    service = LookupService(session)
    scope = resolve_site(session, site_id)
    if ids:
        return service.resolve_ids(kind, ids, site_id=scope)
    return service.lookup(
        kind, q or "", site_id=scope, limit=limit, include_archived=include_archived
    )
