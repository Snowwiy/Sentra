"""Búsqueda global de la Analyst Console (Fase 7B.4): GET /search con monitoring:read."""

from datetime import timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from app.api.auth import READ, CurrentAuth
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.console_search import SearchResult
from app.services.console_search import ConsoleSearch
from app.services.site_service import resolve_site

router = APIRouter(tags=["console"], responses=error_responses(401, 403))


@router.get("/search", response_model=SearchResult, dependencies=[READ])
def search(
    ctx: CurrentAuth,
    session: DbSession,
    settings: AppSettings,
    q: Annotated[str, Query(min_length=2, max_length=128)],
    site_id: Annotated[UUID | None, Query()] = None,
) -> SearchResult:
    """IP, MAC, SHA-256, id de regla, número de caso o texto. Hasta 10 resultados por grupo.

    Los usuarios de Sentra solo se buscan con incidents:manage: es el mismo criterio que
    GET /incidents/assignees (quien asigna casos necesita verlos; un viewer no).
    """
    service = ConsoleSearch(session, timedelta(seconds=settings.heartbeat_timeout_seconds))
    return service.search(
        q,
        resolve_site(session, site_id),
        include_users=ctx.has(Permission.INCIDENTS_MANAGE),
    )
