from datetime import timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.auth import CurrentAuth, require_permission
from app.api.deps import AppSettings, DbSession
from app.core.permissions import Permission
from app.schemas.dashboard import DashboardSummary
from app.services.dashboard_service import DashboardService
from app.services.site_service import resolve_site

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_permission(Permission.MONITORING_READ))],
)


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    session: DbSession,
    ctx: CurrentAuth,
    settings: AppSettings,
    site_id: Annotated[UUID | None, Query()] = None,
) -> DashboardSummary:
    """Contadores del dashboard en SQL agregado (Fase 4M): nunca descarga activos.

    Fase 5F: `site_id` limita todos los contadores a ese site (404 site_not_found).
    """
    service = DashboardService(
        session,
        timedelta(seconds=settings.heartbeat_timeout_seconds),
        resolve_site(session, site_id),
    )
    return service.summary(
        include_incidents=ctx.has(Permission.INCIDENTS_READ),
        include_vulnerabilities=ctx.has(Permission.VULNERABILITIES_READ),
        site_public_id=site_id,
    )
