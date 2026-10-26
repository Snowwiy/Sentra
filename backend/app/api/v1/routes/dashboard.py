from datetime import timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.auth import CurrentAuth, require_permission
from app.api.deps import AppSettings, DbSession
from app.core.permissions import Permission
from app.risk.config import RiskConfig
from app.schemas.dashboard import DashboardSummary, SecurityOverview
from app.services.dashboard_service import DashboardService
from app.services.security_overview_service import (
    MAX_DAYS,
    MIN_DAYS,
    SecurityOverviewService,
)
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
        catalog_stale_after=timedelta(hours=settings.vuln_source_stale_hours),
    )
    return service.summary(
        include_incidents=ctx.has(Permission.INCIDENTS_READ),
        include_vulnerabilities=ctx.has(Permission.VULNERABILITIES_READ),
        site_public_id=site_id,
    )


@router.get("/security-overview", response_model=SecurityOverview)
def security_overview(
    session: DbSession,
    ctx: CurrentAuth,
    settings: AppSettings,
    site_id: Annotated[UUID | None, Query()] = None,
    days: Annotated[int, Query(ge=MIN_DAYS, le=MAX_DAYS)] = 30,
) -> SecurityOverview:
    """Gráficas del dashboard (Fase 7A.7): postura ponderada, historial de riesgo, detecciones
    recientes, dispositivos nuevos y puertos expuestos. Ver docs/security-dashboard.md.

    `incidents_by_status` es null sin incidents:read, como en /dashboard/summary.
    """
    service = SecurityOverviewService(
        session,
        timedelta(seconds=settings.heartbeat_timeout_seconds),
        RiskConfig.from_settings(settings),
        resolve_site(session, site_id),
    )
    return service.overview(
        days, include_incidents=ctx.has(Permission.INCIDENTS_READ), site_public_id=site_id
    )
