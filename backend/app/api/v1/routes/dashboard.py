from datetime import timedelta

from fastapi import APIRouter, Depends

from app.api.auth import CurrentAuth, require_permission
from app.api.deps import AppSettings, DbSession
from app.core.permissions import Permission
from app.schemas.dashboard import DashboardSummary
from app.services.dashboard_service import DashboardService

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_permission(Permission.MONITORING_READ))],
)


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    session: DbSession, ctx: CurrentAuth, settings: AppSettings
) -> DashboardSummary:
    """Contadores del dashboard en SQL agregado (Fase 4M): nunca descarga activos."""
    service = DashboardService(session, timedelta(seconds=settings.heartbeat_timeout_seconds))
    return service.summary(
        include_incidents=ctx.has(Permission.INCIDENTS_READ),
        include_vulnerabilities=ctx.has(Permission.VULNERABILITIES_READ),
    )
