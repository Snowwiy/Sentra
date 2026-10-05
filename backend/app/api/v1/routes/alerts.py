from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.auth import READ, actor, require_permission
from app.api.deps import DbSession, get_alert_service
from app.api.params import text_query
from app.api.responses import error_responses
from app.core.exceptions import SentraError
from app.core.permissions import Permission
from app.models.alert import AlertRule, AlertSeverity, AlertStatus
from app.repositories.alert_repository import AlertFilter
from app.schemas.alert import AlertList, AlertRead
from app.services import audit_service
from app.services.alert_service import AlertService
from app.services.auth_service import AuthContext

router = APIRouter(prefix="/alerts", tags=["alerts"])
Service = Annotated[AlertService, Depends(get_alert_service)]
Manager = Annotated[AuthContext, Depends(require_permission(Permission.ALERTS_MANAGE))]


@router.get("", response_model=AlertList, responses=error_responses(404), dependencies=[READ])
def list_alerts(
    service: Service,
    status: AlertStatus | None = None,
    # Open or acknowledged; ignored when `status` is given.
    active: bool = False,
    severity: AlertSeverity | None = None,
    rule: AlertRule | None = None,
    asset_id: UUID | None = None,
    # Case-insensitive text in the message or the hostname.
    q: Annotated[str | None, text_query(200)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> AlertList:
    search = q.strip() if q else None
    return service.list_alerts(
        AlertFilter(status=status, active=active, severity=severity, rule=rule, search=search),
        asset_id,
        limit,
        offset,
    )


@router.get(
    "/{alert_id}", response_model=AlertRead, responses=error_responses(404), dependencies=[READ]
)
def get_alert(alert_id: UUID, service: Service) -> AlertRead:
    return service.get_alert(alert_id)


def _alert_action(
    alert_id: UUID, ctx: AuthContext, service: AlertService, session: DbSession, command: str
) -> AlertRead:
    # Mismas operaciones que la CLI (ack-alert / resolve-alert), ahora con login y permiso
    # alerts:manage (admin y analyst). Se auditan también los intentos fallidos (404/409).
    action = "alert_acknowledged" if command == "acknowledge" else "alert_resolved"
    try:
        if command == "acknowledge":
            service.acknowledge(alert_id)
        else:
            service.resolve(alert_id)
    except SentraError as exc:
        session.rollback()
        audit_service.record(
            session,
            actor(ctx),
            action,
            audit_service.FAILURE,
            "alert",
            alert_id,
            details={"error": exc.code},
        )
        raise
    audit_service.record(session, actor(ctx), action, target_type="alert", target_id=alert_id)
    return service.get_alert(alert_id)


@router.post(
    "/{alert_id}/acknowledge",
    response_model=AlertRead,
    responses=error_responses(401, 403, 404, 409),
)
def acknowledge_alert(
    alert_id: UUID, ctx: Manager, service: Service, session: DbSession
) -> AlertRead:
    """Marca la alerta como vista; sigue activa (deduplicada) hasta resolverse."""
    return _alert_action(alert_id, ctx, service, session, "acknowledge")


@router.post(
    "/{alert_id}/resolve", response_model=AlertRead, responses=error_responses(401, 403, 404)
)
def resolve_alert(alert_id: UUID, ctx: Manager, service: Service, session: DbSession) -> AlertRead:
    """Cierra la alerta a mano; si la condición sigue, se abrirá una nueva más adelante."""
    return _alert_action(alert_id, ctx, service, session, "resolve")
