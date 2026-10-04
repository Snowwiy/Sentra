from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_alert_service
from app.api.params import text_query
from app.api.responses import error_responses
from app.models.alert import AlertRule, AlertSeverity, AlertStatus
from app.repositories.alert_repository import AlertFilter
from app.schemas.alert import AlertList, AlertRead
from app.services.alert_service import AlertService

router = APIRouter(prefix="/alerts", tags=["alerts"])
Service = Annotated[AlertService, Depends(get_alert_service)]


@router.get("", response_model=AlertList, responses=error_responses(404))
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


@router.get("/{alert_id}", response_model=AlertRead, responses=error_responses(404))
def get_alert(alert_id: UUID, service: Service) -> AlertRead:
    return service.get_alert(alert_id)
