from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_alert_service
from app.models.alert import AlertStatus
from app.schemas.alert import AlertList
from app.services.alert_service import AlertService

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertList)
def list_alerts(
    service: Annotated[AlertService, Depends(get_alert_service)],
    status: AlertStatus | None = None,
    asset_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> AlertList:
    return service.list_alerts(status, asset_id, limit)
