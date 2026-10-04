from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import AgentToken, get_event_service
from app.models.event import EventLevel
from app.schemas.event import EventBatch, EventBatchAccepted, EventList
from app.services.event_service import EventService

router = APIRouter(prefix="/events", tags=["events"])
Service = Annotated[EventService, Depends(get_event_service)]


@router.post("", response_model=EventBatchAccepted, status_code=status.HTTP_201_CREATED)
def ingest_events(payload: EventBatch, service: Service, token: AgentToken) -> EventBatchAccepted:
    return service.ingest(payload, token)


@router.get("", response_model=EventList)
def list_events(
    service: Service,
    asset_id: UUID | None = None,
    # Minimum severity: "warning" returns warnings, errors and critical events.
    min_level: EventLevel | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> EventList:
    return service.list_events(asset_id, min_level, limit)
