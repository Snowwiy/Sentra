from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from app.api.auth import READ
from app.api.deps import AgentToken, get_event_service
from app.api.params import text_query
from app.api.responses import error_responses
from app.models.event import EventLevel
from app.schemas.event import EventBatch, EventBatchAccepted, EventList
from app.services.event_service import EventFilter, EventService

router = APIRouter(prefix="/events", tags=["events"])
Service = Annotated[EventService, Depends(get_event_service)]


@router.post(
    "",
    response_model=EventBatchAccepted,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(401, 413),
)
def ingest_events(payload: EventBatch, service: Service, token: AgentToken) -> EventBatchAccepted:
    return service.ingest(payload, token)


@router.get("", response_model=EventList, responses=error_responses(404), dependencies=[READ])
def list_events(
    service: Service,
    asset_id: UUID | None = None,
    # Minimum severity: "warning" returns warnings, errors and critical events.
    min_level: EventLevel | None = None,
    channel: Annotated[str | None, text_query(255)] = None,
    event_code: Annotated[int | None, Query(ge=0, le=2**31 - 1)] = None,
    # Case-insensitive text in the message or the provider.
    q: Annotated[str | None, text_query(200)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> EventList:
    search = q.strip() if q else None
    return service.list_events(
        asset_id,
        EventFilter(min_level=min_level, channel=channel, event_code=event_code, search=search),
        limit,
        offset,
    )
