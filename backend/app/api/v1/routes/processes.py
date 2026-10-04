from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import AgentToken, get_process_service
from app.api.responses import error_responses
from app.schemas.process import ProcessSnapshotAccepted, ProcessSnapshotCreate
from app.services.process_service import ProcessService

router = APIRouter(prefix="/processes", tags=["processes"])


@router.post(
    "",
    response_model=ProcessSnapshotAccepted,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(401, 413),
)
def ingest_processes(
    payload: ProcessSnapshotCreate,
    service: Annotated[ProcessService, Depends(get_process_service)],
    token: AgentToken,
) -> ProcessSnapshotAccepted:
    return service.ingest(payload, token)
