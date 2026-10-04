from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import AgentToken, get_telemetry_service
from app.schemas.telemetry import TelemetryAccepted, TelemetryCreate
from app.services.telemetry_service import TelemetryService

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.post("", response_model=TelemetryAccepted, status_code=status.HTTP_201_CREATED)
def ingest_telemetry(
    payload: TelemetryCreate,
    service: Annotated[TelemetryService, Depends(get_telemetry_service)],
    token: AgentToken,
) -> TelemetryAccepted:
    return service.ingest(payload, token)
