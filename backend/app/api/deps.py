from datetime import timedelta
from typing import Annotated

from fastapi import Depends, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.services.agent_service import AgentService
from app.services.alert_service import AlertService, AlertThresholds
from app.services.asset_service import AssetService
from app.services.event_service import EventService
from app.services.health_service import HealthService
from app.services.inventory_service import InventoryService
from app.services.telemetry_service import TelemetryService

DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]


def get_alert_thresholds(settings: AppSettings) -> AlertThresholds:
    return AlertThresholds.from_settings(settings)


Thresholds = Annotated[AlertThresholds, Depends(get_alert_thresholds)]


def get_agent_service(
    session: DbSession, thresholds: Thresholds, settings: AppSettings
) -> AgentService:
    key = settings.agent_enrollment_key
    return AgentService(session, thresholds, key.get_secret_value() if key else None)


# auto_error=False: a missing header must reach the service, which answers with the same
# 401 body as a wrong token instead of FastAPI's generic 403.
_bearer = HTTPBearer(auto_error=False)


def get_agent_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str | None:
    return credentials.credentials if credentials else None


AgentToken = Annotated[str | None, Depends(get_agent_token)]
EnrollmentKey = Annotated[str | None, Header(alias="X-Enrollment-Key")]


def get_asset_service(session: DbSession, settings: AppSettings) -> AssetService:
    return AssetService(session, timedelta(seconds=settings.heartbeat_timeout_seconds))


def get_telemetry_service(session: DbSession, thresholds: Thresholds) -> TelemetryService:
    return TelemetryService(session, thresholds)


def get_alert_service(session: DbSession, thresholds: Thresholds) -> AlertService:
    return AlertService(session, thresholds)


def get_health_service(session: DbSession) -> HealthService:
    return HealthService(session)


def get_inventory_service(session: DbSession) -> InventoryService:
    return InventoryService(session)


def get_event_service(session: DbSession) -> EventService:
    return EventService(session)
