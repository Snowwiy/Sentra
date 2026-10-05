from datetime import timedelta
from typing import Annotated

from fastapi import Depends, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.security import MAX_CREDENTIAL_LENGTH, enrollment_key_matches
from app.db.session import get_db
from app.detection.config import DetectionConfig
from app.services.agent_management_service import AgentManagementService
from app.services.agent_service import AgentService
from app.services.alert_service import AlertService, AlertThresholds
from app.services.asset_service import AssetService
from app.services.enrollment_token_service import EnrollmentTokenService
from app.services.event_service import EventService
from app.services.exposure_service import ExposureService
from app.services.health_service import HealthService
from app.services.inventory_service import InventoryService
from app.services.process_service import ProcessService
from app.services.telemetry_service import TelemetryService

DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]


def get_alert_thresholds(settings: AppSettings) -> AlertThresholds:
    return AlertThresholds.from_settings(settings)


Thresholds = Annotated[AlertThresholds, Depends(get_alert_thresholds)]


def get_detection_config(settings: AppSettings) -> DetectionConfig:
    return DetectionConfig.from_settings(settings)


Detection = Annotated[DetectionConfig, Depends(get_detection_config)]


def get_agent_service(session: DbSession, settings: AppSettings) -> AgentService:
    key = settings.agent_enrollment_key
    return AgentService(session, key.get_secret_value() if key else None)


# auto_error=False: a missing header must reach the service, which answers with the same
# 401 body as a wrong token instead of FastAPI's generic 403.
_bearer = HTTPBearer(auto_error=False)


def get_agent_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str | None:
    return credentials.credentials if credentials else None


AgentToken = Annotated[str | None, Depends(get_agent_token)]
EnrollmentKey = Annotated[str | None, Header(alias="X-Enrollment-Key")]
# One-time bootstrap token (recommended); only POST /agents/register reads it.
EnrollmentTokenHeader = Annotated[str | None, Header(alias="X-Enrollment-Token")]


def require_admin(
    settings: AppSettings, admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None
) -> None:
    """Guard for the administration API (enrollment tokens).

    Fail closed: without ADMIN_API_KEY configured the endpoints answer 403, so a server never
    exposes them by accident. There are no dashboard users yet; this single operator key is
    the stopgap, and the CLI (shell access) remains the alternative.
    """
    expected = settings.admin_api_key
    if expected is None:
        raise ForbiddenError("Administration API disabled: set ADMIN_API_KEY on the server")
    if (
        not admin_key
        or len(admin_key) > MAX_CREDENTIAL_LENGTH
        or not enrollment_key_matches(admin_key, expected.get_secret_value())
    ):
        raise UnauthorizedError("Invalid or missing admin key")


def get_enrollment_token_service(
    session: DbSession, settings: AppSettings
) -> EnrollmentTokenService:
    return EnrollmentTokenService(session, timedelta(minutes=settings.enrollment_token_ttl_minutes))


def get_agent_management_service(
    session: DbSession, settings: AppSettings
) -> AgentManagementService:
    return AgentManagementService(session, timedelta(seconds=settings.heartbeat_timeout_seconds))


def get_asset_service(session: DbSession, settings: AppSettings) -> AssetService:
    return AssetService(session, timedelta(seconds=settings.heartbeat_timeout_seconds))


def get_telemetry_service(session: DbSession, thresholds: Thresholds) -> TelemetryService:
    return TelemetryService(session, thresholds)


def get_alert_service(session: DbSession, thresholds: Thresholds) -> AlertService:
    return AlertService(session, thresholds)


def get_health_service(session: DbSession) -> HealthService:
    return HealthService(session)


def get_inventory_service(
    session: DbSession, thresholds: Thresholds, detection: Detection
) -> InventoryService:
    return InventoryService(session, thresholds, detection)


def get_event_service(
    session: DbSession, thresholds: Thresholds, detection: Detection
) -> EventService:
    return EventService(session, thresholds, detection)


def get_process_service(session: DbSession, detection: Detection) -> ProcessService:
    return ProcessService(session, detection)


def get_exposure_service(session: DbSession, settings: AppSettings) -> ExposureService:
    return ExposureService(session, settings)
