"""Detecciones del motor (Fase 4H): lectura para cualquier rol, gestión con detections:manage.

El permiso se comprueba en el backend en cada petición (require_permission); ocultar los
botones en la UI es solo comodidad. Reconocer y resolver quedan en audit_events, también
los intentos fallidos (404/409).
"""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Query

from app.api.auth import READ, actor, require_permission
from app.api.deps import DbSession, get_detection_config
from app.api.params import text_query
from app.api.responses import error_responses
from app.core.exceptions import SentraError
from app.core.permissions import Permission
from app.detection.config import DetectionConfig
from app.models.detection import DetectionConfidence, DetectionSeverity, DetectionStatus
from app.schemas.detection import (
    DetectionAction,
    DetectionDetail,
    DetectionList,
)
from app.schemas.detection_rule import RULE_UID_PATTERN
from app.services import audit_service
from app.services.auth_service import AuthContext
from app.services.detection_service import DetectionFilter, DetectionService

router = APIRouter(tags=["detections"])
Manager = Annotated[AuthContext, Depends(require_permission(Permission.DETECTIONS_MANAGE))]


def get_detection_service(
    session: DbSession, config: Annotated[DetectionConfig, Depends(get_detection_config)]
) -> DetectionService:
    return DetectionService(session, config)


Service = Annotated[DetectionService, Depends(get_detection_service)]


@router.get(
    "/detections", response_model=DetectionList, responses=error_responses(404), dependencies=[READ]
)
def list_detections(
    service: Service,
    status: DetectionStatus | None = None,
    # Abiertas o reconocidas; se ignora si se indica `status`.
    active: bool = False,
    severity: DetectionSeverity | None = None,
    # Esta severidad o superior.
    min_severity: DetectionSeverity | None = None,
    confidence: DetectionConfidence | None = None,
    rule_id: Annotated[str | None, Query(max_length=32, pattern=RULE_UID_PATTERN)] = None,
    asset_id: UUID | None = None,
    # Rango sobre la última actividad (last_seen_at).
    since: datetime | None = None,
    until: datetime | None = None,
    # Texto en título, resumen, regla o activo.
    q: Annotated[str | None, text_query(200)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> DetectionList:
    return service.list(
        DetectionFilter(
            status=status,
            active=active,
            severity=severity,
            min_severity=min_severity,
            confidence=confidence,
            rule_id=rule_id,
            asset_public_id=asset_id,
            since=since,
            until=until,
            search=q.strip() if q and q.strip() else None,
        ),
        limit,
        offset,
    )


@router.get(
    "/detections/{detection_id}",
    response_model=DetectionDetail,
    responses=error_responses(404),
    dependencies=[READ],
)
def get_detection(detection_id: UUID, service: Service) -> DetectionDetail:
    return service.get(detection_id)


def _action(
    detection_id: UUID,
    ctx: AuthContext,
    service: DetectionService,
    session: DbSession,
    command: str,
    note: str | None,
) -> DetectionDetail:
    action = "detection_acknowledged" if command == "acknowledge" else "detection_resolved"
    try:
        if command == "acknowledge":
            service.acknowledge(detection_id, ctx.user.username)
        else:
            service.resolve(detection_id, ctx.user.username, note or None)
    except SentraError as exc:
        session.rollback()
        audit_service.record(
            session,
            actor(ctx),
            action,
            audit_service.FAILURE,
            "detection",
            detection_id,
            details={"error": exc.code},
        )
        raise
    audit_service.record(
        session,
        actor(ctx),
        action,
        target_type="detection",
        target_id=detection_id,
        details={"note": note} if note else None,
    )
    return service.get(detection_id)


@router.post(
    "/detections/{detection_id}/acknowledge",
    response_model=DetectionDetail,
    responses=error_responses(401, 403, 404, 409),
)
def acknowledge_detection(
    detection_id: UUID, ctx: Manager, service: Service, session: DbSession
) -> DetectionDetail:
    """Marca la detección como vista; sigue activa hasta resolverse."""
    return _action(detection_id, ctx, service, session, "acknowledge", None)


@router.post(
    "/detections/{detection_id}/resolve",
    response_model=DetectionDetail,
    responses=error_responses(401, 403, 404),
)
def resolve_detection(
    detection_id: UUID,
    ctx: Manager,
    service: Service,
    session: DbSession,
    body: Annotated[DetectionAction | None, Body()] = None,
) -> DetectionDetail:
    """Cierra la detección (con nota opcional). No se borra: queda como historial."""
    return _action(detection_id, ctx, service, session, "resolve", body.note if body else None)
