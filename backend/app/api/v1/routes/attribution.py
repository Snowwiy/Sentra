"""Operaciones de mantenimiento autorizadas y atribución de detecciones (Fase 7B.1).

- /maintenance-operations: lectura monitoring:read; crear, aprobar, revocar, vista previa y
  aplicar con maintenance:manage (solo admin). Una operación nunca se borra.
- /detections/{id}/attribution: veredicto, comprobaciones e historial (monitoring:read);
  reevaluar y dar un veredicto de analista con detections:manage.

Ver docs/detection-attribution.md.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.auth import READ, actor, require_permission
from app.api.deps import DbSession
from app.api.responses import error_responses
from app.core.exceptions import SentraError
from app.core.permissions import Permission
from app.schemas.attribution import (
    AnalystVerdictIn,
    AttributionApplyResult,
    AttributionPreview,
    DetectionAttributionRead,
    MaintenanceOperationCreate,
    MaintenanceOperationList,
    MaintenanceOperationRead,
    OperationApply,
    OperationDecision,
    OperationRevoke,
    OperationStatus,
    ReferenceArtifactList,
)
from app.services import audit_service
from app.services.attribution_service import AttributionService, reference_artifacts
from app.services.auth_service import AuthContext
from app.services.site_service import resolve_site

router = APIRouter(tags=["attribution"], responses=error_responses(401, 403))
Maintainer = Annotated[AuthContext, Depends(require_permission(Permission.MAINTENANCE_MANAGE))]
DetectionManager = Annotated[AuthContext, Depends(require_permission(Permission.DETECTIONS_MANAGE))]


def get_service(session: DbSession) -> AttributionService:
    return AttributionService(session)


Service = Annotated[AttributionService, Depends(get_service)]


def _audited_failure(
    session: DbSession, ctx: AuthContext, action: str, target: object, exc: SentraError
) -> None:
    session.rollback()
    audit_service.record(
        session,
        actor(ctx),
        action,
        audit_service.FAILURE,
        "maintenance_operation",
        target,
        details={"error": exc.code},
    )


@router.get(
    "/maintenance-operations",
    response_model=MaintenanceOperationList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_operations(
    service: Service,
    session: DbSession,
    asset_id: UUID | None = None,
    status: OperationStatus | None = None,
    site_id: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> MaintenanceOperationList:
    return service.list(resolve_site(session, site_id), asset_id, status, limit, offset)


# Antes de /{operation_id}: "reference-artifacts" no es un UUID.
@router.get(
    "/maintenance-operations/reference-artifacts",
    response_model=ReferenceArtifactList,
    dependencies=[READ],
)
def list_reference_artifacts() -> ReferenceArtifactList:
    """Hashes de los scripts que distribuye este servidor (referencia, no aprendidos)."""
    return reference_artifacts()


@router.get(
    "/maintenance-operations/{operation_id}",
    response_model=MaintenanceOperationRead,
    dependencies=[READ],
    responses=error_responses(404),
)
def get_operation(operation_id: UUID, service: Service) -> MaintenanceOperationRead:
    return service.get(operation_id)


@router.post(
    "/maintenance-operations",
    response_model=MaintenanceOperationRead,
    status_code=201,
    responses=error_responses(404, 409),
)
def create_operation(
    body: MaintenanceOperationCreate, ctx: Maintainer, service: Service, session: DbSession
) -> MaintenanceOperationRead:
    """Registra una operación en estado pending_review (no verifica nada hasta aprobarla)."""
    try:
        return service.create(body, actor(ctx))
    except SentraError as exc:
        _audited_failure(session, ctx, "maintenance_operation_created", body.asset_id, exc)
        raise


@router.post(
    "/maintenance-operations/{operation_id}/approve",
    response_model=MaintenanceOperationRead,
    responses=error_responses(404, 409),
)
def approve_operation(
    operation_id: UUID,
    ctx: Maintainer,
    service: Service,
    session: DbSession,
    body: OperationDecision | None = None,
) -> MaintenanceOperationRead:
    try:
        return service.approve(operation_id, body.note if body else None, actor(ctx))
    except SentraError as exc:
        _audited_failure(session, ctx, "maintenance_operation_approved", operation_id, exc)
        raise


@router.post(
    "/maintenance-operations/{operation_id}/revoke",
    response_model=MaintenanceOperationRead,
    responses=error_responses(404, 409),
)
def revoke_operation(
    operation_id: UUID, body: OperationRevoke, ctx: Maintainer, service: Service, session: DbSession
) -> MaintenanceOperationRead:
    try:
        return service.revoke(operation_id, body.reason, actor(ctx))
    except SentraError as exc:
        _audited_failure(session, ctx, "maintenance_operation_revoked", operation_id, exc)
        raise


@router.post(
    "/maintenance-operations/{operation_id}/preview",
    response_model=AttributionPreview,
    responses=error_responses(404, 409),
)
def preview_operation(operation_id: UUID, _: Maintainer, service: Service) -> AttributionPreview:
    """Veredicto que tendría cada detección de la ventana. No cambia nada."""
    return service.preview(operation_id)


@router.post(
    "/maintenance-operations/{operation_id}/apply",
    response_model=AttributionApplyResult,
    responses=error_responses(404, 409),
)
def apply_operation(
    operation_id: UUID, body: OperationApply, ctx: Maintainer, service: Service, session: DbSession
) -> AttributionApplyResult:
    """Aplica los veredictos tras la vista previa (`confirm: true`) y recalcula el riesgo."""
    try:
        return service.apply(operation_id, actor(ctx))
    except SentraError as exc:
        _audited_failure(session, ctx, "maintenance_operation_applied", operation_id, exc)
        raise


@router.get(
    "/detections/{detection_id}/attribution",
    response_model=DetectionAttributionRead,
    dependencies=[READ],
    responses=error_responses(404),
)
def get_attribution(detection_id: UUID, service: Service) -> DetectionAttributionRead:
    return service.detection_attribution(detection_id)


@router.post(
    "/detections/{detection_id}/attribution/evaluate",
    response_model=DetectionAttributionRead,
    responses=error_responses(404),
)
def evaluate_attribution(
    detection_id: UUID, ctx: DetectionManager, service: Service
) -> DetectionAttributionRead:
    return service.evaluate(detection_id, actor(ctx))


@router.post(
    "/detections/{detection_id}/attribution/verdict",
    response_model=DetectionAttributionRead,
    responses=error_responses(404),
)
def set_analyst_verdict(
    detection_id: UUID, body: AnalystVerdictIn, ctx: DetectionManager, service: Service
) -> DetectionAttributionRead:
    """Decisión del analista (inmutable). No admite verified_benign: eso exige operación."""
    return service.analyst_verdict(detection_id, body, actor(ctx))
