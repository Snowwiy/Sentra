"""Revisión de correlaciones CORR-002 anteriores a la v5 (Fase 7B-Fix1).

Vista previa y aplicar con detections:manage. Aplicar exige `confirm: true` y la lista de
detecciones revisadas; solo resuelve las que la v5 no considera causales. Ver
docs/fase-7b-fix1.md.
"""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.auth import actor, require_permission
from app.api.deps import DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.correlation_review import (
    CorrelationReviewApply,
    CorrelationReviewApplyResult,
    CorrelationReviewPreview,
    CorrelationReviewQuery,
)
from app.services.auth_service import AuthContext
from app.services.correlation_review_service import CorrelationReviewService

router = APIRouter(tags=["detections"], responses=error_responses(401, 403))
DetectionManager = Annotated[AuthContext, Depends(require_permission(Permission.DETECTIONS_MANAGE))]


def get_service(session: DbSession) -> CorrelationReviewService:
    return CorrelationReviewService(session)


Service = Annotated[CorrelationReviewService, Depends(get_service)]


@router.post(
    "/detections/correlation-review/preview",
    response_model=CorrelationReviewPreview,
    responses=error_responses(404),
)
def preview_correlation_review(
    body: CorrelationReviewQuery, _: DetectionManager, service: Service
) -> CorrelationReviewPreview:
    """Veredicto v5 de cada CORR-002 anterior aún activa. No cambia nada."""
    return service.preview(body.asset_id)


@router.post(
    "/detections/correlation-review/apply",
    response_model=CorrelationReviewApplyResult,
    responses=error_responses(404),
)
def apply_correlation_review(
    body: CorrelationReviewApply, ctx: DetectionManager, service: Service
) -> CorrelationReviewApplyResult:
    """Resuelve las revisadas sin relación causal, con auditoría y recálculo del riesgo."""
    return service.apply(body, actor(ctx))
