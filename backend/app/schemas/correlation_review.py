"""Revisión de correlaciones CORR-002 anteriores a la v5 (Fase 7B-Fix1)."""

from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.schemas.common import RequestModel, ResponseModel

ReviewVerdict = Literal["causal", "temporal_only", "insufficient_evidence"]


class CorrelationReviewQuery(RequestModel):
    # Sin activo: todas las CORR-002 activas (acotado a REVIEW_LIMIT).
    asset_id: UUID | None = None


class CorrelationReviewItem(ResponseModel):
    detection_id: UUID
    asset_id: UUID
    hostname: str | None
    rule_version: int
    status: str
    title: str
    verdict: ReviewVerdict
    # Solo las no causales sin decisión de un analista: el resto no se toca.
    would_resolve: bool
    causal_links: list[dict[str, Any]]
    temporal_context: dict[str, Any]
    explanation: list[str]


class CorrelationReviewPreview(ResponseModel):
    items: list[CorrelationReviewItem]
    causal: int
    temporal_only: int
    insufficient_evidence: int


class CorrelationReviewApply(RequestModel):
    # Las detecciones revisadas en la vista previa, una a una: nunca "todas".
    detection_ids: list[UUID] = Field(min_length=1, max_length=200)
    note: str | None = Field(default=None, max_length=500)
    confirm: Literal[True]


class CorrelationReviewApplyResult(ResponseModel):
    reviewed: int
    resolved: int
    kept: int
