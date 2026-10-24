"""Contratos del aislamiento seguro (Fase 6E.7, docs/safe-isolation.md)."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.schemas.common import RequestModel, ResponseModel

IsolationState = Literal[
    "requested",
    "approved",
    "applying",
    "isolated",
    "reverting",
    "restored",
    "failed",
    "expired",
    "unknown",
]
NOT_AVAILABLE_MESSAGE = "Aislamiento no disponible para este dispositivo"


class IsolationRequest(RequestModel):
    duration_minutes: int = Field(ge=5, le=1440)
    reason: str = Field(min_length=10, max_length=500)
    # Confirmación escrita: el nombre del equipo tal como lo muestra Sentra.
    confirm_name: str = Field(min_length=1, max_length=255)


class ReleaseRequest(RequestModel):
    version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=500)


class Reason(ResponseModel):
    code: str
    message: str


class IsolationSessionRead(ResponseModel):
    id: UUID
    asset_id: UUID
    asset_label: str
    status: IsolationState
    reason: str
    duration_minutes: int
    requested_by: str
    requested_at: datetime
    approved_by: str | None
    approved_at: datetime | None
    expires_at: datetime
    applied_at: datetime | None
    released_by: str | None
    release_reason: str | None
    released_at: datetime | None
    ended_at: datetime | None
    method: str | None
    verified: bool
    allowed: list[str]
    rules: list[dict[str, Any]]
    error_code: str | None
    reported_state: str | None
    reported_at: datetime | None
    isolate_execution_id: UUID | None
    release_execution_id: UUID | None
    version: int


class IsolationOverview(ResponseModel):
    """Previsualización: si se puede aislar, por qué no, impacto y sesión actual."""

    asset_id: UUID
    asset_label: str
    available: bool
    # "Aislamiento no disponible para este dispositivo" cuando no tiene agente o la
    # plataforma no lo admite; null si el bloqueo es temporal (servidor, helper, conexión).
    unavailable_message: str | None
    reasons: list[Reason]
    server_enabled: bool
    platform: str | None
    helper: dict[str, Any] | None
    helper_reported_at: datetime | None
    confirm_name: str
    default_minutes: int
    max_minutes: int
    impact: list[str]
    manual_recommendations: list[str]
    current: IsolationSessionRead | None


class IsolationSessionList(ResponseModel):
    items: list[IsolationSessionRead]
    total: int
