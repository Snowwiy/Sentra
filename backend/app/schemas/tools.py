"""Contratos de la API del Analyst Tool Engine (Fase 7A)."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.schemas.common import RequestModel, ResponseModel

IdempotencyKey = Field(default=None, min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


class ToolOut(ResponseModel):
    id: str
    version: int
    name: str
    description: str
    category: str
    scope: str
    risk_level: str
    policy: str
    required_permissions: list[str]
    required_role: str
    timeout_seconds: int
    max_rows: int
    required_capabilities: list[str]
    sources: list[str]
    # available | unavailable (con el motivo: p. ej. response_disabled).
    availability: Literal["available", "unavailable"]
    unavailable_reason: str | None
    # El rol del usuario tiene todos los permisos (ocultar o deshabilitar es solo UX).
    permitted: bool
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]


class ToolCatalog(ResponseModel):
    items: list[ToolOut]
    enabled: bool


class ToolRunRequest(RequestModel):
    """Ejecutar (o previsualizar) una herramienta. `input` lo valida el modelo cerrado de la
    herramienta (extra=forbid): un campo desconocido es 422."""

    input: dict[str, Any] = Field(default_factory=dict)
    # Alcance de site (por defecto, todos). Un objetivo de otro site responde 404.
    site_id: UUID | None = None
    # Caso desde el que se lanza: la ejecución queda vinculada a él.
    incident_id: UUID | None = None
    idempotency_key: str | None = IdempotencyKey


class ToolConfirmRequest(RequestModel):
    version: int = Field(ge=1, le=2**31 - 1)
    # Confirmación explícita: sin ella la petición es 422.
    confirm: bool
    note: str | None = Field(default=None, min_length=3, max_length=500)


class ToolCancelRequest(RequestModel):
    version: int = Field(ge=1, le=2**31 - 1)


class DelegatedExecution(ResponseModel):
    execution_id: UUID
    action_id: str
    status: str


class ToolExecutionOut(ResponseModel):
    execution_id: UUID
    correlation_id: UUID
    tool_id: str
    tool_version: int
    tool_name: str
    category: str
    risk_level: str
    status: str
    invoker: str
    actor: str
    input: dict[str, Any]
    input_sha256: str
    output: dict[str, Any] | None
    output_sha256: str | None
    output_bytes: int | None
    truncated: bool
    summary: str | None
    evidence: list[dict[str, Any]]
    provenance: dict[str, Any] | None
    error_code: str | None
    error_message: str | None
    target_type: str | None
    target_id: UUID | None
    target_label: str | None
    site_id: UUID | None
    asset_id: UUID | None
    incident_id: UUID | None
    response_execution: DelegatedExecution | None
    approved_by: str | None
    approved_at: datetime | None
    approval_note: str | None
    cancelled_by: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    deadline_at: datetime | None
    duration_ms: int | None
    version: int
    # True si la petición coincidió con una ejecución existente (idempotencia o duplicado).
    deduplicated: bool = False


class ToolExecutionList(ResponseModel):
    items: list[ToolExecutionOut]
    total: int
