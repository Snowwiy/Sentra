"""Contrato de la API de Response y Playbooks (Fase 5D).

Ningún modelo de entrada tiene un campo de comando, script, ruta o plantilla: una acción se
pide por `action_id` del catálogo y sus `parameters` los valida el modelo de esa acción.
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.response.playbooks import PlaybookStepIn
from app.schemas.common import RequestModel, ResponseModel

IdempotencyKey = Field(default=None, min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
Reason = Field(default=None, max_length=500)


class IssueOut(ResponseModel):
    code: str
    message: str


# --- Catálogo --------------------------------------------------------------------------------


class ActionOut(ResponseModel):
    id: str
    name: str
    description: str
    category: str
    scope: Literal["server", "agent"]
    target_type: Literal["asset", "incident"]
    risk_level: str
    destructive: bool
    requires_confirmation: bool
    requires_agent: bool
    supported_platforms: list[str]
    required_role: str
    required_permissions: list[str]
    timeout_seconds: int
    retry_policy: str
    availability: str
    expected_effect: str
    # JSON Schema de los parámetros (para formularios), generado del modelo pydantic.
    parameters_schema: dict[str, Any]
    # Con ?asset_id=: si el rol del usuario puede ejecutarla y qué la bloquea en ese activo.
    permitted: bool
    blockers: list[IssueOut] = Field(default_factory=list)


class ActionList(ResponseModel):
    items: list[ActionOut]
    response_enabled: bool
    playbooks_enabled: bool


# --- Ejecución -------------------------------------------------------------------------------


class ExecutionRequest(RequestModel):
    action_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]{1,63}$")
    target_type: Literal["asset", "incident"] = "asset"
    target_id: UUID
    parameters: dict[str, Any] = Field(default_factory=dict)
    # Contexto opcional: ejecución lanzada desde un incidente o desde una detección.
    incident_id: UUID | None = None
    detection_id: UUID | None = None
    # Confirmación explícita (acciones con requires_confirmation).
    confirm: bool = False
    reason: str | None = Reason
    # Una por diálogo en la UI: repetir la petición devuelve la misma ejecución.
    idempotency_key: str | None = IdempotencyKey


class PreviewOut(ResponseModel):
    action: str
    action_name: str
    target_type: str
    target_id: UUID
    target_label: str
    parameters: dict[str, Any]
    risk_level: str
    required_role: str
    requires_confirmation: bool
    requires_agent: bool
    expected_effect: str
    preconditions: list[str]
    blockers: list[IssueOut]
    warnings: list[IssueOut]
    allowed: bool


class ExecutionOut(ResponseModel):
    execution_id: UUID
    correlation_id: UUID
    action_id: str
    action_name: str
    status: str
    risk_level: str
    requires_agent: bool
    target_type: str
    target_id: UUID
    target_label: str
    asset_id: UUID | None
    incident_id: UUID | None
    detection_id: UUID | None
    parameters: dict[str, Any]
    result: dict[str, Any] | None
    result_summary: str | None
    error_code: str | None
    error_message: str | None
    blockers: list[IssueOut]
    actor: str
    reason: str | None
    playbook_run_id: UUID | None
    step_index: int | None
    created_at: datetime
    queued_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    deadline_at: datetime | None
    duration_ms: int | None
    version: int
    # True si la petición coincidió con una ejecución ya existente (idempotencia/dedupe).
    deduplicated: bool = False


class ExecutionList(ResponseModel):
    items: list[ExecutionOut]
    total: int


class CancelRequest(RequestModel):
    version: int = Field(ge=1, le=2**31 - 1)
    reason: str | None = Reason


# --- Playbooks -------------------------------------------------------------------------------


class PlaybookStepOut(ResponseModel):
    order: int
    action_id: str
    action_name: str
    parameters: dict[str, Any]
    on_success: str
    on_failure: str
    timeout_seconds: int
    risk_level: str


class PlaybookOut(ResponseModel):
    playbook_id: UUID
    key: str
    name: str
    description: str
    builtin: bool
    enabled: bool
    version: int
    risk_level: str
    required_role: str
    requires_confirmation: bool
    requires_agent: bool
    steps: list[PlaybookStepOut]
    created_by: str
    created_at: datetime
    updated_at: datetime
    revision: int
    # Con ?asset_id=: si se puede ejecutar ahora sobre ese activo (sin bloqueos).
    permitted: bool
    blockers: list[IssueOut] = Field(default_factory=list)


class PlaybookList(ResponseModel):
    items: list[PlaybookOut]


class PlaybookCreate(RequestModel):
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=1000)
    steps: list[PlaybookStepIn] = Field(min_length=1, max_length=10)


class PlaybookUpdate(RequestModel):
    revision: int = Field(ge=1, le=2**31 - 1)
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=1000)
    steps: list[PlaybookStepIn] = Field(min_length=1, max_length=10)


class PlaybookToggle(RequestModel):
    revision: int = Field(ge=1, le=2**31 - 1)


class PlaybookRunRequest(RequestModel):
    target_id: UUID
    incident_id: UUID | None = None
    detection_id: UUID | None = None
    confirm: bool = False
    reason: str | None = Reason
    idempotency_key: str | None = IdempotencyKey


class PlaybookStepPreview(ResponseModel):
    order: int
    action_id: str
    action_name: str
    risk_level: str
    requires_agent: bool
    blockers: list[IssueOut]
    warnings: list[IssueOut]


class PlaybookPreviewOut(ResponseModel):
    playbook_id: UUID
    name: str
    version: int
    target_id: UUID
    target_label: str
    risk_level: str
    required_role: str
    requires_confirmation: bool
    steps: list[PlaybookStepPreview]
    blockers: list[IssueOut]
    allowed: bool


class PlaybookRunStepOut(ResponseModel):
    order: int
    action_id: str
    action_name: str
    on_failure: str
    status: str
    execution_id: UUID | None
    result_summary: str | None
    error_code: str | None
    error_message: str | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None


class PlaybookRunOut(ResponseModel):
    run_id: UUID
    playbook_id: UUID | None
    playbook_key: str
    playbook_name: str
    playbook_version: int
    status: str
    current_step: int
    risk_level: str
    target_id: UUID
    target_label: str
    incident_id: UUID | None
    detection_id: UUID | None
    actor: str
    reason: str | None
    error_code: str | None
    error_message: str | None
    created_at: datetime
    finished_at: datetime | None
    version: int
    steps: list[PlaybookRunStepOut]
    deduplicated: bool = False


class PlaybookRunList(ResponseModel):
    items: list[PlaybookRunOut]
    total: int


# --- Protocolo del agente --------------------------------------------------------------------


class CommandPollRequest(RequestModel):
    agent_id: UUID
    max_commands: int = Field(default=5, ge=1, le=10)


class AgentCommandOut(ResponseModel):
    request_id: UUID
    type: str
    params: dict[str, Any]
    # Hasta cuándo acepta el servidor el resultado de esta entrega.
    deadline_at: datetime


class CommandPollResponse(ResponseModel):
    commands: list[AgentCommandOut]


class CommandResultRequest(RequestModel):
    agent_id: UUID
    status: Literal["succeeded", "failed", "rejected"]
    summary: str = Field(default="", max_length=500)
    data: dict[str, Any] = Field(default_factory=dict)
    error_code: str | None = Field(default=None, max_length=64, pattern=r"^[a-z][a-z0-9_]{0,63}$")


class CommandResultResponse(ResponseModel):
    accepted: bool
    duplicate: bool
    status: str
