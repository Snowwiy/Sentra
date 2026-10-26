"""Contratos de tareas de caso y solicitudes de control de red (Fase 7A.6).

Igual que en los casos (4K): el cliente solo envía referencias (ids públicos) y texto del
analista; el servidor valida cada referencia y deriva las etiquetas. Toda mutación lleva
`version` (concurrencia optimista, 409 si otro usuario cambió la fila).
"""

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, model_validator

from app.incidents.network_controls import ControlTargetError, check_direction, normalize_target
from app.schemas.common import RequestModel, ResponseModel
from app.schemas.incident import IncidentUserRef

Version = Annotated[int, Field(ge=1, le=2_147_483_647)]
TaskKind = Literal[
    "investigate_port",
    "verify_service",
    "review_vulnerability",
    "analyze_evidence",
    "investigate_script",
    "review_network_activity",
    "request_policy",
    "verify_remediation",
    "prepare_block_rule",
    "document_exception",
    "other",
]
TaskStatus = Literal["open", "in_progress", "blocked", "done", "cancelled"]
EvidenceType = Literal[
    "detection",
    "alert",
    "asset",
    "vulnerability",
    "tool_execution",
    "response_execution",
]
ControlType = Literal[
    "block_port",
    "block_service",
    "block_address",
    "block_domain",
    "restrict_site_access",
    "prevent_upload",
]
ControlStatus = Literal["pending_approval", "approved", "rejected", "cancelled", "expired"]
EnforcementStatus = Literal["not_evaluated", "no_enforcement_point", "applied_manually"]
Direction = Literal["inbound", "outbound", "both"]


# --- Tareas ------------------------------------------------------------------------------------


class TaskCreate(RequestModel):
    kind: TaskKind
    title: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    # Activo del caso sobre el que trata la tarea (debe estar ya vinculado al caso).
    asset_id: UUID | None = None
    # Responsable (id público). Null = sin asignar. Ver docs/case-operations.md para quién
    # puede asignar a quién.
    assignee_user_id: UUID | None = None
    due_at: datetime | None = None


class TaskUpdate(RequestModel):
    """PATCH: solo cambian los campos presentes. Terminar (`done`) exige `result`."""

    version: Version
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    status: TaskStatus | None = None
    result: str | None = Field(default=None, min_length=1, max_length=10_000)
    due_at: datetime | None = None


class TaskAssign(RequestModel):
    version: Version
    # Null = asignársela uno mismo.
    user_id: UUID | None = None


class TaskVersioned(RequestModel):
    version: Version


class TaskEvidenceAdd(RequestModel):
    version: Version
    type: EvidenceType
    id: UUID


class TaskEvidenceRead(ResponseModel):
    type: EvidenceType
    id: UUID
    label: str
    added_by: str
    added_at: datetime


class TaskAssetRef(ResponseModel):
    asset_id: UUID
    name: str


class TaskRead(ResponseModel):
    task_id: UUID
    incident_id: UUID
    incident_key: str
    kind: TaskKind
    title: str
    description: str | None
    status: TaskStatus
    asset: TaskAssetRef | None
    assignee: IncidentUserRef | None
    # Nombre copiado al asignar (se conserva aunque la cuenta cambie o se borre).
    assignee_name: str | None
    assigned_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    completed_by: str | None
    due_at: datetime | None
    overdue: bool
    result: str | None
    evidence: list[TaskEvidenceRead]
    version: int
    # Estados a los que se puede pasar (comodidad de UI; el backend vuelve a validar).
    allowed_transitions: list[TaskStatus]


class TaskList(ResponseModel):
    items: list[TaskRead]
    total: int


# --- Solicitudes de control de red ------------------------------------------------------------


class NetworkControlCreate(RequestModel):
    control_type: ControlType
    # Claves exactas por tipo (app/incidents/network_controls.py): port+protocol, service
    # (+port), cidr, domain o destination. Se normaliza antes de guardarse.
    target: dict[str, Any]
    direction: Direction | None = None
    # Alcance: un activo o un site (como mucho uno). Sin ninguno, toda la instalación.
    asset_id: UUID | None = None
    site_id: UUID | None = None
    task_id: UUID | None = None
    justification: str = Field(min_length=10, max_length=5000)
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def _normalize(self) -> "NetworkControlCreate":
        try:
            self.target = normalize_target(self.control_type, self.target)
            self.direction = check_direction(self.control_type, self.direction)
        except ControlTargetError as exc:
            raise ValueError(str(exc)) from exc
        if self.asset_id is not None and self.site_id is not None:
            raise ValueError("scope is either one asset or one site, not both")
        return self


class NetworkControlDecision(RequestModel):
    version: Version
    note: str | None = Field(default=None, max_length=1000)


class NetworkControlReject(RequestModel):
    version: Version
    # Un rechazo siempre explica por qué (queda en el caso y en la auditoría).
    note: str = Field(min_length=3, max_length=1000)


class NetworkControlApplied(RequestModel):
    version: Version
    # Dónde y cómo se aplicó fuera de Sentra (regla de firewall, política del proxy...).
    note: str = Field(min_length=3, max_length=1000)


class ControlScope(ResponseModel):
    type: Literal["asset", "site", "global"]
    asset_id: UUID | None
    site_id: UUID | None
    label: str


class EnforcementRead(ResponseModel):
    points: list[str]
    applied_by_sentra: bool
    needs: str
    note: str


class NetworkControlRead(ResponseModel):
    control_id: UUID
    incident_id: UUID
    incident_key: str
    task_id: UUID | None
    control_type: ControlType
    target: dict[str, Any]
    direction: Direction | None
    scope: ControlScope
    justification: str
    status: ControlStatus
    enforcement_status: EnforcementStatus
    enforcement: EnforcementRead | None
    expires_at: datetime | None
    requested_by: str
    created_at: datetime
    updated_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    decision_note: str | None
    # Aprobada por quien la pidió (instalaciones con un solo admin): visible, no oculto.
    self_approved: bool
    applied_by: str | None
    applied_at: datetime | None
    applied_note: str | None
    version: int


class NetworkControlList(ResponseModel):
    items: list[NetworkControlRead]
    total: int


class ControlCapability(ResponseModel):
    control_type: ControlType
    available: bool
    points: list[str]
    needs: str
    note: str


class ControlCapabilities(ResponseModel):
    # Siempre false en 7A: Sentra registra la decisión pero no aplica controles de red.
    any_available: bool
    items: list[ControlCapability]
