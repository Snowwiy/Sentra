"""Contratos de operaciones de mantenimiento y atribución de detecciones (Fase 7B.1)."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from app.schemas.common import RequestModel, ResponseModel

OperationKind = Literal[
    "agent_install",
    "agent_upgrade",
    "sensor_install",
    "database_init",
    "server_setup",
    "software_install",
    "other",
]
OperationStatus = Literal["pending_review", "approved", "revoked", "superseded"]
ArtifactKind = Literal["script", "binary", "service"]
ReferenceSource = Literal["manual", "server_distribution"]
Verdict = Literal[
    "verified_benign", "suspicious_unverified", "insufficient_evidence", "confirmed_malicious"
]
# Lo que un analista puede declarar a mano. "verified_benign" no: verificar exige una
# operación aprobada cuya evidencia case (no basta con la opinión de alguien).
AnalystVerdict = Literal["confirmed_malicious", "suspicious_unverified", "insufficient_evidence"]

SHA256 = r"^[0-9a-fA-F]{64}$"


class ArtifactIn(RequestModel):
    kind: ArtifactKind
    path: str | None = Field(default=None, min_length=3, max_length=1024)
    sha256: str | None = Field(default=None, pattern=SHA256)
    signer: str | None = Field(default=None, min_length=1, max_length=255)
    reference_source: ReferenceSource = "manual"
    service_name: str | None = Field(default=None, min_length=1, max_length=255)
    service_display_name: str | None = Field(default=None, min_length=1, max_length=255)
    image_path: str | None = Field(default=None, min_length=3, max_length=1024)
    service_account: str | None = Field(default=None, min_length=1, max_length=255)


class MaintenanceOperationCreate(RequestModel):
    asset_id: UUID
    kind: OperationKind
    title: str = Field(min_length=3, max_length=200)
    reason: str = Field(min_length=10, max_length=1000)
    window_start: AwareDatetime
    window_end: AwareDatetime
    expires_at: AwareDatetime
    accounts: list[str] = Field(default_factory=list, max_length=10)
    interpreters: list[str] = Field(default_factory=list, max_length=5)
    parents: list[str] = Field(default_factory=list, max_length=5)
    signer: str | None = Field(default=None, min_length=1, max_length=255)
    artifacts: list[ArtifactIn] = Field(min_length=1, max_length=20)
    # Versión nueva de una operación existente (la anterior pasa a "superseded" al aprobar).
    supersedes: UUID | None = None


class OperationDecision(RequestModel):
    note: str | None = Field(default=None, max_length=500)


class OperationRevoke(RequestModel):
    reason: str = Field(min_length=3, max_length=500)


class OperationApply(RequestModel):
    # Confirmación explícita tras ver la vista previa: aplica los veredictos a las
    # detecciones de la ventana y recalcula el riesgo del activo.
    confirm: Literal[True]


class MaintenanceArtifactRead(ResponseModel):
    kind: ArtifactKind
    path: str | None
    sha256: str | None
    signer: str | None
    reference_source: ReferenceSource
    service_name: str | None
    service_display_name: str | None
    image_path: str | None
    service_account: str | None


class MaintenanceOperationRead(ResponseModel):
    id: UUID
    operation_key: UUID
    version: int
    supersedes: UUID | None
    asset_id: UUID
    asset_name: str
    kind: OperationKind
    title: str
    reason: str
    status: OperationStatus
    active: bool
    window_start: datetime
    window_end: datetime
    expires_at: datetime
    accounts: list[str]
    interpreters: list[str]
    parents: list[str]
    signer: str | None
    artifacts: list[MaintenanceArtifactRead]
    created_by: str
    created_at: datetime
    approved_by: str | None
    approved_at: datetime | None
    approval_note: str | None
    revoked_by: str | None
    revoked_at: datetime | None
    revoke_reason: str | None
    matches: int
    last_match_at: datetime | None


class MaintenanceOperationList(ResponseModel):
    items: list[MaintenanceOperationRead]
    total: int


class AttributionPreviewItem(ResponseModel):
    detection_id: UUID
    rule_id: str
    title: str
    status: str
    current_verdict: Verdict | None
    verdict: Verdict
    # Si al aplicar la detección se cerraría como mantenimiento verificado.
    would_resolve: bool
    attribution: dict[str, Any]


class AttributionPreview(ResponseModel):
    operation_id: UUID
    items: list[AttributionPreviewItem]
    verified: int
    not_verified: int


class AttributionApplyResult(ResponseModel):
    operation_id: UUID
    evaluated: int
    verified: int
    resolved: int


class ReferenceArtifact(ResponseModel):
    """Script que distribuye este servidor, con su hash calculado aquí (no aprendido)."""

    name: str
    relative_path: str
    sha256: str
    size: int


class ReferenceArtifactList(ResponseModel):
    root_available: bool
    items: list[ReferenceArtifact]


class AttributionEventRead(ResponseModel):
    id: UUID
    verdict: Verdict
    previous_verdict: Verdict | None
    source: Literal["system", "analyst"]
    actor: str
    reason: str | None
    operation_id: UUID | None
    created_at: datetime
    evidence: dict[str, Any] | None


class DetectionAttributionRead(ResponseModel):
    detection_id: UUID
    rule_id: str
    attributable: bool
    verdict: Verdict | None
    attribution: dict[str, Any] | None
    evaluated_at: datetime | None
    history: list[AttributionEventRead]


class AnalystVerdictIn(RequestModel):
    verdict: AnalystVerdict
    reason: str = Field(min_length=10, max_length=1000)
