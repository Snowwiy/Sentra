"""Contratos de la investigación forense remota (Fase 6E.6, docs/forensic-investigation.md)."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.schemas.common import RequestModel, ResponseModel

InvestigationStatus = Literal["open", "closed"]
Integrity = Literal["verified", "mismatch"]
NoteKind = Literal["note", "ai_summary"]


class InvestigationCreate(RequestModel):
    asset_id: UUID
    title: str = Field(min_length=3, max_length=200)
    incident_id: UUID | None = None


class InvestigationVersion(RequestModel):
    version: int = Field(ge=1)


class LegalHoldUpdate(RequestModel):
    version: int = Field(ge=1)
    legal_hold: bool


class NoteCreate(RequestModel):
    # Texto plano: la UI lo muestra escapado. `ai_summary` marca una interpretación de IA
    # pegada por el analista; nunca se confunde con evidencia.
    kind: NoteKind = "note"
    body: str = Field(min_length=1, max_length=8000)


class InvestigationRead(ResponseModel):
    id: UUID
    asset_id: UUID
    asset_label: str
    asset_exists: bool
    incident_id: UUID | None
    title: str
    status: InvestigationStatus
    legal_hold: bool
    created_by: str
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    closed_by: str | None
    version: int
    artifact_count: int
    mismatch_count: int


class InvestigationList(ResponseModel):
    items: list[InvestigationRead]
    total: int


class ArtifactRead(ResponseModel):
    id: UUID
    action: str
    operator: str
    scope: dict[str, Any]
    sha256: str
    agent_sha256: str | None
    integrity: Integrity
    size_bytes: int
    truncated: bool
    limitations: list[dict[str, Any]]
    agent_version: str | None
    platform: str | None
    collected_at: datetime | None
    received_at: datetime
    execution_id: UUID | None


class ArtifactDetail(ArtifactRead):
    investigation_id: UUID
    content: Any


class NoteRead(ResponseModel):
    id: UUID
    kind: NoteKind
    body: str
    author: str
    created_at: datetime


class PackageRead(ResponseModel):
    id: UUID
    sha256: str
    size_bytes: int
    artifact_count: int
    includes_mismatch: bool
    created_by: str
    created_at: datetime


class CollectionRead(ResponseModel):
    """Recogida pedida (ejecución de Response) con su estado, haya o no artefacto aún."""

    execution_id: UUID
    action: str
    status: str
    actor: str
    created_at: datetime
    finished_at: datetime | None
    error_code: str | None


class InvestigationDetail(ResponseModel):
    investigation: InvestigationRead
    artifacts: list[ArtifactRead]
    notes: list[NoteRead]
    collections: list[CollectionRead]
    packages: list[PackageRead]
