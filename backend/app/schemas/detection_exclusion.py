"""Contratos de las excepciones de reglas de detección (Fase 6E.5)."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from app.schemas.common import RequestModel, ResponseModel

ExclusionField = Literal[
    "exe",
    "name",
    "sha256",
    "signer",
    "parent_name",
    "remote_address",
    "script_path",
    "script_sha256",
]


class DetectionExclusionCreate(RequestModel):
    rule_id: str = Field(min_length=3, max_length=64, pattern=r"^[A-Z0-9-]+$")
    asset_id: UUID | None = None
    field: ExclusionField
    value: str = Field(min_length=1, max_length=1024)
    reason: str = Field(min_length=3, max_length=500)
    expires_at: AwareDatetime | None = None
    # Fase 7A.8: condiciones que además deben coincidir (ver app/detection/exclusions.py,
    # RULE_POLICIES: en SCR-001/CORR-002/NET-001/NET-002 son obligatorias según el campo).
    require_sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    port: int | None = Field(default=None, ge=1, le=65535)


class DetectionExclusionRead(ResponseModel):
    id: UUID
    rule_id: str
    asset_id: UUID | None
    asset_name: str | None
    field: ExclusionField
    value: str
    reason: str
    created_by: str
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    revoked_by: str | None
    active: bool
    hits: int
    last_hit_at: datetime | None
    require_sha256: str | None = None
    port: int | None = None


class DetectionExclusionList(ResponseModel):
    items: list[DetectionExclusionRead]
