"""Contratos de la API de Reporting (Fase 5E). Ver docs/reporting.md."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from app.schemas.common import RequestModel

RangePreset = Literal["24h", "7d", "30d", "90d", "custom"]
Classification = Literal["internal", "confidential", "restricted"]
# Los valores de cada lista se validan en el servicio contra el catálogo del tipo.
_ShortValue = Field(min_length=1, max_length=32, pattern=r"^[a-z0-9_]+$")


class ReportRange(RequestModel):
    preset: RangePreset = "30d"
    # Solo con preset=custom. Con zona horaria obligatoria (AwareDatetime): internamente UTC.
    from_: AwareDatetime | None = Field(default=None, alias="from")
    to: AwareDatetime | None = None

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, populate_by_name=True)


class ReportFilters(RequestModel):
    # Los topes de longitud aquí son de defensa (anti payload enorme); el límite real de ids
    # es REPORT_MAX_ASSETS y lo aplica el servicio con su propio código de error.
    asset_ids: list[UUID] = Field(default_factory=list, max_length=1000)
    incident_ids: list[UUID] = Field(default_factory=list, max_length=1000)
    detection_ids: list[UUID] = Field(default_factory=list, max_length=1000)
    execution_ids: list[UUID] = Field(default_factory=list, max_length=1000)
    playbook_ids: list[UUID] = Field(default_factory=list, max_length=1000)
    severities: list[str] = Field(default_factory=list, max_length=10)
    statuses: list[str] = Field(default_factory=list, max_length=20)
    risk_levels: list[str] = Field(default_factory=list, max_length=10)
    platforms: list[str] = Field(default_factory=list, max_length=5)
    include_archived: bool = False
    # Fase 5F: limita las secciones basadas en activos a los de un site (cualquier tipo).
    site_id: UUID | None = None


class ReportRequest(RequestModel):
    # Texto libre acotado: un id fuera del catálogo responde 422 report_type_unknown.
    report_type: str = Field(min_length=1, max_length=64)
    format: str = Field(min_length=1, max_length=16)
    classification: Classification = "internal"
    range: ReportRange = Field(default_factory=ReportRange)
    filters: ReportFilters = Field(default_factory=ReportFilters)


class ReportCreate(ReportRequest):
    # Una por diálogo/petición en la UI: repetirla devuelve el mismo informe.
    idempotency_key: str | None = Field(
        default=None, min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"
    )


class ReportTypeOut(BaseModel):
    id: str
    name: str
    description: str
    audience: str
    template_version: int
    supported_formats: list[str]
    filters: list[str]
    required_filters: list[str]
    severity_values: list[str]
    status_values: list[str]
    risk_level_values: list[str]
    platform_values: list[str]
    uses_range: bool
    max_range_days: int
    can_generate: bool


class ReportLimits(BaseModel):
    max_range_days: int
    max_ids: int
    max_rows: int


class ReportCatalog(BaseModel):
    items: list[ReportTypeOut]
    classifications: list[str]
    limits: ReportLimits
    enabled: bool


class ReportWarning(BaseModel):
    code: str
    message: str


class ReportPreview(BaseModel):
    report_type: str
    name: str
    format: str
    classification: str
    template_version: int
    time_from: datetime | None
    time_to: datetime | None
    timezone: str
    filters: dict[str, Any]
    sections: list[str]
    scope: dict[str, Any]
    warnings: list[ReportWarning]
    can_generate: bool


class ReportArtifactOut(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    created_at: datetime


class ReportOut(BaseModel):
    id: UUID
    report_type: str
    name: str
    title: str
    format: str
    classification: str
    status: str
    template_version: int
    requested_by: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    cutoff_at: datetime | None
    time_from: datetime | None
    time_to: datetime | None
    timezone: str
    filters: dict[str, Any]
    scope: dict[str, Any]
    summary: list[str]
    artifact: ReportArtifactOut | None
    snapshot_sha256: str | None
    error_code: str | None
    error_message: str | None
    cancel_requested: bool
    deduplicated: bool = False
    can_cancel: bool
    can_delete: bool
    version: int


class ReportList(BaseModel):
    items: list[ReportOut]
    total: int
