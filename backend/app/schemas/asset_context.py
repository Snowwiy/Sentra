"""Contratos de Asset Context y del resumen de amenaza interno por activo (Fase 4L)."""

import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.discovery.device_types import ClassificationConfidence
from app.models.asset import AssetCriticality
from app.models.asset_context import AssetEnvironment, AssetRole, DataSensitivity, NetworkZone
from app.schemas.common import RequestModel, ResponseModel

# Límites de los campos de texto libre. Son metadatos administrativos, no documentos.
OWNER_MAX = 128
DEPARTMENT_MAX = 64
RATIONALE_MAX = 200
# Etiquetas: por activo y longitud de cada una (tras normalizar). El total de etiquetas
# distintas de toda la plataforma se limita en el servicio (MAX_DISTINCT_TAGS).
MAX_TAGS = 20
TAG_MAX = 32
TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")

# Texto administrativo: se trata como texto plano no confiable. Se rechazan los caracteres
# de control y los delimitadores de marcado (< >): no aportan nada a un nombre de equipo o
# departamento y evitan que un valor con HTML llegue a otros consumidores (exportaciones,
# IA, futuros informes) aunque la UI siempre lo escape.
_FORBIDDEN_TEXT = re.compile(r"[\x00-\x1f\x7f<>]")

ManagedState = Literal["DISCOVERED", "MONITORED", "MANAGED"]
# Tipo de dato: configurado por una persona, observado por Sentra o inferido (sugerencia).
ContextKind = Literal["configured", "observed", "inferred"]


def clean_admin_text(value: str | None, limit: int) -> str | None:
    """Normaliza un texto administrativo: recorta, colapsa espacios y valida. "" = borrar."""
    if value is None:
        return None
    text = " ".join(value.split())
    if not text:
        return None
    if len(text) > limit:
        raise ValueError(f"must be at most {limit} characters")
    if _FORBIDDEN_TEXT.search(text):
        raise ValueError("must be plain text (no control characters, '<' or '>')")
    return text


def normalize_tag(raw: str) -> str:
    """ "Critical Service" -> "critical-service". Lanza ValueError si no queda válida."""
    tag = "-".join(raw.strip().lower().split())
    if not TAG_PATTERN.fullmatch(tag):
        raise ValueError(
            f"invalid tag {raw[:40]!r}: 1-{TAG_MAX} characters a-z, 0-9, '.', '_' or '-'"
        )
    return tag


def normalize_tags(values: list[str]) -> list[str]:
    """Normaliza, quita duplicados (conservando el orden) y aplica el límite por activo."""
    tags = list(dict.fromkeys(normalize_tag(v) for v in values))
    if len(tags) > MAX_TAGS:
        raise ValueError(f"at most {MAX_TAGS} tags per asset")
    return tags


class AssetContextUpdate(RequestModel):
    """PATCH parcial: solo se cambian los campos presentes. `version` es obligatoria.

    No existe ningún campo de origen (source): todo lo que entra por la API es manual. Un
    cliente que intente fijar source/provenance recibe 422 (extra="forbid").
    """

    # Versión leída en GET /assets/{id}/context (0 si el activo aún no tiene contexto).
    version: int = Field(ge=0, le=2_147_483_647)
    criticality: AssetCriticality | None = None
    criticality_rationale: str | None = Field(default=None, max_length=RATIONALE_MAX * 2)
    role: AssetRole | None = None
    environment: AssetEnvironment | None = None
    owner: str | None = Field(default=None, max_length=OWNER_MAX * 2)
    department: str | None = Field(default=None, max_length=DEPARTMENT_MAX * 2)
    data_sensitivity: DataSensitivity | None = None
    network_zone: NetworkZone | None = None
    # true / false; null = desconocido (vuelve a "unknown").
    internet_exposed: bool | None = None
    # Conjunto completo de etiquetas (reemplaza). [] borra todas.
    tags: list[str] | None = Field(default=None, max_length=MAX_TAGS * 2)

    @field_validator("owner")
    @classmethod
    def _owner(cls, value: str | None) -> str | None:
        return clean_admin_text(value, OWNER_MAX)

    @field_validator("department")
    @classmethod
    def _department(cls, value: str | None) -> str | None:
        return clean_admin_text(value, DEPARTMENT_MAX)

    @field_validator("criticality_rationale")
    @classmethod
    def _rationale(cls, value: str | None) -> str | None:
        return clean_admin_text(value, RATIONALE_MAX)

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        for item in value:
            if len(item) > TAG_MAX * 2:
                raise ValueError(f"tags must be at most {TAG_MAX} characters")
        return normalize_tags(value)

    @model_validator(mode="after")
    def _not_empty(self) -> "AssetContextUpdate":
        # Los enums y la criticidad no admiten null explícito: "unknown" es el valor que
        # borra un rol/entorno/zona/sensibilidad. La criticidad siempre tiene valor (4I).
        for name in (
            "criticality",
            "role",
            "environment",
            "data_sensitivity",
            "network_zone",
            "tags",
        ):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} cannot be null")
        if not (self.model_fields_set - {"version"}):
            raise ValueError("no context fields to update")
        return self


class FieldProvenance(ResponseModel):
    # manual hoy; agent/discovery/inferred y las fuentes futuras usan la misma forma.
    source: str
    kind: ContextKind
    # Solo para datos inferidos: nunca se inventa una confianza para un dato manual.
    confidence: ClassificationConfidence | None = None
    updated_at: datetime | None = None
    updated_by: str | None = None


class RoleSuggestion(ResponseModel):
    """Rol sugerido por la identificación (4E). Nunca sustituye a un rol confirmado."""

    value: AssetRole
    # agent o discovery: quién observó los datos de los que sale la sugerencia.
    source: str
    kind: ContextKind = "inferred"
    confidence: ClassificationConfidence | None
    reason: str | None


class ContextCompleteness(ResponseModel):
    """Calidad del inventario (no seguridad): cuántos campos administrativos se conocen."""

    percent: int
    complete: bool
    known: list[str]
    missing: list[str]


class AssetContextRead(ResponseModel):
    asset_id: UUID
    # Token de concurrencia: 0 si el activo aún no tiene contexto guardado.
    version: int
    criticality: AssetCriticality
    # False mientras la criticidad sea el valor por defecto de 4I sin confirmar.
    criticality_confirmed: bool
    criticality_rationale: str | None
    criticality_updated_at: datetime | None
    criticality_updated_by: str | None
    role: AssetRole
    role_suggestion: RoleSuggestion | None
    environment: AssetEnvironment
    owner: str | None
    department: str | None
    data_sensitivity: DataSensitivity
    network_zone: NetworkZone
    # null = desconocido (no es "no expuesto").
    internet_exposed: bool | None
    tags: list[str]
    # DISCOVERED / MONITORED / MANAGED (reutiliza monitoring_method) y de dónde viene la
    # visibilidad: agent, discovery y/o manual.
    managed_state: ManagedState
    visibility_sources: list[str]
    provenance: dict[str, FieldProvenance]
    completeness: ContextCompleteness
    updated_at: datetime | None
    updated_by: str | None


class AssetContextBrief(ResponseModel):
    """Contexto relevante para incidentes, detecciones y listados (sin etiquetas)."""

    criticality: AssetCriticality
    role: AssetRole
    environment: AssetEnvironment
    owner: str | None
    department: str | None
    data_sensitivity: DataSensitivity
    network_zone: NetworkZone
    internet_exposed: bool | None
    context_complete: bool


class AssetContextSnapshot(ResponseModel):
    """Snapshot mínimo guardado en un incidente (al crear/vincular y al resolver)."""

    criticality: str | None = None
    role: str | None = None
    environment: str | None = None
    data_sensitivity: str | None = None
    network_zone: str | None = None
    internet_exposed: bool | None = None
    captured_at: datetime | None = None


class AssetContextChangeRead(ResponseModel):
    changed_at: datetime
    field: str
    old_value: str | None
    new_value: str | None
    source: str
    actor: str


class AssetContextHistory(ResponseModel):
    items: list[AssetContextChangeRead]
    total: int


class ContextLimits(ResponseModel):
    owner_max: int = OWNER_MAX
    department_max: int = DEPARTMENT_MAX
    rationale_max: int = RATIONALE_MAX
    max_tags: int = MAX_TAGS
    tag_max: int = TAG_MAX
    tag_pattern: str = TAG_PATTERN.pattern


class AssetContextOptions(ResponseModel):
    criticality: list[AssetCriticality]
    role: list[AssetRole]
    environment: list[AssetEnvironment]
    data_sensitivity: list[DataSensitivity]
    network_zone: list[NetworkZone]
    # Valores ya usados, para autocompletar y mantener el texto "controlado".
    departments: list[str]
    tags: list[str]
    limits: ContextLimits


class ThreatRisk(ResponseModel):
    score: int
    level: str
    confidence: str
    calculated_at: datetime | None


class AssetThreatSummary(ResponseModel):
    """Contexto de amenaza INTERNO (datos que Sentra ya tiene). Sin feeds externos."""

    asset_id: UUID
    # Ventana de "reciente" para cambios de exposición y de contexto.
    window_days: int
    active_detection_count: int
    high_critical_detection_count: int
    open_incident_count: int
    highest_incident_severity: str | None
    current_risk: ThreatRisk | None
    recent_exposure_changes: int
    recent_context_changes: int
    last_security_activity: datetime | None
    criticality: AssetCriticality
    environment: AssetEnvironment
    managed_state: ManagedState
