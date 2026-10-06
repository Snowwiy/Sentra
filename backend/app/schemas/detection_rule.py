"""Contratos de la API de reglas de detección (Fase 5A): catálogo, CRUD, versiones, pruebas y
Sigma. Las definiciones viajan como JSON declarativo (sentra-rule/1) y se validan en el
servicio con una allowlist estricta; aquí solo se acotan tamaños.
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.models.detection import DetectionConfidence, DetectionSeverity
from app.schemas.common import RequestModel, ResponseModel

RuleSourceName = Literal["builtin", "custom", "sigma"]
RuleStatusName = Literal["draft", "active", "disabled", "retired"]
CompileStatusName = Literal["valid", "partial", "unsupported", "invalid"]
SortField = Literal["title", "updated_at", "last_triggered", "severity", "source"]
RULE_UID_PATTERN = r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$"
MAX_SIGMA_CHARS = 64 * 1024
# Valores de un evento sintético: escalares acotados (nunca estructuras anidadas).
SyntheticValue = str | int | bool | None


class RuleIssue(ResponseModel):
    code: str
    message: str
    path: str = ""


class RuleStatsRead(ResponseModel):
    evaluations: int = 0
    matches: int = 0
    errors: int = 0
    consecutive_errors: int = 0
    slow_evaluations: int = 0
    avg_eval_ms: float | None = None
    last_evaluated_at: datetime | None = None
    last_matched_at: datetime | None = None
    last_error_at: datetime | None = None
    # Categoría del error (tipo de excepción), nunca datos del evento.
    last_error: str | None = None


class DetectionRuleRead(ResponseModel):
    """Una regla del listado unificado (built-in, custom o Sigma).

    Superconjunto del contrato de la Fase 4H: los campos antiguos (kind, triggers,
    required_data, cooldown_minutes...) siguen igual para no romper la UI existente.
    """

    rule_id: str
    source: RuleSourceName
    version: int
    status: RuleStatusName
    enabled: bool
    compile_status: CompileStatusName
    # Built-in: siempre de solo lectura (se activan/desactivan con DETECTION_DISABLED_RULES).
    read_only: bool
    kind: str
    category: str
    title: str
    description: str
    why: str
    severity: DetectionSeverity
    confidence: DetectionConfidence
    logsource: str | None
    triggers: list[str]
    required_data: list[str]
    recommendations: list[str]
    mitre_tactic: str | None
    mitre_technique: str | None
    mitre_subtechnique: str | None
    cooldown_minutes: int
    sigma_id: UUID | None = None
    # Concurrencia optimista: hay que enviarla en cada cambio (409 si es antigua).
    revision: int | None = None
    updated_at: datetime | None = None
    updated_by: str | None = None
    detections_24h: int = 0
    last_triggered_at: datetime | None = None
    errors: int = 0
    consecutive_errors: int = 0


class DetectionRuleList(ResponseModel):
    items: list[DetectionRuleRead]
    total: int
    windows: dict[str, int]
    alert_min_severity: DetectionSeverity | None


class RuleDetail(DetectionRuleRead):
    tags: list[str]
    # Definición declarativa normalizada (custom/Sigma). None en built-in (viven en código).
    definition: dict[str, Any] | None
    compiled: dict[str, Any] | None
    compile_issues: list[RuleIssue]
    complexity: Literal["low", "medium", "high"] | None
    stats: RuleStatsRead
    detections_total: int
    sigma_metadata: dict[str, Any] | None
    has_sigma_source: bool
    created_at: datetime | None
    created_by: str | None
    retired_at: datetime | None
    logsource_title: str | None


class RuleVersionRead(ResponseModel):
    version: int
    created_at: datetime
    created_by: str
    change_note: str
    compile_status: CompileStatusName
    title: str
    severity: DetectionSeverity
    confidence: DetectionConfidence
    current: bool


class RuleVersionList(ResponseModel):
    items: list[RuleVersionRead]


class RuleVersionDetail(RuleVersionRead):
    description: str
    why: str
    recommendations: list[str]
    category: str
    mitre_tactic: str | None
    mitre_technique: str | None
    mitre_subtechnique: str | None
    tags: list[str]
    definition: dict[str, Any]
    compiled: dict[str, Any]
    compile_issues: list[RuleIssue]
    content_hash: str


class RuleChange(ResponseModel):
    field: str
    before: Any
    after: Any


class RuleDiff(ResponseModel):
    rule_id: str
    from_version: int
    to_version: int
    changes: list[RuleChange]


# --- Entradas ---------------------------------------------------------------------------------


class RuleContentIn(RequestModel):
    """Campos de contenido de una regla (todo lo que crea una versión nueva)."""

    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=2000)
    why: str = Field(default="", max_length=1000)
    recommendations: list[str] = Field(default_factory=list, max_length=10)
    severity: DetectionSeverity = DetectionSeverity.MEDIUM
    confidence: DetectionConfidence = DetectionConfidence.LOW
    category: str | None = Field(default=None, max_length=32)
    mitre_tactic: str | None = Field(default=None, max_length=16)
    mitre_technique: str | None = Field(default=None, max_length=16)
    mitre_subtechnique: str | None = Field(default=None, max_length=16)
    tags: list[str] = Field(default_factory=list, max_length=20)
    # JSON declarativo sentra-rule/1. Se valida con allowlist en el servicio.
    definition: dict[str, Any]


class RuleCreate(RuleContentIn):
    pass


class RuleUpdate(RequestModel):
    revision: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    why: str | None = Field(default=None, max_length=1000)
    recommendations: list[str] | None = Field(default=None, max_length=10)
    severity: DetectionSeverity | None = None
    confidence: DetectionConfidence | None = None
    category: str | None = Field(default=None, max_length=32)
    mitre_tactic: str | None = Field(default=None, max_length=16)
    mitre_technique: str | None = Field(default=None, max_length=16)
    mitre_subtechnique: str | None = Field(default=None, max_length=16)
    tags: list[str] | None = Field(default=None, max_length=20)
    definition: dict[str, Any] | None = None
    # Una regla activa que pasa a una versión "partial" exige confirmarlo.
    acknowledge_partial: bool = False


class RuleStateChange(RequestModel):
    revision: int = Field(ge=1)
    # Activar una regla de cobertura parcial (p. ej. Sigma process_creation) exige confirmar
    # que se entienden sus límites.
    acknowledge_partial: bool = False


class RuleValidateIn(RequestModel):
    definition: dict[str, Any]
    mitre_tactic: str | None = Field(default=None, max_length=16)
    mitre_technique: str | None = Field(default=None, max_length=16)
    mitre_subtechnique: str | None = Field(default=None, max_length=16)
    category: str | None = Field(default=None, max_length=32)


class RuleValidation(ResponseModel):
    valid: bool
    compile_status: CompileStatusName
    errors: list[RuleIssue]
    warnings: list[RuleIssue]
    definition: dict[str, Any] | None
    compiled: dict[str, Any] | None
    complexity: Literal["low", "medium", "high"] | None


class SyntheticEvent(RequestModel):
    # Campos del catálogo del logsource (event.code, event.data.TargetUserName, asset.role...).
    fields: dict[str, SyntheticValue] = Field(max_length=64)
    occurred_at: datetime | None = None


class RuleTestIn(RequestModel):
    # Una definición en edición o una regla guardada (su versión vigente).
    definition: dict[str, Any] | None = None
    rule_id: str | None = Field(default=None, max_length=32, pattern=RULE_UID_PATTERN)
    events: list[SyntheticEvent] = Field(min_length=1, max_length=100)


class EventTestResult(ResponseModel):
    index: int
    matched: bool
    group: str | None
    missing_fields: list[str]


class SimulatedDetection(ResponseModel):
    group: str
    count: int
    first_at: datetime
    last_at: datetime


class RuleTestResult(ResponseModel):
    matched: int
    events: list[EventTestResult]
    # Detecciones que se habrían creado (con umbral: grupos que lo alcanzan). Nada se guarda.
    would_detect: list[SimulatedDetection]
    threshold: int | None
    window_minutes: int | None
    duration_ms: float


class HistoricalTestIn(RequestModel):
    definition: dict[str, Any] | None = None
    rule_id: str | None = Field(default=None, max_length=32, pattern=RULE_UID_PATTERN)
    since: datetime | None = None
    until: datetime | None = None
    asset_id: UUID | None = None
    # Coincidencias de ejemplo devueltas (las filas examinadas las acota RULE_TEST_MAX_ROWS).
    limit: int = Field(default=20, ge=1, le=50)


class HistoricalMatch(ResponseModel):
    occurred_at: datetime
    asset_id: UUID
    hostname: str
    source_id: str | None
    summary: str
    fields: dict[str, Any]


class HistoricalGroup(ResponseModel):
    asset_id: UUID
    hostname: str
    group: str
    max_count: int
    first_at: datetime


class HistoricalTestResult(ResponseModel):
    # "events" (system_events) o "signals" (detection_signals, retención corta).
    data_source: str
    since: datetime
    until: datetime
    scanned: int
    matched: int
    # True si se alcanzó RULE_TEST_MAX_ROWS: hay más datos sin examinar en el rango.
    truncated: bool
    sample: list[HistoricalMatch]
    would_detect: list[HistoricalGroup]
    threshold: int | None
    duration_ms: float
    notes: list[str]


class SigmaIn(RequestModel):
    # Texto YAML (pegado o leído de un .yml en el navegador). Nunca se guarda en disco.
    yaml: str = Field(min_length=1, max_length=MAX_SIGMA_CHARS)


class SigmaImportIn(SigmaIn):
    # Misma regla Sigma (mismo id) ya importada con otro contenido: "update" crea una
    # versión nueva (con `revision`); "reject" (por defecto) no toca nada.
    on_duplicate: Literal["reject", "update"] = "reject"
    revision: int | None = Field(default=None, ge=1)


class SigmaSource(ResponseModel):
    rule_id: str
    # YAML original tal como se importó (versión vigente). Texto: la UI nunca lo interpreta.
    yaml: str


class SigmaDuplicate(ResponseModel):
    # none | identical | changed | retired
    state: str
    rule_id: str | None = None
    current_version: int | None = None
    revision: int | None = None


class SigmaPreview(ResponseModel):
    # supported | partial | unsupported | invalid
    outcome: str
    title: str
    sigma_id: UUID | None
    level: str | None
    severity: DetectionSeverity
    confidence: DetectionConfidence
    logsource: dict[str, str]
    sentra_logsource: str | None
    mitre_tactic: str | None
    mitre_technique: str | None
    mitre_subtechnique: str | None
    tags: list[str]
    metadata: dict[str, Any]
    errors: list[RuleIssue]
    unsupported: list[RuleIssue]
    warnings: list[RuleIssue]
    definition: dict[str, Any] | None
    compiled: dict[str, Any] | None
    duplicate: SigmaDuplicate


class SigmaImportResult(ResponseModel):
    # imported | imported_with_warnings | updated | unchanged | unsupported | rejected
    result: str
    rule: RuleDetail | None
    preview: SigmaPreview


class FieldRead(ResponseModel):
    name: str
    type: str
    description: str
    values: list[str]
    operators: list[str]


class LogSourceRead(ResponseModel):
    name: str
    title: str
    support: str
    platforms: list[str]
    notes: str
    event_codes: list[int]
    sigma_hint: str
    default_category: str
    fields: list[FieldRead]


class CompatibilityRead(ResponseModel):
    area: str
    support: str
    notes: str
    logsources: list[str]


class RuleCatalog(ResponseModel):
    logsources: list[LogSourceRead]
    asset_fields: list[FieldRead]
    categories: list[str]
    limits: dict[str, int]
    compatibility: list[CompatibilityRead]
    sigma_default_confidence: DetectionConfidence
