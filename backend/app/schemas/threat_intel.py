"""Contratos de la API de Threat Intelligence (Fase 5C). Ver docs/threat-intelligence.md.

Nunca se devuelven secretos ni URLs completas de descarga (solo el host): una URL de
THREAT_INTEL_SOURCE_URLS podría llevar un token en la query.
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.schemas.common import RequestModel, ResponseModel

Trust = Literal["official", "trusted", "community", "local"]
Category = Literal[
    "vulnerability", "ioc", "advisory", "exploitation", "reputation", "campaign", "other"
]
ImportFormat = Literal["sentra-ioc", "stix"]
SourceKey = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,63}$")


# --- Fuentes -----------------------------------------------------------------------------------


class ThreatSourceRead(ResponseModel):
    id: int
    source_key: str
    name: str
    description: str | None
    provider: str
    provider_title: str
    category: str
    trust: str
    enabled: bool
    archived: bool
    network_required: bool
    capabilities: list[str]
    sync_interval_hours: int | None
    stale_after_hours: int | None
    # never | ok | error | unavailable | syncing (último intento).
    status: str
    # fresh | stale | never_synced | disabled | archived (lo que pinta la UI).
    state: str
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_error: str | None
    last_error_message: str | None
    record_count: int
    next_sync_at: datetime | None
    sync_requested_at: datetime | None
    # Solo el host de descarga (nunca la URL completa).
    download_host: str | None
    reference_url: str | None
    revision: int
    created_at: datetime
    updated_at: datetime


class ThreatSourceList(ResponseModel):
    items: list[ThreatSourceRead]
    sync_enabled: bool
    detection_policy: str


class ThreatSourceCreate(RequestModel):
    source_key: str = SourceKey
    name: str = Field(min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=500)
    # local_import (IOCs importados a mano) o un adapter de feed (espejo interno de KEV/EPSS:
    # su URL se configura en el servidor con THREAT_INTEL_SOURCE_URLS, nunca aquí).
    provider: Literal["local_import", "cisa_kev", "first_epss"] = "local_import"
    category: Category = "ioc"
    trust: Trust = "local"


class ThreatSourceUpdate(RequestModel):
    # Concurrencia optimista: revisión que vio el cliente.
    revision: int = Field(ge=0)
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=500)
    trust: Trust | None = None
    sync_interval_hours: int | None = Field(default=None, ge=1, le=24 * 30)
    stale_after_hours: int | None = Field(default=None, ge=1, le=24 * 90)


class ThreatSourceAction(RequestModel):
    revision: int = Field(ge=0)


class ThreatSyncRead(ResponseModel):
    id: int
    kind: str
    trigger: str
    status: str
    actor: str
    started_at: datetime
    finished_at: datetime | None
    duration_ms: int | None
    records_seen: int
    records_new: int
    records_updated: int
    records_unchanged: int
    records_removed: int
    records_invalid: int
    content_sha256: str | None
    error_code: str | None
    error_message: str | None


class ThreatSyncList(ResponseModel):
    items: list[ThreatSyncRead]
    total: int


# --- Resumen -----------------------------------------------------------------------------------


class ThreatChangeRead(ResponseModel):
    occurred_at: datetime
    source_name: str
    record_kind: str
    change: str
    cve_id: str | None
    indicator_id: UUID | None
    indicator_value: str | None
    details: dict[str, Any] | None


class ThreatIntelOverview(ResponseModel):
    # none_configured: ninguna fuente activa ("No intelligence source configured").
    status: Literal["none_configured", "ok", "degraded"]
    sources_total: int
    sources_enabled: int
    sources_stale: int
    sources_failing: int
    sync_enabled: bool
    detection_policy: str
    last_success_at: datetime | None
    # Findings activos confirmados/probables cuyo CVE está en KEV, y activos afectados.
    kev_findings: int
    kev_assets: int
    # Findings activos con EPSS >= 0,5 (banda "alta").
    high_epss_findings: int
    indicators_total: int
    indicators_active: int
    # Matches no descartados con datos locales.
    active_matches: int
    malicious_matches: int
    matched_assets: int
    recent_changes: list[ThreatChangeRead]


# --- Indicadores -------------------------------------------------------------------------------


class IndicatorSourceRef(ResponseModel):
    id: int
    name: str
    trust: str
    state: str


class IndicatorSummary(ResponseModel):
    indicator_id: UUID
    indicator_type: str
    value: str
    classification: str
    confidence: str
    confidence_score: int | None
    # active | revoked | expired | not_yet_valid.
    state: str
    valid_from: datetime | None
    valid_until: datetime | None
    # supported | partial | unsupported: si la telemetría de Sentra puede casarlo.
    matching: str
    match_count: int
    last_matched_at: datetime | None
    tags: list[str]
    source: IndicatorSourceRef
    retrieved_at: datetime


class IndicatorList(ResponseModel):
    items: list[IndicatorSummary]
    total: int


class IndicatorDetail(IndicatorSummary):
    value_original: str
    description: str | None
    # URLs http/https validadas. Metadatos: Sentra nunca las abre.
    references: list[str]
    related: list[dict[str, Any]]
    external_id: str | None
    pattern: str | None
    first_seen_external: datetime | None
    last_seen_external: datetime | None
    matching_reason: str | None
    # La misma clave (tipo + valor) en otras fuentes, con lo que declara cada una.
    other_sources: list[dict[str, Any]]
    conflicting: bool
    matches: list["MatchSummary"]
    changes: list[ThreatChangeRead]


# --- Matches -----------------------------------------------------------------------------------


class MatchAssetRef(ResponseModel):
    asset_id: UUID
    name: str
    primary_ip: str


class MatchSummary(ResponseModel):
    match_id: UUID
    asset: MatchAssetRef
    indicator_id: UUID
    indicator_type: str
    indicator_value: str
    source_name: str
    source_trust: str
    classification: str
    match_confidence: str
    observation_type: str
    observed_value: str
    first_observed_at: datetime
    last_observed_at: datetime
    observation_count: int
    status: str
    detection_id: UUID | None
    version: int


class MatchList(ResponseModel):
    items: list[MatchSummary]
    total: int


class MatchIncidentRef(ResponseModel):
    incident_id: UUID
    key: str
    title: str
    status: str


class MatchDetail(MatchSummary):
    observed_field: str
    event_id: UUID | None
    evidence: dict[str, Any]
    indicator_confidence: str
    indicator_state: str
    status_reason: str | None
    status_changed_at: datetime
    status_changed_by: str
    matched_at: datetime
    incidents: list[MatchIncidentRef]
    # Acciones que el usuario actual puede ejecutar ahora (el backend vuelve a validar).
    actions: list[str]


class MatchAction(RequestModel):
    version: int = Field(ge=1)
    reason: str | None = Field(default=None, max_length=1000)


class MatchDecision(RequestModel):
    """Descartar (falso positivo) o reabrir: siempre con motivo escrito."""

    version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=1000)


class MatchIncidentIn(RequestModel):
    version: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    priority: Literal["low", "medium", "high", "critical"] | None = None


# --- Importación -------------------------------------------------------------------------------


class ThreatImportIn(RequestModel):
    source_id: int = Field(ge=1)
    format: ImportFormat
    # Fichero JSON como texto (sentra-ioc/1 o bundle STIX 2.x). Ficheros grandes: CLI.
    content: str = Field(min_length=2)


class ThreatImportConfirm(ThreatImportIn):
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    skip_invalid: bool = False


class ThreatInvalidRecord(ResponseModel):
    index: int
    reference: str | None
    code: str
    message: str


class ThreatImportPreview(ResponseModel):
    """Qué haría la importación. NADA se guarda hasta confirmar con /threat-intel/import."""

    source_key: str
    format: str
    sha256: str
    size_bytes: int
    source_version: str | None
    total: int
    valid: int
    new: int
    updated: int
    unchanged: int
    invalid: int
    invalid_records: list[ThreatInvalidRecord]
    # Objetos válidos fuera del subset soportado (patrones STIX complejos...).
    unsupported: dict[str, int]
    by_type: dict[str, int]
    # Indicadores que Sentra no puede casar con su telemetría (hashes, URLs, emails).
    not_matchable: int


class ThreatImportResult(ResponseModel):
    source_key: str
    sha256: str
    new: int
    updated: int
    unchanged: int
    invalid: int
    # Indicadores en cola para buscarse en los datos locales existentes.
    pending_match: int


class ReevaluateResult(ResponseModel):
    indicators_queued: int


IndicatorDetail.model_rebuild()
