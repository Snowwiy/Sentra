"""Contratos de la API de gestión de incidentes (Fase 4K).

Las peticiones solo aceptan referencias (ids públicos) y texto del analista; la evidencia
nunca la envía el cliente: el servidor la deriva de las detecciones, alertas y activos
relacionados, validando cada referencia (ver services/incident_service.py).

Toda mutación de campos del caso exige `version` (concurrencia optimista): si otro operador
cambió el caso, la respuesta es 409 `incident_conflict` con la versión actual.
"""

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field

from app.models.incident import (
    IncidentConfidence,
    IncidentLevel,
    IncidentStatus,
    ResolutionCategory,
)
from app.schemas.asset_context import AssetContextBrief, AssetContextSnapshot
from app.schemas.common import RequestModel, ResponseModel
from app.schemas.risk import RiskContributionRead

Version = Annotated[int, Field(ge=1, le=2_147_483_647)]
Title = Annotated[str, Field(min_length=3, max_length=200)]
Description = Annotated[str, Field(max_length=10_000)]


# --- Peticiones ----------------------------------------------------------------------------


class IncidentCreate(RequestModel):
    title: Title
    description: Description | None = None
    severity: IncidentLevel
    priority: IncidentLevel
    # Opcional: juicio explícito del analista. Si no se indica queda vacía (no se inventa).
    confidence: IncidentConfidence | None = None
    asset_ids: list[UUID] = Field(default_factory=list, max_length=20)


class IncidentUpdate(RequestModel):
    """PATCH: solo los campos presentes cambian. `status` solo admite transiciones de trabajo
    (triage, investigating, contained); resolver, cerrar y reabrir tienen su acción."""

    version: Version
    title: Title | None = None
    description: Description | None = None
    severity: IncidentLevel | None = None
    priority: IncidentLevel | None = None
    confidence: IncidentConfidence | None = None
    status: IncidentStatus | None = None


class IncidentVersioned(RequestModel):
    version: Version


class IncidentAssign(RequestModel):
    version: Version
    # Null = asignarse a uno mismo.
    user_id: UUID | None = None


class IncidentResolve(RequestModel):
    version: Version
    category: ResolutionCategory
    summary: str | None = Field(default=None, max_length=2000)
    # Solo con category=duplicate: incidente principal (referencia, no merge).
    duplicate_of: UUID | None = None


class IncidentMerge(RequestModel):
    """Fusiona el incidente de la ruta EN `target_id` (el de la ruta queda "merged")."""

    version: Version
    target_id: UUID
    target_version: Version


class IncidentNoteCreate(RequestModel):
    body: str = Field(min_length=1, max_length=5000)


class IncidentPromote(RequestModel):
    """Crear incidente desde una detección o alerta. Lo no indicado se deriva de ella."""

    title: Title | None = None
    description: Description | None = None
    # Sin valor se usa la prioridad sugerida (ver `suggested_priority` en el servicio).
    priority: IncidentLevel | None = None


# --- Respuestas ----------------------------------------------------------------------------


class IncidentUserRef(ResponseModel):
    user_id: UUID
    username: str
    role: str
    # False si la cuenta se desactivó después: se muestra como owner histórico.
    active: bool


class IncidentLink(ResponseModel):
    incident_id: UUID
    key: str
    title: str
    status: IncidentStatus


class IncidentAssetRef(ResponseModel):
    # Id público copiado: sigue presente aunque el activo se borre (exists=false).
    asset_id: UUID
    name: str
    exists: bool
    primary_ip: str | None
    # manual, detection, alert o merge.
    source: str
    added_at: datetime
    # Fase 4L: contexto ACTUAL del activo (null si ya no existe) y el contexto crítico
    # guardado al vincularlo y al resolver el caso (null en vínculos anteriores a 4L).
    context: AssetContextBrief | None = None
    context_snapshot: AssetContextSnapshot | None = None
    resolved_context_snapshot: AssetContextSnapshot | None = None


class IncidentSummary(ResponseModel):
    incident_id: UUID
    number: int
    # INC-000001
    key: str
    title: str
    severity: IncidentLevel
    priority: IncidentLevel
    status: IncidentStatus
    confidence: IncidentConfidence | None
    owner: IncidentUserRef | None
    # Como mucho 3 nombres para el listado; el total en asset_count.
    assets: list[str]
    asset_count: int
    last_activity_at: datetime
    created_at: datetime
    updated_at: datetime
    version: int


class IncidentList(ResponseModel):
    items: list[IncidentSummary]
    total: int


class IncidentDetectionRef(ResponseModel):
    detection_id: UUID
    rule_id: str
    # Fase 5A: versión y origen (builtin/custom/sigma) de la regla; null si se purgó.
    rule_version: int | None = None
    rule_source: str | None = None
    # single o correlation.
    kind: str
    title: str
    severity: str
    # Estado actual de la detección; null si la retención ya la purgó (available=false).
    status: str | None
    confidence: str | None
    available: bool
    asset_id: UUID | None
    hostname: str | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    source: str
    attached_at: datetime


class IncidentAlertRef(ResponseModel):
    alert_id: UUID
    rule: str
    severity: str
    status: str | None
    message: str
    available: bool
    asset_id: UUID | None
    hostname: str | None
    opened_at: datetime | None
    source: str
    attached_at: datetime


class IncidentRiskAsset(ResponseModel):
    asset_id: UUID
    name: str
    # False = el Risk Engine aún no lo evaluó (sin puntuación que mostrar).
    evaluated: bool
    score: int | None
    level: str | None
    confidence: str | None
    calculated_at: datetime | None
    changed_at: datetime | None
    top_contributors: list[RiskContributionRead]


class IncidentRiskSnapshot(ResponseModel):
    score: int | None
    level: str | None
    confidence: str | None
    taken_at: datetime | None


class IncidentRiskContext(ResponseModel):
    # Snapshot persistido (creación / resolución): el riesgo tal como era entonces.
    snapshot: IncidentRiskSnapshot
    # Riesgo actual de los activos relacionados, leído de 4I (nunca recalculado aquí).
    assets: list[IncidentRiskAsset]


class IncidentMetrics(ResponseModel):
    """Tiempos observados (no SLA): segundos o null si aún no aplica."""

    age_seconds: int
    time_to_triage_seconds: int | None
    time_to_resolve_seconds: int | None


class IncidentDetail(IncidentSummary):
    description: str | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    triaged_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    resolution_category: ResolutionCategory | None
    resolution_summary: str | None
    duplicate_of: IncidentLink | None
    merged_into: IncidentLink | None
    merged_at: datetime | None
    # Incidentes absorbidos por este (merge), con su número original.
    merged_from: list[IncidentLink]
    created_by: IncidentUserRef | None
    assigned_by: IncidentUserRef | None
    assigned_at: datetime | None
    updated_by: IncidentUserRef | None
    resolved_by: IncidentUserRef | None
    risk: IncidentRiskContext
    asset_refs: list[IncidentAssetRef]
    detections: list[IncidentDetectionRef]
    detections_total: int
    alerts: list[IncidentAlertRef]
    alerts_total: int
    notes_total: int
    metrics: IncidentMetrics
    # Estados a los que la state machine permite pasar con PATCH (comodidad de UI; el
    # backend vuelve a validar cada transición).
    allowed_transitions: list[IncidentStatus]


class IncidentNoteRead(ResponseModel):
    note_id: UUID
    author: str
    body: str
    created_at: datetime
    # Incidente donde se escribió (distinto del actual si llegó por un merge).
    incident_key: str


class IncidentNoteList(ResponseModel):
    items: list[IncidentNoteRead]
    total: int


TimelineSource = Literal[
    "incident", "note", "event", "detection", "correlation", "alert", "risk", "ai_insight"
]


class TimelineItem(ResponseModel):
    # Identificador estable del elemento (también la clave del cursor).
    item_id: str
    occurred_at: datetime
    source_type: TimelineSource
    # Acción concreta (created, status_changed...) en elementos "incident"; si no, null.
    action: str | None
    entity_type: str | None
    entity_id: str | None
    actor: str | None
    # Resumen generado por Sentra o texto del analista: SIEMPRE texto plano.
    summary: str
    incident_key: str


class IncidentTimeline(ResponseModel):
    items: list[TimelineItem]
    # Cursor opaco para la página siguiente (más antigua); null si no hay más.
    next_cursor: str | None


class EvidenceEventRead(ResponseModel):
    detection_id: UUID
    signal_kind: str
    source_type: str
    source_id: str | None
    occurred_at: datetime
    summary: str


class EvidenceExposureRead(ResponseModel):
    asset_id: UUID
    asset_name: str
    protocol: str
    port: int
    service_hint: str | None
    opened_at: datetime


class EvidenceRiskRead(ResponseModel):
    asset_id: UUID
    asset_name: str
    contributions: list[RiskContributionRead]


class IncidentEvidence(ResponseModel):
    """Evidencia agrupada, siempre derivada en el servidor de las relaciones del caso."""

    detections: list[IncidentDetectionRef]
    correlations: list[IncidentDetectionRef]
    events: list[EvidenceEventRead]
    events_total: int
    exposure: list[EvidenceExposureRead]
    alerts: list[IncidentAlertRef]
    risk_contributions: list[EvidenceRiskRead]


class RelatedIncident(ResponseModel):
    incident: IncidentSummary
    # already_linked, same_asset, same_rule, correlation, evidence_overlap, same_account,
    # time_window.
    reasons: list[str]
    score: int


class RelatedIncidentList(ResponseModel):
    """Sugerencias (nunca se adjunta ni fusiona automáticamente)."""

    items: list[RelatedIncident]
    # Prioridad sugerida si se crea un caso nuevo desde esta detección/alerta.
    suggested_priority: IncidentLevel
    suggested_severity: IncidentLevel


class IncidentActivityRead(ResponseModel):
    incident_id: UUID
    incident_key: str
    incident_title: str
    occurred_at: datetime
    action: str
    actor: str
    summary: str


class IncidentOverview(ResponseModel):
    open: int
    triage: int
    investigating: int
    contained: int
    # Casos activos (no resueltos ni cerrados) con severidad critical.
    critical: int
    unassigned: int
    assigned_to_me: int
    # Edad media observada de los casos activos (null sin casos activos). No es un SLA.
    mean_age_seconds: int | None
    recent_activity: list[IncidentActivityRead]


class AssignableUser(ResponseModel):
    user_id: UUID
    username: str
    role: str


class AssignableUserList(ResponseModel):
    items: list[AssignableUser]


class IncidentAuditEvent(ResponseModel):
    created_at: datetime
    actor: str
    action: str
    result: str
    details: dict[str, Any] | None


class IncidentAuditList(ResponseModel):
    items: list[IncidentAuditEvent]
    total: int
