"""Contratos de la API de AI Security Insights (Fase 4J).

Las peticiones solo aceptan la pregunta y referencias a entidades de Sentra: nunca
proveedor, URL, modelo ni parámetros del modelo (configuración exclusiva del servidor).
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from app.schemas.common import RequestModel, ResponseModel

InsightKindName = Literal[
    "asset_summary",
    "detection_analysis",
    "risk_explanation",
    "soc_summary",
    "ask",
    "incident_summary",
    "incident_timeline",
    "incident_evidence",
    "incident_next_steps",
    "vulnerability_analysis",
]
# Fase 4K: tareas de asistencia sobre un incidente (todas de solo lectura).
IncidentTask = Literal["summary", "timeline", "evidence", "next_steps"]
Certainty = Literal["observed", "detected", "correlated", "possible", "requires_validation"]


class AnalyzeRequest(RequestModel):
    # true = ignorar la caché y generar un análisis nuevo (cuenta para el rate limit).
    refresh: bool = False


class IncidentAnalyzeRequest(RequestModel):
    task: IncidentTask = "summary"
    refresh: bool = False


class AskRequest(RequestModel):
    question: str = Field(min_length=3, max_length=500)
    # Contexto explícito desde la UI (botón en el detalle de un activo o una detección).
    asset_id: UUID | None = None
    detection_id: UUID | None = None
    refresh: bool = False


class SocSummaryRequest(RequestModel):
    window: Literal["24h", "7d", "30d"] = "24h"
    refresh: bool = False


class EvidenceRefRead(ResponseModel):
    # Identificador corto que citó el modelo (D1, C2...), válido solo dentro del insight.
    ref: str
    # asset, detection, event, evidence, exposure, risk_contribution, risk_snapshot, alert,
    # change, incident, note, vulnerability (finding de la Fase 5B).
    type: str
    # Id público de Sentra (UUID) o compuesto ("<activo>:tcp/3389", "<activo>#0").
    id: str
    label: str
    asset_id: str | None


class InsightFinding(ResponseModel):
    text: str
    certainty: Certainty
    evidence: list[str]


class InsightAction(ResponseModel):
    text: str
    evidence: list[str]


class InsightResult(ResponseModel):
    summary: str
    assessment: str
    confidence_note: str
    key_findings: list[InsightFinding]
    recommended_actions: list[InsightAction]
    evidence_refs: list[EvidenceRefRead]
    limitations: list[str]
    # El modelo (o Sentra, sin llamar al modelo) concluyó que no hay datos suficientes.
    insufficient_data: bool
    # Avisos del guardia de grounding (referencias descartadas, afirmaciones no respaldadas).
    warnings: list[str]
    dropped_refs: int


class InsightRead(ResponseModel):
    insight_id: UUID
    kind: InsightKindName
    scope: Literal["asset", "detection", "incident", "vulnerability", "fleet"]
    asset_id: UUID | None
    asset_name: str | None
    detection_id: UUID | None
    incident_id: UUID | None
    # Finding de vulnerabilidad analizado (Fase 5B).
    vulnerability_finding_id: UUID | None = None
    risk_snapshot_id: UUID | None
    question: str | None
    provider: str
    model: str
    prompt_version: str
    generated_at: datetime
    expires_at: datetime
    # El análisis ya no describe los datos actuales (caducó o cambiaron los datos).
    stale: bool
    stale_reason: Literal["expired", "data_changed", "entity_deleted"] | None
    # Solo en POST: la respuesta salió de la caché (no se llamó al modelo).
    cached: bool
    evidence_count: int
    context_items: int
    latency_ms: int | None
    requested_by: str
    result: InsightResult


class InsightList(ResponseModel):
    items: list[InsightRead]
    total: int


# Estado del proveedor (4J.1). "Local" se decide por AI_BASE_URL/AI_LOCAL_NETWORKS, nunca por
# el protocolo: un servidor local OpenAI-compatible es "Local AI", no "OpenAI".
AIProviderState = Literal[
    "disabled",
    "not_configured",
    "local_available",
    "local_unavailable",
    "external_blocked",
    "external_available",
    "external_unavailable",
]


class AIStatus(ResponseModel):
    """Estado de la IA para la UI. Nunca incluye la clave ni la URL del proveedor."""

    enabled: bool
    # Utilizable ahora mismo (activada, configurada y permitida).
    available: bool
    # Motivo legible cuando no está disponible ("IA no configurada...").
    reason: str | None
    state: AIProviderState
    # "Local AI" / "External AI" para la UI (None si la IA está desactivada).
    mode_label: Literal["Local AI", "External AI"] | None
    # Resultado del último health check (cacheado unos segundos); None si no se sondeó.
    reachable: bool | None
    health_detail: str | None
    health_latency_ms: int | None
    checked_at: datetime | None
    # Protocolo del cliente (openai_compatible), no el fabricante del modelo.
    provider: str | None
    model: str | None
    # local / external según AI_BASE_URL (ver app/ai/config.py).
    location: Literal["local", "external"] | None
    external_allowed: bool
    # Campos seudonimizados antes de enviar datos al proveedor.
    redaction: list[str]
    max_context_items: int
    rate_limit_per_user_per_minute: int
    prompt_versions: dict[str, str]
