"""Contratos de la API de AI Security Insights (Fase 4J).

Las peticiones solo aceptan la pregunta y referencias a entidades de Sentra: nunca
proveedor, URL, modelo ni parámetros del modelo (configuración exclusiva del servidor).
"""

from datetime import datetime
from typing import Any, Literal
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
    # Fase 7C.2: asistente de la Analyst Console.
    "console_summary",
    "console_risk",
    "console_hypotheses",
    "console_draft",
]
# Fase 7C.2: tareas del asistente de la consola (todas de solo lectura).
ConsoleTask = Literal["summary", "explain_risk", "hypotheses", "draft_note"]
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


class ConsoleContextRequest(RequestModel):
    """Qué se quiere analizar en la consola (7C-Security-Fix1: también para la revisión).

    Solo referencias a datos de Sentra: ejecuciones de herramientas (propias, o de otros con
    tools:manage) y, opcionalmente, el activo o la detección del workspace. Nunca proveedor,
    modelo, prompt ni parámetros del modelo.
    """

    task: ConsoleTask = "summary"
    execution_ids: list[UUID] = Field(default_factory=list, max_length=20)
    asset_id: UUID | None = None
    detection_id: UUID | None = None
    # Pregunta opcional del analista (se trata como dato, igual que en Ask).
    question: str | None = Field(default=None, min_length=3, max_length=500)


class ConsoleAssistRequest(ConsoleContextRequest):
    """Petición del asistente de la consola (Fase 7C.2).

    7C-Security-Fix1: nada se envía al modelo sin revisión previa. `context_sha256` es la
    huella que devolvió POST /ai/console/context de exactamente lo que se va a enviar, y
    `confirm_send` la confirmación explícita del analista. Si los datos cambiaron desde la
    revisión, el servidor responde 409 console_context_changed y no envía nada.
    """

    context_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    confirm_send: bool = False
    refresh: bool = False


class ConsoleContextItem(ResponseModel):
    ref: str
    type: str
    label: str


class ConsoleContextPreview(ResponseModel):
    """7C-Security-Fix1: documento exacto que recibiría el modelo, para revisarlo antes."""

    task: ConsoleTask
    # Huella de lo que se enviará (documento de datos sin la hora de la petición, tarea y
    # pregunta). Hay que devolverla en POST /ai/console/assist con confirm_send=true.
    context_sha256: str
    # Siempre "loopback": el asistente no habla con otro destino.
    destination: Literal["loopback"] = "loopback"
    model: str | None
    # Elementos citables incluidos (resultados de herramientas, activo, detección...).
    items: list[ConsoleContextItem]
    # Valores con aspecto de secreto sustituidos por [REDACTED] antes de enviar.
    redacted_values: int
    # Campos seudonimizados por AI_REDACT (vacío = ninguno).
    pseudonymized: list[str]
    # Caracteres del documento de datos (presupuesto AI_MAX_PROMPT_CHARS).
    chars: int
    # Pregunta tal como se enviaría (seudonimizada si AI_REDACT lo pide).
    question: str | None
    # Documento de datos tal como se enviaría (sin la hora de la petición).
    document: dict[str, Any]


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


class InsightHypothesis(ResponseModel):
    """Hipótesis del asistente de la consola (Fase 7C.2): siempre sugerencia del modelo."""

    text: str
    certainty: Literal["possible"]
    evidence: list[str]
    validate_with: str


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
    # Fase 7C.2 (solo consola; vacíos en el resto y en los insights anteriores).
    hypotheses: list[InsightHypothesis] = Field(default_factory=list)
    # Borrador de nota con encabezado fijo de Sentra que dice que lo generó la IA.
    draft: str | None = None
    # "model": generado por el modelo y validado; "sentra": respuesta determinista sin
    # llamar al modelo (sin datos). None en insights anteriores a 7C.
    origin: Literal["model", "sentra"] | None = None


class InsightRead(ResponseModel):
    insight_id: UUID
    kind: InsightKindName
    scope: Literal["asset", "detection", "incident", "vulnerability", "fleet", "console"]
    asset_id: UUID | None
    asset_name: str | None
    detection_id: UUID | None
    incident_id: UUID | None
    # Finding de vulnerabilidad analizado (Fase 5B).
    vulnerability_finding_id: UUID | None = None
    risk_snapshot_id: UUID | None
    question: str | None
    # Fase 7C.2: ejecuciones de herramientas que vio el modelo (solo consola).
    tool_execution_ids: list[UUID] = Field(default_factory=list)
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
    # Fase 7C.1: modelo open-weight opcional.
    # "settings" (AI_MODEL) o "local_manager" (modelo local activo, Fase 4J.2).
    model_source: Literal["settings", "local_manager"] = "settings"
    # Cómo se envían las instrucciones al modelo (AI_SYSTEM_PROMPT_MODE).
    system_prompt_mode: Literal["system", "user_prefix"] = "system"
    # Asistente de la consola utilizable (IA disponible, AI_CONSOLE_ASSIST_ENABLED y modelo
    # en loopback; 7C-Security-Fix1).
    console_assist_available: bool = False
    console_max_executions: int = 6
    # Por qué no está disponible (None si lo está). Texto para la UI.
    console_assist_reason: str | None = None
