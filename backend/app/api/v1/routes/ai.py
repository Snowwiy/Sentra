"""AI Security Insights (Fase 4J): análisis de IA bajo demanda.

Todas las rutas exigen sesión, monitoring:read y ai:use: la IA solo interpreta datos que el
rol ya puede leer, así que nunca amplía su alcance. Los POST son "pedir un análisis" (no
modifican activos, detecciones, riesgo ni alertas) y llevan CSRF como cualquier mutación.

El cliente nunca elige proveedor, URL, modelo ni parámetros: solo la entidad y, en Ask, la
pregunta. La configuración es exclusiva del servidor y la clave nunca sale de él.
"""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from app.api.auth import READ, CurrentAuth, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.ai import (
    AIStatus,
    AnalyzeRequest,
    AskRequest,
    ConsoleAssistRequest,
    ConsoleContextPreview,
    ConsoleContextRequest,
    IncidentAnalyzeRequest,
    InsightKindName,
    InsightList,
    InsightRead,
    SocSummaryRequest,
)
from app.schemas.common import ErrorResponse
from app.services.ai_service import AIInsightService, Requester
from app.services.audit_service import Actor
from app.services.local_model_service import effective_ai_config

router = APIRouter(
    prefix="/ai",
    tags=["ai"],
    dependencies=[READ, Depends(require_permission(Permission.AI_USE))],
)

# Errores propios de un análisis: IA no configurada (409), límites (429), proveedor
# caído o respuesta inválida (502/503) y timeout (504).
_ANALYSIS_ERRORS = {
    **error_responses(404),
    409: {
        "model": ErrorResponse,
        "description": "AI disabled, not configured or external provider blocked"
        " (`ai_not_configured`)",
    },
    429: {
        "model": ErrorResponse,
        "description": "Too many AI analyses (`rate_limited`, `ai_busy`); see `Retry-After`",
    },
    502: {
        "model": ErrorResponse,
        "description": "Provider unavailable, credentials rejected, invalid or ungrounded answer"
        " (`ai_provider_unavailable`, `ai_provider_auth_failed`, `ai_invalid_response`,"
        " `ai_ungrounded_response`)",
    },
    504: {"model": ErrorResponse, "description": "The AI provider timed out (`ai_timeout`)"},
}


def get_ai_service(
    request: Request, session: DbSession, settings: AppSettings, ctx: CurrentAuth
) -> AIInsightService:
    return AIInsightService(
        session,
        settings,
        request.app.state.ai_runtime,
        request.app.state.ai_provider_factory,
        Requester(Actor.for_user(ctx.user, ctx.client_ip), ctx.user.id),
        # Fase 4J.2: el modelo local activo (si lo hay) sustituye a AI_MODEL; el destino y
        # todas las garantías de 4J.1 no cambian.
        config=effective_ai_config(session, settings),
    )


Service = Annotated[AIInsightService, Depends(get_ai_service)]


@router.get("/status", response_model=AIStatus)
def ai_status(service: Service) -> AIStatus:
    """Si la IA está disponible y con qué modelo (sin URL ni clave)."""
    return service.status()


@router.post("/ask", response_model=InsightRead, responses=_ANALYSIS_ERRORS)
def ask(body: AskRequest, service: Service) -> InsightRead:
    """Ask Sentra AI: el alcance lo resuelve Sentra de forma determinista, no el modelo."""
    return service.ask(body.question, body.asset_id, body.detection_id, body.refresh)


@router.post("/assets/{asset_id}/analyze", response_model=InsightRead, responses=_ANALYSIS_ERRORS)
def analyze_asset(
    asset_id: UUID, service: Service, body: AnalyzeRequest | None = None
) -> InsightRead:
    return service.analyze_asset(asset_id, bool(body and body.refresh))


@router.post(
    "/detections/{detection_id}/analyze", response_model=InsightRead, responses=_ANALYSIS_ERRORS
)
def analyze_detection(
    detection_id: UUID, service: Service, body: AnalyzeRequest | None = None
) -> InsightRead:
    return service.analyze_detection(detection_id, bool(body and body.refresh))


@router.post(
    "/risk/assets/{asset_id}/analyze", response_model=InsightRead, responses=_ANALYSIS_ERRORS
)
def analyze_risk(
    asset_id: UUID, service: Service, body: AnalyzeRequest | None = None
) -> InsightRead:
    return service.analyze_risk(asset_id, bool(body and body.refresh))


@router.post(
    "/incidents/{incident_id}/analyze",
    response_model=InsightRead,
    responses=_ANALYSIS_ERRORS,
    dependencies=[Depends(require_permission(Permission.INCIDENTS_READ))],
)
def analyze_incident(
    incident_id: UUID, service: Service, body: IncidentAnalyzeRequest | None = None
) -> InsightRead:
    """Fase 4K: resumir, explicar timeline/evidencia o sugerir pasos defensivos.

    Solo lectura: genera un insight y nunca cambia el incidente.
    """
    request = body or IncidentAnalyzeRequest()
    return service.analyze_incident(incident_id, request.task, request.refresh)


@router.post(
    "/vulnerabilities/{finding_id}/analyze",
    response_model=InsightRead,
    responses=_ANALYSIS_ERRORS,
    dependencies=[Depends(require_permission(Permission.VULNERABILITIES_READ))],
)
def analyze_vulnerability(
    finding_id: UUID, service: Service, body: AnalyzeRequest | None = None
) -> InsightRead:
    """Fase 5B: explicar un finding de vulnerabilidad con los datos de Sentra.

    Solo lectura: genera un insight y nunca cambia el finding ni consulta fuentes externas.
    """
    return service.analyze_vulnerability(finding_id, bool(body and body.refresh))


# 7C-Security-Fix1: enviar resultados de herramientas a un modelo exige poder ejecutarlas
# (tools:execute, analyst y admin) además de ai:use; un viewer no comparte datos con la IA
# desde la consola.
_CONSOLE_DEPS = [
    Depends(require_permission(Permission.TOOLS_READ)),
    Depends(require_permission(Permission.TOOLS_EXECUTE)),
]
_CONSOLE_ERRORS: dict[int | str, dict[str, Any]] = {
    **_ANALYSIS_ERRORS,
    409: {
        "model": ErrorResponse,
        "description": "AI not configured, console assistant disabled, model not on loopback or"
        " data changed since the review (`ai_not_configured`, `ai_console_disabled`,"
        " `ai_console_loopback_required`, `console_context_changed`)",
    },
    422: {
        "model": ErrorResponse,
        "description": "Execution without output or an action, invalid combination or missing"
        " review (`console_execution_not_usable`, `console_assist_invalid`,"
        " `console_context_review_required`)",
    },
}


@router.post(
    "/console/context",
    response_model=ConsoleContextPreview,
    responses=_CONSOLE_ERRORS,
    dependencies=_CONSOLE_DEPS,
)
def console_context(
    body: ConsoleContextRequest, service: Service, ctx: CurrentAuth
) -> ConsoleContextPreview:
    """7C-Security-Fix1: documento exacto que recibiría el modelo, para revisarlo antes.

    No llama al modelo. Devuelve `context_sha256`, que el envío tiene que repetir con
    `confirm_send=true`. Solo con un modelo en loopback (`ai_console_loopback_required`).
    """
    return service.console_context(
        body.task,
        body.execution_ids,
        body.asset_id,
        body.detection_id,
        body.question,
        can_read_all_executions=ctx.has(Permission.TOOLS_MANAGE),
    )


@router.post(
    "/console/assist",
    response_model=InsightRead,
    responses=_CONSOLE_ERRORS,
    dependencies=_CONSOLE_DEPS,
)
def console_assist(body: ConsoleAssistRequest, service: Service, ctx: CurrentAuth) -> InsightRead:
    """Fase 7C.2: asistente de la Analyst Console sobre resultados de herramientas.

    Solo lectura: resume, explica el riesgo, propone hipótesis o redacta un borrador de nota.
    No ejecuta herramientas ni acciones. Las ejecuciones ajenas solo con tools:manage.
    7C-Security-Fix1: exige la huella de la revisión (`context_sha256`) y `confirm_send`; si
    los datos cambiaron, 409 `console_context_changed` y no se envía nada.
    """
    return service.console_assist(
        body.task,
        body.execution_ids,
        body.asset_id,
        body.detection_id,
        body.question,
        body.refresh,
        can_read_all_executions=ctx.has(Permission.TOOLS_MANAGE),
        context_sha256=body.context_sha256,
        confirm_send=body.confirm_send,
    )


@router.post("/soc/analyze", response_model=InsightRead, responses=_ANALYSIS_ERRORS)
def soc_summary(service: Service, body: SocSummaryRequest | None = None) -> InsightRead:
    """Resumen SOC: detecciones graves, activos con más riesgo y cambios recientes."""
    window = body.window if body else "24h"
    return service.soc_summary(window, bool(body and body.refresh))


@router.get("/insights", response_model=InsightList)
def list_insights(
    service: Service,
    kind: InsightKindName | None = None,
    asset_id: UUID | None = None,
    detection_id: UUID | None = None,
    incident_id: UUID | None = None,
    vulnerability_finding_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> InsightList:
    """Historial de análisis (más recientes primero) con su estado stale actual."""
    return service.list(
        kind, asset_id, detection_id, limit, offset, incident_id, vulnerability_finding_id
    )


@router.get("/insights/{insight_id}", response_model=InsightRead, responses=error_responses(404))
def get_insight(insight_id: UUID, service: Service) -> InsightRead:
    return service.get(insight_id)
