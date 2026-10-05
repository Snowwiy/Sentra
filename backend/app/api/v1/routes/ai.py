"""AI Security Insights (Fase 4J): análisis de IA bajo demanda.

Todas las rutas exigen sesión, monitoring:read y ai:use: la IA solo interpreta datos que el
rol ya puede leer, así que nunca amplía su alcance. Los POST son "pedir un análisis" (no
modifican activos, detecciones, riesgo ni alertas) y llevan CSRF como cualquier mutación.

El cliente nunca elige proveedor, URL, modelo ni parámetros: solo la entidad y, en Ask, la
pregunta. La configuración es exclusiva del servidor y la clave nunca sale de él.
"""

from typing import Annotated
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
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> InsightList:
    """Historial de análisis (más recientes primero) con su estado stale actual."""
    return service.list(kind, asset_id, detection_id, limit, offset, incident_id)


@router.get("/insights/{insight_id}", response_model=InsightRead, responses=error_responses(404))
def get_insight(insight_id: UUID, service: Service) -> InsightRead:
    return service.get(insight_id)
