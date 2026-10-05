"""Gestor de modelos locales (Fase 4J.2): hardware, runtime, modelos y benchmarks.

RBAC:
- lectura (hardware, runtime, modelos, recomendaciones): monitoring:read + ai:use, es decir
  viewer, analyst y admin. No incluye secretos: ni URL ni clave del proveedor, y las rutas de
  ficheros solo se devuelven a ai:manage;
- cualquier cambio (registrar, seleccionar, benchmark, runtime, refrescar hardware):
  ai:manage, solo admin. Lleva CSRF como toda mutación.

El navegador nunca envía comandos, URLs ni parámetros del runtime: como mucho una ruta de
fichero (validada contra AI_MODEL_DIRECTORIES) o el nombre de un modelo que el runtime ya
lista.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status

from app.api.auth import READ, CurrentAuth, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.ai_local import (
    BenchmarkRead,
    HardwareRead,
    LocalModelDetail,
    LocalModelList,
    LocalModelRead,
    LocalSettingsUpdate,
    RecommendationList,
    RecommendationProfile,
    RegisterModelRequest,
    RuntimeStatusRead,
)
from app.schemas.common import ErrorResponse
from app.services.audit_service import Actor
from app.services.local_model_service import LocalModelService

router = APIRouter(
    prefix="/ai/local",
    tags=["ai-local"],
    dependencies=[READ, Depends(require_permission(Permission.AI_USE))],
)
MANAGE = [Depends(require_permission(Permission.AI_MANAGE))]

_RUNTIME_ERRORS = {
    **error_responses(404),
    409: {
        "model": ErrorResponse,
        "description": "AI not configured or not local, model not loaded/unavailable, runtime"
        " mismatch or benchmark busy (`ai_not_configured`, `local_model_not_loaded`,"
        " `local_model_unavailable`, `local_model_runtime_mismatch`, `ai_benchmark_busy`)",
    },
    502: {
        "model": ErrorResponse,
        "description": "Local runtime failed (`ai_provider_unavailable`)",
    },
    504: {"model": ErrorResponse, "description": "Local runtime timed out (`ai_timeout`)"},
}
# Contextos razonables para la UI; la API acepta cualquier valor dentro de los límites.
Context = Annotated[int | None, Query(ge=2048, le=1_048_576)]


def get_service(
    request: Request, session: DbSession, settings: AppSettings, ctx: CurrentAuth
) -> LocalModelService:
    return LocalModelService(
        session,
        settings,
        request.app.state.ai_local,
        Actor.for_user(ctx.user, ctx.client_ip),
        can_manage=ctx.has(Permission.AI_MANAGE),
        # Cambiar de modelo invalida el health cacheado de /ai/status (4J.1).
        on_model_changed=request.app.state.ai_runtime.forget_health,
    )


Service = Annotated[LocalModelService, Depends(get_service)]


@router.get("/hardware", response_model=HardwareRead)
def hardware(service: Service) -> HardwareRead:
    """Perfil de hardware del servidor (cacheado; se refresca a mano)."""
    return service.hardware()


@router.post("/hardware/refresh", response_model=HardwareRead, dependencies=MANAGE)
def refresh_hardware(service: Service) -> HardwareRead:
    return service.hardware(refresh=True)


@router.get("/runtime", response_model=RuntimeStatusRead)
def runtime_status(service: Service) -> RuntimeStatusRead:
    """Runtime configurado, capacidades reales, salud y modelo activo."""
    return service.runtime_status()


@router.patch("/settings", response_model=RuntimeStatusRead, dependencies=MANAGE)
def update_settings(body: LocalSettingsUpdate, service: Service) -> RuntimeStatusRead:
    """Cambia el runtime detrás de AI_BASE_URL (nunca la URL: es configuración del servidor)."""
    return service.update_runtime(body.runtime)


@router.get("/models", response_model=LocalModelList)
def list_models(
    service: Service,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> LocalModelList:
    return service.list_models(limit, offset)


@router.post(
    "/models/register",
    response_model=LocalModelRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=MANAGE,
    responses=_RUNTIME_ERRORS,
)
def register_model(body: RegisterModelRequest, service: Service) -> LocalModelRead:
    """Registra un GGUF de AI_MODEL_DIRECTORIES o un modelo que el runtime ya lista."""
    return service.register(body)


@router.get("/models/{model_id}", response_model=LocalModelDetail, responses=error_responses(404))
def get_model(
    model_id: UUID,
    service: Service,
    context: Context = None,
    profile: RecommendationProfile = "balanced",
) -> LocalModelDetail:
    return service.get_model(model_id, context, profile)


@router.post(
    "/models/{model_id}/select",
    response_model=RuntimeStatusRead,
    dependencies=MANAGE,
    responses=_RUNTIME_ERRORS,
)
def select_model(model_id: UUID, service: Service) -> RuntimeStatusRead:
    """Activa el modelo solo si el runtime lo sirve y responde; si no, sigue el anterior."""
    return service.select_model(model_id)


@router.post(
    "/models/{model_id}/unregister",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=MANAGE,
    responses=error_responses(404),
)
def unregister_model(model_id: UUID, service: Service) -> None:
    """Quita el registro. El fichero del disco NO se borra."""
    service.unregister(model_id)


@router.post(
    "/models/{model_id}/benchmark",
    response_model=BenchmarkRead,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=MANAGE,
    responses=_RUNTIME_ERRORS,
)
def start_benchmark(model_id: UUID, service: Service) -> BenchmarkRead:
    """Lanza un benchmark en segundo plano (uno a la vez); consultar GET /benchmarks/{id}."""
    return service.start_benchmark(model_id)


@router.get(
    "/benchmarks/{benchmark_id}", response_model=BenchmarkRead, responses=error_responses(404)
)
def get_benchmark(benchmark_id: UUID, service: Service) -> BenchmarkRead:
    return service.get_benchmark(benchmark_id)


@router.post(
    "/benchmarks/{benchmark_id}/cancel",
    response_model=BenchmarkRead,
    dependencies=MANAGE,
    responses=error_responses(404),
)
def cancel_benchmark(benchmark_id: UUID, service: Service) -> BenchmarkRead:
    return service.cancel_benchmark(benchmark_id)


@router.get("/recommendations", response_model=RecommendationList)
def recommendations(
    service: Service,
    profile: RecommendationProfile = "balanced",
    context: Context = None,
    include_catalog: bool = True,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> RecommendationList:
    """Clasificación determinista de modelos registrados y del catálogo para este servidor."""
    return service.recommendations(profile, context, include_catalog, limit)
