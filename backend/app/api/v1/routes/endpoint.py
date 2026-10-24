"""Telemetría avanzada de endpoint, árbol de procesos y excepciones de reglas (Fase 6E.3-6E.5).

- POST /agents/activity: lote de actividad del agente 0.5.0 (token del agente, gzip opcional).
- Lectura por activo (telemetry:read, analyst y admin): árbol de procesos por niveles, detalle
  de una instancia, actividad y estado de la telemetría.
- GET /endpoint/metrics: retraso de ingesta y latencia de detección medidos (telemetry:read).
- /detection-exclusions: excepciones de reglas integradas (lectura rules:read, cambios
  rules:manage, solo admin).
"""

import zlib
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from app.api.auth import actor, require_permission
from app.api.deps import AgentToken, AppSettings, DbSession
from app.api.responses import error_responses
from app.core.exceptions import RateLimitedError, SentraError
from app.core.permissions import Permission
from app.detection.exclusions import ExclusionService
from app.endpoint.metrics import EndpointMetrics, endpoint_metrics
from app.endpoint.service import ActivityIngest, EndpointReadService
from app.schemas.detection_exclusion import (
    DetectionExclusionCreate,
    DetectionExclusionList,
    DetectionExclusionRead,
)
from app.schemas.endpoint import (
    ActivityAccepted,
    ActivityBatchIn,
    ActivityCategory,
    ActivityList,
    ProcessInstanceDetail,
    ProcessTree,
    TelemetryStatus,
)
from app.services.auth_service import AuthContext

agent_router = APIRouter(prefix="/agents", tags=["agents"])
asset_router = APIRouter(prefix="/assets", tags=["endpoint"], responses=error_responses(401, 403))
metrics_router = APIRouter(
    prefix="/endpoint", tags=["endpoint"], responses=error_responses(401, 403)
)
exclusion_router = APIRouter(
    prefix="/detection-exclusions", tags=["detections"], responses=error_responses(401, 403)
)
TELEMETRY = Depends(require_permission(Permission.TELEMETRY_READ))
RULES_READ = Depends(require_permission(Permission.RULES_READ))
RulesManager = Annotated[AuthContext, Depends(require_permission(Permission.RULES_MANAGE))]
InstanceKey = Annotated[str, Query(pattern=r"^[0-9a-f]{32}$")]


class PayloadTooLargeError(SentraError):
    status_code = status.HTTP_413_CONTENT_TOO_LARGE
    code = "payload_too_large"


def _decompress(raw: bytes, limit: int) -> bytes:
    """gzip con tope de tamaño descomprimido: una bomba de compresión no agota la memoria."""
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        data = inflater.decompress(raw, limit + 1)
    except zlib.error as exc:
        raise RequestValidationError(
            [{"loc": ("body",), "msg": "invalid gzip body", "type": "value_error"}]
        ) from exc
    if len(data) > limit or inflater.unconsumed_tail:
        raise PayloadTooLargeError(f"Decompressed body exceeds {limit} bytes")
    return data


@agent_router.post(
    "/activity",
    response_model=ActivityAccepted,
    responses=error_responses(401, 403, 409, 413, 422, 429),
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/ActivityBatchIn"}}
            },
            "description": "Optional `Content-Encoding: gzip`.",
        }
    },
)
async def ingest_activity(
    request: Request, session: DbSession, settings: AppSettings, token: AgentToken
) -> ActivityAccepted:
    """Lote de actividad del agente 0.5.0 (máx. 1000 eventos). Un evento inválido se rechaza
    solo (`rejected`); un reenvío del mismo evento cuenta como `duplicates`."""
    raw = await request.body()
    if request.headers.get("content-encoding", "").lower() == "gzip":
        raw = _decompress(raw, settings.max_request_bytes)
    try:
        batch = ActivityBatchIn.model_validate_json(raw)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors(include_url=False)) from exc
    limiter = request.app.state.activity_limiter

    def run() -> ActivityAccepted:
        # Fuera del bucle de eventos: la sesión y el limitador (base de datos en producción)
        # son síncronos y bloquearían al resto de peticiones.
        # Autenticar antes de consumir cupo: si no, cualquiera que conozca un agent_id podría
        # agotar el cupo de ese agente real sin tener su token.
        ingest = ActivityIngest(session, settings)
        asset = ingest.authenticate(batch, token)
        wait = limiter.acquire(str(asset.agent_id))
        if wait > 0:
            raise RateLimitedError("Too many activity batches, retry later", wait, "agent_activity")
        return ingest.ingest(batch, asset)

    return await run_in_threadpool(run)


def get_reader(session: DbSession, settings: AppSettings) -> EndpointReadService:
    return EndpointReadService(session, settings)


Reader = Annotated[EndpointReadService, Depends(get_reader)]


@asset_router.get(
    "/{asset_id}/process-tree",
    response_model=ProcessTree,
    dependencies=[TELEMETRY],
    responses=error_responses(404),
)
def process_tree(
    asset_id: UUID,
    reader: Reader,
    parent: Annotated[str | None, Query(pattern=r"^[0-9a-f]{32}$")] = None,
    at: datetime | None = None,
    search: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> ProcessTree:
    """Un nivel del árbol: raíces o hijos de `parent` (carga perezosa). Con `at`, los
    procesos vivos en ese instante; sin él, los vivos y los terminados en la última hora.
    `search` (nombre, ruta o PID) devuelve coincidencias planas."""
    return reader.process_tree(asset_id, parent, at, search, limit)


@asset_router.get(
    "/{asset_id}/process-instances/{instance_id}",
    response_model=ProcessInstanceDetail,
    dependencies=[TELEMETRY],
    responses=error_responses(404),
)
def process_instance(asset_id: UUID, instance_id: str, reader: Reader) -> ProcessInstanceDetail:
    """Una instancia con sus antecesores (hasta 32) y sus últimas conexiones."""
    return reader.instance(asset_id, instance_id.lower())


@asset_router.get(
    "/{asset_id}/activity",
    response_model=ActivityList,
    dependencies=[TELEMETRY],
    responses=error_responses(404),
)
def activity(
    asset_id: UUID,
    reader: Reader,
    category: ActivityCategory | None = None,
    action: Annotated[str | None, Query(max_length=24)] = None,
    instance_key: Annotated[str | None, Query(pattern=r"^[0-9a-f]{32}$")] = None,
    start: datetime | None = None,
    end: datetime | None = None,
    before_id: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> ActivityList:
    """Eventos de actividad, del más reciente al más antiguo (cursor `before_id`)."""
    return reader.activity(asset_id, category, action, instance_key, start, end, before_id, limit)


@asset_router.get(
    "/{asset_id}/telemetry-status",
    response_model=TelemetryStatus,
    dependencies=[TELEMETRY],
    responses=error_responses(404),
)
def telemetry_status(asset_id: UUID, reader: Reader) -> TelemetryStatus:
    """Estado de la cola y de los colectores del agente y retraso de ingesta medido."""
    return reader.status(asset_id)


@metrics_router.get("/metrics", response_model=EndpointMetrics, dependencies=[TELEMETRY])
def metrics(session: DbSession) -> EndpointMetrics:
    """Volumen de la última hora, retraso de ingesta (evento → servidor) y latencia de las
    detecciones de comportamiento (evidencia → detección) de las últimas 24 horas."""
    return endpoint_metrics(session)


def get_exclusions(session: DbSession) -> ExclusionService:
    return ExclusionService(session)


Exclusions = Annotated[ExclusionService, Depends(get_exclusions)]


@exclusion_router.get("", response_model=DetectionExclusionList, dependencies=[RULES_READ])
def list_exclusions(service: Exclusions, include_inactive: bool = False) -> DetectionExclusionList:
    return service.list(include_inactive)


@exclusion_router.post(
    "",
    response_model=DetectionExclusionRead,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(404, 409, 422),
)
def create_exclusion(
    body: DetectionExclusionCreate, service: Exclusions, ctx: RulesManager
) -> DetectionExclusionRead:
    """Excepción de una regla integrada para un valor exacto (exe, nombre, hash, firmante,
    padre o IP remota). Auditada (detection_exclusion_created)."""
    return service.create(body, actor(ctx))


@exclusion_router.post(
    "/{exclusion_id}/revoke",
    response_model=DetectionExclusionRead,
    responses=error_responses(404),
)
def revoke_exclusion(
    exclusion_id: UUID, service: Exclusions, ctx: RulesManager
) -> DetectionExclusionRead:
    return service.revoke(exclusion_id, actor(ctx))
