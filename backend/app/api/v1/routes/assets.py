from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.exceptions import RequestValidationError
from pydantic import IPvAnyNetwork

from app.api.auth import READ, actor, require_permission
from app.api.deps import (
    DbSession,
    get_agent_management_service,
    get_asset_context_service,
    get_asset_service,
    get_exposure_service,
    get_inventory_service,
    get_process_service,
    get_risk_config,
    get_risk_service,
    get_telemetry_service,
)
from app.api.params import text_query
from app.api.responses import error_responses
from app.core.config import get_settings
from app.core.exceptions import SentraError
from app.core.permissions import Permission
from app.models.asset import AssetCriticality, AssetStatus, MonitoringMethod
from app.models.asset_context import AssetEnvironment, AssetRole, DataSensitivity, NetworkZone
from app.models.change import ChangeCategory
from app.risk.config import RiskConfig
from app.risk.engine import RiskEngine
from app.risk.queue import request_recalculation
from app.schemas.agent_management import AgentRead
from app.schemas.asset import AssetList, AssetRead
from app.schemas.asset_context import (
    DEPARTMENT_MAX,
    TAG_MAX,
    AssetContextHistory,
    AssetContextOptions,
    AssetContextRead,
    AssetContextUpdate,
    AssetThreatSummary,
    normalize_tag,
)
from app.schemas.change import ChangeList
from app.schemas.discovery import ExposureRead
from app.schemas.inventory import InventoryRead
from app.schemas.process import ProcessSnapshotRead
from app.schemas.risk import CriticalityUpdate, RiskAssetDetail
from app.schemas.telemetry import TelemetryHistory
from app.services import audit_service
from app.services.agent_management_service import AgentManagementService
from app.services.alert_service import AlertThresholds
from app.services.asset_context_service import AssetContextService
from app.services.asset_service import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    AssetFilter,
    AssetService,
    AssetSort,
)
from app.services.auth_service import AuthContext
from app.services.exposure_service import ExposureService
from app.services.inventory_service import InventoryService
from app.services.process_service import ProcessService
from app.services.risk_service import RiskService
from app.services.telemetry_service import TelemetryService
from app.vulnerabilities.queue import mark_dirty

# Solo lectura del dashboard: cualquier rol con monitoring:read (viewer incluido).
router = APIRouter(prefix="/assets", tags=["assets"], dependencies=[READ])
Service = Annotated[AssetService, Depends(get_asset_service)]
ContextService = Annotated[AssetContextService, Depends(get_asset_context_service)]
AssetManager = Annotated[AuthContext, Depends(require_permission(Permission.ASSETS_MANAGE))]


@router.get("", response_model=AssetList)
def list_assets(
    service: Service,
    # discovered / agentless / agent (DISCOVERED / MONITORED / MANAGED).
    method: MonitoringMethod | None = None,
    status: AssetStatus | None = None,
    # A type from app/discovery/classify.py, or "unknown".
    device_type: Annotated[str | None, Query(pattern=r"^[a-z_]{1,32}$")] = None,
    # Only assets whose address is inside this network, e.g. 192.168.1.0/24.
    subnet: IPvAnyNetwork | None = None,
    q: Annotated[str | None, text_query(200)] = None,
    # Fase 4L: contexto. "unknown" incluye a los activos sin contexto guardado.
    criticality: AssetCriticality | None = None,
    role: AssetRole | None = None,
    environment: AssetEnvironment | None = None,
    network_zone: NetworkZone | None = None,
    data_sensitivity: DataSensitivity | None = None,
    internet_exposed: Literal["true", "false", "unknown"] | None = None,
    department: Annotated[str | None, Query(min_length=1, max_length=DEPARTMENT_MAX)] = None,
    tag: Annotated[str | None, Query(min_length=1, max_length=TAG_MAX * 2)] = None,
    sort: AssetSort = "name",
    order: Literal["asc", "desc"] = "asc",
    # Fase 4M: siempre paginado en el servidor. Sin limit, una página de DEFAULT_PAGE_SIZE
    # (antes devolvía todos los activos, ~1,5 s con 10 000).
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> AssetList:
    search = q.strip() if q else None
    try:
        tag_value = normalize_tag(tag) if tag is not None else None
    except ValueError as exc:
        raise RequestValidationError(
            [{"loc": ("query", "tag"), "msg": str(exc), "type": "value_error"}]
        ) from exc
    return service.list_assets(
        AssetFilter(
            method=method,
            status=status,
            device_type=device_type,
            subnet=subnet,
            search=search,
            criticality=criticality,
            role=role,
            environment=environment,
            network_zone=network_zone,
            data_sensitivity=data_sensitivity,
            internet_exposed=internet_exposed,
            department=" ".join(department.split()) if department else None,
            tag=tag_value,
        ),
        sort=sort,
        limit=limit,
        offset=offset,
        descending=order == "desc",
    )


# Antes de /{asset_id}: "context" no es un UUID y la ruta genérica respondería 422.
@router.get("/context/options", response_model=AssetContextOptions)
def get_asset_context_options(service: ContextService) -> AssetContextOptions:
    """Valores permitidos, límites y departamentos/etiquetas ya usados (autocompletar)."""
    return service.options()


@router.get("/{asset_id}", response_model=AssetRead, responses=error_responses(404))
def get_asset(asset_id: UUID, service: Service) -> AssetRead:
    return service.get_asset(asset_id)


@router.get("/{asset_id}/context", response_model=AssetContextRead, responses=error_responses(404))
def get_asset_context(asset_id: UUID, service: ContextService) -> AssetContextRead:
    """Contexto operacional y de negocio con procedencia y completitud. Lectura: todos."""
    return service.get(asset_id)


@router.patch(
    "/{asset_id}/context",
    response_model=AssetContextRead,
    responses=error_responses(401, 403, 404, 409),
)
def update_asset_context(
    asset_id: UUID,
    body: AssetContextUpdate,
    ctx: AssetManager,
    session: DbSession,
    service: ContextService,
    config: Annotated[RiskConfig, Depends(get_risk_config)],
) -> AssetContextRead:
    """Edita el contexto (solo admin, assets:manage). PATCH parcial con `version`.

    Analyst y viewer no editan: varios campos (criticidad, entorno, sensibilidad, exposición)
    son entradas del riesgo y rebajarlos ocultaría prioridad. Versión obsoleta: 409
    asset_context_conflict. Si cambia un campo que usa el Risk Engine, el riesgo del activo
    se recalcula en el momento (mismo patrón que la criticidad en 4I).
    """
    try:
        result = service.update(asset_id, body, actor(ctx))
    except SentraError as exc:
        session.rollback()
        audit_service.record(
            session,
            actor(ctx),
            "asset_context_updated",
            audit_service.FAILURE,
            "asset",
            asset_id,
            details={"error": exc.code, "fields": sorted(body.model_fields_set - {"version"})},
        )
        raise
    if result.risk_relevant:
        # En la misma transacción que el cambio: si el recálculo inmediato fallara, el job
        # lo hará en su siguiente vuelta.
        request_recalculation(session, [result.asset.id])
        # Fase 5B: exposición a Internet, entorno y datos cambian la prioridad de findings.
        mark_dirty(session, [result.asset.id], "context")
    session.commit()
    if result.risk_relevant:
        RiskEngine(session, config, AlertThresholds.from_settings(get_settings())).recalculate(
            [result.asset.id]
        )
        session.commit()
    return service.get(asset_id)


@router.get(
    "/{asset_id}/context/history",
    response_model=AssetContextHistory,
    responses=error_responses(404),
)
def get_asset_context_history(
    asset_id: UUID,
    service: ContextService,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> AssetContextHistory:
    return service.history(asset_id, limit, offset)


@router.get(
    "/{asset_id}/threat-summary",
    response_model=AssetThreatSummary,
    responses=error_responses(404),
)
def get_asset_threat_summary(asset_id: UUID, service: ContextService) -> AssetThreatSummary:
    """Contexto de amenaza INTERNO (detecciones, incidentes, riesgo, exposición, cambios).

    Calculado al vuelo de datos que Sentra ya tiene; sin Threat Intelligence externa.
    """
    return service.threat_summary(asset_id)


@router.get("/{asset_id}/agent", response_model=AgentRead, responses=error_responses(404))
def get_asset_agent(
    asset_id: UUID,
    service: Annotated[AgentManagementService, Depends(get_agent_management_service)],
) -> AgentRead:
    """The asset's agent and credential state (404 for assets without agent). No secrets."""
    return service.get_agent(asset_id)


@router.get(
    "/{asset_id}/telemetry", response_model=TelemetryHistory, responses=error_responses(404)
)
def get_asset_telemetry(
    asset_id: UUID,
    service: Annotated[TelemetryService, Depends(get_telemetry_service)],
    # Bounded so a single request cannot pull an asset's entire history into memory.
    limit: Annotated[int, Query(ge=1, le=1000)] = 120,
) -> TelemetryHistory:
    return service.history(asset_id, limit)


@router.get(
    "/{asset_id}/inventory",
    response_model=InventoryRead,
    # 404 also when the asset exists but has not reported an inventory yet.
    responses=error_responses(404),
)
def get_asset_inventory(
    asset_id: UUID, service: Annotated[InventoryService, Depends(get_inventory_service)]
) -> InventoryRead:
    return service.get(asset_id)


@router.get(
    "/{asset_id}/processes",
    response_model=ProcessSnapshotRead,
    # 404 also when the asset exists but has not sent a process snapshot yet.
    responses=error_responses(404),
)
def get_asset_processes(
    asset_id: UUID, service: Annotated[ProcessService, Depends(get_process_service)]
) -> ProcessSnapshotRead:
    return service.get(asset_id)


@router.get("/{asset_id}/exposure", response_model=ExposureRead, responses=error_responses(404))
def get_asset_exposure(
    asset_id: UUID, service: Annotated[ExposureService, Depends(get_exposure_service)]
) -> ExposureRead:
    """Ports reachable from the Sentra server, correlated with the agent's listeners."""
    return service.exposure(asset_id)


@router.get("/{asset_id}/changes", response_model=ChangeList, responses=error_responses(404))
def get_asset_changes(
    asset_id: UUID,
    service: Annotated[InventoryService, Depends(get_inventory_service)],
    category: ChangeCategory | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ChangeList:
    return service.changes(asset_id, category, limit, offset)


@router.patch(
    "/{asset_id}/criticality",
    response_model=RiskAssetDetail,
    responses=error_responses(401, 403, 404),
)
def set_asset_criticality(
    asset_id: UUID,
    body: CriticalityUpdate,
    ctx: AssetManager,
    session: DbSession,
    service: Annotated[RiskService, Depends(get_risk_service)],
    config: Annotated[RiskConfig, Depends(get_risk_config)],
) -> RiskAssetDetail:
    """Cambia la criticidad del activo (solo admin) y recalcula su riesgo en el momento.

    Es una entrada del riesgo: un viewer o un analyst no pueden rebajarla (403, auditado como
    permission_denied). El cambio se audita como asset_criticality_changed con el valor
    anterior y el nuevo, también los intentos fallidos.
    """
    action = "asset_criticality_changed"
    try:
        asset, previous = service.set_criticality(asset_id, body.criticality)
    except SentraError as exc:
        session.rollback()
        audit_service.record(
            session,
            actor(ctx),
            action,
            audit_service.FAILURE,
            "asset",
            asset_id,
            details={"error": exc.code, "to": body.criticality.value},
        )
        raise
    # Fase 4L: misma trazabilidad que el PATCH de contexto (quién/cuándo, historial) y
    # nueva versión del contexto, para que una edición de contexto obsoleta reciba 409.
    AssetContextService(session).record_criticality(asset, previous, actor(ctx))
    # Se encola primero (va en la misma transacción que el cambio): si el recálculo
    # inmediato fallara, el job lo hará en su siguiente vuelta.
    request_recalculation(session, [asset.id])
    mark_dirty(session, [asset.id], "context")
    audit_service.record(
        session,
        actor(ctx),
        action,
        target_type="asset",
        target_id=asset_id,
        details={"from": previous.value, "to": body.criticality.value},
        commit=False,
    )
    session.commit()
    if previous != body.criticality:
        # Recalcular un solo activo es barato; cada activo va en su SAVEPOINT, así que un
        # fallo aquí no deshace el cambio ya confirmado.
        RiskEngine(session, config, AlertThresholds.from_settings(get_settings())).recalculate(
            [asset.id]
        )
        session.commit()
    return service.detail(asset_id)
