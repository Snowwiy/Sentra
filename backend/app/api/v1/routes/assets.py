from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import IPvAnyNetwork

from app.api.auth import READ, actor, require_permission
from app.api.deps import (
    DbSession,
    get_agent_management_service,
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
from app.models.asset import AssetStatus, MonitoringMethod
from app.models.change import ChangeCategory
from app.risk.config import RiskConfig
from app.risk.engine import RiskEngine
from app.risk.queue import request_recalculation
from app.schemas.agent_management import AgentRead
from app.schemas.asset import AssetList, AssetRead
from app.schemas.change import ChangeList
from app.schemas.discovery import ExposureRead
from app.schemas.inventory import InventoryRead
from app.schemas.process import ProcessSnapshotRead
from app.schemas.risk import CriticalityUpdate, RiskAssetDetail
from app.schemas.telemetry import TelemetryHistory
from app.services import audit_service
from app.services.agent_management_service import AgentManagementService
from app.services.alert_service import AlertThresholds
from app.services.asset_service import AssetFilter, AssetService
from app.services.auth_service import AuthContext
from app.services.exposure_service import ExposureService
from app.services.inventory_service import InventoryService
from app.services.process_service import ProcessService
from app.services.risk_service import RiskService
from app.services.telemetry_service import TelemetryService

# Solo lectura del dashboard: cualquier rol con monitoring:read (viewer incluido).
router = APIRouter(prefix="/assets", tags=["assets"], dependencies=[READ])
Service = Annotated[AssetService, Depends(get_asset_service)]
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
) -> AssetList:
    search = q.strip() if q else None
    return service.list_assets(
        AssetFilter(
            method=method, status=status, device_type=device_type, subnet=subnet, search=search
        )
    )


@router.get("/{asset_id}", response_model=AssetRead, responses=error_responses(404))
def get_asset(asset_id: UUID, service: Service) -> AssetRead:
    return service.get_asset(asset_id)


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
    # Se encola primero (va en la misma transacción que el cambio): si el recálculo
    # inmediato fallara, el job lo hará en su siguiente vuelta.
    request_recalculation(session, [asset.id])
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
