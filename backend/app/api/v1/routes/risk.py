"""Riesgo de activos (Fase 4I): lectura para cualquier rol con monitoring:read.

Solo lectura: el riesgo lo calcula el job del Risk Engine. Lo único que lo altera desde la
API es la criticidad del activo (PATCH /assets/{id}/criticality, solo admin, en assets.py).
Las respuestas están pensadas para la UI y para AI Security Insights (Fase 4J).
"""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.auth import READ
from app.api.deps import get_risk_service
from app.api.params import text_query
from app.api.responses import error_responses
from app.models.asset import AssetCriticality, AssetStatus
from app.models.risk import RiskConfidence, RiskLevel
from app.schemas.risk import (
    RiskAssetDetail,
    RiskAssetList,
    RiskContributionList,
    RiskHistory,
    RiskOverview,
    RiskRange,
)
from app.services.risk_service import RiskFilter, RiskService, RiskSort

router = APIRouter(prefix="/risk", tags=["risk"], dependencies=[READ])
Service = Annotated[RiskService, Depends(get_risk_service)]


@router.get("/overview", response_model=RiskOverview)
def risk_overview(service: Service) -> RiskOverview:
    """Recuento por nivel y confianza, factores principales y últimas transiciones."""
    return service.overview()


@router.get("/assets", response_model=RiskAssetList)
def list_risk_assets(
    service: Service,
    level: RiskLevel | None = None,
    confidence: RiskConfidence | None = None,
    # Tipo de dispositivo (app/discovery/classify.py) o "unknown".
    device_type: Annotated[str | None, Query(pattern=r"^[a-z_]{1,32}$")] = None,
    # online / offline / unknown (misma regla que el listado de activos).
    status: AssetStatus | None = None,
    criticality: AssetCriticality | None = None,
    min_score: Annotated[int | None, Query(ge=0, le=100)] = None,
    q: Annotated[str | None, text_query(200)] = None,
    sort: RiskSort = "score",
    order: Literal["asc", "desc"] = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> RiskAssetList:
    return service.list_assets(
        RiskFilter(
            level=level,
            confidence=confidence,
            device_type=device_type,
            status=status,
            criticality=criticality,
            min_score=min_score,
            search=q.strip() if q and q.strip() else None,
        ),
        sort,
        order == "desc",
        limit,
        offset,
    )


@router.get("/assets/{asset_id}", response_model=RiskAssetDetail, responses=error_responses(404))
def get_asset_risk(asset_id: UUID, service: Service) -> RiskAssetDetail:
    """Riesgo actual con su explicación, contribuciones, detecciones activas y cambios."""
    return service.detail(asset_id)


@router.get(
    "/assets/{asset_id}/history", response_model=RiskHistory, responses=error_responses(404)
)
def get_asset_risk_history(
    asset_id: UUID, service: Service, range: RiskRange = "24h"
) -> RiskHistory:
    """Tendencia por rango (24h, 7d, 30d), agregada en rangos largos: nunca todo el historial."""
    return service.history(asset_id, range)


@router.get(
    "/assets/{asset_id}/contributions",
    response_model=RiskContributionList,
    responses=error_responses(404),
)
def get_asset_risk_contributions(
    asset_id: UUID, service: Service, snapshot_id: UUID | None = None
) -> RiskContributionList:
    """Contribuciones vigentes o, con `snapshot_id`, las de ese punto del historial."""
    return service.contributions(asset_id, snapshot_id)
