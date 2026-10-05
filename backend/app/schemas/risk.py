"""Contratos de la API de riesgo (Fase 4I).

Pensados también como entrada estructurada para AI Security Insights (Fase 4J): score,
nivel, confianza, contribuciones con referencias navegables y explicación determinista. Sin
ids internos: activos, detecciones y snapshots se identifican por su id público.
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from app.models.asset import AssetCriticality, AssetStatus, MonitoringMethod
from app.models.detection import DetectionConfidence, DetectionSeverity, DetectionStatus
from app.models.risk import RiskConfidence, RiskLevel
from app.schemas.common import RequestModel, ResponseModel

RiskRange = Literal["24h", "7d", "30d"]


class RiskContributionRead(ResponseModel):
    # detection, exposure, criticality, asset_type o saturation.
    factor: str
    # Categoría de la regla (authentication, defense...), "exposure" o "context".
    category: str
    # Texto determinista (plantilla), nunca generado por IA.
    label: str
    # Puntos que aportó (negativos si redujo). 0 = absorbida por otra (sin doble conteo).
    points: float
    # Puntos antes de antigüedad, estado y rendimientos decrecientes.
    nominal_points: float | None
    # Referencias navegables cuando existen: detección (/detections/{id}) y puerto
    # (exposición del activo).
    detection_id: UUID | None
    rule_id: str | None
    port: int | None
    # Factores aplicados (recency_factor, status_factor, position_factor), severidad,
    # confianza, estado y, si se agrupó, absorbed / absorbed_by.
    details: dict[str, Any]


class RiskExplanationItem(ResponseModel):
    label: str
    points: float


class ConfidenceFactorRead(ResponseModel):
    # "+" sube la confianza, "-" la baja, "=" informativo.
    effect: Literal["+", "-", "="]
    label: str


class RiskExplanation(ResponseModel):
    """¿Por qué este activo tiene este riesgo? Determinista: sale del cálculo guardado."""

    # "82 / Crítico — confianza baja": la incertidumbre siempre visible junto al score.
    headline: str
    # Motivos principales en una línea cada uno.
    reasons: list[str]
    increased: list[RiskExplanationItem]
    reduced: list[RiskExplanationItem]
    confidence_factors: list[ConfidenceFactorRead]


class RiskAssetSummary(ResponseModel):
    asset_id: UUID
    display_name: str
    # Nombre resuelto (null si nada lo nombra: la UI muestra "Dispositivo desconocido").
    device_name: str | None
    primary_ip: str
    device_type: str | None
    monitoring_method: MonitoringMethod
    status: AssetStatus
    criticality: AssetCriticality
    # Último contacto del agente o última vez visto en la red (el más reciente).
    last_seen_at: datetime | None
    # False hasta el primer cálculo (activo nuevo en cola): score y nivel son null.
    evaluated: bool
    score: int | None
    level: RiskLevel | None
    confidence: RiskConfidence | None
    top_factor: str | None
    calculated_at: datetime | None
    # Último cambio material (último punto del historial).
    changed_at: datetime | None


class RiskAssetList(ResponseModel):
    items: list[RiskAssetSummary]
    # Activos que cumplen los filtros (todas las páginas).
    total: int


class RiskFactorRead(ResponseModel):
    category: str
    label: str
    # Activos en los que aporta y suma de puntos que aporta en todos ellos.
    assets: int
    points: float


class RiskSnapshotRead(ResponseModel):
    snapshot_id: UUID
    calculated_at: datetime
    score: int
    level: RiskLevel
    confidence: RiskConfidence
    previous_score: int | None
    previous_level: RiskLevel | None
    # "up", "down" o null (sin cambio de nivel).
    transition: Literal["up", "down"] | None
    # initial, level_change, material_change, new_contribution o interval.
    reason: str
    top_factor: str | None


class RiskTransitionRead(RiskSnapshotRead):
    asset_id: UUID
    display_name: str


class RiskLevelRange(ResponseModel):
    level: RiskLevel
    min: int
    max: int


class RiskOverview(ResponseModel):
    total_assets: int
    evaluated: int
    # Activos en cola de recálculo (nuevos o con cambios aún sin procesar).
    pending: int
    by_level: dict[RiskLevel, int]
    by_confidence: dict[RiskConfidence, int]
    top_factors: list[RiskFactorRead]
    top_assets: list[RiskAssetSummary]
    recent_transitions: list[RiskTransitionRead]
    thresholds: list[RiskLevelRange]
    last_calculated_at: datetime | None


class RiskDetectionRef(ResponseModel):
    detection_id: UUID
    rule_id: str
    title: str
    category: str
    severity: DetectionSeverity
    confidence: DetectionConfidence
    status: DetectionStatus
    occurrence_count: int
    last_seen_at: datetime


class RiskAssetDetail(RiskAssetSummary):
    formula_version: int | None
    # Hay un recálculo pendiente (el valor mostrado puede cambiar en segundos).
    pending_recalculation: bool
    explanation: RiskExplanation
    contributions: list[RiskContributionRead]
    # Detecciones abiertas o reconocidas del activo (las más graves primero, máx. 20).
    active_detections: list[RiskDetectionRef]
    active_detections_total: int
    # Últimos puntos del historial (más recientes primero, máx. 10).
    recent_changes: list[RiskSnapshotRead]
    # Score actual menos el de hace 24 h (null sin historial suficiente).
    trend_24h: int | None
    # Desglose del cálculo (puntos base, modificadores, reducciones) para auditoría y 4J.
    breakdown: dict[str, Any] | None
    thresholds: list[RiskLevelRange]


class RiskHistory(ResponseModel):
    asset_id: UUID
    range: RiskRange
    since: datetime
    # Minutos por punto cuando el rango se agrega (7d: 60, 30d: 240); null = puntos reales.
    bucket_minutes: int | None
    # Último valor anterior a `since` (para empezar la línea en su nivel real).
    start_score: int | None
    points: list[RiskSnapshotRead]
    # Valor actual (puede ser más reciente que el último punto: el historial solo guarda
    # cambios materiales).
    current_score: int | None
    current_level: RiskLevel | None
    calculated_at: datetime | None


class RiskContributionList(ResponseModel):
    asset_id: UUID
    # null = contribuciones vigentes; si no, las de ese punto del historial.
    snapshot_id: UUID | None
    calculated_at: datetime | None
    score: int | None
    items: list[RiskContributionRead]


class CriticalityUpdate(RequestModel):
    criticality: AssetCriticality
