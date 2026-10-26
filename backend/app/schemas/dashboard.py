from datetime import datetime
from typing import Literal
from uuid import UUID

from app.schemas.common import ResponseModel


class DashboardAssets(ResponseModel):
    total: int
    online: int
    offline: int
    unknown: int
    # Por método de monitorización: discovered / agentless / agent (gestionados).
    by_method: dict[str, int]
    # Por tipo de dispositivo (o "unknown"); cardinalidad acotada por el catálogo de tipos.
    by_device_type: dict[str, int]


class DashboardRisk(ResponseModel):
    # Activos con riesgo calculado, por nivel; `unscored` aún no se ha calculado.
    by_level: dict[str, int]
    unscored: int


class DashboardIncidents(ResponseModel):
    # Casos activos (open, triage, investigating, contained) y cuántos son críticos.
    active: int
    critical: int
    unassigned: int


class DashboardDetections(ResponseModel):
    # Detecciones activas (open o acknowledged) por severidad.
    active: int
    by_severity: dict[str, int]


EvaluationState = Literal[
    "no_catalog",
    "pending",
    "insufficient_catalog",
    "vulnerabilities_found",
    "no_vulnerabilities",
]


class DashboardVulnerabilities(ResponseModel):
    # Fase 5B. Findings activos (open, acknowledged, mitigating) con evidencia confirmed o
    # probable, por severidad. Los potenciales van aparte: nunca cuentan como confirmados.
    by_severity: dict[str, int]
    potential: int
    assets_affected: int
    # Fase 6C.4: distingue "no hay vulnerabilidades" de "no hay catálogo suficiente":
    # no_catalog (ningún registro), pending (nada evaluado aún), insufficient_catalog (los
    # activos evaluados no tienen ningún componente descrito por el catálogo),
    # vulnerabilities_found o no_vulnerabilities. Campos añadidos: el contrato anterior sigue.
    evaluation_state: EvaluationState = "no_catalog"
    # Alguna fuente con registros sin actualizar en VULN_SOURCE_STALE_HOURS.
    catalog_stale: bool = False
    assets_evaluated: int = 0
    assets_covered: int = 0
    assets_pending: int = 0


class DashboardSummary(ResponseModel):
    """GET /dashboard/summary (Fase 4M): contadores agregados en SQL.

    Sustituye a descargar todos los activos para contarlos en el navegador. Ninguna fila se
    carga entera: solo COUNT/GROUP BY.
    """

    generated_at: datetime
    assets: DashboardAssets
    risk: DashboardRisk
    # None si el rol no puede leer incidentes (incidents:read).
    incidents: DashboardIncidents | None
    detections: DashboardDetections
    active_alerts: int
    # None si el rol no puede leer vulnerabilidades (vulnerabilities:read).
    vulnerabilities: DashboardVulnerabilities | None = None
    # Fase 5F: site al que se limita el resumen (null = todos los sites).
    site_id: UUID | None = None


# --- Fase 7A.7: vista de seguridad del dashboard ----------------------------------------------


class PostureMethod(ResponseModel):
    """Cómo se calcula el indicador global: va en la respuesta para que la UI lo enseñe."""

    formula: str
    population: str
    # Peso de cada criticidad de activo en la media ponderada.
    weights: dict[str, int]
    missing_data: str
    thresholds: dict[str, int]
    reference: str


class SecurityPosture(ResponseModel):
    """Riesgo global ponderado (fórmula v1, docs/security-dashboard.md).

    `score` es null sin datos: nunca se rellena con un valor inventado.
    """

    formula_version: int
    # ok: cobertura >= 50 %; partial: hay datos pero menos de la mitad de los activos tienen
    # riesgo calculado; no_data: ningún activo con riesgo calculado.
    state: Literal["ok", "partial", "no_data"]
    score: int | None
    level: str | None
    # Peor activo: la media no debe ocultar un activo crítico.
    peak_score: int | None
    high_or_critical: int
    assets_current: int
    assets_scored: int
    coverage: float
    method: PostureMethod


class RecentDetection(ResponseModel):
    detection_id: UUID
    rule_id: str
    title: str
    severity: str
    status: str
    asset_id: UUID
    asset_name: str
    last_seen_at: datetime


class RiskHistoryPoint(ResponseModel):
    day: datetime
    # Activos con algún valor de riesgo conocido al final de ese día (historial disponible).
    assets_scored: int
    average_score: float | None
    high: int
    critical: int


class NewDevice(ResponseModel):
    asset_id: UUID
    name: str
    device_type: str | None
    monitoring_method: str
    first_seen_at: datetime


class NewDevices(ResponseModel):
    window_days: int
    count: int
    items: list[NewDevice]


class ExposedPortCount(ResponseModel):
    port: int
    protocol: str
    assets: int


class ExposedPortSummary(ResponseModel):
    open_ports: int
    assets_with_open_ports: int
    top: list[ExposedPortCount]


class SecurityOverview(ResponseModel):
    """GET /dashboard/security-overview (Fase 7A.7). Complementa a /dashboard/summary."""

    generated_at: datetime
    site_id: UUID | None
    window_days: int
    posture: SecurityPosture
    # None si el rol no puede leer incidentes (incidents:read).
    incidents_by_status: dict[str, int] | None
    detections_recent: list[RecentDetection]
    risk_history: list[RiskHistoryPoint]
    new_devices: NewDevices
    exposed_ports: ExposedPortSummary
