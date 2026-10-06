from datetime import datetime

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


class DashboardVulnerabilities(ResponseModel):
    # Fase 5B. Findings activos (open, acknowledged, mitigating) con evidencia confirmed o
    # probable, por severidad. Los potenciales van aparte: nunca cuentan como confirmados.
    by_severity: dict[str, int]
    potential: int
    assets_affected: int


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
