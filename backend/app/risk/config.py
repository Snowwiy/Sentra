"""Parámetros del Risk Engine en un único sitio: umbrales, pesos, decay y saturación.

Ninguna otra parte de la aplicación conoce los números de la fórmula: el cálculo, la API y
la documentación leen RiskConfig. Los umbrales de nivel y los tiempos de decay salen de
Settings (RISK_*); los pesos son constantes razonadas aquí (docs/risk-engine.md) y se pueden
convertir en configuración el día que haga falta sin tocar el cálculo.

Cambiar un peso cambia lo que significa un score: hay que subir FORMULA_VERSION para que el
historial siga siendo interpretable.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from types import MappingProxyType

from app.core.config import Settings, parse_risk_thresholds
from app.models.asset import AssetCriticality
from app.models.asset_context import AssetEnvironment, DataSensitivity
from app.models.detection import DetectionConfidence, DetectionSeverity, DetectionStatus
from app.models.risk import RiskLevel

# Versión de la fórmula guardada en cada cálculo y snapshot.
# v2 (Fase 4L): factores de contexto de negocio acotados (entorno, sensibilidad de datos,
# exposición a Internet confirmada). Con contexto desconocido el resultado es idéntico a v1.
# v3 (Fase 5B): findings de vulnerabilidad activos como evidencia acotada (ver
# VULNERABILITY_POINTS). Sin findings el resultado es idéntico a v2.
# v4 (Fase 5C): inteligencia de amenazas. (a) Explotabilidad de findings confirmados o
# probables (CISA KEV, EPSS) como factor acotado sobre la vulnerabilidad (VULNERABILITY_
# EXPLOIT_FACTOR); (b) matches de IOCs con datos locales como evidencia propia (THREAT_*).
# Un IOC sin match local no aporta nada. Sin inteligencia el resultado es idéntico a v3.
FORMULA_VERSION = 4


# Puntos base por severidad: impacto si la detección es cierta, en la escala 0-100. No es
# una suma por categoría ("critical = +50"): cada detección aporta como mucho estos puntos y
# después se aplican confianza, estado, antigüedad, rendimientos decrecientes y saturación.
# Calibrado para que UNA detección reciente y abierta caiga en su propio nivel:
# high/high -> 70 (high), critical/high -> ~85 tras saturación (critical), medium -> < 40.
SEVERITY_POINTS: Mapping[DetectionSeverity, float] = MappingProxyType(
    {
        DetectionSeverity.INFORMATIONAL: 3.0,
        DetectionSeverity.LOW: 12.0,
        DetectionSeverity.MEDIUM: 35.0,
        DetectionSeverity.HIGH: 70.0,
        DetectionSeverity.CRITICAL: 90.0,
    }
)

# Confianza de la detección: una señal dudosa aporta poco más de la mitad. Así una señal
# crítica aislada con confianza baja (90 x 0,55 = 49,5) nunca llega sola a critical.
CONFIDENCE_FACTOR: Mapping[DetectionConfidence, float] = MappingProxyType(
    {
        DetectionConfidence.LOW: 0.55,
        DetectionConfidence.MEDIUM: 0.8,
        DetectionConfidence.HIGH: 1.0,
    }
)

# Estado: reconocida NO es mitigada (alguien la mira, el riesgo sigue); resuelta conserva
# memoria reciente y decae con su propia semivida (RISK_RESOLVED_HALF_LIFE_HOURS).
STATUS_FACTOR: Mapping[DetectionStatus, float] = MappingProxyType(
    {
        DetectionStatus.OPEN: 1.0,
        DetectionStatus.ACKNOWLEDGED: 0.85,
        DetectionStatus.RESOLVED: 0.5,
    }
)

# Criticidad del activo: modificador acotado y multiplicativo. Multiplica riesgo existente,
# nunca lo crea (0 x 1,4 = 0): un activo crítico sin evidencia sigue en 0.
CRITICALITY_FACTOR: Mapping[AssetCriticality, float] = MappingProxyType(
    {
        AssetCriticality.LOW: 0.8,
        AssetCriticality.MEDIUM: 1.0,
        AssetCriticality.HIGH: 1.2,
        AssetCriticality.CRITICAL: 1.4,
    }
)

# Contexto de negocio (Fase 4L): modificadores PEQUEÑOS y multiplicativos sobre el riesgo
# que ya aporta la evidencia. Nunca crean riesgo (0 x f = 0) ni restan: "unknown", entornos
# no productivos o datos públicos valen 1,0. Un laboratorio no resta porque los atacantes
# pivotan precisamente desde equipos olvidados; y lo desconocido no es evidencia de nada.
ENVIRONMENT_FACTOR: Mapping[AssetEnvironment, float] = MappingProxyType(
    {AssetEnvironment.PRODUCTION: 1.1}
)
DATA_SENSITIVITY_FACTOR: Mapping[DataSensitivity, float] = MappingProxyType(
    {DataSensitivity.CONFIDENTIAL: 1.05, DataSensitivity.RESTRICTED: 1.1}
)
# Solo exposición CONFIRMADA por un admin (internet_exposed = true). Un puerto abierto visto
# desde el servidor de Sentra ya cuenta como "exposure" y no implica Internet.
INTERNET_EXPOSED_FACTOR = 1.1
# Tope del producto de los factores de contexto: aunque se acumulen los tres (1,331), el
# contexto como mucho multiplica la evidencia por 1,25.
CONTEXT_FACTOR_CAP = 1.25

# Tipo de dispositivo, con prudencia: solo infraestructura compartida pesa algo más (lo que
# le pase afecta a otros). Ningún tipo resta y "desconocido" es neutro (1,0): no estar
# identificado no es evidencia de nada.
INFRASTRUCTURE_TYPES = frozenset({"server", "nas", "router", "network_switch", "access_point"})
INFRASTRUCTURE_FACTOR = 1.1


# Fase 5B: puntos de un finding de vulnerabilidad por severidad del catálogo. Debilidad, no
# ataque: una crítica confirmada (40) en un activo de criticidad media queda en "medium";
# solo con exposición, criticidad y contexto se acerca a "high"/"critical", nunca a 100.
VULNERABILITY_POINTS: Mapping[str, float] = MappingProxyType(
    {"informational": 0.0, "low": 4.0, "medium": 14.0, "high": 28.0, "critical": 40.0}
)
# Evidencia del match: una potencial aporta poco (posible backport, versión no comparable).
VULNERABILITY_MATCH_FACTOR: Mapping[str, float] = MappingProxyType(
    {"confirmed": 1.0, "probable": 0.7, "potential": 0.25}
)
# Servicio afectado observado (o con Internet confirmada): más fácil de explotar.
VULNERABILITY_EXPOSURE_FACTOR: Mapping[str, float] = MappingProxyType(
    {"internet_exposed": 1.3, "observed": 1.15, "listening": 1.05}
)
# Estado de trabajo: mitigando pesa menos; un riesgo ACEPTADO sigue existiendo (aceptar no
# es corregir) pero a la mitad; resueltos y falsos positivos no llegan al cálculo.
VULNERABILITY_STATUS_FACTOR: Mapping[str, float] = MappingProxyType(
    {"open": 1.0, "acknowledged": 0.9, "mitigating": 0.6, "accepted_risk": 0.5}
)

# Fase 5C: explotabilidad externa de un finding CONFIRMADO o PROBABLE (multiplicador sobre
# sus puntos; cuenta el mayor, no se suman). Una potencial no gana nada: la duda es si el
# activo es vulnerable, no si la vulnerabilidad se explota. Fuente caducada: la mitad del
# incremento.
VULNERABILITY_EXPLOIT_FACTOR: Mapping[str, float] = MappingProxyType(
    {"known_exploited": 1.35, "epss_high": 1.2, "epss_elevated": 1.1}
)
VULNERABILITY_EXPLOIT_STATES = frozenset({"confirmed", "probable"})

# Fase 5C: match de un IOC con un dato LOCAL. Puntos por clasificación de la fuente
# ("unknown" no aporta: aparecer en una lista no dice nada), por confianza del match, por
# confianza en la fuente y por estado del match. Un IOC malicioso de confianza alta de una
# fuente oficial, recién observado, aporta 30: medio, nunca "critical" por sí solo.
THREAT_CLASSIFICATION_POINTS: Mapping[str, float] = MappingProxyType(
    {"malicious": 30.0, "suspicious": 12.0}
)
THREAT_CONFIDENCE_FACTOR: Mapping[str, float] = MappingProxyType(
    {"low": 0.4, "medium": 0.7, "high": 1.0}
)
THREAT_TRUST_FACTOR: Mapping[str, float] = MappingProxyType(
    {"official": 1.0, "trusted": 0.9, "local": 0.85, "community": 0.7}
)
THREAT_STATUS_FACTOR: Mapping[str, float] = MappingProxyType(
    {"open": 1.0, "acknowledged": 0.85, "dismissed": 0.0}
)
# Indicador revocado o caducado DESPUÉS del match: se conserva la memoria a la mitad.
THREAT_INACTIVE_FACTOR = 0.5


@dataclass(frozen=True)
class RiskConfig:
    # Límites inferiores de low, medium, high y critical.
    thresholds: tuple[int, int, int, int] = (20, 40, 60, 80)

    severity_points: Mapping[DetectionSeverity, float] = field(default=SEVERITY_POINTS)
    confidence_factor: Mapping[DetectionConfidence, float] = field(default=CONFIDENCE_FACTOR)
    status_factor: Mapping[DetectionStatus, float] = field(default=STATUS_FACTOR)
    criticality_factor: Mapping[AssetCriticality, float] = field(default=CRITICALITY_FACTOR)
    environment_factor: Mapping[AssetEnvironment, float] = field(default=ENVIRONMENT_FACTOR)
    data_sensitivity_factor: Mapping[DataSensitivity, float] = field(
        default=DATA_SENSITIVITY_FACTOR
    )
    internet_exposed_factor: float = INTERNET_EXPOSED_FACTOR
    context_factor_cap: float = CONTEXT_FACTOR_CAP

    # Persistencia: ocurrencias (oleadas separadas por el cooldown de la regla, no eventos
    # brutos) suben el peso de forma logarítmica y acotada: 1 + 0,12 * log2(n), máx. 1,35.
    occurrence_slope: float = 0.12
    occurrence_cap: float = 1.35
    # Una correlación une varias señales independientes: pesa un 15 % más que su severidad.
    correlation_factor: float = 1.15

    # Decay temporal por antigüedad de la última actividad (semivida) con suelo para las no
    # resueltas, y decay de las resueltas desde que se resolvieron.
    activity_half_life: timedelta = timedelta(hours=24)
    active_floor: float = 0.25
    resolved_half_life: timedelta = timedelta(hours=12)
    resolved_memory: timedelta = timedelta(hours=72)

    # Rendimientos decrecientes: el grupo n-ésimo (por peso) aporta beta^(n-1). Con 0,5 la
    # suma de infinitas señales iguales es como mucho el doble de una sola.
    diminishing_beta: float = 0.5

    # Saturación: lineal hasta `saturation_knee` y asintótica hasta 100 por encima, para que
    # una avalancha de señales nunca lleve "automáticamente" a 100.
    saturation_knee: float = 70.0

    # Fase 5B: findings de vulnerabilidad (ver constantes VULNERABILITY_*). Como mucho
    # `max_vulnerabilities` por activo (los de más prioridad); con beta 0,5 el resto apenas
    # sumaría y así el cálculo sigue acotado.
    vulnerability_points: Mapping[str, float] = field(default=VULNERABILITY_POINTS)
    vulnerability_match_factor: Mapping[str, float] = field(default=VULNERABILITY_MATCH_FACTOR)
    vulnerability_exposure_factor: Mapping[str, float] = field(
        default=VULNERABILITY_EXPOSURE_FACTOR
    )
    vulnerability_status_factor: Mapping[str, float] = field(default=VULNERABILITY_STATUS_FACTOR)
    max_vulnerabilities: int = 20
    vulnerability_exploit_factor: Mapping[str, float] = field(default=VULNERABILITY_EXPLOIT_FACTOR)

    # Fase 5C: matches de IOCs (ver THREAT_*). Frescura: semivida desde la última
    # observación local y olvido completo pasado `threat_memory`.
    threat_classification_points: Mapping[str, float] = field(default=THREAT_CLASSIFICATION_POINTS)
    threat_confidence_factor: Mapping[str, float] = field(default=THREAT_CONFIDENCE_FACTOR)
    threat_trust_factor: Mapping[str, float] = field(default=THREAT_TRUST_FACTOR)
    threat_status_factor: Mapping[str, float] = field(default=THREAT_STATUS_FACTOR)
    threat_inactive_factor: float = THREAT_INACTIVE_FACTOR
    threat_half_life: timedelta = timedelta(hours=72)
    threat_memory: timedelta = timedelta(days=30)
    max_threat_matches: int = 50

    # Exposición observada por discovery (no vulnerabilidad): puntos por puerto sensible.
    exposure_admin_points: float = 10.0
    exposure_cleartext_admin_points: float = 12.0
    exposure_data_points: float = 7.0
    exposure_recent_factor: float = 1.3
    exposure_recent: timedelta = timedelta(hours=24)

    # Datos del agente más antiguos que esto: evaluación incompleta (menos confianza).
    stale_data: timedelta = timedelta(hours=24)

    # Historial: snapshot si cambia el nivel, si el score se mueve al menos `snapshot_min_delta`,
    # si aparece una contribución nueva, o tras `snapshot_interval` si cambió algo.
    snapshot_min_delta: int = 5
    snapshot_interval: timedelta = timedelta(minutes=60)
    # Una contribución "nueva" solo cuenta para snapshot si aporta al menos esto.
    new_contribution_min_points: float = 3.0

    # Job: lotes y frecuencias.
    batch_size: int = 100
    decay_interval: timedelta = timedelta(minutes=15)
    full_refresh: timedelta = timedelta(hours=6)

    # Alertas: solo al cruzar hacia critical, con cooldown por activo.
    alert_enabled: bool = True
    alert_cooldown: timedelta = timedelta(hours=6)

    # Cotas defensivas de la entrada del cálculo por activo (consultas acotadas).
    max_detections: int = 500
    # Contribuciones guardadas por cálculo (las de más peso; el resto se resume).
    max_contributions: int = 40

    @classmethod
    def from_settings(cls, settings: Settings) -> "RiskConfig":
        return cls(
            thresholds=parse_risk_thresholds(settings.risk_level_thresholds),
            activity_half_life=timedelta(hours=settings.risk_activity_half_life_hours),
            active_floor=settings.risk_active_floor,
            resolved_half_life=timedelta(hours=settings.risk_resolved_half_life_hours),
            resolved_memory=timedelta(hours=settings.risk_resolved_memory_hours),
            exposure_recent=timedelta(hours=settings.risk_exposure_recent_hours),
            stale_data=timedelta(hours=settings.risk_stale_data_hours),
            snapshot_min_delta=settings.risk_snapshot_min_delta,
            snapshot_interval=timedelta(minutes=settings.risk_snapshot_interval_minutes),
            batch_size=settings.risk_batch_size,
            decay_interval=timedelta(minutes=settings.risk_decay_interval_minutes),
            full_refresh=timedelta(hours=settings.risk_full_refresh_hours),
            alert_enabled=settings.risk_alert_enabled,
            alert_cooldown=timedelta(hours=settings.risk_alert_cooldown_hours),
        )

    def level_for(self, score: int) -> RiskLevel:
        """Nivel de una puntuación con los umbrales centralizados."""
        low, medium, high, critical = self.thresholds
        if score >= critical:
            return RiskLevel.CRITICAL
        if score >= high:
            return RiskLevel.HIGH
        if score >= medium:
            return RiskLevel.MEDIUM
        if score >= low:
            return RiskLevel.LOW
        return RiskLevel.INFORMATIONAL

    def level_ranges(self) -> dict[str, tuple[int, int]]:
        """Rango [mín, máx] de cada nivel, para la API y la UI (nunca se duplican en el front)."""
        low, medium, high, critical = self.thresholds
        return {
            RiskLevel.INFORMATIONAL.value: (0, low - 1),
            RiskLevel.LOW.value: (low, medium - 1),
            RiskLevel.MEDIUM.value: (medium, high - 1),
            RiskLevel.HIGH.value: (high, critical - 1),
            RiskLevel.CRITICAL.value: (critical, 100),
        }
