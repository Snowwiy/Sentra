"""Prioridad Sentra de un finding (0-100) con su explicación (Fase 5B).

NO es el CVSS (gravedad intrínseca que publica la fuente) ni el riesgo del activo (4I): ordena
qué corregir primero combinando, de forma explicable y acotada:
1. severidad normalizada del registro del catálogo (la de la fuente, o la escala estándar
   del CVSS que trae la fuente; Sentra nunca calcula un CVSS propio);
2. evidencia del match: confirmed pesa entero; probable, potencial y desconocido menos;
3. exposición del servicio afectado (observado desde el sensor, Internet confirmada);
4. contexto del activo: criticidad, entorno de producción y datos sensibles (4I/4L);
5. (Fase 5C, FORMULA_VERSION 2) inteligencia de explotabilidad del CVE: explotación conocida
   reportada (CISA KEV) y probabilidad de explotación EPSS. Es contexto EXTERNO: solo modula
   un finding con evidencia (igual que la exposición), está acotado (EXPLOIT_CAP) y nunca
   cambia match_state ni la lógica de versiones. Con la fuente caducada cuenta la mitad.

El desglose (factors) suma exactamente la puntuación antes de recortar a 0-100.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.models.asset import AssetCriticality
from app.models.asset_context import AssetEnvironment, DataSensitivity
from app.threat_intel.epss import band as epss_band

FORMULA_VERSION = 2

SEVERITY_POINTS: Mapping[str, float] = {
    "informational": 2.0,
    "low": 10.0,
    "medium": 26.0,
    "high": 42.0,
    "critical": 55.0,
}
SEVERITY_LABELS: Mapping[str, str] = {
    "informational": "informativa",
    "low": "baja",
    "medium": "media",
    "high": "alta",
    "critical": "crítica",
}
# Factor de evidencia: una coincidencia potencial ordena por debajo de una confirmada de
# menor severidad (high confirmada 42 > critical potencial 55 x 0,45 = 24,75).
MATCH_FACTOR: Mapping[str, float] = {
    "confirmed": 1.0,
    "probable": 0.8,
    "potential": 0.45,
    "unknown": 0.3,
    "not_affected": 0.0,
}
EXPOSURE_POINTS: Mapping[str, float] = {
    "internet_exposed": 22.0,
    "observed": 12.0,
    "listening": 4.0,
}
EXPOSURE_LABELS: Mapping[str, str] = {
    "internet_exposed": "Servicio afectado observado y exposición a Internet confirmada",
    "observed": "Servicio afectado observado desde el sensor de Sentra",
    "listening": "Servicio afectado en escucha en el equipo (no observado desde la red)",
}
CRITICALITY_POINTS: Mapping[AssetCriticality, float] = {
    AssetCriticality.LOW: -5.0,
    AssetCriticality.MEDIUM: 0.0,
    AssetCriticality.HIGH: 8.0,
    AssetCriticality.CRITICAL: 14.0,
}
# Fase 5C. KEV pesa más que EPSS: es explotación observada y reportada por una fuente
# oficial; EPSS es una predicción. Juntos nunca superan EXPLOIT_CAP (antes del factor de
# evidencia): una vulnerabilidad media en KEV no adelanta a una crítica confirmada expuesta.
KEV_POINTS = 10.0
EPSS_POINTS: Mapping[str, float] = {"high": 6.0, "elevated": 3.0}
EXPLOIT_CAP = 14.0
STALE_INTEL_FACTOR = 0.5
PRODUCTION_POINTS = 4.0
SENSITIVE_DATA_POINTS = 4.0
# Límites inferiores de low, medium, high y critical (mismos cortes que el riesgo 4I).
LEVELS: tuple[tuple[int, str], ...] = ((80, "critical"), (60, "high"), (40, "medium"), (20, "low"))


@dataclass(frozen=True)
class PriorityInputs:
    severity: str
    match_state: str
    exposure_state: str
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    environment: AssetEnvironment = AssetEnvironment.UNKNOWN
    data_sensitivity: DataSensitivity = DataSensitivity.UNKNOWN
    # Fase 5C (app/threat_intel/lookup.py).
    known_exploited: bool = False
    epss_score: float | None = None
    intel_stale: bool = False


@dataclass(frozen=True)
class Priority:
    score: int
    level: str
    factors: tuple[dict[str, Any], ...]


def level_for(score: int) -> str:
    for threshold, level in LEVELS:
        if score >= threshold:
            return level
    return "informational"


def _exploitation(
    inputs: PriorityInputs, match_factor: float, factors: list[dict[str, Any]]
) -> float:
    """Puntos por inteligencia de explotabilidad (añade sus factores a la explicación)."""
    weight = max(match_factor, 0.45) * (STALE_INTEL_FACTOR if inputs.intel_stale else 1.0)
    stale = " (inteligencia desactualizada)" if inputs.intel_stale else ""
    budget = EXPLOIT_CAP * weight
    total = 0.0
    if inputs.known_exploited:
        points = min(KEV_POINTS * weight, budget)
        factors.append(
            {
                "factor": "known_exploited",
                "label": f"Explotación conocida reportada (CISA KEV){stale}",
                "points": round(points, 2),
            }
        )
        total += points
    level = epss_band(inputs.epss_score)
    if level in EPSS_POINTS and inputs.epss_score is not None:
        points = min(EPSS_POINTS[level] * weight, budget - total)
        if points > 0:
            label = "alta" if level == "high" else "elevada"
            percent = f"{inputs.epss_score * 100:.1f}".replace(".", ",")
            factors.append(
                {
                    "factor": "epss",
                    "label": f"Probabilidad de explotación EPSS {label} ({percent} %){stale}",
                    "points": round(points, 2),
                }
            )
            total += points
    return total


def calculate(inputs: PriorityInputs) -> Priority:
    factors: list[dict[str, Any]] = []
    severity = SEVERITY_POINTS.get(inputs.severity, 0.0)
    factors.append(
        {
            "factor": "severity",
            "label": f"Severidad {SEVERITY_LABELS.get(inputs.severity, inputs.severity)}",
            "points": severity,
        }
    )
    match_factor = MATCH_FACTOR.get(inputs.match_state, 0.0)
    if match_factor != 1.0:
        factors.append(
            {
                "factor": "match",
                "label": f"Evidencia {inputs.match_state} (x{match_factor:g})".replace(".", ","),
                "points": round(severity * (match_factor - 1.0), 2),
            }
        )
    evidence = severity * match_factor
    total = evidence
    if evidence > 0:
        # La exposición y el contexto solo modulan una vulnerabilidad con evidencia: un
        # activo crítico sin evidencia no gana prioridad por serlo.
        exposure = EXPOSURE_POINTS.get(inputs.exposure_state, 0.0) * max(match_factor, 0.45)
        if exposure:
            factors.append(
                {
                    "factor": "exposure",
                    "label": EXPOSURE_LABELS[inputs.exposure_state],
                    "points": round(exposure, 2),
                }
            )
            total += exposure
        exploitation = _exploitation(inputs, match_factor, factors)
        total += exploitation
        criticality = CRITICALITY_POINTS[inputs.criticality]
        if criticality:
            factors.append(
                {
                    "factor": "criticality",
                    "label": f"Criticidad del activo: {inputs.criticality.value}",
                    "points": criticality,
                }
            )
            total += criticality
        if inputs.environment == AssetEnvironment.PRODUCTION:
            factors.append(
                {"factor": "context", "label": "Entorno de producción", "points": PRODUCTION_POINTS}
            )
            total += PRODUCTION_POINTS
        if inputs.data_sensitivity in (DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED):
            factors.append(
                {
                    "factor": "context",
                    "label": f"Datos {inputs.data_sensitivity.value}",
                    "points": SENSITIVE_DATA_POINTS,
                }
            )
            total += SENSITIVE_DATA_POINTS
    score = max(0, min(100, round(total)))
    return Priority(score=score, level=level_for(score), factors=tuple(factors))
