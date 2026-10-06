"""Explicación determinista de un riesgo guardado ("¿por qué este activo tiene este riesgo?").

Se construye a partir de lo persistido (contribuciones y desglose), no recalculando: así un
punto antiguo del historial se explica con los datos con los que se calculó. Plantillas
fijas, sin IA: nunca se dice que "la IA considera" nada.
"""

from collections.abc import Mapping, Sequence
from typing import Any

from app.models.risk import RiskConfidence, RiskLevel
from app.schemas.risk import ConfidenceFactorRead, RiskExplanation, RiskExplanationItem

LEVEL_LABELS = {
    RiskLevel.INFORMATIONAL: "Informativo",
    RiskLevel.LOW: "Bajo",
    RiskLevel.MEDIUM: "Medio",
    RiskLevel.HIGH: "Alto",
    RiskLevel.CRITICAL: "Crítico",
}
CONFIDENCE_LABELS = {
    RiskConfidence.LOW: "baja",
    RiskConfidence.MEDIUM: "media",
    RiskConfidence.HIGH: "alta",
}

# Reducciones del desglose (en puntos base, antes de modificadores del activo). La
# saturación y una criticidad baja ya aparecen como contribuciones negativas.
REDUCTION_LABELS = {
    "decay": "Antigüedad de la actividad (decay temporal)",
    "resolved": "Detecciones resueltas (memoria reciente que decae)",
    # Fase 5B: también vulnerabilidades reconocidas, en mitigación o con riesgo aceptado.
    "acknowledged": "Detecciones o vulnerabilidades en gestión (siguen activas, peso menor)",
    "absorbed": "Señales ya contadas en una correlación o en el mismo puerto (sin doble conteo)",
    "diminishing": "Rendimientos decrecientes por varias señales",
}

# Contribuciones que son contexto del activo (no evidencia): criticidad, tipo de
# infraestructura y contexto de negocio (Fase 4L).
CONTEXT_FACTORS = frozenset({"criticality", "asset_type", "business_context"})

# Por debajo de esto una reducción no se menciona (ruido de redondeo).
MIN_POINTS = 0.5
MAX_ITEMS = 8


def headline(score: int, level: RiskLevel, confidence: RiskConfidence) -> str:
    return f"{score} / {LEVEL_LABELS[level]} — confianza {CONFIDENCE_LABELS[confidence]}"


def explain(
    score: int,
    level: RiskLevel,
    confidence: RiskConfidence,
    contributions: Sequence[Mapping[str, Any]],
    breakdown: Mapping[str, Any] | None,
) -> RiskExplanation:
    breakdown = breakdown or {}
    positive = sorted((c for c in contributions if _points(c) > 0), key=lambda c: -_points(c))
    negative = sorted((c for c in contributions if _points(c) < 0), key=lambda c: _points(c))
    increased = [
        RiskExplanationItem(label=str(c.get("label", "")), points=_points(c))
        for c in positive[:MAX_ITEMS]
    ]
    reduced = [
        RiskExplanationItem(label=str(c.get("label", "")), points=_points(c)) for c in negative
    ]
    reductions = breakdown.get("reductions")
    if isinstance(reductions, Mapping):
        for key, label in REDUCTION_LABELS.items():
            value = _number(reductions.get(key))
            if value >= MIN_POINTS:
                reduced.append(RiskExplanationItem(label=label, points=-round(value, 2)))
    reduced.sort(key=lambda item: item.points)

    # Contexto del activo aparte (Fase 4L): modifica la evidencia, no es un motivo en sí.
    context = [
        RiskExplanationItem(label=str(c.get("label", "")), points=_points(c))
        for c in contributions
        if c.get("factor") in CONTEXT_FACTORS and _points(c) != 0
    ]
    reasons = [
        str(c.get("label", ""))
        for c in positive[:4]
        if c.get("factor") not in ("criticality", "business_context")
    ]
    categories = breakdown.get("independent_categories")
    if isinstance(categories, list) and len(categories) >= 2:
        reasons.append(f"Señales independientes de {len(categories)} tipos")
    if not reasons:
        reasons = ["No hay detecciones ni exposición sensible que aporten riesgo."]

    factors: list[ConfidenceFactorRead] = []
    raw_factors = breakdown.get("confidence_factors")
    if isinstance(raw_factors, list):
        for item in raw_factors:
            if isinstance(item, Mapping) and item.get("effect") in ("+", "-", "="):
                factors.append(
                    ConfidenceFactorRead(effect=item["effect"], label=str(item.get("label", "")))
                )
    return RiskExplanation(
        headline=headline(score, level, confidence),
        reasons=reasons,
        increased=increased,
        reduced=reduced[:MAX_ITEMS],
        confidence_factors=factors,
        context=context,
    )


def _points(contribution: Mapping[str, Any]) -> float:
    return _number(contribution.get("points"))


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
