"""Cálculo puro del riesgo de un activo: entradas -> RiskResult. Sin base de datos ni reloj.

Determinista y reproducible: el mismo RiskInputs con el mismo `now` y la misma RiskConfig da
siempre el mismo resultado (orden estable incluso en empates). Por eso se puede probar sin
PostgreSQL y recalcular un valor pasado para auditarlo.

Fórmula (detalle y justificación en docs/risk-engine.md):

1. Fuerza de cada detección = puntos de severidad x confianza x ocurrencias x correlación
   (nominal) x estado x antigüedad (efectiva).
2. Agrupación sin doble conteo: una correlación y las detecciones simples cuya evidencia
   comparte señales con ella forman UN grupo; lo mismo una detección de puerto y la
   exposición de ese puerto. El grupo vale lo que su miembro más fuerte; el resto queda
   "absorbido" (aparece en la explicación con 0 puntos).
3. Rendimientos decrecientes: grupos ordenados por valor; el n-ésimo aporta beta^(n-1).
4. Modificadores acotados del activo: criticidad y tipo (multiplican, nunca crean riesgo).
5. Saturación: lineal hasta el codo (70) y asintótica hasta 100 por encima.

El ledger de contribuciones suma exactamente el score antes de redondear: cada factor que
sube o baja la puntuación aparece con sus puntos.
"""

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from app.discovery.ports import SENSITIVE_PORTS, SERVICE_HINTS
from app.models.asset import AssetCriticality
from app.models.detection import DetectionConfidence, DetectionSeverity, DetectionStatus
from app.models.risk import RiskConfidence, RiskLevel
from app.risk.config import (
    FORMULA_VERSION,
    INFRASTRUCTURE_FACTOR,
    INFRASTRUCTURE_TYPES,
    RiskConfig,
)

# Servicios de administración remota (texto claro aparte) y de datos o compartición. Todos
# están en SENSITIVE_PORTS de discovery; un puerto no sensible abierto no suma riesgo: estar
# abierto no demuestra ninguna vulnerabilidad.
ADMIN_PORTS = frozenset({22, 3389, 5900, 5985, 5986})
CLEARTEXT_ADMIN_PORTS = frozenset({23})

# Valor de cada confianza de detección en la confianza del riesgo (0-1).
_CONFIDENCE_VALUE = {
    DetectionConfidence.LOW: 0.35,
    DetectionConfidence.MEDIUM: 0.65,
    DetectionConfidence.HIGH: 0.9,
}
# La exposición la observa Sentra directamente (discovery): evidencia de calidad alta.
_EXPOSURE_CONFIDENCE = 0.85

# Factores de contribución.
DETECTION = "detection"
EXPOSURE = "exposure"
CRITICALITY = "criticality"
ASSET_TYPE = "asset_type"
SATURATION = "saturation"

CRITICALITY_LABELS = {
    AssetCriticality.LOW: "baja",
    AssetCriticality.MEDIUM: "media",
    AssetCriticality.HIGH: "alta",
    AssetCriticality.CRITICAL: "crítica",
}

# Cobertura de datos del activo (completeness): cuánto podemos ver de él.
FULL = "full"
PARTIAL = "partial"
LIMITED = "limited"


@dataclass(frozen=True)
class DetectionInput:
    id: int
    public_id: UUID
    rule_id: str
    title: str
    category: str
    # "single" o "correlation".
    kind: str
    severity: DetectionSeverity
    confidence: DetectionConfidence
    status: DetectionStatus
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None = None
    # Puerto al que se refiere (NET-001/NET-002), para unirla con la exposición del puerto.
    port: int | None = None
    # Solo correlaciones: ids de las detecciones simples del mismo activo que comparten
    # señales de evidencia con ella (las que la correlación ya incluye).
    members: frozenset[int] = frozenset()


@dataclass(frozen=True)
class ExposureInput:
    """Un puerto sensible abierto y accesible desde el servidor de Sentra (discovery)."""

    port: int
    opened_at: datetime
    protocol: str = "tcp"
    service_hint: str | None = None


@dataclass(frozen=True)
class AssetContext:
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    device_type: str | None = None
    # Con agente (managed) o solo visto en la red.
    managed: bool = False
    os_name: str | None = None
    # Último contacto del agente (para saber si sus datos están al día).
    last_seen_at: datetime | None = None


@dataclass(frozen=True)
class RiskInputs:
    asset: AssetContext
    detections: Sequence[DetectionInput] = ()
    exposure: Sequence[ExposureInput] = ()


@dataclass(frozen=True)
class RiskContribution:
    """Una línea del ledger: qué factor, cuántos puntos y a qué se refiere."""

    factor: str
    category: str
    label: str
    points: float
    nominal_points: float | None = None
    detection_id: int | None = None
    detection_public_id: UUID | None = None
    rule_id: str | None = None
    port: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        """Forma guardada en asset_risk.contributions (sin ids internos)."""
        return {
            "factor": self.factor,
            "category": self.category,
            "label": self.label,
            "points": self.points,
            "nominal_points": self.nominal_points,
            "detection_id": str(self.detection_public_id) if self.detection_public_id else None,
            "rule_id": self.rule_id,
            "port": self.port,
            "details": self.details,
        }


@dataclass(frozen=True)
class RiskResult:
    score: int
    level: RiskLevel
    confidence: RiskConfidence
    contributions: tuple[RiskContribution, ...]
    breakdown: dict[str, Any]
    calculated_at: datetime

    @property
    def top_factor(self) -> str | None:
        positive = [c for c in self.contributions if c.factor in (DETECTION, EXPOSURE)]
        positive = [c for c in positive if c.points > 0]
        return positive[0].label if positive else None

    def detection_ids(self, min_points: float = 0.0) -> set[str]:
        """Detecciones (id público) que aportan al menos `min_points`."""
        return {
            str(c.detection_public_id)
            for c in self.contributions
            if c.detection_public_id is not None and c.points >= min_points
        }


@dataclass
class _Item:
    """Detección o puerto expuesto ya ponderado, antes de agrupar."""

    key: str
    effective: float
    nominal: float
    recency: float
    status_factor: float
    category: str
    confidence_value: float
    order: tuple[Any, ...]
    detection: DetectionInput | None = None
    exposure: ExposureInput | None = None


def half_life_factor(age_seconds: float, half_life_seconds: float) -> float:
    """0,5^(edad/semivida): 1 recién ocurrido, 0,5 a una semivida, 0,25 a dos..."""
    if age_seconds <= 0:
        return 1.0
    return float(0.5 ** (age_seconds / half_life_seconds))


def saturate(raw: float, knee: float) -> float:
    """Lineal hasta `knee`; por encima se acerca a 100 sin alcanzarlo nunca de forma lineal.

    S(x) = x                                si x <= k
    S(x) = k + (100 - k) * (1 - e^-(x-k)/(100-k))   si x > k
    Continua y con pendiente 1 en el codo (sin saltos al cruzarlo).
    """
    if raw <= knee:
        return raw
    span = 100.0 - knee
    return knee + span * (1.0 - math.exp(-(raw - knee) / span))


def _occurrence_factor(count: int, config: RiskConfig) -> float:
    # Ocurrencias = oleadas (el motor 4H agrupa por cooldown), no eventos: 1000 fallos en
    # una ráfaga son 1 ocurrencia. Crecimiento logarítmico y con tope.
    if count <= 1:
        return 1.0
    return min(config.occurrence_cap, 1.0 + config.occurrence_slope * math.log2(count))


def _detection_item(d: DetectionInput, config: RiskConfig, now: datetime) -> _Item | None:
    age = (now - d.last_seen_at).total_seconds()
    recency = half_life_factor(age, config.activity_half_life.total_seconds())
    if d.status == DetectionStatus.RESOLVED:
        resolved_at = d.resolved_at or d.last_seen_at
        since = (now - resolved_at).total_seconds()
        if since > config.resolved_memory.total_seconds():
            # Fuera de la memoria reciente: ya no aporta (el historial sigue en detections).
            return None
        status = config.status_factor[d.status] * half_life_factor(
            since, config.resolved_half_life.total_seconds()
        )
    else:
        # Sin resolver nunca baja del suelo: una detección abierta olvidada sigue contando.
        recency = max(config.active_floor, recency)
        status = config.status_factor[d.status]
    nominal = (
        config.severity_points[d.severity]
        * config.confidence_factor[d.confidence]
        * _occurrence_factor(d.occurrence_count, config)
        * (config.correlation_factor if d.kind == "correlation" else 1.0)
    )
    confidence_value = _CONFIDENCE_VALUE[d.confidence]
    if d.kind == "correlation":
        confidence_value = min(0.95, confidence_value + 0.05)
    return _Item(
        key=f"d:{d.id}",
        effective=nominal * recency * status,
        nominal=nominal,
        recency=recency,
        status_factor=status,
        category=d.category,
        confidence_value=confidence_value,
        # Orden estable en empates: más reciente, luego regla y id.
        order=(-d.last_seen_at.timestamp(), d.rule_id, d.id),
        detection=d,
    )


def _exposure_item(e: ExposureInput, config: RiskConfig, now: datetime) -> _Item | None:
    if e.port not in SENSITIVE_PORTS:
        return None
    if e.port in CLEARTEXT_ADMIN_PORTS:
        points = config.exposure_cleartext_admin_points
    elif e.port in ADMIN_PORTS:
        points = config.exposure_admin_points
    else:
        points = config.exposure_data_points
    recent = now - e.opened_at <= config.exposure_recent
    effective = points * (config.exposure_recent_factor if recent else 1.0)
    return _Item(
        key=f"p:{e.port}",
        effective=effective,
        nominal=effective,
        recency=1.0,
        status_factor=1.0,
        category="exposure",
        confidence_value=_EXPOSURE_CONFIDENCE,
        order=(0.0, "~port", e.port),
        exposure=e,
    )


class _Groups:
    """Union-find mínimo para formar grupos de evidencia relacionada."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def find(self, key: str) -> str:
        self._parent.setdefault(key, key)
        root = key
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[key] != root:
            self._parent[key], key = root, self._parent[key]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Raíz determinista (la menor) para que el resultado no dependa del orden.
            low, high = sorted((ra, rb))
            self._parent[high] = low


def _completeness(asset: AssetContext, config: RiskConfig, now: datetime) -> tuple[str, str]:
    """Qué parte del activo vemos: (nivel, explicación)."""
    if not asset.managed:
        return LIMITED, "Solo visibilidad de red (sin agente)"
    if asset.last_seen_at is None or now - asset.last_seen_at > config.stale_data:
        return LIMITED, "Datos del agente desactualizados"
    if "windows" not in (asset.os_name or "").lower():
        # Hoy solo el agente de Windows envía eventos del sistema (Linux: inventario,
        # procesos y exposición). Menos fuentes = evaluación parcial.
        return PARTIAL, "Sin eventos del sistema en este SO (solo inventario y red)"
    return FULL, "Agente activo con eventos, inventario y procesos"


def calculate(inputs: RiskInputs, config: RiskConfig, now: datetime) -> RiskResult:
    items: list[_Item] = []
    for detection in inputs.detections:
        item = _detection_item(detection, config, now)
        if item is not None:
            items.append(item)
    for port in inputs.exposure:
        item = _exposure_item(port, config, now)
        if item is not None:
            items.append(item)

    # --- Agrupación (sin doble conteo) ----------------------------------------------------
    groups = _Groups()
    present = {item.key for item in items}
    for item in items:
        groups.find(item.key)
        d = item.detection
        if d is None:
            continue
        for member in d.members:
            if f"d:{member}" in present:
                groups.union(item.key, f"d:{member}")
        if d.port is not None:
            # Detección de puerto + exposición del mismo puerto (o NET-001 y NET-002 del
            # mismo puerto): es el mismo hecho visto desde dos sitios.
            groups.union(item.key, f"p:{d.port}")
    by_root: dict[str, list[_Item]] = {}
    for item in items:
        by_root.setdefault(groups.find(item.key), []).append(item)
    ranked_groups = []
    for members in by_root.values():
        members.sort(key=lambda i: (-i.effective, i.order))
        ranked_groups.append(members)
    ranked_groups.sort(key=lambda g: (-g[0].effective, g[0].order))

    # --- Rendimientos decrecientes y ledger ---------------------------------------------
    contributions: list[RiskContribution] = []
    reductions = {
        "decay": 0.0,
        "acknowledged": 0.0,
        "resolved": 0.0,
        "absorbed": 0.0,
        "diminishing": 0.0,
    }
    base = 0.0
    weighted_conf = 0.0
    weighted_recency = 0.0
    categories: set[str] = set()
    has_correlation = False
    for rank, members in enumerate(ranked_groups):
        lead = members[0]
        position = config.diminishing_beta**rank
        points = lead.effective * position
        base += points
        reductions["decay"] += lead.nominal * (1.0 - lead.recency)
        status_loss = lead.nominal * lead.recency * (1.0 - lead.status_factor)
        if lead.detection is not None and lead.detection.status == DetectionStatus.RESOLVED:
            reductions["resolved"] += status_loss
        else:
            reductions["acknowledged"] += status_loss
        reductions["diminishing"] += lead.effective - points
        for absorbed in members[1:]:
            reductions["absorbed"] += absorbed.effective
        if points > 0:
            weighted_conf += points * lead.confidence_value
            weighted_recency += points * lead.recency
            if points >= 5:
                categories.add(lead.category)
            if any(m.detection is not None and m.detection.kind == "correlation" for m in members):
                has_correlation = True
        contributions.append(_lead_contribution(lead, members[1:], points, position))
        contributions.extend(_absorbed_contribution(m, lead) for m in members[1:])

    # --- Modificadores del activo ---------------------------------------------------------
    asset = inputs.asset
    criticality = config.criticality_factor[asset.criticality]
    type_factor = INFRASTRUCTURE_FACTOR if asset.device_type in INFRASTRUCTURE_TYPES else 1.0
    raw = base * criticality * type_factor
    if base > 0 and criticality != 1.0:
        contributions.append(
            RiskContribution(
                factor=CRITICALITY,
                category="context",
                label=(
                    f"Criticidad del activo: {CRITICALITY_LABELS[asset.criticality]}"
                    f" (x{_num(criticality)})"
                ),
                points=_round(base * (criticality - 1.0)),
                details={"criticality": asset.criticality.value, "factor": criticality},
            )
        )
    if base > 0 and type_factor != 1.0:
        contributions.append(
            RiskContribution(
                factor=ASSET_TYPE,
                category="context",
                label=f"Infraestructura compartida ({asset.device_type}, x{_num(type_factor)})",
                points=_round(base * criticality * (type_factor - 1.0)),
                details={"device_type": asset.device_type, "factor": type_factor},
            )
        )
    saturated = saturate(raw, config.saturation_knee)
    if saturated < raw:
        contributions.append(
            RiskContribution(
                factor=SATURATION,
                category="context",
                label=f"Saturación por encima de {_num(config.saturation_knee)} puntos",
                points=_round(saturated - raw),
                details={"raw_points": _round(raw)},
            )
        )
    score = max(0, min(100, round(saturated)))

    # --- Confianza del riesgo (separada del score) ----------------------------------------
    completeness, completeness_label = _completeness(asset, config, now)
    factors: list[dict[str, str]] = []
    if base > 0:
        quality = weighted_conf / base
        factors.append(
            {"effect": "=", "label": f"Confianza media de la evidencia: {_pct(quality)}"}
        )
        if has_correlation:
            factors.append({"effect": "+", "label": "Correlación de varias señales"})
        if len(categories) >= 3:
            quality += 0.12
            factors.append(
                {"effect": "+", "label": f"Señales independientes de {len(categories)} tipos"}
            )
        elif len(categories) == 2:
            quality += 0.08
            factors.append({"effect": "+", "label": "Señales independientes de 2 tipos"})
        if weighted_recency / base < 0.5:
            quality -= 0.1
            factors.append({"effect": "-", "label": "La evidencia principal es antigua"})
        penalty = {FULL: 0.0, PARTIAL: 0.05, LIMITED: 0.15}[completeness]
        if penalty:
            quality -= penalty
        factors.append(
            {"effect": "-" if penalty else "+", "label": f"Cobertura: {completeness_label}"}
        )
    else:
        # Sin evidencia: la confianza en "no hay riesgo" depende de cuánto vemos del activo.
        quality = {FULL: 0.8, PARTIAL: 0.6, LIMITED: 0.4}[completeness]
        factors.append(
            {"effect": "=", "label": f"Sin evidencia de riesgo. Cobertura: {completeness_label}"}
        )
    quality = max(0.0, min(1.0, quality))
    if quality < 0.5:
        confidence = RiskConfidence.LOW
    elif quality < 0.75:
        confidence = RiskConfidence.MEDIUM
    else:
        confidence = RiskConfidence.HIGH

    omitted = max(0, len(contributions) - config.max_contributions)
    if omitted:
        # Se conservan las de más peso absoluto (las absorbidas, con 0, son las primeras en
        # salir); el desglose dice cuántas se omitieron.
        keep = sorted(contributions, key=lambda c: -abs(c.points))[: config.max_contributions]
        kept = set(map(id, keep))
        contributions = [c for c in contributions if id(c) in kept]

    breakdown = {
        "formula_version": FORMULA_VERSION,
        "base_points": _round(base),
        "criticality": asset.criticality.value,
        "criticality_factor": criticality,
        "asset_type_factor": type_factor,
        "raw_points": _round(raw),
        "saturated_points": _round(saturated),
        "reductions": {key: _round(value) for key, value in reductions.items()}
        | {"saturation": _round(raw - saturated)},
        "groups": len(ranked_groups),
        "independent_categories": sorted(categories),
        "detections_considered": sum(1 for i in items if i.detection is not None),
        "confidence_score": round(quality, 3),
        "confidence_factors": factors,
        "data_completeness": completeness,
        "omitted_contributions": omitted,
        "thresholds": list(config.thresholds),
    }
    return RiskResult(
        score=score,
        level=config.level_for(score),
        confidence=confidence,
        contributions=tuple(contributions),
        breakdown=breakdown,
        calculated_at=now,
    )


def _lead_contribution(
    lead: _Item, absorbed: Sequence[_Item], points: float, position: float
) -> RiskContribution:
    absorbed_refs = [_ref(item) for item in absorbed]
    common = {
        "recency_factor": round(lead.recency, 3),
        "status_factor": round(lead.status_factor, 3),
        "position_factor": round(position, 3),
        "absorbed": absorbed_refs,
    }
    d = lead.detection
    if d is not None:
        return RiskContribution(
            factor=DETECTION,
            category=d.category,
            label=f"{d.rule_id} · {d.title}",
            points=_round(points),
            nominal_points=_round(lead.nominal),
            detection_id=d.id,
            detection_public_id=d.public_id,
            rule_id=d.rule_id,
            port=d.port,
            details=common
            | {
                "kind": d.kind,
                "severity": d.severity.value,
                "confidence": d.confidence.value,
                "status": d.status.value,
                "occurrence_count": d.occurrence_count,
                "last_seen_at": d.last_seen_at.isoformat(),
            },
        )
    e = lead.exposure
    assert e is not None  # noqa: S101  (un _Item es detección o exposición)
    return RiskContribution(
        factor=EXPOSURE,
        category="exposure",
        label=_exposure_label(e),
        points=_round(points),
        nominal_points=_round(lead.nominal),
        port=e.port,
        details=common | {"opened_at": e.opened_at.isoformat(), "protocol": e.protocol},
    )


def _absorbed_contribution(item: _Item, lead: _Item) -> RiskContribution:
    """Miembro de un grupo: se explica, pero aporta 0 (ya lo cuenta el representante)."""
    ref = _ref(lead)
    d = item.detection
    if d is not None:
        return RiskContribution(
            factor=DETECTION,
            category=d.category,
            label=f"{d.rule_id} · {d.title}",
            points=0.0,
            nominal_points=_round(item.nominal),
            detection_id=d.id,
            detection_public_id=d.public_id,
            rule_id=d.rule_id,
            port=d.port,
            details={
                "absorbed_by": ref,
                "kind": d.kind,
                "severity": d.severity.value,
                "confidence": d.confidence.value,
                "status": d.status.value,
                "occurrence_count": d.occurrence_count,
                "last_seen_at": d.last_seen_at.isoformat(),
            },
        )
    e = item.exposure
    assert e is not None  # noqa: S101
    return RiskContribution(
        factor=EXPOSURE,
        category="exposure",
        label=_exposure_label(e),
        points=0.0,
        nominal_points=_round(item.nominal),
        port=e.port,
        details={"absorbed_by": ref, "opened_at": e.opened_at.isoformat()},
    )


def _ref(item: _Item) -> dict[str, Any]:
    if item.detection is not None:
        return {
            "detection_id": str(item.detection.public_id),
            "rule_id": item.detection.rule_id,
            "title": item.detection.title,
        }
    assert item.exposure is not None  # noqa: S101
    return {"port": item.exposure.port}


def _exposure_label(e: ExposureInput) -> str:
    hint = e.service_hint or SERVICE_HINTS.get(e.port)
    kind = "administración" if e.port in ADMIN_PORTS | CLEARTEXT_ADMIN_PORTS else "datos"
    return f"Exposición sensible ({kind}): {e.port}/{e.protocol}" + (f" ({hint})" if hint else "")


def _round(value: float) -> float:
    return round(value, 2)


def _num(value: float) -> str:
    return f"{value:g}".replace(".", ",")


def _pct(value: float) -> str:
    return f"{round(value * 100)} %"
