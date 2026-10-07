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
   Fase 4L: contexto de negocio (entorno de producción, datos confidenciales/restringidos,
   exposición a Internet confirmada) con su propio tope (x1,25). Desconocido = 1,0.
5. Saturación: lineal hasta el codo (70) y asintótica hasta 100 por encima.

Fase 5B (fórmula v3): cada finding de vulnerabilidad activo aporta como una "señal" más:
severidad del catálogo x evidencia del match x exposición del servicio x estado de trabajo.
Una vulnerabilidad NO es un ataque: sus puntos (crítica = 40) quedan muy por debajo de una
detección crítica (90), una crítica sola nunca lleva a 100 y las potenciales aportan poco.
Se agrupa con la exposición de su puerto (mismo hecho, sin doble conteo) y entra en los
rendimientos decrecientes y la saturación como cualquier otro grupo. Sin findings, el
resultado es idéntico a v2.

Fase 5C (fórmula v4): inteligencia de amenazas, siempre como contexto acotado:
- un finding confirmado o probable de un CVE con explotación conocida reportada (CISA KEV) o
  con probabilidad de explotación EPSS alta/elevada multiplica sus puntos (x1,35 como
  mucho; cuenta el mayor). Una fuente caducada aporta la mitad del incremento;
- un match de un IOC con un dato LOCAL (evento, conexión, IP o nombre del activo) es
  evidencia propia: clasificación x confianza x fuente x estado x frescura. Todos los matches
  del mismo indicador forman UN grupo, y la detección TI-001 que generaron va en ese grupo
  (el mismo hecho no cuenta dos veces). Un IOC sin match local no aporta nada.

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
from app.models.asset_context import AssetEnvironment, DataSensitivity
from app.models.detection import DetectionConfidence, DetectionSeverity, DetectionStatus
from app.models.risk import RiskConfidence, RiskLevel
from app.risk.config import (
    FORMULA_VERSION,
    INFRASTRUCTURE_FACTOR,
    INFRASTRUCTURE_TYPES,
    VULNERABILITY_EXPLOIT_STATES,
    RiskConfig,
)
from app.threat_intel.epss import band as epss_band

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
VULNERABILITY = "vulnerability"
THREAT_INTEL = "threat_intel"
CRITICALITY = "criticality"
ASSET_TYPE = "asset_type"
# Fase 4L: un factor de contexto de negocio (entorno, sensibilidad, exposición confirmada)
# y el tope que los limita.
BUSINESS_CONTEXT = "business_context"
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
class VulnerabilityInput:
    """Finding de vulnerabilidad activo del activo (Fase 5B)."""

    id: int
    public_id: UUID
    vulnerability_id: str
    title: str
    # Severidad normalizada del catálogo (informational..critical).
    severity: str
    # confirmed, probable o potential (unknown y not_affected no llegan aquí).
    match_state: str
    # open, acknowledged, mitigating o accepted_risk.
    status: str
    # internet_exposed, observed, listening, not_observed o unknown.
    exposure_state: str
    first_seen_at: datetime
    # Puertos del servicio afectado observados abiertos: se agrupa con su exposición.
    ports: tuple[int, ...] = ()
    # Fase 5C: inteligencia de explotabilidad del CVE (app/threat_intel/lookup.py).
    known_exploited: bool = False
    epss_score: float | None = None
    intel_stale: bool = False


@dataclass(frozen=True)
class ThreatMatchInput:
    """Match de un IOC con un dato local del activo (Fase 5C)."""

    id: int
    public_id: UUID
    indicator_public_id: UUID
    indicator_type: str
    indicator_value: str
    # Lo que declara la fuente AHORA (malicious, suspicious, unknown).
    classification: str
    # Confianza del match (la del indicador, rebajada para CIDR o nombres).
    confidence: str
    source_name: str
    source_trust: str
    observation_type: str
    # open | acknowledged (dismissed no llega aquí).
    status: str
    last_observed_at: datetime
    # False si el indicador se revocó o caducó después del match.
    indicator_active: bool = True
    # Detección TI-001 que generó (id interno), para agruparla con el match.
    detection_id: int | None = None


@dataclass(frozen=True)
class AssetContext:
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    device_type: str | None = None
    # Con agente (managed) o solo visto en la red.
    managed: bool = False
    os_name: str | None = None
    # Último contacto del agente (para saber si sus datos están al día).
    last_seen_at: datetime | None = None
    # Fase 4L: Asset Context confirmado. Desconocido por defecto (neutro en la fórmula).
    environment: AssetEnvironment = AssetEnvironment.UNKNOWN
    data_sensitivity: DataSensitivity = DataSensitivity.UNKNOWN
    internet_exposed: bool | None = None


@dataclass(frozen=True)
class RiskInputs:
    asset: AssetContext
    detections: Sequence[DetectionInput] = ()
    exposure: Sequence[ExposureInput] = ()
    vulnerabilities: Sequence[VulnerabilityInput] = ()
    threat_matches: Sequence[ThreatMatchInput] = ()


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
    # Fase 5B: finding de vulnerabilidad al que se refiere (id público).
    finding_public_id: UUID | None = None
    # Fase 5C: match de inteligencia de amenazas al que se refiere (id público).
    threat_match_public_id: UUID | None = None

    def to_json(self) -> dict[str, Any]:
        """Forma guardada en asset_risk.contributions (sin ids internos)."""
        data = {
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
        if self.finding_public_id is not None:
            data["finding_id"] = str(self.finding_public_id)
        if self.threat_match_public_id is not None:
            data["threat_match_id"] = str(self.threat_match_public_id)
        return data


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
        evidence = (DETECTION, EXPOSURE, VULNERABILITY, THREAT_INTEL)
        positive = [c for c in self.contributions if c.factor in evidence]
        positive = [c for c in positive if c.points > 0]
        return positive[0].label if positive else None

    def detection_ids(self, min_points: float = 0.0) -> set[str]:
        """Detecciones (id público) que aportan al menos `min_points`."""
        return {
            str(c.detection_public_id)
            for c in self.contributions
            if c.detection_public_id is not None and c.points >= min_points
        }

    def finding_ids(self, min_points: float = 0.0) -> set[str]:
        """Findings de vulnerabilidad (id público) que aportan al menos `min_points`."""
        return {
            str(c.finding_public_id)
            for c in self.contributions
            if c.finding_public_id is not None and c.points >= min_points
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
    vulnerability: VulnerabilityInput | None = None
    threat: ThreatMatchInput | None = None


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


def exploit_reason(v: VulnerabilityInput) -> str | None:
    """Motivo de explotabilidad que cuenta para un finding (el más fuerte: KEV > EPSS)."""
    if v.match_state not in VULNERABILITY_EXPLOIT_STATES:
        return None
    if v.known_exploited:
        return "known_exploited"
    level = epss_band(v.epss_score)
    if level in ("high", "elevated"):
        return f"epss_{level}"
    return None


def exploit_factor(v: VulnerabilityInput, config: RiskConfig) -> float:
    """Multiplicador por inteligencia de explotabilidad (1,0 si no hay o no aplica)."""
    reason = exploit_reason(v)
    if reason is None:
        return 1.0
    factor = config.vulnerability_exploit_factor[reason]
    return 1.0 + (factor - 1.0) / 2 if v.intel_stale else factor


def _vulnerability_item(v: VulnerabilityInput, config: RiskConfig) -> _Item | None:
    points = config.vulnerability_points.get(v.severity, 0.0)
    match = config.vulnerability_match_factor.get(v.match_state, 0.0)
    status = config.vulnerability_status_factor.get(v.status, 0.0)
    exposure = config.vulnerability_exposure_factor.get(v.exposure_state, 1.0)
    exploit = exploit_factor(v, config)
    nominal = points * match * exposure * exploit
    if nominal <= 0 or status <= 0:
        return None
    return _Item(
        key=f"v:{v.id}",
        effective=nominal * status,
        nominal=nominal,
        recency=1.0,
        status_factor=status,
        category="vulnerability",
        confidence_value=_MATCH_CONFIDENCE.get(v.match_state, 0.35),
        order=(-v.first_seen_at.timestamp(), v.vulnerability_id, v.id),
        vulnerability=v,
    )


# Calidad de la evidencia de un finding para la confianza del riesgo (como las detecciones).
_MATCH_CONFIDENCE = {"confirmed": 0.9, "probable": 0.65, "potential": 0.35}
# Un match de IOC es una coincidencia exacta con un dato local, pero la clasificación es
# de un tercero: confianza algo menor que una detección equivalente.
_THREAT_CONFIDENCE = {"high": 0.8, "medium": 0.6, "low": 0.35}


def _threat_item(t: ThreatMatchInput, config: RiskConfig, now: datetime) -> _Item | None:
    points = config.threat_classification_points.get(t.classification, 0.0)
    status = config.threat_status_factor.get(t.status, 0.0)
    age = (now - t.last_observed_at).total_seconds()
    if points <= 0 or status <= 0 or age > config.threat_memory.total_seconds():
        return None
    nominal = (
        points
        * config.threat_confidence_factor.get(t.confidence, 0.4)
        * config.threat_trust_factor.get(t.source_trust, 0.7)
        * (1.0 if t.indicator_active else config.threat_inactive_factor)
    )
    recency = half_life_factor(age, config.threat_half_life.total_seconds())
    return _Item(
        key=f"t:{t.id}",
        effective=nominal * recency * status,
        nominal=nominal,
        recency=recency,
        status_factor=status,
        category="threat_intel",
        confidence_value=_THREAT_CONFIDENCE.get(t.confidence, 0.35),
        order=(-t.last_observed_at.timestamp(), t.indicator_value, t.id),
        threat=t,
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
    for vulnerability in inputs.vulnerabilities[: config.max_vulnerabilities]:
        item = _vulnerability_item(vulnerability, config)
        if item is not None:
            items.append(item)
    for match in inputs.threat_matches[: config.max_threat_matches]:
        item = _threat_item(match, config, now)
        if item is not None:
            items.append(item)

    # --- Agrupación (sin doble conteo) ----------------------------------------------------
    groups = _Groups()
    present = {item.key for item in items}
    for item in items:
        groups.find(item.key)
        t = item.threat
        if t is not None:
            # Matches del mismo indicador (varias observaciones) y la detección TI-001 que
            # generaron: un solo hecho, cuenta el más fuerte.
            groups.union(item.key, f"i:{t.indicator_public_id}")
            if t.detection_id is not None and f"d:{t.detection_id}" in present:
                groups.union(item.key, f"d:{t.detection_id}")
            continue
        v = item.vulnerability
        if v is not None:
            # Vulnerabilidad de un servicio expuesto + exposición de ese puerto: el mismo
            # hecho; cuenta el más fuerte de los dos.
            for number in v.ports:
                if f"p:{number}" in present:
                    groups.union(item.key, f"p:{number}")
            continue
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
    raw, context_factor = _business_context(asset, config, base, raw, contributions)
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
        "context_factor": context_factor,
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


ENVIRONMENT_LABELS = {AssetEnvironment.PRODUCTION: "producción"}
SENSITIVITY_LABELS = {
    DataSensitivity.CONFIDENTIAL: "datos confidenciales",
    DataSensitivity.RESTRICTED: "datos restringidos",
}


def _business_context(
    asset: AssetContext,
    config: RiskConfig,
    base: float,
    raw: float,
    contributions: list[RiskContribution],
) -> tuple[float, float]:
    """Aplica el contexto de negocio a `raw` y añade sus líneas al ledger.

    Solo amplifica evidencia existente (base > 0) y solo con valores CONFIRMADOS; con
    contexto desconocido devuelve `raw` sin cambios. Cada factor aparece con sus puntos
    ("+ contexto: producción") y, si el producto supera el tope, una línea negativa lo
    recorta: el ledger sigue sumando exactamente el score.
    """
    if base <= 0:
        return raw, 1.0
    factors: list[tuple[str, float, dict[str, Any]]] = []
    env = config.environment_factor.get(asset.environment, 1.0)
    if env != 1.0:
        env_label = ENVIRONMENT_LABELS.get(asset.environment, asset.environment.value)
        factors.append(
            (
                f"Contexto: entorno de {env_label}",
                env,
                {"environment": asset.environment.value},
            )
        )
    sensitivity = config.data_sensitivity_factor.get(asset.data_sensitivity, 1.0)
    if sensitivity != 1.0:
        data_label = SENSITIVITY_LABELS.get(asset.data_sensitivity, asset.data_sensitivity.value)
        factors.append(
            (
                f"Contexto: {data_label}",
                sensitivity,
                {"data_sensitivity": asset.data_sensitivity.value},
            )
        )
    if asset.internet_exposed is True:
        factors.append(
            (
                "Contexto: exposición a Internet confirmada",
                config.internet_exposed_factor,
                {"internet_exposed": True},
            )
        )
    product = 1.0
    running = raw
    for label, factor, details in factors:
        contributions.append(
            RiskContribution(
                factor=BUSINESS_CONTEXT,
                category="context",
                label=f"{label} (x{_num(factor)})",
                points=_round(running * (factor - 1.0)),
                details=details | {"factor": factor},
            )
        )
        running *= factor
        product *= factor
    if product > config.context_factor_cap:
        capped = raw * config.context_factor_cap
        contributions.append(
            RiskContribution(
                factor=BUSINESS_CONTEXT,
                category="context",
                label=f"Tope del contexto de negocio (x{_num(config.context_factor_cap)})",
                points=_round(capped - running),
                details={"cap": config.context_factor_cap, "uncapped_factor": round(product, 4)},
            )
        )
        return capped, config.context_factor_cap
    return running, round(product, 4)


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
    v = lead.vulnerability
    if v is not None:
        return _vulnerability_contribution(v, _round(points), _round(lead.nominal), common)
    if lead.threat is not None:
        return _threat_contribution(lead.threat, _round(points), _round(lead.nominal), common)
    e = lead.exposure
    assert e is not None  # noqa: S101  (un _Item es detección, exposición o vulnerabilidad)
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
    v = item.vulnerability
    if v is not None:
        return _vulnerability_contribution(v, 0.0, _round(item.nominal), {"absorbed_by": ref})
    if item.threat is not None:
        return _threat_contribution(item.threat, 0.0, _round(item.nominal), {"absorbed_by": ref})
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


_MATCH_LABELS = {"confirmed": "confirmada", "probable": "probable", "potential": "potencial"}


_EXPLOIT_LABELS = {
    "known_exploited": "explotación conocida reportada (KEV)",
    "epss_high": "probabilidad de explotación EPSS alta",
    "epss_elevated": "probabilidad de explotación EPSS elevada",
}


def _vulnerability_contribution(
    v: VulnerabilityInput, points: float, nominal: float, details: dict[str, Any]
) -> RiskContribution:
    reason = exploit_reason(v)
    suffix = f" · {_EXPLOIT_LABELS[reason]}" if reason else ""
    exploit = (
        {
            "exploitability": reason,
            "intel_stale": v.intel_stale,
            "epss_score": v.epss_score,
        }
        if reason
        else {}
    )
    return RiskContribution(
        factor=VULNERABILITY,
        category="vulnerability",
        label=(
            f"Vulnerabilidad {v.vulnerability_id} ({v.severity},"
            f" {_MATCH_LABELS.get(v.match_state, v.match_state)}){suffix}"
        ),
        points=points,
        nominal_points=nominal,
        port=v.ports[0] if v.ports else None,
        finding_public_id=v.public_id,
        details=details
        | {
            "finding_id": str(v.public_id),
            "vulnerability_id": v.vulnerability_id,
            "title": v.title[:200],
            "severity": v.severity,
            "match_state": v.match_state,
            "status": v.status,
            "exposure_state": v.exposure_state,
        }
        | exploit,
    )


_CLASSIFICATION_LABELS = {"malicious": "maliciosa", "suspicious": "sospechosa"}
_OBSERVATION_LABELS = {
    "auth_source_ip": "IP de origen de inicio de sesión",
    "connection_remote_ip": "IP remota de una conexión",
    "asset_address": "IP del propio activo",
    "asset_name": "nombre del propio activo",
}


def _threat_contribution(
    t: ThreatMatchInput, points: float, nominal: float, details: dict[str, Any]
) -> RiskContribution:
    classification = _CLASSIFICATION_LABELS.get(t.classification, t.classification)
    return RiskContribution(
        factor=THREAT_INTEL,
        category="threat_intel",
        label=(
            f"IOC {t.indicator_value[:80]} ({classification} según {t.source_name[:60]})"
            f" · {_OBSERVATION_LABELS.get(t.observation_type, t.observation_type)}"
        ),
        points=points,
        nominal_points=nominal,
        threat_match_public_id=t.public_id,
        details=details
        | {
            "threat_match_id": str(t.public_id),
            "indicator_id": str(t.indicator_public_id),
            "indicator_type": t.indicator_type,
            "classification": t.classification,
            "confidence": t.confidence,
            "source": t.source_name[:200],
            "source_trust": t.source_trust,
            "observation_type": t.observation_type,
            "status": t.status,
            "indicator_active": t.indicator_active,
            "last_observed_at": t.last_observed_at.isoformat(),
        },
    )


def _ref(item: _Item) -> dict[str, Any]:
    if item.threat is not None:
        return {
            "threat_match_id": str(item.threat.public_id),
            "indicator_value": item.threat.indicator_value[:80],
        }
    if item.vulnerability is not None:
        return {
            "finding_id": str(item.vulnerability.public_id),
            "vulnerability_id": item.vulnerability.vulnerability_id,
        }
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
