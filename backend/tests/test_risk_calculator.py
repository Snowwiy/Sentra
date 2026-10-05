"""Fórmula del Risk Engine (Fase 4I), sin base de datos: el cálculo es una función pura.

Cada test fija `NOW` y construye entradas sintéticas, así los resultados son exactos y
reproducibles. Los casos negativos (lo que NUNCA debe pasar) están marcados como tales.
"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import count
from uuid import uuid4

import pytest

from app.models.asset import AssetCriticality
from app.models.detection import DetectionConfidence, DetectionSeverity, DetectionStatus
from app.models.risk import RiskConfidence, RiskLevel
from app.risk.calculator import (
    AssetContext,
    DetectionInput,
    ExposureInput,
    RiskInputs,
    RiskResult,
    calculate,
    saturate,
)
from app.risk.config import RiskConfig

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
CONFIG = RiskConfig()
Sev = DetectionSeverity
Conf = DetectionConfidence
Status = DetectionStatus
_ids = count(1)

# Activo Windows con agente al día: cobertura completa (no penaliza la confianza).
WINDOWS = AssetContext(managed=True, os_name="Windows", last_seen_at=NOW - timedelta(minutes=1))


def det(
    severity: DetectionSeverity = Sev.HIGH,
    confidence: DetectionConfidence = Conf.HIGH,
    *,
    status: DetectionStatus = Status.OPEN,
    age: timedelta = timedelta(minutes=2),
    rule_id: str = "DEF-001",
    category: str = "defense",
    kind: str = "single",
    occurrences: int = 1,
    resolved_ago: timedelta | None = None,
    port: int | None = None,
    members: frozenset[int] = frozenset(),
    id: int | None = None,
) -> DetectionInput:
    return DetectionInput(
        id=id if id is not None else next(_ids),
        public_id=uuid4(),
        rule_id=rule_id,
        title=f"Regla {rule_id}",
        category=category,
        kind=kind,
        severity=severity,
        confidence=confidence,
        status=status,
        occurrence_count=occurrences,
        first_seen_at=NOW - age - timedelta(minutes=5),
        last_seen_at=NOW - age,
        resolved_at=NOW - resolved_ago if resolved_ago is not None else None,
        port=port,
        members=members,
    )


def risk(
    *detections: DetectionInput,
    asset: AssetContext = WINDOWS,
    exposure: tuple[ExposureInput, ...] = (),
    now: datetime = NOW,
    config: RiskConfig = CONFIG,
) -> RiskResult:
    return calculate(RiskInputs(asset, detections, exposure), config, now)


# --- Escala, niveles y ledger -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0, RiskLevel.INFORMATIONAL),
        (19, RiskLevel.INFORMATIONAL),
        (20, RiskLevel.LOW),
        (39, RiskLevel.LOW),
        (40, RiskLevel.MEDIUM),
        (59, RiskLevel.MEDIUM),
        (60, RiskLevel.HIGH),
        (79, RiskLevel.HIGH),
        (80, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_level_boundaries(score: int, level: RiskLevel) -> None:
    assert CONFIG.level_for(score) == level


def test_thresholds_are_configurable_in_one_place() -> None:
    strict = RiskConfig(thresholds=(10, 30, 50, 70))
    assert strict.level_for(70) == RiskLevel.CRITICAL
    assert strict.level_ranges()["critical"] == (70, 100)
    result = risk(det(Sev.HIGH, Conf.HIGH), config=strict)
    assert result.level == RiskLevel.CRITICAL  # 70 con estos umbrales


def test_asset_without_evidence_has_zero_risk() -> None:
    # Negativo: un activo sin detecciones ni exposición nunca tiene riesgo.
    result = risk()
    assert result.score == 0
    assert result.level == RiskLevel.INFORMATIONAL
    assert result.contributions == ()
    assert result.top_factor is None


def test_contributions_add_up_to_the_score() -> None:
    result = risk(
        det(Sev.CRITICAL, Conf.HIGH, rule_id="CORR-004", kind="correlation"),
        det(Sev.HIGH, Conf.MEDIUM, rule_id="DEF-004"),
        det(Sev.MEDIUM, Conf.MEDIUM, rule_id="PER-001", category="persistence"),
        asset=replace(WINDOWS, criticality=AssetCriticality.CRITICAL),
        exposure=(ExposureInput(port=3389, opened_at=NOW - timedelta(days=30)),),
    )
    total = sum(c.points for c in result.contributions)
    assert abs(total - result.breakdown["saturated_points"]) < 0.05
    assert result.score == round(result.breakdown["saturated_points"])
    factors = {c.factor for c in result.contributions}
    assert {"detection", "exposure", "criticality", "saturation"} <= factors


def test_result_is_deterministic() -> None:
    inputs = (
        det(Sev.HIGH, Conf.HIGH, id=1, rule_id="DEF-001"),
        det(Sev.HIGH, Conf.HIGH, id=2, rule_id="DEF-004"),
    )
    first = risk(*inputs)
    second = risk(*reversed(inputs))
    assert first.score == second.score
    assert [c.label for c in first.contributions] == [c.label for c in second.contributions]


# --- Severidad, confianza y señales aisladas -------------------------------------------------


def test_single_recent_detection_lands_in_its_own_level() -> None:
    assert risk(det(Sev.HIGH, Conf.HIGH)).score == 70
    assert risk(det(Sev.HIGH, Conf.HIGH)).level == RiskLevel.HIGH
    assert risk(det(Sev.CRITICAL, Conf.HIGH)).level == RiskLevel.CRITICAL
    assert risk(det(Sev.MEDIUM, Conf.HIGH)).level == RiskLevel.LOW
    assert risk(det(Sev.LOW, Conf.HIGH)).level == RiskLevel.INFORMATIONAL


def test_severity_orders_the_score() -> None:
    scores = [risk(det(severity, Conf.HIGH)).score for severity in DetectionSeverity]
    assert scores == sorted(scores)
    assert len(set(scores)) == len(scores)


def test_detection_confidence_scales_the_contribution() -> None:
    high = risk(det(Sev.HIGH, Conf.HIGH)).score
    medium = risk(det(Sev.HIGH, Conf.MEDIUM)).score
    low = risk(det(Sev.HIGH, Conf.LOW)).score
    assert high > medium > low


def test_isolated_low_confidence_signal_is_never_critical() -> None:
    # Negativo: una señal crítica pero dudosa no basta, ni en un servidor crítico.
    server = replace(WINDOWS, criticality=AssetCriticality.CRITICAL, device_type="server")
    result = risk(det(Sev.CRITICAL, Conf.LOW), asset=server)
    assert result.level != RiskLevel.CRITICAL
    assert result.confidence == RiskConfidence.LOW


def test_risk_confidence_is_separate_from_the_score() -> None:
    certain = risk(det(Sev.HIGH, Conf.HIGH))
    doubtful = risk(det(Sev.CRITICAL, Conf.LOW), det(Sev.HIGH, Conf.LOW, rule_id="AUTH-001"))
    assert certain.confidence == RiskConfidence.HIGH
    assert doubtful.confidence == RiskConfidence.LOW
    assert doubtful.score > 40  # riesgo alto-medio, pero la incertidumbre no se oculta


def test_confidence_reflects_data_completeness() -> None:
    discovered = AssetContext(managed=False)
    stale = replace(WINDOWS, last_seen_at=NOW - timedelta(days=3))
    linux = replace(WINDOWS, os_name="Ubuntu")
    assert risk(asset=WINDOWS).confidence == RiskConfidence.HIGH
    assert risk(asset=linux).confidence == RiskConfidence.MEDIUM
    assert risk(asset=discovered).confidence == RiskConfidence.LOW
    assert risk(asset=stale).confidence == RiskConfidence.LOW
    labels = [f["label"] for f in risk(asset=discovered).breakdown["confidence_factors"]]
    assert any("sin agente" in label for label in labels)


# --- Tiempo: recencia, decay, estado -----------------------------------------------------------


def test_recent_activity_weighs_more_than_old() -> None:
    fresh = risk(det(age=timedelta(minutes=2))).score
    hours = risk(det(age=timedelta(hours=6))).score
    days = risk(det(age=timedelta(days=30))).score
    assert fresh > hours > days


def test_decay_halves_at_each_half_life() -> None:
    fresh = risk(det(Sev.HIGH, Conf.HIGH, age=timedelta(0))).breakdown["base_points"]
    day = risk(det(Sev.HIGH, Conf.HIGH, age=timedelta(hours=24))).breakdown["base_points"]
    assert day == pytest.approx(fresh / 2, abs=0.05)


def test_unresolved_detection_never_decays_below_the_floor() -> None:
    old = risk(det(Sev.HIGH, Conf.HIGH, age=timedelta(days=60))).breakdown["base_points"]
    assert old == pytest.approx(70 * CONFIG.active_floor, abs=0.05)


def test_acknowledged_is_not_mitigated() -> None:
    open_ = risk(det(status=Status.OPEN)).score
    acknowledged = risk(det(status=Status.ACKNOWLEDGED)).score
    assert acknowledged < open_
    # Sigue en el mismo orden de magnitud: reconocer no es resolver.
    assert acknowledged >= open_ * 0.8


def test_resolved_keeps_recent_memory_and_decays() -> None:
    open_ = risk(det()).score
    just_resolved = risk(det(status=Status.RESOLVED, resolved_ago=timedelta(minutes=1))).score
    later = risk(det(status=Status.RESOLVED, resolved_ago=timedelta(hours=24))).score
    forgotten = risk(det(status=Status.RESOLVED, resolved_ago=timedelta(hours=80)))
    assert 0 < just_resolved < open_
    assert just_resolved >= open_ * 0.45  # no se borra de golpe al resolver
    assert 0 < later < just_resolved
    assert forgotten.score == 0
    assert forgotten.breakdown["detections_considered"] == 0


def test_old_resolved_detection_does_not_dominate() -> None:
    # Negativo: una crítica resuelta hace días no pesa más que una media abierta de ahora.
    current = det(Sev.MEDIUM, Conf.HIGH, rule_id="PER-001", category="persistence")
    old = det(
        Sev.CRITICAL,
        Conf.HIGH,
        rule_id="CORR-004",
        kind="correlation",
        status=Status.RESOLVED,
        age=timedelta(days=2),
        resolved_ago=timedelta(days=2),
    )
    result = risk(current, old)
    assert result.contributions[0].rule_id == "PER-001"
    assert result.level in (RiskLevel.LOW, RiskLevel.INFORMATIONAL)


# --- Persistencia, floods y saturación ------------------------------------------------------


def test_occurrences_raise_weight_logarithmically_and_capped() -> None:
    one = risk(det(Sev.MEDIUM, Conf.MEDIUM, occurrences=1)).breakdown["base_points"]
    four = risk(det(Sev.MEDIUM, Conf.MEDIUM, occurrences=4)).breakdown["base_points"]
    many = risk(det(Sev.MEDIUM, Conf.MEDIUM, occurrences=10_000)).breakdown["base_points"]
    assert one < four < many
    assert many == pytest.approx(one * CONFIG.occurrence_cap, abs=0.05)


def test_thousand_identical_events_do_not_reach_100() -> None:
    # Negativo: 1000 fallos de login son UNA detección deduplicada (motor 4H); ni siquiera
    # con 1000 oleadas distintas el riesgo llega a 100.
    flood = det(Sev.HIGH, Conf.MEDIUM, rule_id="AUTH-001", occurrences=1000)
    assert risk(flood).score < 80


def test_many_distinct_detections_saturate() -> None:
    # 200 detecciones distintas de la misma importancia: rendimientos decrecientes.
    many = [det(Sev.MEDIUM, Conf.LOW, rule_id="PROC-001", category="process") for _ in range(200)]
    result = risk(*many)
    single = risk(many[0]).score
    assert result.score <= 2 * single + 1
    assert result.score < 60
    extreme = risk(*[det(Sev.CRITICAL, Conf.HIGH) for _ in range(500)])
    assert extreme.score < 100  # asintótico: nunca "automáticamente" 100


def test_saturation_is_continuous_and_bounded() -> None:
    assert saturate(50, 70) == 50
    assert saturate(70, 70) == 70
    assert saturate(70.01, 70) == pytest.approx(70.01, abs=0.01)
    assert saturate(1_000, 70) < 100
    assert saturate(130, 70) > saturate(100, 70) > 70


def test_multiple_independent_signals_raise_risk_and_confidence() -> None:
    one = risk(det(Sev.HIGH, Conf.MEDIUM, rule_id="DEF-003"))
    three = risk(
        det(Sev.HIGH, Conf.MEDIUM, rule_id="DEF-003"),
        det(Sev.HIGH, Conf.MEDIUM, rule_id="ACCT-002", category="account"),
        det(Sev.MEDIUM, Conf.MEDIUM, rule_id="PER-001", category="persistence"),
    )
    assert three.score > one.score
    assert three.breakdown["confidence_score"] > one.breakdown["confidence_score"]
    assert len(three.breakdown["independent_categories"]) == 3


# --- Sin doble conteo --------------------------------------------------------------------------


def test_correlation_does_not_double_count_its_signals() -> None:
    a = det(Sev.MEDIUM, Conf.MEDIUM, rule_id="AUTH-001", category="authentication", id=101)
    b = det(Sev.HIGH, Conf.HIGH, rule_id="ACCT-002", category="account", id=102)
    c = det(Sev.MEDIUM, Conf.HIGH, rule_id="ACCT-001", category="account", id=103)
    corr = det(
        Sev.CRITICAL,
        Conf.HIGH,
        rule_id="CORR-004",
        category="account",
        kind="correlation",
        members=frozenset({101, 102, 103}),
        id=104,
    )
    grouped = risk(a, b, c, corr)
    alone = risk(corr)
    # La correlación con sus miembros vale lo mismo que la correlación sola...
    assert grouped.score == alone.score
    assert grouped.breakdown["groups"] == 1
    # ...y los miembros aparecen en la explicación con 0 puntos, absorbidos por ella.
    absorbed = [c for c in grouped.contributions if c.details.get("absorbed_by")]
    assert {c.rule_id for c in absorbed} == {"AUTH-001", "ACCT-002", "ACCT-001"}
    assert all(c.points == 0 for c in absorbed)
    assert grouped.breakdown["reductions"]["absorbed"] > 0
    # Sumar las cuatro como independientes daría bastante más.
    independent = risk(a, b, c, replace(corr, members=frozenset()))
    assert independent.score > grouped.score


def test_correlation_weighs_more_than_its_isolated_signal() -> None:
    failures = det(Sev.MEDIUM, Conf.MEDIUM, rule_id="AUTH-001", category="authentication", id=7)
    corr = det(
        Sev.HIGH,
        Conf.MEDIUM,
        rule_id="CORR-001",
        category="authentication",
        kind="correlation",
        members=frozenset({7}),
    )
    assert risk(failures, corr).score > risk(failures).score + 20


def test_port_detection_and_its_exposure_are_one_fact() -> None:
    exposure = (ExposureInput(port=3389, opened_at=NOW - timedelta(minutes=5)),)
    net = det(Sev.HIGH, Conf.HIGH, rule_id="NET-001", category="network", port=3389)
    both = risk(net, exposure=exposure)
    assert both.score == risk(net).score
    assert both.breakdown["groups"] == 1


# --- Exposición, criticidad y tipo ----------------------------------------------------------


def test_open_port_is_not_a_vulnerability() -> None:
    # Puertos no sensibles no suman; los sensibles suman poco y sin detecciones nunca es alto.
    web = risk(exposure=(ExposureInput(port=443, opened_at=NOW - timedelta(days=10)),))
    assert web.score == 0
    sensitive = tuple(
        ExposureInput(port=port, opened_at=NOW - timedelta(days=10))
        for port in (22, 23, 445, 3389, 5900, 5985, 1433, 3306)
    )
    exposed = risk(exposure=sensitive)
    assert 0 < exposed.score < 40
    assert exposed.contributions[0].factor == "exposure"


def test_recent_exposure_change_weighs_more() -> None:
    old = risk(exposure=(ExposureInput(port=3389, opened_at=NOW - timedelta(days=10)),))
    new = risk(exposure=(ExposureInput(port=3389, opened_at=NOW - timedelta(hours=1)),))
    assert new.breakdown["base_points"] > old.breakdown["base_points"]


def test_criticality_modifies_but_never_creates_risk() -> None:
    critical = replace(WINDOWS, criticality=AssetCriticality.CRITICAL)
    low = replace(WINDOWS, criticality=AssetCriticality.LOW)
    assert risk(asset=critical).score == 0
    medium = risk(det(Sev.MEDIUM, Conf.HIGH)).score
    assert risk(det(Sev.MEDIUM, Conf.HIGH), asset=critical).score > medium
    assert risk(det(Sev.MEDIUM, Conf.HIGH), asset=low).score < medium
    line = next(c for c in risk(det(), asset=critical).contributions if c.factor == "criticality")
    assert line.points > 0 and "crítica" in line.label


def test_unknown_device_is_not_penalized() -> None:
    # Negativo: desconocido sin evidencia = 0; con la misma evidencia, igual que un PC.
    unknown = AssetContext(managed=False, device_type=None)
    pc = AssetContext(managed=False, device_type="pc")
    assert risk(asset=unknown).score == 0
    new_device = det(Sev.LOW, Conf.MEDIUM, rule_id="NET-003", category="network")
    assert risk(new_device, asset=unknown).score == risk(new_device, asset=pc).score
    assert risk(new_device, asset=unknown).level == RiskLevel.INFORMATIONAL


def test_infrastructure_weighs_slightly_more() -> None:
    server = replace(WINDOWS, device_type="server")
    assert risk(det(), asset=server).score > risk(det()).score
    assert any(c.factor == "asset_type" for c in risk(det(), asset=server).contributions)


def test_contribution_list_is_bounded() -> None:
    result = risk(*[det(Sev.LOW, Conf.LOW, rule_id="PROC-001") for _ in range(300)])
    assert len(result.contributions) <= CONFIG.max_contributions
    assert result.breakdown["omitted_contributions"] > 0
