"""Fase 7B.1: fórmula v6 del riesgo (claves causales, mantenimiento verificado, componentes).

Reconstruye con entradas sintéticas el caso de la auditoría 7B.0 (equipo ravenslg, 99/100):
la instalación del agente produce SCR-001, PER-001 (7045 e inventario), CORR-002 y su alerta,
y el equipo expone PostgreSQL en 5432. Cada test fija `NOW`, así los números son exactos.
"""

from dataclasses import replace
from typing import Any

from app.models.asset import AssetCriticality
from app.risk.calculator import ATTRIBUTION, DetectionInput, ExposureInput, RiskInputs, calculate
from tests.test_risk_calculator import (
    CONFIG,
    NOW,
    WINDOWS,
    Conf,
    Sev,
    risk,
)
from tests.test_risk_calculator import det as _det


def det(
    *args: Any,
    causal_keys: frozenset[str] = frozenset(),
    attribution_verdict: str | None = None,
    **kwargs: Any,
) -> DetectionInput:
    return replace(
        _det(*args, **kwargs), causal_keys=causal_keys, attribution_verdict=attribution_verdict
    )


SCRIPT_KEY = "script:" + "a" * 64
INIT_KEY = "script:" + "b" * 64
SERVICE_KEY = "service:sentraagent"
HIGH_ASSET = replace(WINDOWS, criticality=AssetCriticality.HIGH)


def _install(verdict: str | None = None, causal: bool = True) -> list[DetectionInput]:
    """Las representaciones de UNA instalación del agente."""
    keys = (
        (frozenset({SCRIPT_KEY}), frozenset({SERVICE_KEY}), frozenset({SCRIPT_KEY, SERVICE_KEY}))
        if causal
        else (frozenset(), frozenset(), frozenset())
    )
    return [
        det(
            Sev.MEDIUM,
            Conf.MEDIUM,
            rule_id="SCR-001",
            category="scripting",
            causal_keys=keys[0],
            attribution_verdict=verdict,
        ),
        det(
            Sev.MEDIUM,
            Conf.HIGH,
            rule_id="PER-001",
            category="persistence",
            causal_keys=keys[1],
            attribution_verdict=verdict,
        ),
        det(
            Sev.HIGH,
            Conf.HIGH,
            rule_id="CORR-002",
            category="persistence",
            kind="correlation",
            occurrences=3,
            causal_keys=keys[2],
            attribution_verdict=verdict,
        ),
    ]


def _postgres() -> tuple[list[DetectionInput], tuple[ExposureInput, ...]]:
    detection = det(Sev.HIGH, Conf.HIGH, rule_id="NET-001", category="network", port=5432)
    exposure = (ExposureInput(port=5432, opened_at=NOW.replace(day=1), protocol="tcp"),)
    return [detection], exposure


def test_one_operation_counts_once_through_causal_keys() -> None:
    without = risk(*_install(causal=False), asset=HIGH_ASSET)
    grouped = risk(*_install(), asset=HIGH_ASSET)
    # Sin claves causales (v5) SCR-001 y PER-001 suman como grupos independientes.
    assert without.breakdown["groups"] == 3
    assert grouped.breakdown["groups"] == 1
    assert grouped.score < without.score
    absorbed = [c for c in grouped.contributions if c.points == 0 and c.factor == "detection"]
    assert {c.rule_id for c in absorbed} == {"SCR-001", "PER-001"}


def test_ravenslg_reconstruction_no_longer_reaches_99_from_one_operation() -> None:
    port_detections, exposure = _postgres()
    # Antes: el mismo comportamiento en tres grupos más PER-001 contado dos veces (7045 e
    # inventario) y el puerto 5432: el activo saturaba cerca de 99.
    duplicated_per = det(Sev.MEDIUM, Conf.HIGH, rule_id="PER-001", occurrences=2)
    before = risk(
        *_install(causal=False), duplicated_per, *port_detections, asset=HIGH_ASSET,
        exposure=exposure,
    )  # fmt: skip
    assert before.score >= 95
    # Después, con la operación verificada: solo queda la exposición real de PostgreSQL.
    after = risk(
        *_install("verified_benign"), *port_detections, asset=HIGH_ASSET, exposure=exposure
    )
    assert after.score < before.score
    ledger = {c.rule_id: c for c in after.contributions if c.rule_id}
    assert ledger["NET-001"].points > 0
    for rule in ("SCR-001", "PER-001", "CORR-002"):
        assert ledger[rule].factor == ATTRIBUTION and ledger[rule].points == 0
        assert ledger[rule].details["avoided_points"] > 0
    assert after.breakdown["reductions"]["verified_benign"] > 0
    components = after.breakdown["components"]
    assert components["residual"] == after.score
    assert components["inherent"] > 0
    assert components["without_attribution"] > after.score
    assert components["verified_detections"] == 3


def test_a_true_detection_keeps_its_severity_during_development() -> None:
    # Sin operación verificada (o con un veredicto sospechoso), la correlación cuenta entera.
    suspicious = risk(*_install("suspicious_unverified"), asset=HIGH_ASSET)
    plain = risk(*_install(), asset=HIGH_ASSET)
    assert suspicious.score == plain.score
    assert suspicious.score >= 80


def test_verified_exposure_rule_still_counts() -> None:
    port = det(
        Sev.HIGH,
        Conf.HIGH,
        rule_id="NET-001",
        category="network",
        port=5432,
        attribution_verdict="verified_benign",
    )
    result = risk(port)
    assert result.score > 0
    assert all(c.factor != ATTRIBUTION for c in result.contributions)


def test_analyst_confirmation_raises_confidence_not_severity() -> None:
    low_conf = det(Sev.MEDIUM, Conf.LOW, rule_id="SCR-001", category="scripting")
    confirmed = replace(low_conf, attribution_verdict="confirmed_malicious")
    assert risk(confirmed).score > risk(low_conf).score
    assert risk(confirmed).score == risk(replace(low_conf, confidence=Conf.HIGH)).score


def test_without_verdicts_or_keys_v6_equals_v5() -> None:
    detections = [det(Sev.HIGH, Conf.HIGH), det(Sev.MEDIUM, Conf.MEDIUM, rule_id="AUTH-001")]
    result = calculate(RiskInputs(WINDOWS, detections, ()), CONFIG, NOW)
    assert result.breakdown["components"]["without_attribution"] == result.score
    assert result.breakdown["reductions"]["verified_benign"] == 0
