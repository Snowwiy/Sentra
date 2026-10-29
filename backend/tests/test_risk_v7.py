"""Risk Engine v7 (Fase 7B-Fix1): repetición de SCR-001, clases de riesgo y exposición.

Caso real (ravenslg, 100/100): cada SCR-001 de una oleada de 200 bloques contaba como un
grupo independiente, CORR-002 solo unía los 3 últimos scripts y el 5432 visto por el propio
servidor sumaba como exposición confirmada. No se fija ninguna puntuación concreta: se
comprueban las propiedades (acotado, monótono, trazable).
"""

from dataclasses import replace
from datetime import timedelta

from app.risk.calculator import DetectionInput, ExposureInput
from app.risk.engine import causal_keys, listen_scope
from tests.test_risk_calculator import NOW, Conf, Sev, det, risk


def _scr(n: int) -> list[DetectionInput]:
    return [
        replace(
            det(Sev.HIGH, Conf.MEDIUM, rule_id="SCR-001", category="execution"),
            causal_keys=frozenset({f"script:{i:064x}"}),
        )
        for i in range(n)
    ]


def test_repeated_scr_001_is_a_bounded_family() -> None:
    one = risk(*_scr(1))
    two = risk(*_scr(2))
    many = risk(*_scr(50))
    # Monótono: más repeticiones nunca bajan el riesgo...
    assert one.score <= two.score <= many.score
    # ...pero 50 scripts parecidos no son 50 señales independientes.
    repetition = [c for c in many.contributions if c.factor == "repetition"]
    assert len(repetition) == 1
    assert repetition[0].details["detections"] == 50
    assert 1.0 < repetition[0].details["factor"] <= 3.0
    absorbed = [c for c in many.contributions if c.details.get("absorbed_reason")]
    # El ledger se acota (omitted_contributions); el grupo es uno solo.
    assert absorbed and many.breakdown["groups"] == 1
    assert {c.details["absorbed_reason"] for c in absorbed} == {"same_rule_repetition"}


def test_correlation_absorbs_every_script_of_its_chain() -> None:
    scripts = _scr(10)
    keys: frozenset[str] = frozenset().union(*(s.causal_keys for s in scripts))
    corr = replace(
        det(Sev.HIGH, Conf.HIGH, rule_id="CORR-002", category="correlation", kind="correlation"),
        causal_keys=keys | {"service:evil"},
    )
    result = risk(corr, *scripts)
    leads = [c for c in result.contributions if c.factor == "detection" and c.points > 0]
    assert [c.rule_id for c in leads] == ["CORR-002"]
    assert result.breakdown["groups"] == 1
    reasons = {c.details.get("absorbed_reason") for c in result.contributions if c.rule_id}
    assert "same_causal_chain" in reasons
    by_class = result.breakdown["by_class"]
    assert by_class["correlated"] > 0 and by_class["direct"] == 0


def test_by_class_is_traceable() -> None:
    result = risk(det(Sev.HIGH, Conf.HIGH), *_scr(3))
    by_class = result.breakdown["by_class"]
    assert set(by_class) == {"direct", "correlated", "contextual"}
    assert by_class["direct"] > 0 and by_class["correlated"] == 0
    leads = [c for c in result.contributions if c.factor == "detection" and c.points > 0]
    assert all(c.details["risk_class"] == "direct" for c in leads)


def _postgres(observed_from: str | None, scope: str | None = None) -> ExposureInput:
    return ExposureInput(
        port=5432,
        opened_at=NOW - timedelta(days=10),
        observed_from=observed_from,
        listen_scope=scope,
    )


def test_port_seen_only_from_itself_counts_less_but_still_counts() -> None:
    remote = risk(exposure=(_postgres("remote"),))
    self_only = risk(exposure=(_postgres("self", "all_interfaces"),))
    unknown = risk(exposure=(_postgres(None),))
    assert 0 < self_only.score < remote.score
    # Sin dato (antes de 0050) el resultado es el de v6.
    assert unknown.score == remote.score
    (item,) = [c for c in self_only.contributions if c.factor == "exposure"]
    assert item.details["reachability"] == "self_only"
    assert item.details["listen_scope"] == "all_interfaces"
    assert "firewall_rules" in item.details["missing"]
    (item,) = [c for c in remote.contributions if c.factor == "exposure"]
    assert item.details["reachability"] == "lan_confirmed"


def test_listen_scope_reads_the_bind_address() -> None:
    assert listen_scope("0.0.0.0") == "all_interfaces"  # noqa: S104
    assert listen_scope("::") == "all_interfaces"
    assert listen_scope("127.0.0.1") == "loopback"
    assert listen_scope("::1") == "loopback"
    assert listen_scope("192.168.50.201") == "specific"
    assert listen_scope(None) == "all_interfaces"


def test_corr_002_causal_keys_include_every_script_key() -> None:
    keys = [f"script:{i:064x}" for i in range(20)]
    found = causal_keys("CORR-002", "svc", None, [], [*keys, "nope", 7])
    assert set(keys) <= found and "service:svc" in found
    assert "nope" not in found
