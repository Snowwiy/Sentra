"""Unidades de la Fase 5A sin base de datos: regex seguras, compilador, Sigma y catálogo."""

import importlib.util
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.detection.custom import mitre, safe_regex, sigma
from app.detection.custom.catalog import AGENT_DATA_FIELDS, AGENT_EVENT_CODES, LOGSOURCES
from app.detection.custom.definition import compile_definition, content_hash
from app.detection.custom.runtime import CustomRule, CustomRuleIndex, rule_from_version

AGENT_EVENTS = Path(__file__).resolve().parents[2] / "agent" / "sentra_agent" / "events.py"


def _leaf(field: str, op: str, value: Any, **extra: Any) -> dict[str, Any]:
    return {
        "logsource": "windows_security",
        "condition": {"field": field, "op": op, "value": value, **extra},
    }


def _rule(definition: dict[str, Any], pk: int = 1) -> CustomRule:
    result = compile_definition(definition)
    assert result.ok and result.rule is not None, result.errors
    record = SimpleNamespace(
        id=pk, rule_uid=f"SENTRA-CUSTOM-{pk:06d}", source="custom", sigma_id=None
    )
    version = SimpleNamespace(
        version=1, title="t", description="", why="", recommendations=[], severity="medium",
        confidence="low", category="account", mitre_tactic=None, mitre_technique=None,
        mitre_subtechnique=None, created_at=datetime.now(UTC),
    )  # fmt: skip
    return rule_from_version(record, version, result.rule)  # type: ignore[arg-type]


def _match(rule: CustomRule, code: int, **data: Any) -> bool:
    payload = {"channel": "Security", "code": code, **{f"data.{k}": v for k, v in data.items()}}
    matched, _ = rule.matches("event", f"Security:{code}", payload, None)
    return matched


# --- Regex seguras ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    ["(a+)+$", "(a|aa)*", "(?=x)", r"(a)\1", "a.*b.*c", "a{1,100}", "a++", "x" * 200, "((((a))))"],
)
def test_dangerous_regex_is_rejected(pattern: str) -> None:
    with pytest.raises(safe_regex.UnsafeRegexError):
        safe_regex.check(pattern)


@pytest.mark.parametrize(
    "pattern", [r"^svc_[a-z0-9]{2,8}$", r"^adm(in|inistrador)$", r"\d{4}", r"^(a|b|c)x"]
)
def test_reasonable_regex_is_accepted(pattern: str) -> None:
    safe_regex.check(pattern)


def test_regex_worst_case_is_bounded() -> None:
    compiled = safe_regex.compile_safe(r"a.*b", case_sensitive=True)
    started = time.perf_counter()
    for _ in range(50):
        compiled.search(("a" * safe_regex.MAX_SUBJECT)[: safe_regex.MAX_SUBJECT])
    assert (time.perf_counter() - started) / 50 < 0.05


# --- Operadores ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("op", "value", "subject", "expected"),
    [
        ("equals", "Admin", "admin", True),
        ("not_equals", "admin", "ana", True),
        ("contains", "DMI", "xadminx", True),
        ("starts_with", "svc_", "SVC_backup", True),
        ("ends_with", "$", "PC01$", True),
        ("in", ["a", "b"], "B", True),
        ("regex", r"^svc_\d+$", "svc_12", True),
        ("regex", r"^svc_\d+$", "svc_x", False),
        ("equals", "admin", "administrador", False),
    ],
)
def test_string_operators(op: str, value: Any, subject: str, expected: bool) -> None:
    rule = _rule(_leaf("event.data.TargetUserName", op, value))
    assert _match(rule, 4720, TargetUserName=subject) is expected


def test_case_sensitive_and_missing_fields() -> None:
    sensitive = _rule(_leaf("event.data.TargetUserName", "equals", "Admin", case_sensitive=True))
    assert _match(sensitive, 4720, TargetUserName="Admin")
    assert not _match(sensitive, 4720, TargetUserName="admin")
    # Campo ausente: nunca coincide (ni siquiera not_equals).
    neq = _rule(_leaf("event.data.TargetUserName", "not_equals", "x"))
    assert not _match(neq, 4720)
    exists = _rule(_leaf("event.data.TargetUserName", "exists", False))
    assert _match(exists, 4720)


def test_numeric_comparisons_and_boolean_logic() -> None:
    rule = _rule(
        {
            "logsource": "windows_security",
            "condition": {
                "all": [
                    {"field": "event.code", "op": "gte", "value": 4624},
                    {"field": "event.code", "op": "lt", "value": 4626},
                    {"not": {"field": "event.data.LogonType", "op": "in", "value": ["3", "5"]}},
                    {"any": [
                        {"field": "event.data.TargetUserName", "op": "equals", "value": "root"},
                        {"field": "event.data.TargetUserName", "op": "ends_with", "value": "adm"},
                    ]},
                ]
            },
        }
    )  # fmt: skip
    assert _match(rule, 4625, TargetUserName="jadm", LogonType="10")
    assert not _match(rule, 4625, TargetUserName="jadm", LogonType="3")
    assert not _match(rule, 4627, TargetUserName="root", LogonType="10")


def test_other_channel_never_matches() -> None:
    rule = _rule(_leaf("event.code", "equals", 7045))
    matched, _ = rule.matches("event", "System:7045", {"channel": "System", "code": 7045}, None)
    assert not matched


def test_content_hash_is_canonical() -> None:
    # Mismo contenido con otro orden de claves: mismo hash (no crea versión nueva).
    a = {"logsource": "windows_security", "condition": {"field": "event.code", "op": "equals"}}
    b = {"condition": {"op": "equals", "field": "event.code"}, "logsource": "windows_security"}
    assert content_hash(a) == content_hash(b)
    assert content_hash(a) != content_hash({**a, "logsource": "windows_system"})


# --- Índice (fast path) -------------------------------------------------------------------------


def test_index_only_returns_rules_for_the_event_code() -> None:
    index = CustomRuleIndex()
    for pk in range(1, 1001):
        index.add(_rule(_leaf("event.code", "equals", 4600 + pk % 50), pk))
    index.add(_rule(_leaf("event.data.TargetUserName", "equals", "x"), 5000))
    data = {"channel": "Security", "code": 4625}
    candidates = index.candidates("event", data)
    assert len(candidates) == 21  # 20 con ese código + 1 sin código
    assert index.candidates("event", {"channel": "System", "code": 4625}) == []
    assert index.candidates("logon_failure", {}) == []


# --- MITRE --------------------------------------------------------------------------------------


def test_mitre_validation_and_sigma_tags() -> None:
    assert mitre.validate(None, "t1110", None)[0] == mitre.MitreMapping(None, "T1110", None)
    assert mitre.validate(None, None, "T1059.001")[0] == mitre.MitreMapping(
        None, "T1059", "T1059.001"
    )
    assert mitre.validate("TA06", "T1110", None)[1]
    assert mitre.validate(None, "T1110", "T1059.001")[1]
    tags = mitre.from_sigma_tags(["attack.execution", "attack.t1059.001", "attack.g0016", "cve.x"])
    assert tags.mapping == mitre.MitreMapping("TA0002", "T1059", "T1059.001")
    assert tags.other == ["attack.g0016", "cve.x"]


# --- Sigma --------------------------------------------------------------------------------------


def _sigma(detection: str, logsource: str = "  product: windows\n  service: security\n") -> str:
    return f"title: prueba\nlogsource:\n{logsource}detection:\n{detection}level: low\n"


@pytest.mark.parametrize(
    ("detection", "outcome"),
    [
        ("  sel:\n    EventID: 4720\n  condition: sel\n", "supported"),
        ("  sel:\n    EventID: [4720, 4722]\n  condition: 1 of sel*\n", "supported"),
        (
            "  a:\n    EventID: 4720\n  b:\n    EventID: 4722\n  condition: all of them\n",
            "supported",
        ),
        (
            "  sel:\n    TargetUserName|contains|all: ['a', 'b']\n  condition: sel\n",
            "supported",
        ),
        ("  sel:\n    TargetUserName|re: '^svc'\n  condition: sel\n", "supported"),
        (
            "  sel:\n    TargetUserName|base64offset|contains: 'x'\n  condition: sel\n",
            "unsupported",
        ),
        ("  sel:\n    - 'mimikatz'\n  condition: sel\n", "unsupported"),
        ("  sel:\n    EventID: 1\n  condition: sel | count(x) > 2\n", "unsupported"),
        ("  sel:\n    EventID: 1\n  condition: sel | near other\n", "unsupported"),
        ("  sel:\n    TargetUserName|re: '(a+)+$'\n  condition: sel\n", "unsupported"),
    ],
)
def test_sigma_subset(detection: str, outcome: str) -> None:
    analysis = sigma.analyze(_sigma(detection))
    assert analysis.outcome == outcome, (analysis.errors, analysis.unsupported)


def test_sigma_wildcards_map_to_operators() -> None:
    analysis = sigma.analyze(_sigma("  sel:\n    TargetUserName: 'svc_*'\n  condition: sel\n"))
    assert analysis.definition is not None
    assert analysis.definition["condition"]["op"] == "starts_with"


def test_sigma_levels_and_default_confidence() -> None:
    for level, severity in (
        ("informational", "informational"),
        ("critical", "critical"),
        ("high", "high"),
    ):
        source = _sigma("  sel:\n    EventID: 1\n  condition: sel\n").replace(
            "level: low", f"level: {level}"
        )
        assert sigma.analyze(source).severity.value == severity


@pytest.mark.parametrize(
    "source",
    [
        "!!python/object/apply:os.system ['id']",
        "a: !!binary aGk=",
        "a: &x 1\nb: *x",
        "- " * 50 + "x",
        "a: 1\n---\nb: 2",
        "\x00\x01",
        "",
        "just a string",
    ],
)
def test_sigma_parser_rejects_unsafe_yaml(source: str) -> None:
    assert sigma.analyze(source).outcome == "invalid"


def test_sigma_parser_limits_size() -> None:
    assert sigma.analyze("a: " + "x" * (sigma.MAX_YAML_BYTES + 1)).outcome == "invalid"


def test_sigma_unknown_logsource_is_unsupported() -> None:
    analysis = sigma.analyze(
        _sigma("  sel:\n    x: 1\n  condition: sel\n", "  product: linux\n  service: auditd\n")
    )
    assert analysis.outcome == "unsupported"


# --- Catálogo frente al agente --------------------------------------------------------------------


def test_catalog_fields_match_what_the_agent_really_sends() -> None:
    spec = importlib.util.spec_from_file_location("agent_events_for_test", AGENT_EVENTS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for channel, by_code in module.DATA_FIELDS.items():
        sent = {name for names in by_code.values() for name in names}
        assert set(AGENT_DATA_FIELDS.get(channel, ())) == sent, channel
        if channel in AGENT_EVENT_CODES:
            assert set(AGENT_EVENT_CODES[channel]) >= set(by_code), channel
    # Nunca contenido de scripts ni línea de comandos: el agente no los envía.
    every = {name for names in AGENT_DATA_FIELDS.values() for name in names}
    assert not every & {"ScriptBlockText", "CommandLine"}
    assert all(source.fields for source in LOGSOURCES.values())
