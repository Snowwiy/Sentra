"""Reglas personalizadas e importación Sigma (Fase 5A) de extremo a extremo.

Ingesta real -> señales -> motor 4H (el mismo, sin motor paralelo) -> detecciones -> API.
Los YAML y eventos son fixtures sintéticos; nunca se ejecuta nada de su contenido.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.detection.custom import runtime
from app.detection.custom.runtime import CustomRule
from app.models.alert import Alert
from app.models.audit import AuditEvent
from app.models.detection import Detection
from app.models.detection_rule import (
    DetectionRuleMatch,
    DetectionRuleRecord,
    DetectionRuleStats,
    DetectionRuleVersion,
)
from tests.conftest import authenticate
from tests.test_detections import _agent, _ago, _detail, _detections, _run, _send, ev, fail

API = "/api/v1"
RULES = f"{API}/detection-rules"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    runtime.reset_caches()
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session
    runtime.reset_caches()


def _single(code: int = 4720, **extra: Any) -> dict[str, Any]:
    return {
        "logsource": "windows_security",
        "condition": {
            "all": [
                {"field": "event.code", "op": "equals", "value": code},
                {"field": "event.data.TargetUserName", "op": "starts_with", "value": "svc_"},
            ]
        },
        **extra,
    }


def _threshold(count: int = 5, window: int = 10) -> dict[str, Any]:
    return {
        "logsource": "windows_security",
        "condition": {"field": "event.code", "op": "equals", "value": 4625},
        "threshold": {"count": count, "window_minutes": window},
        "group_by": ["event.data.TargetUserName"],
    }


def _create(client: TestClient, definition: dict[str, Any], **body: Any) -> dict[str, Any]:
    payload = {
        "title": "Cuenta de servicio creada",
        "description": "Alta de una cuenta svc_*.",
        "why": "Las cuentas de servicio nuevas suelen tener privilegios.",
        "recommendations": ["Confirmar quién la creó."],
        "severity": "high",
        "confidence": "medium",
        "category": "account",
        "mitre_tactic": "TA0003",
        "mitre_technique": "T1136",
        "mitre_subtechnique": "T1136.001",
        **body,
        "definition": definition,
    }
    response = client.post(RULES, json=payload)
    assert response.status_code == 201, response.text
    rule: dict[str, Any] = response.json()
    return rule


def _state(client: TestClient, rule: dict[str, Any], action: str, **extra: Any) -> Any:
    return client.post(
        f"{RULES}/{rule['rule_id']}/{action}", json={"revision": rule["revision"], **extra}
    )


def _enable(client: TestClient, rule: dict[str, Any], **extra: Any) -> dict[str, Any]:
    response = _state(client, rule, "enable", **extra)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _audit(db: Session, action: str) -> list[AuditEvent]:
    db.expire_all()
    return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)).all())


def _custom(client: TestClient) -> list[dict[str, Any]]:
    return [d for d in _detections(client) if d["rule_source"] != "builtin"]


# --- Catálogo y listado unificado --------------------------------------------------------------


def test_catalog_lists_logsources_fields_and_limits(client: TestClient) -> None:
    body = client.get(f"{RULES}/catalog").json()
    sources = {s["name"]: s for s in body["logsources"]}
    security = sources["windows_security"]
    fields = {f["name"]: f for f in security["fields"]}
    assert "event.code" in fields and "event.data.TargetUserName" in fields
    assert "regex" in fields["event.data.TargetUserName"]["operators"]
    assert sources["process"]["support"] == "partial"
    assert {f["name"] for f in body["asset_fields"]} >= {"asset.role", "asset.criticality"}
    assert body["limits"]["sigma_max_bytes"] > 0 and body["sigma_default_confidence"] == "low"
    # Nada de "CommandLine": el agente no lo recoge y no se puede fingir que sí.
    names = {f["name"] for s in body["logsources"] for f in s["fields"]}
    assert not any("commandline" in name.lower() for name in names)


def test_list_merges_builtin_and_custom_with_filters(client: TestClient, db: Session) -> None:
    rule = _create(client, _single())
    body = client.get(RULES).json()
    by_id = {r["rule_id"]: r for r in body["items"]}
    assert by_id["AUTH-001"]["source"] == "builtin" and by_id["AUTH-001"]["read_only"]
    assert by_id[rule["rule_id"]]["source"] == "custom"
    assert by_id[rule["rule_id"]]["status"] == "draft"
    assert body["total"] == len(body["items"])
    custom = client.get(RULES, params={"source": "custom"}).json()
    assert [r["rule_id"] for r in custom["items"]] == [rule["rule_id"]]
    assert client.get(RULES, params={"q": "servicio creada"}).json()["total"] == 1
    assert client.get(RULES, params={"mitre": "T1136"}).json()["total"] >= 1
    page = client.get(RULES, params={"limit": 2, "offset": 1, "sort": "title"}).json()
    assert len(page["items"]) == 2 and page["total"] == body["total"]
    assert rule["rule_id"].startswith("SENTRA-CUSTOM-")


# --- Ciclo de vida, versiones y concurrencia ---------------------------------------------------


def test_custom_rule_produces_versioned_detections(
    client: TestClient, engine: Engine, db: Session
) -> None:
    rule = _enable(client, _create(client, _single()))
    assert rule["status"] == "active" and rule["enabled"]
    agent = _agent(client)
    _send(
        client,
        agent,
        [
            ev(4720, _ago(2), TargetUserName="svc_backup", SubjectUserName="eve"),
            ev(4720, _ago(2), TargetUserName="ana"),
        ],
    )
    _run(engine)
    (found,) = _custom(client)
    assert found["rule_id"] == rule["rule_id"] and found["rule_version"] == 1
    assert found["rule_source"] == "custom" and found["category"] == "account"
    assert found["mitre_subtechnique"] == "T1136.001" and found["severity"] == "high"
    detail = _detail(client, found["detection_id"])
    assert detail["why"].startswith("Las cuentas de servicio")
    assert detail["details"]["rule_uid"] == rule["rule_id"]
    assert detail["evidence"][0]["summary"].startswith("Evento 4720")
    # Estadísticas por regla (sin datos del evento).
    stats = client.get(f"{RULES}/{rule['rule_id']}").json()["stats"]
    assert stats["evaluations"] >= 2 and stats["matches"] == 1 and stats["errors"] == 0


def test_update_creates_immutable_versions_and_detections_keep_theirs(
    client: TestClient, engine: Engine, db: Session
) -> None:
    rule = _enable(client, _create(client, _single()))
    agent = _agent(client)
    _send(client, agent, [ev(4720, _ago(3), TargetUserName="svc_a")])
    _run(engine)

    uid = rule["rule_id"]
    # Sin cambios reales: ni versión nueva ni auditoría de versión.
    same = client.patch(
        f"{RULES}/{uid}", json={"revision": rule["revision"], "title": rule["title"]}
    )
    assert same.status_code == 200 and same.json()["version"] == 1
    rule = same.json()
    changed = client.patch(
        f"{RULES}/{uid}",
        json={"revision": rule["revision"], "severity": "critical", "title": "Cuenta svc nueva"},
    )
    assert changed.status_code == 200, changed.text
    v2 = changed.json()
    assert v2["version"] == 2 and v2["severity"] == "critical" and v2["status"] == "active"
    # Revisión antigua: 409 sin pisar el cambio del otro administrador.
    stale = client.patch(f"{RULES}/{uid}", json={"revision": rule["revision"], "why": "x"})
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "detection_rule_conflict"

    versions = client.get(f"{RULES}/{uid}/versions").json()["items"]
    assert [v["version"] for v in versions] == [2, 1]
    diff = client.get(f"{RULES}/{uid}/diff", params={"from": 1, "to": 2}).json()
    assert {c["field"] for c in diff["changes"]} == {"severity", "title"}
    # La detección creada por v1 sigue diciendo v1.
    (found,) = _custom(client)
    assert found["rule_version"] == 1
    # Restaurar v1 crea v3 (la historia no se reescribe).
    restored = client.post(
        f"{RULES}/{uid}/versions/1/restore", json={"revision": v2["revision"]}
    ).json()
    assert restored["version"] == 3 and restored["severity"] == "high"
    v1 = client.get(f"{RULES}/{uid}/versions/1").json()
    assert v1["title"] == "Cuenta de servicio creada" and v1["content_hash"]
    assert len(_audit(db, "rule_version_created")) == 2
    assert len(_audit(db, "rule_created")) == 1


def test_disable_retire_and_unretire(client: TestClient, engine: Engine, db: Session) -> None:
    rule = _enable(client, _create(client, _single()))
    disabled = _state(client, rule, "disable").json()
    assert disabled["status"] == "disabled" and not disabled["enabled"]
    agent = _agent(client)
    _send(client, agent, [ev(4720, _ago(2), TargetUserName="svc_x")])
    _run(engine)
    assert _custom(client) == []
    retired = _state(client, disabled, "retire").json()
    assert retired["status"] == "retired" and retired["retired_at"]
    # Retirar no borra: sigue consultable con sus versiones.
    assert client.get(f"{RULES}/{rule['rule_id']}/versions").status_code == 200
    blocked = _state(client, retired, "enable")
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "detection_rule_invalid_state"
    edit = client.patch(f"{RULES}/{rule['rule_id']}", json={"revision": retired["revision"]})
    assert edit.status_code == 409
    back = _state(client, retired, "unretire").json()
    assert back["status"] == "disabled"
    assert {e.action for e in db.scalars(select(AuditEvent)).all()} >= {
        "rule_created", "rule_enabled", "rule_disabled", "rule_retired", "rule_unretired",
    }  # fmt: skip
    assert db.scalar(select(func.count()).select_from(DetectionRuleRecord)) == 1


def test_builtin_rules_are_read_only(client: TestClient, db: Session) -> None:
    detail = client.get(f"{RULES}/AUTH-001").json()
    assert detail["source"] == "builtin" and detail["read_only"] and detail["definition"] is None
    for action in ("enable", "disable", "retire"):
        response = client.post(f"{RULES}/AUTH-001/{action}", json={"revision": 1})
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "detection_rule_read_only"
    patch = client.patch(f"{RULES}/AUTH-001", json={"revision": 1, "title": "otra"})
    assert patch.status_code == 409
    # El intento fallido queda auditado.
    assert {e.result for e in _audit(db, "rule_enabled")} == {"failure"}


def test_threshold_rule_counts_per_group_in_window(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _enable(client, _create(client, _threshold(), category="authentication", mitre_tactic=None,
                            mitre_technique="T1110", mitre_subtechnique=None))  # fmt: skip
    agent = _agent(client)
    # 4 fallos de "ana" (no llega) y 5 de "luis" (llega): grupos separados.
    events = [fail("ana", _ago(5 - i * 0.5)) for i in range(4)]
    events += [fail("luis", _ago(6 - i * 0.5)) for i in range(5)]
    _send(client, agent, events)
    _run(engine)
    (found,) = _custom(client)
    detail = _detail(client, found["detection_id"])
    assert detail["details"]["group"] == "luis" and detail["details"]["count"] >= 5
    # Reprocesar no duplica (índice único de coincidencias y dedupe de 4H).
    _run(engine)
    assert len(_custom(client)) == 1
    assert db.scalar(select(func.count()).select_from(DetectionRuleMatch)) == 9


def test_threshold_outside_window_does_not_fire(client: TestClient, engine: Engine) -> None:
    _enable(client, _create(client, _threshold(count=3, window=5), category="authentication"))
    agent = _agent(client)
    _send(client, agent, [fail("ana", _ago(m)) for m in (1, 9, 18)])
    _run(engine)
    assert _custom(client) == []


def test_asset_context_conditions(client: TestClient, engine: Engine, db: Session) -> None:
    definition = _single()
    definition["condition"]["all"].append(
        {"field": "asset.hostname", "op": "equals", "value": "pc-admin-01"}
    )
    _enable(client, _create(client, definition))
    _send(client, _agent(client, "PC-OTRO"), [ev(4720, _ago(2), TargetUserName="svc_a")])
    _send(client, _agent(client, "PC-ADMIN-01"), [ev(4720, _ago(2), TargetUserName="svc_b")])
    _run(engine)
    assert [d["hostname"] for d in _custom(client)] == ["PC-ADMIN-01"]


def test_hot_reload_without_restart(client: TestClient, engine: Engine, db: Session) -> None:
    from app.core.config import get_settings
    from app.detection.engine import DetectionEngine
    from app.services.alert_service import AlertThresholds
    from tests.test_detections import CONFIG

    agent = _agent(client)
    with sessionmaker(bind=engine)() as session:
        # Un único motor vivo (como el job): las reglas nuevas se cargan sin reiniciar.
        live = DetectionEngine(session, CONFIG, AlertThresholds.from_settings(get_settings()))
        live.process_pending()
        rule = _enable(client, _create(client, _single()))
        _send(client, agent, [ev(4720, _ago(2), TargetUserName="svc_a")])
        live.process_pending()
        assert len(_custom(client)) == 1
        _state(client, rule, "disable")
        _send(client, agent, [ev(4720, _ago(1), TargetUserName="svc_b")])
        live.process_pending()
        assert len(_custom(client)) == 1


def test_failing_custom_rule_does_not_stop_others(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule = _enable(client, _create(client, _single()))

    def boom(self: CustomRule, ctx: Any, signal: Any) -> Any:
        raise RuntimeError("fallo simulado")

    monkeypatch.setattr(CustomRule, "evaluate", boom)
    agent = _agent(client)
    _send(client, agent, [ev(4720, _ago(2), TargetUserName="svc_a"), ev(1102, _ago(2))])
    _run(engine)
    rules = {d["rule_id"] for d in _detections(client)}
    assert "DEF-001" in rules and rule["rule_id"] not in rules
    stats = db.get(DetectionRuleStats, rule["rule_id"])
    assert stats is not None and stats.errors >= 1 and stats.consecutive_errors >= 1
    # Categoría del error, nunca el mensaje (podría llevar datos del evento).
    assert stats.last_error == "RuntimeError"


# --- Validación y negativos --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("definition", "code"),
    [
        ({"logsource": "nope", "condition": {}}, "unknown_logsource"),
        ({**_single(), "script": "import os"}, "unknown_key"),
        (
            {"logsource": "windows_security",
             "condition": {"field": "event.data.CommandLine", "op": "contains", "value": "x"}},
            "unknown_field",
        ),
        (
            {"logsource": "windows_security",
             "condition": {"field": "event.code", "op": "regex", "value": "4.*"}},
            "operator_type",
        ),
        (
            {"logsource": "windows_security",
             "condition": {"field": "event.data.TargetUserName", "op": "regex",
                           "value": "(a+)+$"}},
            "unsafe_regex",
        ),
        (
            {"logsource": "windows_security",
             "condition": {"field": "event.data.TargetUserName", "op": "equals",
                           "value": "x", "eval": "1"}},
            "unknown_key",
        ),
        ({**_threshold(), "threshold": {"count": 1, "window_minutes": 5}}, "invalid_threshold"),
        ({**_threshold(), "threshold": {"count": 5, "window_minutes": 99999}}, "invalid_window"),
        (
            {"logsource": "windows_security",
             "condition": {"field": "asset.role", "op": "equals", "value": "server"}},
            "asset_context_only",
        ),
    ],
)  # fmt: skip
def test_invalid_definitions_are_rejected_and_never_saved(
    client: TestClient, db: Session, definition: dict[str, Any], code: str
) -> None:
    validation = client.post(f"{RULES}/validate", json={"definition": definition}).json()
    assert not validation["valid"]
    assert code in {e["code"] for e in validation["errors"]}, validation["errors"]
    response = client.post(RULES, json={"title": "mala", "definition": definition})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "detection_rule_invalid"
    assert db.scalar(select(func.count()).select_from(DetectionRuleRecord)) == 0
    assert {e.result for e in _audit(db, "rule_created")} == {"failure"}


def test_deeply_nested_and_huge_definitions_are_rejected(client: TestClient) -> None:
    node: dict[str, Any] = {"field": "event.code", "op": "equals", "value": 1}
    for _ in range(10):
        node = {"not": node}
    deep = client.post(
        f"{RULES}/validate",
        json={"definition": {"logsource": "windows_security", "condition": node}},
    ).json()
    assert not deep["valid"] and "too_deep" in {e["code"] for e in deep["errors"]}
    many = {"any": [{"field": "event.code", "op": "equals", "value": i} for i in range(200)]}
    wide = client.post(
        f"{RULES}/validate",
        json={"definition": {"logsource": "windows_security", "condition": many}},
    ).json()
    assert not wide["valid"]


def test_invalid_mitre_and_category(client: TestClient) -> None:
    for extra in (
        {"mitre_technique": "T11"},
        {"mitre_technique": "T1110", "mitre_subtechnique": "T1059.001"},
        {"category": "inventada"},
    ):
        response = client.post(RULES, json={"title": "regla", "definition": _single(), **extra})
        assert response.status_code == 422, extra


def test_rule_id_path_is_validated(client: TestClient) -> None:
    assert client.get(f"{RULES}/x;drop").status_code == 422
    assert client.get(f"{RULES}/SENTRA-CUSTOM-424242").status_code == 404


# --- RBAC -------------------------------------------------------------------------------------


def test_rbac_viewer_analyst_admin(client: TestClient, engine: Engine) -> None:
    rule = _create(client, _single())
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        assert viewer.get(RULES).status_code == 200
        assert viewer.get(f"{RULES}/{rule['rule_id']}").status_code == 200
        assert viewer.post(f"{RULES}/validate", json={"definition": _single()}).status_code == 403
        assert viewer.post(f"{API}/sigma/preview", json={"yaml": "title: x"}).status_code == 403
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        assert analyst.post(f"{RULES}/validate", json={"definition": _single()}).status_code == 200
        test = analyst.post(
            f"{RULES}/test",
            json={"definition": _single(), "events": [{"fields": {"event.code": 4720}}]},
        )
        assert test.status_code == 200
        assert analyst.post(RULES, json={"title": "x", "definition": _single()}).status_code == 403
        assert _state(analyst, rule, "enable").status_code == 403
        assert analyst.post(f"{API}/sigma/import", json={"yaml": "title: x"}).status_code == 403
        historical = analyst.post(f"{RULES}/test/historical", json={"definition": _single()})
        assert historical.status_code == 403
        # La auditoría completa es audit:read (admin).
        assert analyst.get(f"{RULES}/{rule['rule_id']}/audit").status_code == 403


# --- Pruebas sin efectos -----------------------------------------------------------------------


def test_synthetic_test_has_no_side_effects(client: TestClient, db: Session) -> None:
    response = client.post(
        f"{RULES}/test",
        json={
            "definition": _threshold(count=3, window=10),
            "events": [
                {"fields": {"event.code": 4625, "event.data.TargetUserName": "ana"}}
                for _ in range(3)
            ]
            + [{"fields": {"event.code": 4624, "event.data.TargetUserName": "ana"}}],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["matched"] == 3 and [e["matched"] for e in body["events"]] == [1, 1, 1, 0]
    assert body["would_detect"][0]["group"] == "ana" and body["would_detect"][0]["count"] == 3
    assert db.scalar(select(func.count()).select_from(Detection)) == 0
    assert db.scalar(select(func.count()).select_from(Alert)) == 0
    assert db.scalar(select(func.count()).select_from(DetectionRuleMatch)) == 0
    tested = _audit(db, "rule_tested")
    assert tested and tested[0].details and tested[0].details["mode"] == "synthetic"


def test_synthetic_test_rejects_unknown_fields(client: TestClient) -> None:
    response = client.post(
        f"{RULES}/test",
        json={"definition": _single(), "events": [{"fields": {"event.data.CommandLine": "x"}}]},
    )
    assert response.status_code == 422


def test_historical_test_reads_real_events_without_mutations(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _agent(client)
    _send(client, agent, [fail("ana", _ago(30 - i)) for i in range(6)])

    def counts() -> dict[str, int]:
        with engine.connect() as connection:
            return {
                table: connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()  # noqa: S608
                for table in ("detections", "alerts", "detection_rule_matches", "incidents")
            }

    before = counts()
    response = client.post(
        f"{RULES}/test/historical",
        json={"definition": _threshold(count=5, window=10), "since": _ago(120).isoformat()},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["data_source"] == "events" and body["scanned"] >= 6 and body["matched"] == 6
    assert body["would_detect"][0]["group"] == "ana" and body["would_detect"][0]["max_count"] == 6
    assert body["sample"] and not body["truncated"]
    assert counts() == before
    assert _audit(db, "rule_tested")[0].details["mode"] == "historical"  # type: ignore[index]


def test_historical_test_limits(client: TestClient) -> None:
    too_long = client.post(
        f"{RULES}/test/historical",
        json={
            "definition": _single(),
            "since": (datetime.now(UTC) - timedelta(days=30)).isoformat(),
        },
    )
    assert too_long.status_code == 422
    both = client.post(f"{RULES}/test/historical", json={})
    assert both.status_code == 422


# --- Sigma -------------------------------------------------------------------------------------

SIGMA_BRUTE = """
title: Muchos fallos de inicio de sesión
id: 5f1c2a39-7a52-4d39-9d7e-2f1f0d5b8a11
status: experimental
description: Varios 4625 para la misma cuenta.
author: Equipo SOC
references:
  - https://example.invalid/no-se-abre
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection | count() by TargetUserName >= 5
  timeframe: 10m
falsepositives:
  - Usuarios que olvidan la contraseña
level: high
"""

SIGMA_COMMANDLINE = """
title: Comando sospechoso
id: 0d1d2a39-7a52-4d39-9d7e-2f1f0d5b8a22
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'mimikatz'
  condition: selection
level: critical
"""

SIGMA_NEW_USER = """
title: Cuenta svc creada
id: 7a7a2a39-7a52-4d39-9d7e-2f1f0d5b8a33
tags: [attack.persistence, attack.t1136.001]
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
    TargetUserName|startswith: 'svc_'
  filter:
    TargetUserName|endswith: '_test'
  condition: selection and not filter
level: medium
"""


def test_sigma_preview_is_side_effect_free(client: TestClient, db: Session) -> None:
    preview = client.post(f"{API}/sigma/preview", json={"yaml": SIGMA_BRUTE}).json()
    assert preview["outcome"] == "supported"
    assert preview["severity"] == "high" and preview["confidence"] == "low"
    assert preview["mitre_technique"] == "T1110" and preview["mitre_subtechnique"] == "T1110.001"
    assert preview["mitre_tactic"] == "TA0006"
    assert preview["compiled"]["threshold"] == 5 and preview["compiled"]["window_minutes"] == 10
    assert preview["duplicate"]["state"] == "none"
    assert db.scalar(select(func.count()).select_from(DetectionRuleRecord)) == 0


def test_sigma_import_is_disabled_until_enabled(
    client: TestClient, engine: Engine, db: Session
) -> None:
    result = client.post(f"{API}/sigma/import", json={"yaml": SIGMA_NEW_USER}).json()
    assert result["result"] == "imported"
    rule = result["rule"]
    assert rule["source"] == "sigma" and rule["status"] == "draft" and not rule["enabled"]
    assert rule["rule_id"].startswith("SENTRA-SIGMA-")
    assert rule["sigma_id"] == "7a7a2a39-7a52-4d39-9d7e-2f1f0d5b8a33"
    source = client.get(f"{RULES}/{rule['rule_id']}/sigma-source").json()
    assert "TargetUserName|startswith" in source["yaml"]
    agent = _agent(client)
    events = [
        ev(4720, _ago(2), TargetUserName="svc_a"),
        ev(4720, _ago(2), TargetUserName="svc_test"),
    ]
    _send(client, agent, events)
    _run(engine)
    assert _custom(client) == []  # importada no evalúa
    _enable(client, rule)
    _send(client, agent, [ev(4720, _ago(1), TargetUserName="svc_b")])
    _run(engine)
    (found,) = _custom(client)
    assert found["rule_source"] == "sigma" and found["mitre_technique"] == "T1136"
    assert len(_audit(db, "rule_imported")) == 1


def test_sigma_duplicates(client: TestClient, db: Session) -> None:
    first = client.post(f"{API}/sigma/import", json={"yaml": SIGMA_NEW_USER}).json()
    again = client.post(f"{API}/sigma/import", json={"yaml": SIGMA_NEW_USER}).json()
    assert again["result"] == "unchanged" and again["rule"]["version"] == 1
    changed_yaml = SIGMA_NEW_USER.replace("level: medium", "level: high")
    preview = client.post(f"{API}/sigma/preview", json={"yaml": changed_yaml}).json()
    assert preview["duplicate"]["state"] == "changed"
    conflict = client.post(f"{API}/sigma/import", json={"yaml": changed_yaml})
    assert conflict.status_code == 409
    updated = client.post(
        f"{API}/sigma/import",
        json={"yaml": changed_yaml, "on_duplicate": "update",
              "revision": first["rule"]["revision"]},
    ).json()  # fmt: skip
    assert updated["result"] == "updated" and updated["rule"]["version"] == 2
    assert updated["rule"]["severity"] == "high"
    assert db.scalar(select(func.count()).select_from(DetectionRuleRecord)) == 1


def test_sigma_unsupported_is_stored_but_cannot_be_enabled(client: TestClient, db: Session) -> None:
    result = client.post(f"{API}/sigma/import", json={"yaml": SIGMA_COMMANDLINE}).json()
    assert result["result"] == "unsupported"
    assert any("CommandLine" in i["message"] for i in result["preview"]["unsupported"])
    rule = result["rule"]
    assert rule["compile_status"] == "unsupported" and rule["status"] == "draft"
    blocked = _state(client, rule, "enable")
    assert blocked.status_code == 409


@pytest.mark.parametrize(
    "source",
    [
        "title: x\nfoo: !!python/object/apply:os.system ['id']\n",
        "a: &x [1]\nb: *x\n",
        "title: x\n---\ntitle: y\n",
        "[" * 200,
        "title: x\ndetection:\n  sel:\n    EventID: 1\n  condition: sel | near other\n",
        "{{ 7*7 }}",
    ],
)
def test_malicious_or_malformed_sigma_is_rejected(
    client: TestClient, db: Session, source: str
) -> None:
    result = client.post(f"{API}/sigma/import", json={"yaml": source})
    assert result.status_code == 200, result.text
    assert result.json()["result"] in ("rejected", "unsupported")
    if result.json()["result"] == "rejected":
        assert db.scalar(select(func.count()).select_from(DetectionRuleRecord)) == 0
        assert _audit(db, "rule_import_failed")


def test_sigma_too_large_is_rejected(client: TestClient) -> None:
    response = client.post(f"{API}/sigma/preview", json={"yaml": "a" * (64 * 1024 + 1)})
    assert response.status_code in (413, 422)


# --- Exportación y migración -------------------------------------------------------------------


def test_export_is_declarative(client: TestClient) -> None:
    rule = _create(client, _single())
    exported = client.get(f"{RULES}/{rule['rule_id']}/export").json()
    assert exported["format"] == "sentra-rule-export/1"
    assert exported["definition"]["logsource"] == "windows_security"


def test_migration_0025_round_trip(client: TestClient, engine: Engine, db: Session) -> None:
    from alembic import command

    from tests.conftest import _alembic_config

    _create(client, _single())
    config = _alembic_config(str(engine.url.render_as_string(hide_password=False)))
    try:
        command.downgrade(config, "0024")
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT to_regclass('detection_rules')")).scalar() is None
            )
    finally:
        command.upgrade(config, "head")
    runtime.reset_caches()
    # Esquema operativo de nuevo (las reglas custom se pierden al bajar: documentado).
    assert db.scalar(select(func.count()).select_from(DetectionRuleVersion)) == 0
    assert _create(client, _single())["version"] == 1
