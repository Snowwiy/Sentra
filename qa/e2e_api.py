"""End-to-end contract and failure-case checks against a *running* Sentra API.

Unlike backend/tests (in-process TestClient), this talks HTTP to a real uvicorn process backed
by a real PostgreSQL, so it also catches problems in startup, middleware, CORS, the error
envelope as serialized on the wire and background jobs (offline sweeper).

Usage (stdlib only, any Python 3.12+):

    set SENTRA_QA_API_URL=http://127.0.0.1:8100
    set SENTRA_QA_ENROLLMENT_KEY=<the AGENT_ENROLLMENT_KEY of that API>
    python qa/e2e_api.py [--offline]

It creates throwaway assets with random agent_ids. Point it at a QA instance, never at
production data: it writes telemetry that opens alerts. `--offline` also waits for the offline
sweeper, which needs the API started with a short HEARTBEAT_TIMEOUT_SECONDS (e.g. 20).
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

API = os.environ.get("SENTRA_QA_API_URL", "http://127.0.0.1:8100").rstrip("/") + "/api/v1"
KEY = os.environ.get("SENTRA_QA_ENROLLMENT_KEY", "")

RESULTS: list[tuple[str, bool, str]] = []


class Response:
    def __init__(self, status: int, body: Any, headers: dict[str, str]) -> None:
        self.status = status
        self.body = body
        self.headers = headers


def call(
    method: str, path: str, body: Any = None, headers: dict[str, str] | None = None
) -> Response:
    data = None
    all_headers = {"Accept": "application/json"}
    if body is not None:
        # Raw strings let us send malformed JSON on purpose.
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        all_headers["Content-Type"] = "application/json"
    all_headers.update(headers or {})
    request = urllib.request.Request(  # noqa: S310  (URL comes from the operator's env var)
        API + path, data=data, headers=all_headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            raw = response.read()
            status, resp_headers = response.status, dict(response.headers)
    except urllib.error.HTTPError as error:
        raw, status, resp_headers = error.read(), error.code, dict(error.headers)
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = raw.decode(errors="replace")
    return Response(status, parsed, {k.lower(): v for k, v in resp_headers.items()})


def check(name: str, condition: bool, detail: Any = "") -> bool:
    RESULTS.append((name, condition, "" if condition else str(detail)[:300]))
    print(("PASS " if condition else "FAIL ") + name + ("" if condition else f"  -> {detail}"))
    return condition


def now_iso(delta: timedelta = timedelta()) -> str:
    return (datetime.now(UTC) + delta).isoformat()


def host(agent_id: str, hostname: str = "qa-host") -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "hostname": hostname,
        "os_name": "Windows",
        "os_version": "11 QA",
        "architecture": "AMD64",
        "primary_ip": "10.0.0.10",
        "agent_version": "0.1.0-qa",
    }


def enroll(hostname: str = "qa-host") -> tuple[str, str, str]:
    agent_id = str(uuid.uuid4())
    r = call("POST", "/agents/register", host(agent_id, hostname), {"X-Enrollment-Key": KEY})
    if r.status != 201:
        raise RuntimeError(f"enrollment failed: {r.status} {r.body}")
    return agent_id, r.body["agent_token"], r.body["asset_id"]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def sample(agent_id: str, **overrides: Any) -> dict[str, Any]:
    payload = {
        "agent_id": agent_id,
        "timestamp": now_iso(),
        "cpu_percent": 10.0,
        "ram_percent": 20.0,
        "disk_percent": 30.0,
        "uptime_seconds": 1000,
    }
    payload.update(overrides)
    return payload


def is_error_envelope(r: Response, code: str | None = None) -> bool:
    """Every error must use {"error": {"code", "message"}} and never leak a traceback."""
    body = r.body if isinstance(r.body, dict) else {}
    err = body.get("error", {})
    text = json.dumps(r.body)
    leaked = "Traceback" in text or 'File "' in text or "sqlalchemy" in text.lower()
    return (
        isinstance(err, dict)
        and "message" in err
        and (code is None or err.get("code") == code)
        and not leaked
    )


# --- groups -------------------------------------------------------------------------------


def test_health_and_meta() -> None:
    r = call("GET", "/health")
    check("health 200 ok", r.status == 200 and r.body.get("status") == "ok", r.body)
    check(
        "X-Request-ID echoed",
        call("GET", "/health", headers={"X-Request-ID": "qa-123"}).headers.get("x-request-id")
        == "qa-123",
    )
    r = call("GET", "/health", headers={"X-Request-ID": "bad id with spaces"})
    echoed = r.headers.get("x-request-id", "")
    check("untrusted X-Request-ID replaced", echoed != "bad id with spaces" and len(echoed) == 36)
    check(
        "security headers (nosniff, no-store)",
        r.headers.get("x-content-type-options") == "nosniff"
        and r.headers.get("cache-control") == "no-store",
        r.headers,
    )
    r = call("GET", "/does-not-exist")
    check("unknown route 404 envelope", r.status == 404 and is_error_envelope(r), r.body)
    r = call("DELETE", "/assets")
    check("wrong method 405 envelope", r.status == 405 and is_error_envelope(r), (r.status, r.body))

    # The published contract documents the real error envelope (development only: production
    # hides the OpenAPI document).
    root = API.removesuffix("/api/v1")
    try:
        with urllib.request.urlopen(root + "/openapi.json", timeout=15) as response:  # noqa: S310
            spec = json.loads(response.read())
        documented = spec["paths"]["/api/v1/telemetry"]["post"]["responses"]
        check(
            "OpenAPI documents the error envelope",
            all(
                documented[status]["content"]["application/json"]["schema"]["$ref"].endswith(
                    "/ErrorResponse"
                )
                for status in ("401", "413", "422", "503")
            ),
            documented,
        )
    except urllib.error.HTTPError as error:
        check("OpenAPI hidden (production)", error.code == 404, error.code)


def test_cors() -> None:
    evil = call("GET", "/health", headers={"Origin": "http://evil.example"})
    check(
        "CORS: foreign origin not allowed",
        "access-control-allow-origin" not in evil.headers,
        evil.headers,
    )
    pre = call(
        "OPTIONS",
        "/assets",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"},
    )
    check(
        "CORS: foreign preflight rejected",
        pre.status >= 400 or "access-control-allow-origin" not in pre.headers,
        (pre.status, pre.headers),
    )


def test_enrollment() -> None:
    agent_id = str(uuid.uuid4())
    r = call("POST", "/agents/register", host(agent_id))
    check(
        "register without key -> 401",
        r.status == 401 and is_error_envelope(r, "unauthorized"),
        (r.status, r.body),
    )
    r = call(
        "POST",
        "/agents/register",
        host(agent_id),
        {"X-Enrollment-Key": "wrong-key-wrong-key-wrong"},
    )
    check("register wrong key -> 401", r.status == 401, (r.status, r.body))
    check("401 sets WWW-Authenticate", r.headers.get("www-authenticate") == "Bearer", r.headers)

    r = call("POST", "/agents/register", host(agent_id), {"X-Enrollment-Key": KEY})
    check(
        "register ok -> 201 + token",
        r.status == 201 and len(r.body.get("agent_token", "")) >= 32,
        r.body,
    )
    check("new asset status unknown", r.body.get("status") == "unknown", r.body)
    token1, asset_id = r.body["agent_token"], r.body["asset_id"]

    r = call("GET", f"/assets/{asset_id}")
    check(
        "registered asset readable, unknown until first contact",
        r.status == 200 and r.body["status"] == "unknown" and r.body["last_seen_at"] is None,
        r.body,
    )
    check("asset read never exposes token/hash", "token" not in json.dumps(r.body).lower(), r.body)

    # Duplicate agent: re-enrolling the same agent_id keeps the asset and rotates the token.
    r = call("POST", "/agents/register", host(agent_id, "qa-renamed"), {"X-Enrollment-Key": KEY})
    check(
        "duplicate agent re-enroll -> 200 same asset",
        r.status == 200 and r.body["asset_id"] == asset_id,
        (r.status, r.body),
    )
    token2 = r.body["agent_token"]
    check("re-enroll rotates token", token2 != token1)
    r = call("POST", "/agents/heartbeat", {"agent_id": agent_id}, bearer(token1))
    check("old token revoked after rotation -> 401", r.status == 401, (r.status, r.body))
    r = call("POST", "/agents/heartbeat", {"agent_id": agent_id}, bearer(token2))
    check("new token works", r.status == 200 and r.body["status"] == "online", r.body)
    assets = call("GET", "/assets").body["items"]
    check(
        "no duplicate asset rows for same agent_id",
        sum(a["asset_id"] == asset_id for a in assets) == 1,
    )

    bad = host(str(uuid.uuid4()))
    bad["primary_ip"] = "999.1.1.1"
    r = call("POST", "/agents/register", bad, {"X-Enrollment-Key": KEY})
    check(
        "register invalid IP -> 422",
        r.status == 422 and is_error_envelope(r, "validation_error"),
        r.body,
    )
    bad = host(str(uuid.uuid4()))
    bad["hostname"] = "   "
    check(
        "register blank hostname -> 422",
        call("POST", "/agents/register", bad, {"X-Enrollment-Key": KEY}).status == 422,
    )
    bad = host(str(uuid.uuid4()))
    bad["is_admin"] = True
    check(
        "register unknown field -> 422",
        call("POST", "/agents/register", bad, {"X-Enrollment-Key": KEY}).status == 422,
    )
    r = call("POST", "/agents/register", "{not json", {"X-Enrollment-Key": KEY})
    check(
        "malformed JSON -> 422 envelope",
        r.status == 422 and is_error_envelope(r),
        (r.status, r.body),
    )
    r = call("POST", "/agents/register", {"agent_id": "nope"}, {"X-Enrollment-Key": KEY})
    check("validation errors do not echo input", "nope" not in json.dumps(r.body), r.body)


def test_agent_auth() -> None:
    agent_id, token, _ = enroll()
    other_id, other_token, _ = enroll("qa-other")
    cases: list[tuple[str, Callable[[], Response]]] = [
        ("heartbeat no token", lambda: call("POST", "/agents/heartbeat", {"agent_id": agent_id})),
        (
            "heartbeat wrong token",
            lambda: call("POST", "/agents/heartbeat", {"agent_id": agent_id}, bearer("x" * 43)),
        ),
        (
            "heartbeat unknown agent",
            lambda: call(
                "POST", "/agents/heartbeat", {"agent_id": str(uuid.uuid4())}, bearer(token)
            ),
        ),
        (
            "heartbeat with another agent's token",
            lambda: call("POST", "/agents/heartbeat", {"agent_id": agent_id}, bearer(other_token)),
        ),
        (
            "heartbeat Basic scheme",
            lambda: call(
                "POST",
                "/agents/heartbeat",
                {"agent_id": agent_id},
                {"Authorization": f"Basic {token}"},
            ),
        ),
        ("telemetry no token", lambda: call("POST", "/telemetry", sample(agent_id))),
        (
            "inventory no token",
            lambda: call("POST", "/inventory", {"agent_id": agent_id, "collected_at": now_iso()}),
        ),
        (
            "events no token",
            lambda: call("POST", "/events", {"agent_id": agent_id, "events": [event(1)]}),
        ),
    ]
    for name, fn in cases:
        r = fn()
        check(
            f"{name} -> 401",
            r.status == 401 and is_error_envelope(r, "unauthorized"),
            (r.status, r.body),
        )
    # Same body for unknown agent and wrong token, so agent ids cannot be probed.
    a = call("POST", "/agents/heartbeat", {"agent_id": str(uuid.uuid4())}, bearer(token)).body
    b = call("POST", "/agents/heartbeat", {"agent_id": agent_id}, bearer("y" * 43)).body
    check("unknown agent and bad token indistinguishable", a == b, (a, b))
    del other_id


def test_telemetry_validation() -> None:
    agent_id, token, asset_id = enroll()
    h = bearer(token)
    bad_cases = {
        "negative cpu": sample(agent_id, cpu_percent=-1),
        "cpu > 100": sample(agent_id, cpu_percent=100.01),
        "ram > 100": sample(agent_id, ram_percent=250),
        "disk negative": sample(agent_id, disk_percent=-0.5),
        "negative uptime": sample(agent_id, uptime_seconds=-5),
        "cpu as string": sample(agent_id, cpu_percent="high"),
        # json.dumps writes the non-standard NaN/Infinity literals Python's json accepts.
        "cpu NaN": json.dumps(sample(agent_id, cpu_percent=float("nan"))),
        "cpu Infinity": json.dumps(sample(agent_id, cpu_percent=float("inf"))),
        "naive timestamp": sample(
            agent_id, timestamp=datetime.now(UTC).replace(tzinfo=None).isoformat()
        ),
        "garbage timestamp": sample(agent_id, timestamp="yesterday"),
        "timestamp 1 day in future": sample(agent_id, timestamp=now_iso(timedelta(days=1))),
        "missing field": {k: v for k, v in sample(agent_id).items() if k != "ram_percent"},
        "extra field": sample(agent_id, gpu_percent=5),
        "huge uptime overflow": sample(agent_id, uptime_seconds=2**70),
    }
    for name, payload in bad_cases.items():
        r = call("POST", "/telemetry", payload, h)
        check(
            f"telemetry {name} -> 422", r.status == 422 and is_error_envelope(r), (r.status, r.body)
        )

    for name, payload in {
        "boundary 0/100": sample(agent_id, cpu_percent=0, ram_percent=100, disk_percent=0),
        "timestamp with +02:00 offset": sample(
            agent_id,
            timestamp=(datetime.now(UTC) + timedelta(hours=2)).replace(tzinfo=None).isoformat()
            + "+02:00",
        ),
        "late sample 1h old (buffered)": sample(agent_id, timestamp=now_iso(timedelta(hours=-1))),
        "uptime int64 max-ish": sample(agent_id, uptime_seconds=2**62),
    }.items():
        r = call("POST", "/telemetry", payload, h)
        check(f"telemetry {name} -> 201", r.status == 201, (r.status, r.body))

    hist = call("GET", f"/assets/{asset_id}/telemetry?limit=10").body["items"]
    times = [i["recorded_at"] for i in hist]
    check("history ordered oldest first", times == sorted(times), times)
    check(
        "history timestamps in UTC (Z)",
        all(t.endswith("Z") or t.endswith("+00:00") for t in times),
        times,
    )
    latest = call("GET", f"/assets/{asset_id}").body["latest_telemetry"]
    check(
        "late sample does not become latest", latest["recorded_at"] == max(times), (latest, times)
    )

    for q, expected in (
        ("limit=0", 422),
        ("limit=1001", 422),
        ("limit=-1", 422),
        ("limit=abc", 422),
        ("limit=1", 200),
        ("limit=1000", 200),
    ):
        r = call("GET", f"/assets/{asset_id}/telemetry?{q}")
        check(f"telemetry history {q} -> {expected}", r.status == expected, (r.status, r.body))
    check(
        "history limit=1 returns 1",
        len(call("GET", f"/assets/{asset_id}/telemetry?limit=1").body["items"]) == 1,
    )


def event(record_id: int, **overrides: Any) -> dict[str, Any]:
    e = {
        "source": "windows_eventlog",
        "channel": "System",
        "record_id": record_id,
        "event_code": 7034,
        "provider": "Service Control Manager",
        "level": "error",
        "message": "QA service crashed",
        "occurred_at": now_iso(timedelta(minutes=-1)),
    }
    e.update(overrides)
    return e


def test_events_and_inventory() -> None:
    agent_id, token, asset_id = enroll()
    h = bearer(token)
    batch = {
        "agent_id": agent_id,
        "events": [event(1), event(2, level="warning"), event(3, level="info")],
    }
    r = call("POST", "/events", batch, h)
    check("events ingest -> 201 stored 3", r.status == 201 and r.body["stored"] == 3, r.body)
    r = call("POST", "/events", batch, h)
    check(
        "events resend idempotent (stored 0)",
        r.status == 201 and r.body["stored"] == 0 and r.body["received"] == 3,
        r.body,
    )
    r = call("POST", "/events", {"agent_id": agent_id, "events": [event(9), event(9)]}, h)
    check(
        "duplicate record in one batch stored once",
        r.status == 201 and r.body["stored"] == 1,
        (r.status, r.body),
    )
    check(
        "events empty batch -> 422",
        call("POST", "/events", {"agent_id": agent_id, "events": []}, h).status == 422,
    )
    check(
        "events too many -> 422",
        call(
            "POST",
            "/events",
            {"agent_id": agent_id, "events": [event(i) for i in range(100, 601)]},
            h,
        ).status
        == 422,
    )
    check(
        "events bad level -> 422",
        call(
            "POST", "/events", {"agent_id": agent_id, "events": [event(50, level="fatal")]}, h
        ).status
        == 422,
    )
    check(
        "events future -> 422",
        call(
            "POST",
            "/events",
            {"agent_id": agent_id, "events": [event(51, occurred_at=now_iso(timedelta(days=2)))]},
            h,
        ).status
        == 422,
    )
    check(
        "events negative record -> 422",
        call("POST", "/events", {"agent_id": agent_id, "events": [event(-1)]}, h).status == 422,
    )
    check(
        "events message too long -> 422",
        call(
            "POST", "/events", {"agent_id": agent_id, "events": [event(52, message="x" * 4001)]}, h
        ).status
        == 422,
    )
    r = call("POST", "/events", {"agent_id": agent_id, "events": [event(2**63)]}, h)
    check("events record_id > int64 -> 422 (not 500)", r.status == 422, (r.status, r.body))
    r = call("GET", f"/events?asset_id={asset_id}&min_level=warning")
    levels = {i["level"] for i in r.body["items"]}
    check(
        "events min_level=warning filters info",
        r.status == 200 and "info" not in levels and levels,
        r.body,
    )
    check(
        "events unknown asset -> 404", call("GET", f"/events?asset_id={uuid.uuid4()}").status == 404
    )
    check("events bad min_level -> 422", call("GET", "/events?min_level=loud").status == 422)
    check("events limit=501 -> 422", call("GET", "/events?limit=501").status == 422)

    r = call("GET", f"/assets/{asset_id}/inventory")
    check(
        "inventory before first snapshot -> 404",
        r.status == 404 and is_error_envelope(r, "not_found"),
        r.body,
    )
    inv = {
        "agent_id": agent_id,
        "collected_at": now_iso(),
        "interfaces": [
            {
                "name": "eth0",
                "mac": "00:11:22:33:44:55",
                "addresses": ["10.0.0.10", "fe80::1"],
                "is_up": True,
                "speed_mbps": 1000,
            }
        ],
        "users": [{"name": "qa"}],
        "processes": [{"pid": 4, "name": "System", "memory_bytes": 1}],
        "services": [{"name": "svc", "status": "running"}],
        "software": [{"name": "QA Tool", "version": "1.0"}],
    }
    check("inventory ingest -> 201", call("POST", "/inventory", inv, h).status == 201)
    older = dict(inv, collected_at=now_iso(timedelta(hours=-2)), software=[])
    call("POST", "/inventory", older, h)
    r = call("GET", f"/assets/{asset_id}/inventory")
    check(
        "older snapshot does not replace newer",
        r.status == 200 and len(r.body["software"]) == 1,
        r.body,
    )
    bad = dict(inv, interfaces=[{"name": "x", "addresses": ["not-an-ip"], "is_up": True}])
    check("inventory bad IP -> 422", call("POST", "/inventory", bad, h).status == 422)
    bad = dict(inv, processes=[{"pid": -1, "name": "x", "memory_bytes": 0}])
    check("inventory negative pid -> 422", call("POST", "/inventory", bad, h).status == 422)
    check(
        "inventory unknown asset -> 404",
        call("GET", f"/assets/{uuid.uuid4()}/inventory").status == 404,
    )


def test_hardening() -> None:
    """Body size limit, migrations health check and telemetry idempotency (sample_id)."""
    checks = call("GET", "/health").body.get("checks", {})
    check("health reports migrations check", checks.get("migrations") == "ok", checks)

    # Over the 4 MiB limit: rejected with 413 before authentication or JSON parsing.
    big = (
        '{"agent_id":"00000000-0000-0000-0000-000000000000","x":"' + "y" * (5 * 1024 * 1024) + '"}'
    )
    try:
        r = call("POST", "/events", big)
        check(
            "oversized body -> 413 envelope",
            r.status == 413 and is_error_envelope(r, "payload_too_large"),
            (r.status, r.body),
        )
    except (ConnectionResetError, BrokenPipeError, urllib.error.URLError) as exc:
        # The server answers 413 and closes while urllib is still uploading, so the client may
        # only see the reset. That still proves the body was rejected early. Windows raises the
        # bare ConnectionResetError; on Linux urllib wraps it in URLError(reason=...), which
        # must not be confused with a genuinely unreachable API (that would fail elsewhere).
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        check(
            "oversized body rejected early (connection closed)",
            isinstance(reason, ConnectionResetError | BrokenPipeError),
            repr(exc),
        )

    agent_id, token, asset_id = enroll("qa-idempotency")
    other_id, other_token, _ = enroll("qa-idempotency-2")
    sample_id = str(uuid.uuid4())
    first = call(
        "POST", "/telemetry", sample(agent_id, sample_id=sample_id, cpu_percent=11), bearer(token)
    )
    again = call(
        "POST", "/telemetry", sample(agent_id, sample_id=sample_id, cpu_percent=99), bearer(token)
    )
    check(
        "telemetry first send stored",
        first.status == 201 and first.body.get("stored") is True,
        first.body,
    )
    check(
        "telemetry resend same sample_id not stored",
        again.status == 201 and again.body.get("stored") is False,
        again.body,
    )
    history = call("GET", f"/assets/{asset_id}/telemetry").body["items"]
    check(
        "resend did not duplicate or overwrite",
        [i["cpu_percent"] for i in history] == [11.0],
        history,
    )
    r = call("POST", "/telemetry", sample(other_id, sample_id=sample_id), bearer(other_token))
    check("sample_id scoped per agent", r.status == 201 and r.body.get("stored") is True, r.body)
    check(
        "invalid sample_id -> 422",
        call("POST", "/telemetry", sample(agent_id, sample_id="abc"), bearer(token)).status == 422,
    )

    # PostgreSQL cannot store U+0000 in text/JSONB. It must be a final 422: a 500 makes agents
    # back off and resend the same payload forever.
    nul_requests = [
        (
            "NUL in hostname -> 422 (not 500)",
            "/agents/register",
            {**host(str(uuid.uuid4())), "hostname": "nul\u0000host"},
            {"X-Enrollment-Key": KEY},
        ),
        (
            "NUL in event message -> 422 (not 500)",
            "/events",
            {"agent_id": agent_id, "events": [event(1, message="bad\u0000message")]},
            bearer(token),
        ),
        (
            "NUL in inventory string (JSONB) -> 422 (not 500)",
            "/inventory",
            {"agent_id": agent_id, "collected_at": now_iso(), "software": [{"name": "a\u0000"}]},
            bearer(token),
        ),
    ]
    for name, path, body, headers in nul_requests:
        r = call("POST", path, body, headers)
        rejected = r.status == 422 and is_error_envelope(r, "validation_error")
        check(name, rejected, (r.status, r.body))


def test_operational() -> None:
    """Process snapshots, inventory changes, inventory/event-based alerts and list filters."""
    agent_id, token, asset_id = enroll("qa-operational")
    auth = bearer(token)

    process = {"pid": 4, "ppid": None, "name": "System", "memory_bytes": 1, "cpu_percent": 2.5}
    r = call(
        "POST",
        "/processes",
        {"agent_id": agent_id, "collected_at": now_iso(), "processes": [process]},
        auth,
    )
    check("process snapshot -> 201", r.status == 201 and r.body.get("stored") is True, r.body)
    late = call(
        "POST",
        "/processes",
        {"agent_id": agent_id, "collected_at": now_iso(timedelta(minutes=-5)), "processes": []},
        auth,
    )
    check("older process snapshot not stored", late.body.get("stored") is False, late.body)
    r = call("GET", f"/assets/{asset_id}/processes")
    check(
        "latest process snapshot readable",
        r.status == 200 and [p["pid"] for p in r.body["processes"]] == [4],
        r.body,
    )
    r = call(
        "POST",
        "/processes",
        {
            "agent_id": agent_id,
            "collected_at": now_iso(),
            "processes": [{**process, "cpu_percent": 900}],
        },
        auth,
    )
    check("process cpu over 100 -> 422", r.status == 422 and is_error_envelope(r), r.body)

    def inventory(at: timedelta, **sections: Any) -> Response:
        return call(
            "POST",
            "/inventory",
            {"agent_id": agent_id, "collected_at": now_iso(at), **sections},
            auth,
        )

    def service(status: str) -> list[dict[str, Any]]:
        return [{"name": "WinDefend", "status": status, "start_type": "automatic"}]

    inventory(timedelta(minutes=-3), services=service("running"), software=[{"name": "A"}])
    inventory(timedelta(minutes=-2), services=service("stopped"), software=[{"name": "B"}])
    changes = call("GET", f"/assets/{asset_id}/changes").body
    kinds = sorted((c["category"], c["kind"]) for c in changes.get("items", []))
    check(
        "inventory changes detected",
        kinds == [("service", "stopped"), ("software", "added"), ("software", "removed")],
        changes,
    )
    r = call("GET", f"/alerts?asset_id={asset_id}&rule=service_stopped&active=true")
    check(
        "watched service stopped -> one active alert",
        r.status == 200 and r.body["total"] == 1 and r.body["items"][0]["status"] == "open",
        r.body,
    )
    inventory(timedelta(minutes=-1), services=service("running"), software=[{"name": "B"}])
    r = call("GET", f"/alerts?asset_id={asset_id}&rule=service_stopped")
    check("service back -> alert resolved", r.body["items"][0]["status"] == "resolved", r.body)

    shutdown = event(70, provider="EventLog", event_code=6008, message="Unexpected shutdown")
    call("POST", "/events", {"agent_id": agent_id, "events": [shutdown]}, auth)
    call("POST", "/events", {"agent_id": agent_id, "events": [shutdown]}, auth)  # resend
    r = call("GET", f"/alerts?asset_id={asset_id}&rule=critical_event")
    alert = (r.body.get("items") or [{}])[0]
    check(
        "critical event -> alert linked to the event, resend not counted",
        alert.get("occurrences") == 1 and alert.get("event_id") is not None,
        r.body,
    )
    r = call("GET", f"/alerts/{alert.get('alert_id')}")
    check("alert detail", r.status == 200 and r.body.get("rule") == "critical_event", r.body)
    check("unknown alert -> 404", call("GET", f"/alerts/{uuid.uuid4()}").status == 404)
    r = call("GET", f"/alerts?asset_id={asset_id}&q=WINDEFEND")
    check("alert search is case-insensitive", r.body.get("total") == 1, r.body)
    r = call("GET", "/alerts?severity=bogus")
    check("bad severity -> 422", r.status == 422 and is_error_envelope(r), r.body)
    for path in ("/alerts?q=a%00b", "/events?q=a%00b", "/events?channel=a%00b"):
        r = call("GET", path)
        name = path.split("?")[1].split("=")[0]
        check(f"NUL in {path[:7]} {name} -> 422", r.status == 422 and is_error_envelope(r), r.body)
    r = call(
        "POST",
        "/inventory",
        {
            "agent_id": agent_id,
            "collected_at": now_iso(),
            "accounts": [{"name": "ana", "password": "x"}],
        },
        auth,
    )
    check("account with a password field -> 422", r.status == 422 and is_error_envelope(r), r.body)

    r = call("GET", f"/events?asset_id={asset_id}&event_code=6008&limit=1")
    check(
        "event filters + has_more",
        r.status == 200
        and [e["event_code"] for e in r.body["items"]] == [6008]
        and r.body["has_more"] is False,
        r.body,
    )


def test_assets_read() -> None:
    check("asset unknown uuid -> 404", call("GET", f"/assets/{uuid.uuid4()}").status == 404)
    r = call("GET", "/assets/not-a-uuid")
    check("asset malformed id -> 422 envelope", r.status == 422 and is_error_envelope(r), r.body)
    check(
        "telemetry unknown asset -> 404",
        call("GET", f"/assets/{uuid.uuid4()}/telemetry").status == 404,
    )
    check(
        "alerts unknown asset -> 404", call("GET", f"/alerts?asset_id={uuid.uuid4()}").status == 404
    )
    check("alerts bad status -> 422", call("GET", "/alerts?status=closed").status == 422)
    check("alerts limit=0 -> 422", call("GET", "/alerts?limit=0").status == 422)
    r = call("GET", "/assets")
    ok = r.status == 200 and all(
        set(a) >= {"asset_id", "hostname", "status", "latest_telemetry", "last_seen_at"}
        for a in r.body["items"]
    )
    check("asset list contract", ok, r.body)
    check("asset list total == len(items)", r.body["total"] == len(r.body["items"]))


def test_alerts() -> None:
    agent_id, token, asset_id = enroll("qa-alerts")
    h = bearer(token)
    # Two hot samples: below the default sustained window (3), so no alert yet.
    for _ in range(2):
        call(
            "POST",
            "/telemetry",
            sample(agent_id, cpu_percent=99, ram_percent=95, disk_percent=97),
            h,
        )
    open_rules = {
        a["rule"] for a in call("GET", f"/alerts?asset_id={asset_id}&status=open").body["items"]
    }
    check("disk alert opens on one sample", "disk_critical" in open_rules, open_rules)
    check("cpu alert waits for sustained samples", "high_cpu" not in open_rules, open_rules)
    call("POST", "/telemetry", sample(agent_id, cpu_percent=99, ram_percent=95, disk_percent=97), h)
    alerts = call("GET", f"/alerts?asset_id={asset_id}&status=open").body["items"]
    rules = [a["rule"] for a in alerts]
    check(
        "cpu+ram alerts open after sustained breach", {"high_cpu", "high_ram"} <= set(rules), rules
    )
    check("no duplicate open alerts per rule", len(rules) == len(set(rules)), rules)
    for _ in range(3):
        call(
            "POST",
            "/telemetry",
            sample(agent_id, cpu_percent=99, ram_percent=95, disk_percent=97),
            h,
        )
    rules = [
        a["rule"] for a in call("GET", f"/alerts?asset_id={asset_id}&status=open").body["items"]
    ]
    check("still no duplicates after more hot samples", len(rules) == len(set(rules)) == 3, rules)
    call("POST", "/telemetry", sample(agent_id), h)
    open_now = call("GET", f"/alerts?asset_id={asset_id}&status=open").body["items"]
    resolved = call("GET", f"/alerts?asset_id={asset_id}&status=resolved").body["items"]
    check(
        "alerts auto-resolve when back to normal",
        not open_now and len(resolved) == 3,
        (open_now, resolved),
    )
    check("resolved alerts have resolved_at", all(a["resolved_at"] for a in resolved))


def test_offline() -> None:
    agent_id, token, asset_id = enroll("qa-offline")
    call("POST", "/agents/heartbeat", {"agent_id": agent_id}, bearer(token))
    check(
        "asset online after heartbeat",
        call("GET", f"/assets/{asset_id}").body["status"] == "online",
    )
    deadline = time.time() + 90
    status, opened = "online", False
    while time.time() < deadline and not (status == "offline" and opened):
        time.sleep(3)
        status = call("GET", f"/assets/{asset_id}").body["status"]
        alerts = call("GET", f"/alerts?asset_id={asset_id}&status=open").body["items"]
        opened = any(a["rule"] == "asset_offline" for a in alerts)
    check("asset goes offline after timeout", status == "offline", status)
    check("sweeper opens asset_offline alert", opened)
    call("POST", "/agents/heartbeat", {"agent_id": agent_id}, bearer(token))
    check(
        "heartbeat brings asset back online",
        call("GET", f"/assets/{asset_id}").body["status"] == "online",
    )
    alerts = call("GET", f"/alerts?asset_id={asset_id}&status=open").body["items"]
    check(
        "offline alert resolved by heartbeat",
        not any(a["rule"] == "asset_offline" for a in alerts),
        alerts,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="also wait for the offline sweeper")
    args = parser.parse_args()
    if not KEY:
        print("SENTRA_QA_ENROLLMENT_KEY is required", file=sys.stderr)
        return 2
    groups = [
        test_health_and_meta,
        test_cors,
        test_enrollment,
        test_agent_auth,
        test_telemetry_validation,
        test_events_and_inventory,
        test_assets_read,
        test_alerts,
        test_hardening,
        test_operational,
    ]
    if args.offline:
        groups.append(test_offline)
    for group in groups:
        print(f"--- {group.__name__}")
        try:
            group()
        except Exception as exc:
            check(f"{group.__name__} crashed", False, repr(exc))
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
