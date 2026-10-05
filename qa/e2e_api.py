"""End-to-end contract and failure-case checks against a *running* Sentra API.

Unlike backend/tests (in-process TestClient), this talks HTTP to a real uvicorn process backed
by a real PostgreSQL, so it also catches problems in startup, middleware, CORS, the error
envelope as serialized on the wire and background jobs (offline sweeper).

Usage (stdlib only, any Python 3.12+):

    set SENTRA_QA_API_URL=http://127.0.0.1:8100
    set SENTRA_QA_ENROLLMENT_KEY=<the AGENT_ENROLLMENT_KEY of that API>
    set SENTRA_QA_ADMIN_USER=<admin created with `python -m app.cli create-admin`>
    set SENTRA_QA_ADMIN_PASSWORD=<its password>
    python qa/e2e_api.py [--offline]

Fase 4G: las lecturas y acciones del dashboard exigen sesión. El script inicia sesión como
ese admin (cookie + token CSRF en memoria) y crea un viewer temporal para probar permisos.

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
ADMIN_USER = os.environ.get("SENTRA_QA_ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("SENTRA_QA_ADMIN_PASSWORD", "")

# Sesión del dashboard: cabeceras Cookie y X-CSRF-Token que `call` añade por defecto.
SESSION: dict[str, str] = {}

RESULTS: list[tuple[str, bool, str]] = []


class Response:
    def __init__(self, status: int, body: Any, headers: dict[str, str]) -> None:
        self.status = status
        self.body = body
        self.headers = headers


def call(
    method: str,
    path: str,
    body: Any = None,
    headers: dict[str, str] | None = None,
    session: dict[str, str] | None = None,
) -> Response:
    """`session=None` usa la sesión de admin; `session={}` es un cliente anónimo."""
    data = None
    all_headers = {"Accept": "application/json"}
    all_headers.update(SESSION if session is None else session)
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


def login(username: str, password: str) -> tuple[Response, dict[str, str]]:
    """Inicia sesión y devuelve las cabeceras de esa sesión (cookie + CSRF)."""
    r = call("POST", "/auth/login", {"username": username, "password": password}, session={})
    if r.status != 200:
        return r, {}
    cookie = r.headers.get("set-cookie", "").split(";", 1)[0]
    return r, {"Cookie": cookie, "X-CSRF-Token": r.body["csrf_token"]}


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


def test_hybrid_read() -> None:
    """Hybrid monitoring read API. Never starts a scan: runs are CLI/periodic only."""
    _, _, asset_id = enroll("qa-hybrid")
    asset = call("GET", f"/assets/{asset_id}").body
    check(
        "agent asset is MANAGED with network fields",
        asset.get("monitoring_method") == "agent"
        and asset.get("agent_status") in ("unknown", "online")
        and asset.get("open_ports") == []
        and "display_name" in asset,
        asset,
    )
    r = call("GET", "/assets?method=agent")
    check(
        "filter by method",
        r.status == 200 and all(a["monitoring_method"] == "agent" for a in r.body["items"]),
        r.body,
    )
    for query in ("method=bogus", "subnet=10.0.0.5/24", "subnet=x", "device_type=A%00", "q=a%00"):
        r = call("GET", f"/assets?{query}")
        check(
            f"assets {query.split('=')[0]} invalid -> 422", r.status == 422 and is_error_envelope(r)
        )
    r = call("GET", f"/assets/{asset_id}/exposure")
    check("exposure of unscanned asset", r.status == 200 and r.body["ports"] == [], r.body)
    check(
        "exposure unknown asset -> 404",
        call("GET", f"/assets/{uuid.uuid4()}/exposure").status == 404,
    )
    r = call("GET", "/discovery/scope")
    check("discovery scope readable", r.status == 200 and "allowed_networks" in r.body, r.body)
    r = call("GET", "/discovery/jobs?limit=5")
    check(
        "discovery jobs readable", r.status == 200 and isinstance(r.body.get("items"), list), r.body
    )
    check("discovery jobs limit 0 -> 422", call("GET", "/discovery/jobs?limit=0").status == 422)
    r = call("POST", "/discovery/jobs", {"target": "0.0.0.0/0"})
    check("no HTTP endpoint starts a scan", r.status in (404, 405), (r.status, r.body))
    # Fase 4D: iniciar/cancelar solo por la consola local del dashboard. Sin la cabecera de
    # consola (o con la consola desactivada) siempre 403, nunca un scan.
    # Fase 4G: iniciar/cancelar exige sesión (401 sin ella) y nunca escanea fuera de la
    # allowlist aunque lo pida un admin.
    for path, body in (
        ("/console/discovery/jobs", {"target": "0.0.0.0/0"}),
        (f"/console/discovery/jobs/{uuid.uuid4()}/cancel", None),
    ):
        r = call("POST", path, body, session={})
        check(
            f"{path.split('/')[-1]} discovery without session -> 401",
            r.status == 401 and is_error_envelope(r, "not_authenticated"),
            (r.status, r.body),
        )
    r = call("POST", "/console/discovery/jobs", {"target": "0.0.0.0/0"})
    check("admin discovery outside allowlist refused", r.status in (409, 422), (r.status, r.body))
    r = call("GET", "/discovery/schedule")
    check("discovery schedule readable", r.status == 200 and "enabled" in r.body, r.body)
    check(
        "discovery job unknown -> 404",
        call("GET", f"/discovery/jobs/{uuid.uuid4()}").status == 404,
    )


def test_enrollment_tokens() -> None:
    """One-time enrollment tokens over real HTTP. The QA server has no ADMIN_API_KEY, so the
    administration API must be closed; token creation itself is covered by backend tests."""
    r = call("POST", "/agent-enrollment-tokens", {})
    check("admin API disabled without ADMIN_API_KEY -> 403", r.status == 403, (r.status, r.body))
    check(
        "admin API listing disabled -> 403", call("GET", "/agent-enrollment-tokens").status == 403
    )
    bogus = "sentra_et_" + "Z" * 43
    r = call("POST", "/agents/register", host(str(uuid.uuid4())), {"X-Enrollment-Token": bogus})
    check(
        "unknown enrollment token -> 401 without echoing it",
        r.status == 401 and is_error_envelope(r) and bogus not in json.dumps(r.body),
        (r.status, r.body),
    )
    r = call("POST", "/agents/heartbeat", {"agent_id": str(uuid.uuid4())}, bearer(bogus))
    check("enrollment token is not an agent credential -> 401", r.status == 401, r.status)


def wait_for(fetch: Callable[[], Any], ready: Callable[[Any], bool], timeout: float = 30) -> Any:
    """Repite `fetch` hasta que `ready` o se agote el tiempo (el motor corre en un job)."""
    deadline = time.monotonic() + timeout
    value = fetch()
    while not ready(value) and time.monotonic() < deadline:
        time.sleep(1)
        value = fetch()
    return value


def test_detections() -> None:
    """Fase 4H: detección simple, correlación, deduplicación y resolución con auditoría.

    Necesita el job del motor activo (DETECTION_ENABLED, por defecto) y conviene un intervalo
    corto (DETECTION_EVAL_INTERVAL_SECONDS=2). Datos sintéticos: no son de ningún host real.
    """
    agent_id, token, asset_id = enroll("qa-detections")
    h = bearer(token)
    security = {"channel": "Security", "provider": "Microsoft-Windows-Security-Auditing"}

    def send(events: list[dict[str, Any]]) -> None:
        r = call("POST", "/events", {"agent_id": agent_id, "events": events}, h)
        check("detection events accepted", r.status == 201, (r.status, r.body))

    def detections() -> list[dict[str, Any]]:
        r = call("GET", f"/detections?asset_id={asset_id}&active=true")
        return r.body["items"] if r.status == 200 else []

    def by_rule(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return {d["rule_id"]: d for d in items}

    # 1. Detección simple: borrado del registro de seguridad.
    send([event(9001, event_code=1102, level="critical", message="QA log cleared",
                data={"SubjectUserName": "qa-user"}, **security)])  # fmt: skip
    found = wait_for(detections, lambda items: "DEF-001" in by_rule(items))
    cleared = by_rule(found).get("DEF-001")
    check("simple detection DEF-001 created", cleared is not None, found)
    if cleared is None:
        return
    check(
        "severity and confidence are separate fields",
        cleared["severity"] == "high" and cleared["confidence"] in ("low", "medium", "high"),
        cleared,
    )

    # 2. Deduplicación: otro borrado no abre una segunda detección activa.
    send([event(9002, event_code=1102, level="critical", message="QA log cleared again",
                **security)])  # fmt: skip
    detail = wait_for(
        lambda: call("GET", f"/detections/{cleared['detection_id']}").body,
        lambda body: isinstance(body, dict) and body.get("evidence_total", 0) >= 2,
    )
    same = [d for d in detections() if d["rule_id"] == "DEF-001"]
    check("dedup keeps one active detection per rule/key", len(same) == 1, same)
    check("dedup adds evidence to the same detection", detail.get("evidence_total", 0) >= 2, detail)

    # 3. Correlación: fallos repetidos y después un inicio de sesión correcto (CORR-001).
    user = {"TargetUserName": "qa-analyst", "TargetUserSid": "S-1-5-21-90-91-92-1001"}
    failures = [
        event(9100 + i, event_code=4625, level="warning", message="QA logon failure",
              occurred_at=now_iso(timedelta(minutes=-3, seconds=i)),
              data={**user, "IpAddress": "10.66.0.9", "LogonType": "3"}, **security)
        for i in range(6)
    ]  # fmt: skip
    success = event(9200, event_code=4624, level="info", message="QA logon",
                    occurred_at=now_iso(timedelta(minutes=-1)),
                    data={**user, "LogonType": "10", "IpAddress": "10.66.0.9"},
                    **security)  # fmt: skip
    send([*failures, success])
    found = by_rule(wait_for(detections, lambda items: "CORR-001" in by_rule(items)))
    check("failed logon burst AUTH-001 detected", "AUTH-001" in found, sorted(found))
    corr = found.get("CORR-001")
    check("correlation CORR-001 detected", corr is not None and corr["kind"] == "correlation", corr)
    if corr:
        body = call("GET", f"/detections/{corr['detection_id']}").body
        roles = {item["role"] for item in body.get("evidence", [])}
        check("correlation evidence keeps both sides", {"failure", "success"} <= roles, roles)
        check(
            "detail explains why and what to do",
            bool(body.get("why") and body.get("recommendations")),
        )

    # 4. Resolver: queda en la auditoría y deja de estar activa.
    r = call("POST", f"/detections/{cleared['detection_id']}/resolve", {"note": "QA: prueba"})
    check(
        "resolve detection",
        r.status == 200
        and r.body["status"] == "resolved"
        and r.body["resolution_note"] == "QA: prueba",
        (r.status, r.body),
    )
    r = call("POST", f"/detections/{cleared['detection_id']}/acknowledge")
    check("acknowledge after resolve -> 409", r.status == 409 and is_error_envelope(r), r.status)
    check("resolved detection leaves the active list", "DEF-001" not in by_rule(detections()))
    audit = call("GET", "/audit?action=detection_resolved&limit=20").body["items"]
    check(
        "resolve written to audit_events",
        any(a["target_id"] == cleared["detection_id"] and a["result"] == "success" for a in audit),
        audit[:3],
    )
    r = call("GET", "/detection-rules")
    check("rule catalogue lists 23 rules", r.status == 200 and len(r.body["items"]) == 23, r.status)


def test_risk() -> None:
    """Fase 4I: activo limpio -> detección alta -> correlación -> criticidad -> resolver.

    Necesita los jobs del motor de detección y del de riesgo con intervalos cortos
    (DETECTION_EVAL_INTERVAL_SECONDS=2, RISK_EVAL_INTERVAL_SECONDS=2). El decaimiento por horas
    no se espera aquí: lo cubren los tests de backend con reloj simulado.
    """
    agent_id, token, asset_id = enroll("qa-risk")
    h = bearer(token)
    security = {"channel": "Security", "provider": "Microsoft-Windows-Security-Auditing"}

    def risk() -> dict[str, Any]:
        r = call("GET", f"/risk/assets/{asset_id}")
        return r.body if r.status == 200 else {}

    def settled(previous: str | None = None) -> Callable[[dict[str, Any]], bool]:
        # Evaluado, sin recálculo pendiente y (si se indica) con un cálculo posterior.
        return lambda body: (
            bool(body.get("evaluated"))
            and not body.get("pending_recalculation")
            and (previous is None or (body.get("calculated_at") or "") > previous)
        )

    def detections() -> dict[str, dict[str, Any]]:
        r = call("GET", f"/detections?asset_id={asset_id}&active=true")
        return {d["rule_id"]: d for d in r.body["items"]} if r.status == 200 else {}

    def send(events: list[dict[str, Any]]) -> Response:
        return call("POST", "/events", {"agent_id": agent_id, "events": events}, h)

    # 1. Activo limpio: se evalúa solo (seed del job) y queda informativo, sin contribuciones.
    clean = wait_for(risk, settled())
    check(
        "clean asset is evaluated as informational",
        clean.get("level") == "informational" and clean.get("score", 99) < 20,
        clean,
    )
    check(
        "clean asset has no contributions",
        clean.get("contributions") == [],
        clean.get("contributions"),
    )
    check(
        "score, level and confidence are separate",
        clean.get("confidence") in ("low", "medium", "high"),
    )
    r = call("POST", "/telemetry", sample(agent_id), h)
    check("telemetry accepted", r.status in (200, 201), r.status)
    after_hb = risk()
    check("telemetry leaves risk unchanged", not after_hb.get("pending_recalculation"), after_hb)

    # 2. Detección alta (DEF-001): el riesgo sube y la contribución enlaza a la detección.
    r = send([event(9501, event_code=1102, level="critical", message="QA risk log cleared",
                    data={"SubjectUserName": "qa-user"}, **security)])  # fmt: skip
    check("risk events accepted", r.status == 201, (r.status, r.body))
    wait_for(detections, lambda found: "DEF-001" in found)
    high = wait_for(
        risk, lambda body: settled()(body) and body.get("score", 0) > clean.get("score", 0)
    )
    check("high detection raises the score", high.get("score", 0) >= 40, high)
    contrib = {c["rule_id"]: c for c in high.get("contributions", []) if c.get("rule_id")}
    check(
        "contribution points to the detection",
        "DEF-001" in contrib
        and contrib["DEF-001"]["detection_id"] == detections()["DEF-001"]["detection_id"],
        contrib,
    )
    check(
        "why is explained",
        bool(high.get("explanation", {}).get("reasons")),
        high.get("explanation"),
    )

    # 3. Correlación (CORR-001): sube más, sin contar dos veces la ráfaga que la compone.
    user = {"TargetUserName": "qa-risk", "TargetUserSid": "S-1-5-21-90-91-92-1501"}
    failures = [
        event(9600 + i, event_code=4625, level="warning", message="QA risk logon failure",
              occurred_at=now_iso(timedelta(minutes=-3, seconds=i)),
              data={**user, "IpAddress": "10.67.0.9", "LogonType": "3"}, **security)
        for i in range(6)
    ]  # fmt: skip
    success = event(9700, event_code=4624, level="info", message="QA risk logon",
                    occurred_at=now_iso(timedelta(minutes=-1)),
                    data={**user, "LogonType": "10", "IpAddress": "10.67.0.9"},
                    **security)  # fmt: skip
    send([*failures, success])
    wait_for(detections, lambda found: "CORR-001" in found)
    corr = wait_for(
        risk, lambda body: settled()(body) and body.get("score", 0) > high.get("score", 0)
    )
    check("correlation raises the score further", corr.get("score", 0) > high.get("score", 0), corr)
    by_rule = {c["rule_id"]: c for c in corr.get("contributions", []) if c.get("rule_id")}
    absorbed = by_rule.get("AUTH-001", {})
    check(
        "burst absorbed by the correlation (no double count)",
        absorbed.get("points") == 0
        and absorbed.get("details", {}).get("absorbed_by", {}).get("rule_id") == "CORR-001",
        absorbed,
    )
    total = sum(c["points"] for c in corr.get("contributions", []))
    check(
        "contributions add up to the score",
        abs(total - corr.get("score", -1)) <= 1,
        (total, corr.get("score")),
    )

    # 4. Criticidad: solo admin, auditada, y recalcula al momento.
    name = "qa-risk-viewer-" + uuid.uuid4().hex[:6]
    password = "qa viewer password " + uuid.uuid4().hex[:8]
    created = call("POST", "/users", {"username": name, "password": password, "role": "viewer"})
    _, viewer = login(name, password)
    check("viewer reads risk overview", call("GET", "/risk/overview", session=viewer).status == 200)
    r = call(
        "PATCH", f"/assets/{asset_id}/criticality", {"criticality": "critical"}, session=viewer
    )
    check(
        "viewer cannot change criticality -> 403",
        r.status == 403 and is_error_envelope(r, "permission_denied"),
        r.status,
    )
    r = call("PATCH", f"/assets/{asset_id}/criticality", {"criticality": "extreme"})
    check("invalid criticality -> 422", r.status == 422, r.status)
    r = call("PATCH", f"/assets/{uuid.uuid4()}/criticality", {"criticality": "high"})
    check("criticality of unknown asset -> 404", r.status == 404, r.status)
    r = call("PATCH", f"/assets/{asset_id}/criticality", {"criticality": "critical"})
    check(
        "admin raises criticality and gets the recalculated risk",
        r.status == 200
        and r.body["criticality"] == "critical"
        and r.body["score"] > corr.get("score", 0),
        (r.status, r.body if r.status != 200 else r.body["score"]),
    )
    peak = r.body if r.status == 200 else {}
    audit = call("GET", "/audit?action=asset_criticality_changed&limit=20").body["items"]
    check("criticality change audited", any(a["target_id"] == asset_id for a in audit), audit[:2])
    if peak.get("level") == "critical":
        alerts = call("GET", f"/alerts?asset_id={asset_id}&rule=risk_critical&active=true").body[
            "items"
        ]
        check("crossing into critical opens one risk_critical alert", len(alerts) == 1, alerts)

    # 5. Resolver: baja (memoria con decaimiento, no cero) y la alerta de riesgo se cierra.
    for rule_id, detection in detections().items():
        r = call(
            "POST",
            f"/detections/{detection['detection_id']}/resolve",
            {"note": f"QA risk {rule_id}"},
        )
        check(f"resolve {rule_id}", r.status == 200, (r.status, r.body))
    calm = wait_for(
        risk, lambda body: settled()(body) and body.get("score", 101) < peak.get("score", 0)
    )
    check("resolving lowers the score", calm.get("score", 101) < peak.get("score", 0), calm)
    check(
        "resolved detections keep a decaying memory",
        any(
            c.get("details", {}).get("status") == "resolved" and c["points"] > 0
            for c in calm.get("contributions", [])
        ),
        calm.get("contributions"),
    )
    if peak.get("level") == "critical" and calm.get("level") != "critical":
        alerts = call("GET", f"/alerts?asset_id={asset_id}&rule=risk_critical&active=true").body[
            "items"
        ]
        check("leaving critical resolves the risk alert", alerts == [], alerts)

    # 6. Historial, contribuciones por punto y resumen.
    history = call("GET", f"/risk/assets/{asset_id}/history?range=24h").body
    transitions = {p.get("transition") for p in history.get("points", [])}
    check("history keeps the way up and down", {"up", "down"} <= transitions, history.get("points"))
    first = history["points"][0]["snapshot_id"] if history.get("points") else None
    r = call("GET", f"/risk/assets/{asset_id}/contributions?snapshot_id={first}")
    check(
        "contributions of a past snapshot",
        r.status == 200 and r.body["snapshot_id"] == first,
        r.status,
    )
    r = call("GET", "/risk/assets?sort=score&order=desc&limit=5")
    scores = [item["score"] for item in r.body.get("items", []) if item["score"] is not None]
    check(
        "risk list sorted by score desc",
        r.status == 200 and scores == sorted(scores, reverse=True),
        scores,
    )
    r = call("GET", "/risk/assets?level=extreme")
    check("invalid risk filter -> 422", r.status == 422, r.status)
    if isinstance(created.body, dict) and created.body.get("user_id"):
        call("PATCH", f"/users/{created.body['user_id']}", {"is_active": False})


def test_ai() -> None:
    """Fase 4J: AI Security Insights sobre HTTP real (sin depender de un modelo).

    Con la IA desactivada (por defecto en QA) comprueba que Sentra responde con un error
    controlado y que nada más cambia. Si la instancia QA tiene un modelo configurado, pide
    además un análisis real y valida que las referencias sean datos de Sentra.
    """
    r = call("GET", "/ai/status")
    check("ai status readable", r.status == 200 and "available" in r.body, (r.status, r.body))
    status = r.body if isinstance(r.body, dict) else {}
    check("ai status never exposes key or url", "api_key" not in json.dumps(status).lower()
          and "base_url" not in json.dumps(status).lower(), status)  # fmt: skip
    # Fase 4J.1: estado del proveedor legible (local/externo y disponible/caído/bloqueado).
    check("ai status reports provider state", status.get("state") in {
        "disabled", "not_configured", "local_available", "local_unavailable",
        "external_blocked", "external_available", "external_unavailable"}, status)  # fmt: skip
    r = call("POST", "/ai/ask", {"question": "¿Qué pasa?"}, session={})
    check("ai ask without session -> 401", r.status == 401, r.status)
    r = call("POST", "/ai/ask", {"question": "¿Qué pasa?", "model": "x", "base_url": "http://x"})
    check("client cannot choose model or url -> 422", r.status == 422, (r.status, r.body))
    _, _, asset_id = enroll("qa-ai")
    r = call("POST", f"/ai/assets/{asset_id}/analyze", {})
    if not status.get("available"):
        check(
            "ai disabled -> 409 ai_not_configured",
            r.status == 409 and is_error_envelope(r, "ai_not_configured"),
            (r.status, r.body),
        )
    else:
        check("ai asset analysis", r.status == 200, (r.status, r.body))
        refs = r.body.get("result", {}).get("evidence_refs", []) if r.status == 200 else []
        check("ai evidence refs are Sentra ids", all(ref.get("id") for ref in refs), refs)
    check("dashboard unaffected by ai", call("GET", f"/risk/assets/{asset_id}").status == 200)


def test_incidents() -> None:
    """Fase 4K: flujo SOC completo, sugerencia de relacionados y concurrencia (409).

    Necesita el job del motor de detección con intervalo corto
    (DETECTION_EVAL_INTERVAL_SECONDS=2). Crea un analyst y un viewer temporales.
    """
    security = {"channel": "Security", "provider": "Microsoft-Windows-Security-Auditing"}
    users: dict[str, dict[str, str]] = {}
    for role in ("analyst", "viewer"):
        name = f"qa-{role}-" + uuid.uuid4().hex[:6]
        password = f"qa {role} password " + uuid.uuid4().hex[:8]
        r = call("POST", "/users", {"username": name, "password": password, "role": role})
        check(f"admin creates an incident {role}", r.status == 201, (r.status, r.body))
        users[role] = login(name, password)[1]
    analyst, viewer = users["analyst"], users["viewer"]

    def detection_on(hostname: str, record: int) -> tuple[str, str, str]:
        agent_id, token, asset_id = enroll(hostname)
        call("POST", "/events", {"agent_id": agent_id, "events": [
            event(record, event_code=1102, level="critical", message="QA log cleared",
                  data={"SubjectUserName": "qa-user"}, **security)]}, bearer(token))  # fmt: skip
        found = wait_for(
            lambda: call("GET", f"/detections?asset_id={asset_id}&rule_id=DEF-001").body,
            lambda body: isinstance(body, dict) and body.get("total", 0) > 0,
        )
        items = found.get("items", []) if isinstance(found, dict) else []
        return agent_id, token, (items[0]["detection_id"] if items else "")

    # 1. Detección -> incidente -> triage -> investigación -> contención -> resuelto -> cerrado.
    _, _, detection_id = detection_on("qa-incident-flow", 9301)
    check("incident flow: detection available", bool(detection_id))
    if not detection_id:
        return
    r = call("POST", f"/detections/{detection_id}/incident", {}, session=analyst)
    check("analyst promotes detection -> 201", r.status == 201, (r.status, r.body))
    incident = r.body if r.status == 201 else {}
    iid = incident.get("incident_id", "")
    check("incident number INC-xxxxxx", str(incident.get("key", "")).startswith("INC-"), incident)
    r = call("POST", f"/detections/{detection_id}/incident", {}, session=analyst)
    check("promote twice -> 409 already linked", r.status == 409
          and is_error_envelope(r, "incident_already_linked"), (r.status, r.body))  # fmt: skip
    r = call("PATCH", f"/incidents/{iid}", {"version": incident.get("version", 1),
             "status": "triage"}, session=viewer)  # fmt: skip
    check("viewer cannot change incidents -> 403", r.status == 403, r.status)
    r = call("GET", f"/incidents/{iid}", session=viewer)
    check("viewer reads the incident", r.status == 200, r.status)

    def step(method: str, path: str, payload: dict[str, Any], name: str) -> None:
        nonlocal incident
        body = {"version": incident.get("version", 1), **payload}
        res = call(method, path, body, session=analyst)
        check(name, res.status == 200, (res.status, res.body))
        if res.status == 200:
            incident = res.body

    step("PATCH", f"/incidents/{iid}", {"status": "triage"}, "analyst moves to triage")
    step("POST", f"/incidents/{iid}/assign", {}, "analyst assigns self")
    note = {"body": "<script>QA</script> nota"}
    r = call("POST", f"/incidents/{iid}/notes", note, session=analyst)
    check("analyst adds a note -> 201", r.status == 201, (r.status, r.body))
    step("PATCH", f"/incidents/{iid}", {"status": "investigating"}, "analyst investigates")
    step("PATCH", f"/incidents/{iid}", {"status": "contained"}, "analyst contains")
    r = call("POST", f"/incidents/{iid}/resolve", {"version": incident.get("version", 1)},
             session=analyst)  # fmt: skip
    check("resolve without category -> 422", r.status == 422, r.status)
    step("POST", f"/incidents/{iid}/resolve", {"category": "true_positive"}, "analyst resolves")
    r = call("POST", f"/incidents/{iid}/close", {"version": incident.get("version", 1)},
             session=analyst)  # fmt: skip
    check("analyst cannot close -> 403", r.status == 403, r.status)
    r = call("POST", f"/incidents/{iid}/close", {"version": incident.get("version", 1)})
    check("admin closes", r.status == 200 and r.body["status"] == "closed", (r.status, r.body))
    r = call("POST", f"/incidents/{iid}/notes", {"body": "tarde"}, session=analyst)
    check("closed incident is frozen -> 409", r.status == 409, (r.status, r.body))
    audit = call("GET", f"/incidents/{iid}/audit?limit=50").body.get("items", [])
    actions = {a["action"] for a in audit if a["result"] == "success"}
    expected = {"incident_created", "incident_status_changed", "incident_assigned",
                "incident_note_added", "incident_resolved", "incident_closed"}  # fmt: skip
    check("incident audit trail complete", expected <= actions, sorted(actions))
    timeline = call("GET", f"/incidents/{iid}/timeline?limit=200").body.get("items", [])
    sources = {item["source_type"] for item in timeline}
    check("timeline unifies case, note and detection", {"incident", "note", "detection"} <= sources,
          sorted(sources))  # fmt: skip
    check("note text stays plain text", any(i["summary"] == "<script>QA</script> nota"
          for i in timeline), [i["summary"] for i in timeline][:5])  # fmt: skip

    # 2. Detección relacionada: se sugiere el incidente abierto y se adjunta sin duplicar.
    agent_id, token, first = detection_on("qa-incident-related", 9401)
    r = call("POST", f"/detections/{first}/incident", {}, session=analyst)
    check("related: first incident created", r.status == 201, (r.status, r.body))
    open_id = r.body.get("incident_id", "") if r.status == 201 else ""
    user = {"TargetUserName": "qa-related", "TargetUserSid": "S-1-5-21-90-91-92-2002"}
    call("POST", "/events", {"agent_id": agent_id, "events": [
        event(9500 + i, event_code=4625, level="warning", message="QA logon failure",
              occurred_at=now_iso(timedelta(minutes=-2, seconds=i)),
              data={**user, "IpAddress": "10.66.0.19", "LogonType": "3"}, **security)
        for i in range(6)]}, bearer(token))  # fmt: skip
    found = wait_for(
        lambda: call("GET", "/detections?rule_id=AUTH-001&active=true&q=qa-incident-related").body,
        lambda body: isinstance(body, dict) and body.get("total", 0) > 0,
    )
    items = found.get("items") if isinstance(found, dict) else None
    burst = (items or [{}])[0].get("detection_id", "")
    check("related: second detection on the same asset", bool(burst), found)
    if burst and open_id:
        related = call("GET", f"/detections/{burst}/related-incidents", session=analyst).body
        ids = [item["incident"]["incident_id"] for item in related.get("items", [])]
        check("open incident suggested as related", open_id in ids, related)
        r = call("POST", f"/incidents/{open_id}/detections/{burst}", session=analyst)
        check("analyst attaches the related detection", r.status == 200
              and r.body["detections_total"] == 2, (r.status, r.body))  # fmt: skip
        listed = call("GET", "/incidents?q=qa-incident-related&limit=50").body
        check("no duplicate incident created", listed.get("total") == 1, listed)

    # 3. Dos sesiones a la vez sobre la misma versión: una gana, la otra recibe 409.
    if open_id:
        current = call("GET", f"/incidents/{open_id}").body
        version = current.get("version", 1)
        a = call("PATCH", f"/incidents/{open_id}", {"version": version, "priority": "critical"})
        b = call("PATCH", f"/incidents/{open_id}", {"version": version, "priority": "low"},
                 session=analyst)  # fmt: skip
        check("first writer wins", a.status == 200, (a.status, a.body))
        check("second writer -> 409 incident_conflict", b.status == 409
              and is_error_envelope(b, "incident_conflict"), (b.status, b.body))  # fmt: skip
        details = (b.body.get("error", {}).get("details") or [{}])[0] if b.status == 409 else {}
        check("conflict reports the current version", details.get("current_version") == version + 1,
              details)  # fmt: skip
        after = call("GET", f"/incidents/{open_id}").body
        check("no silent overwrite", after.get("priority") == "critical", after.get("priority"))


def test_auth() -> None:
    """Fase 4G: login, sesión, CSRF, permisos y separación de credenciales sobre HTTP real."""
    for path in ("/assets", "/alerts", "/events", "/agents", "/discovery/jobs", "/users"):
        r = call("GET", path, session={})
        check(
            f"GET {path} without session -> 401",
            r.status == 401 and is_error_envelope(r, "not_authenticated"),
            r.status,
        )
    r = call("GET", "/health", session={})
    check("health stays public", r.status in (200, 503), r.status)
    wrong, _ = login(ADMIN_USER, ADMIN_PASSWORD + "-wrong")
    unknown, _ = login("qa-nobody-" + uuid.uuid4().hex[:6], ADMIN_PASSWORD)
    check(
        "login errors are identical (no user enumeration)",
        wrong.status == unknown.status == 401 and wrong.body == unknown.body,
        (wrong.body, unknown.body),
    )
    r = call("GET", "/auth/me")
    check("auth/me with session", r.status == 200 and r.body["user"]["role"] == "admin", r.body)
    cookie = SESSION.get("Cookie", "")
    check("session id not in /auth/me body", cookie.split("=", 1)[-1] not in json.dumps(r.body))
    no_csrf = {"Cookie": cookie}
    r = call("POST", "/console/enrollment-tokens", {}, session=no_csrf)
    check("mutation without CSRF -> 403", r.status == 403 and is_error_envelope(r, "csrf_failed"))
    r = call("POST", "/console/enrollment-tokens", {}, headers={"Origin": "http://evil.example"})
    check("mutation from foreign Origin -> 403", r.status == 403, (r.status, r.body))
    # Viewer temporal: puede leer, no puede mutar.
    name = "qa-viewer-" + uuid.uuid4().hex[:6]
    password = "qa viewer password " + uuid.uuid4().hex[:8]
    r = call("POST", "/users", {"username": name, "password": password, "role": "viewer"})
    check("admin creates a viewer", r.status == 201, (r.status, r.body))
    user_id = r.body.get("user_id") if isinstance(r.body, dict) else None
    _, viewer = login(name, password)
    check("viewer reads assets", call("GET", "/assets", session=viewer).status == 200)
    for method, path, body in (
        ("POST", "/console/enrollment-tokens", {}),
        ("POST", "/console/discovery/jobs", {"target": "0.0.0.0/0"}),
        ("POST", f"/alerts/{uuid.uuid4()}/resolve", None),
        ("POST", f"/detections/{uuid.uuid4()}/resolve", None),
        ("GET", "/users", None),
    ):
        r = call(method, path, body, session=viewer)
        check(
            f"viewer {method} {path.split('/')[1]} -> 403",
            r.status == 403 and is_error_envelope(r, "permission_denied"),
            (r.status, r.body),
        )
    if user_id:
        r = call("PATCH", f"/users/{user_id}", {"is_active": False})
        check("admin disables the viewer", r.status == 200, (r.status, r.body))
        r = call("GET", "/assets", session=viewer)
        check("disabled user's session is cut at once -> 401", r.status == 401, r.status)
    r = call("GET", "/assets", headers={"X-Admin-Key": "x" * 30}, session={})
    check("admin key never opens the dashboard -> 401", r.status == 401, r.status)
    # Logout con una sesión propia para no cerrar la del resto del script.
    _, own = login(ADMIN_USER, ADMIN_PASSWORD)
    r = call("POST", "/auth/logout", session=own)
    check("logout -> 204", r.status == 204, (r.status, r.body))
    r = call("GET", "/auth/me", session=own)
    check("session after logout -> 401", r.status == 401, r.status)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="also wait for the offline sweeper")
    args = parser.parse_args()
    if not KEY:
        print("SENTRA_QA_ENROLLMENT_KEY is required", file=sys.stderr)
        return 2
    if not ADMIN_USER or not ADMIN_PASSWORD:
        print("SENTRA_QA_ADMIN_USER and SENTRA_QA_ADMIN_PASSWORD are required", file=sys.stderr)
        return 2
    r, admin = login(ADMIN_USER, ADMIN_PASSWORD)
    if not admin:
        print(f"admin login failed: {r.status} {r.body}", file=sys.stderr)
        return 2
    SESSION.update(admin)
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
        test_hybrid_read,
        test_enrollment_tokens,
        test_detections,
        test_risk,
        test_ai,
        test_incidents,
        test_auth,
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
