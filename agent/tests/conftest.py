"""A small in-process HTTP server that follows the Sentra agent protocol.

It lets the agent tests exercise real HTTP, JSON and error handling without a database.
Backend behavior itself is covered by the backend test suite.
"""

import gzip
import json
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from sentra_agent import credentials, runner, wifi
from sentra_agent.client import SentraClient
from sentra_agent.config import AgentConfig, IsolationSettings
from sentra_agent.credentials import CredentialStoreUnavailableError
from sentra_agent.identity import IdentityStore

ENROLLMENT_KEY = "test-enrollment-key-0123456789"


@dataclass
class FakeApiState:
    agents: dict[str, str] = field(default_factory=dict)  # agent_id -> asset_id
    tokens: dict[str, str] = field(default_factory=dict)  # agent_id -> current token
    requests: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    telemetry: list[dict[str, Any]] = field(default_factory=list)
    inventory: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    unavailable: bool = False
    # Agents an operator revoked: their tokens are gone and enrollment answers 403.
    revoked: set[str] = field(default_factory=set)
    # Inventory sections this fake server does not know (simulates an older backend).
    unknown_sections: set[str] = field(default_factory=set)
    # Item fields it does not know, as (list name, field), e.g. ("events", "computer").
    unknown_item_fields: set[tuple[str, str]] = field(default_factory=set)
    processes: list[dict[str, Any]] = field(default_factory=list)
    # False simulates a backend without the /processes endpoint (404).
    processes_endpoint: bool = True
    # When set, every request is throttled with 429 and this Retry-After value.
    throttle_retry_after: str | None = None
    headers: list[dict[str, str]] = field(default_factory=list)
    # Bodies larger than this get 413, like the real API's 4 MiB limit.
    max_body: int = 4 * 1024 * 1024
    # One-time enrollment tokens the server accepts; each is removed when used.
    enrollment_tokens: set[str] = field(default_factory=set)
    # When True the server stores telemetry but the connection drops before the response.
    lose_next_response: bool = False
    # Campos de host que este servidor no conoce (simula un backend anterior a la Fase 4F):
    # register y heartbeat responden 422 extra_forbidden si llegan.
    unknown_host_fields: set[str] = field(default_factory=set)
    # Fase 5C.1: coberturas recibidas en /events; False simula un servidor anterior que
    # rechaza el campo `coverage` (422 extra_forbidden).
    coverage: list[dict[str, str]] = field(default_factory=list)
    accepts_coverage: bool = True
    # Agentes cuyo activo está archivado: el registro responde 403 asset_archived.
    archived: set[str] = field(default_factory=set)
    # Fase 5D: comandos de Response en cola por agent_id (el heartbeat avisa del número),
    # resultados recibidos por request_id y False para simular un servidor anterior (404).
    commands: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    command_results: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    commands_endpoint: bool = True
    # Fase 6E: POST /agents/activity (False = servidor anterior, 404), lotes recibidos,
    # event_uid ya vistos (deduplicación como el servidor real) y campos de primer nivel del
    # heartbeat que este servidor no conoce (422 extra_forbidden, como un backend 0.2.0).
    activity_endpoint: bool = True
    activity: list[dict[str, Any]] = field(default_factory=list)
    activity_uids: set[str] = field(default_factory=set)
    unknown_heartbeat_fields: set[str] = field(default_factory=set)
    max_activity_body: int | None = None

    def paths(self) -> list[str]:
        return [path for path, _ in self.requests]


def _make_handler(state: FakeApiState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:
            pass

        def _send(
            self, status: int, body: dict[str, Any], headers: dict[str, str] | None = None
        ) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            if self.headers.get("Content-Encoding") == "gzip":
                # Como el servidor real: descompresión acotada a max_request_bytes.
                raw = gzip.decompress(raw)
                if len(raw) > state.max_body:
                    state.requests.append((self.path.removeprefix("/api/v1"), {}))
                    self._send(413, {"error": {"code": "payload_too_large", "message": "big"}})
                    return
            if length > state.max_body:
                state.requests.append((self.path.removeprefix("/api/v1"), {}))
                self._send(413, {"error": {"code": "payload_too_large", "message": "big"}})
                return
            body = json.loads(raw or b"{}")
            path = self.path.removeprefix("/api/v1")
            state.requests.append((path, body))
            state.headers.append(dict(self.headers.items()))
            if state.throttle_retry_after is not None:
                self._send(
                    429,
                    {"error": {"code": "rate_limited", "message": "slow down"}},
                    {"Retry-After": state.throttle_retry_after},
                )
                return
            if state.unavailable:
                self._send(503, {"error": {"code": "unavailable", "message": "down"}})
                return

            agent_id = body.get("agent_id", "")
            if self._reject_unknown_host_fields(path, body):
                return
            if path == "/agents/register":
                one_time = self.headers.get("X-Enrollment-Token")
                if one_time is not None:
                    if one_time not in state.enrollment_tokens:
                        self._send(401, {"error": {"code": "unauthorized", "message": "bad"}})
                        return
                    state.enrollment_tokens.discard(one_time)  # single use, like the server
                elif self.headers.get("X-Enrollment-Key") != ENROLLMENT_KEY:
                    self._send(401, {"error": {"code": "unauthorized", "message": "bad key"}})
                    return
                if agent_id in state.revoked:
                    self._send(403, {"error": {"code": "agent_revoked", "message": "revoked"}})
                    return
                if agent_id in state.archived:
                    self._send(403, {"error": {"code": "asset_archived", "message": "archived"}})
                    return
                created = agent_id not in state.agents
                state.agents.setdefault(agent_id, str(uuid.uuid4()))
                state.tokens[agent_id] = uuid.uuid4().hex  # rotate on every enrollment
                self._send(
                    201 if created else 200,
                    {
                        "asset_id": state.agents[agent_id],
                        "agent_id": agent_id,
                        "agent_token": state.tokens[agent_id],
                    },
                )
            elif (
                agent_id not in state.tokens
                or self.headers.get("Authorization") != f"Bearer {state.tokens[agent_id]}"
            ):
                self._send(401, {"error": {"code": "unauthorized", "message": "bad token"}})
            elif path == "/agents/heartbeat" and self._reject_unknown_heartbeat_fields(body):
                return
            elif path == "/agents/activity":
                self._activity(body, len(raw))
            elif path == "/agents/heartbeat":
                response: dict[str, Any] = {"asset_id": state.agents[agent_id], "status": "online"}
                if state.commands.get(agent_id):
                    response["pending_commands"] = len(state.commands.get(agent_id, []))
                self._send(200, response)
            elif path == "/agents/commands/poll" and state.commands_endpoint:
                limit = body.get("max_commands", 5)
                queue = state.commands.get(agent_id, [])
                delivered, state.commands[agent_id] = queue[:limit], queue[limit:]
                self._send(200, {"commands": delivered})
            elif (
                path.startswith("/agents/commands/")
                and path.endswith("/result")
                and state.commands_endpoint
            ):
                request_id = path.split("/")[3]
                state.command_results.append((request_id, body))
                self._send(200, {"accepted": True, "duplicate": False, "status": body["status"]})
            elif self._reject_unknown_item_fields(body):
                return
            elif path == "/events":
                if "coverage" in body and not state.accepts_coverage:
                    details = [
                        {"loc": ["body", "coverage"], "msg": "Extra", "type": "extra_forbidden"}
                    ]
                    error = {"code": "validation_error", "message": "bad", "details": details}
                    self._send(422, {"error": error})
                    return
                if not body["events"] and not body.get("coverage"):
                    # Como el servidor real: un lote necesita eventos o cobertura.
                    self._send(422, {"error": {"code": "validation_error", "message": "empty"}})
                    return
                if len(body["events"]) > 500:
                    self._send(422, {"error": {"code": "validation_error", "message": "big"}})
                    return
                if body.get("coverage"):
                    state.coverage.append(body["coverage"])
                state.events.extend(body["events"])
                self._send(201, {"asset_id": state.agents[agent_id]})
            elif path == "/processes" and state.processes_endpoint:
                state.processes.append(body)
                self._send(201, {"asset_id": state.agents[agent_id], "stored": True})
            elif path == "/inventory":
                extra = sorted(state.unknown_sections & set(body))
                if extra:
                    details = [
                        {"loc": ["body", name], "msg": "Extra inputs", "type": "extra_forbidden"}
                        for name in extra
                    ]
                    error = {"code": "validation_error", "message": "bad", "details": details}
                    self._send(422, {"error": error})
                    return
                state.inventory.append(body)
                self._send(201, {"asset_id": state.agents[agent_id]})
            elif path == "/telemetry":
                if body.get("cpu_percent", 0) > 100:
                    self._send(422, {"error": {"code": "validation_error", "message": "bad"}})
                    return
                sample_id = body.get("sample_id")
                stored = sample_id is None or all(
                    t.get("sample_id") != sample_id for t in state.telemetry
                )
                if stored:
                    state.telemetry.append(body)
                if state.lose_next_response:
                    state.lose_next_response = False
                    self.close_connection = True
                    self.connection.close()  # stored, but the agent never hears back
                    return
                self._send(201, {"asset_id": state.agents[agent_id], "stored": stored})
            else:
                self._send(404, {"error": {"code": "http_error", "message": "Not Found"}})

        def _reject_unknown_heartbeat_fields(self, body: dict[str, Any]) -> bool:
            details = [
                {"loc": ["body", name], "msg": "Extra inputs", "type": "extra_forbidden"}
                for name in sorted(state.unknown_heartbeat_fields & set(body))
            ]
            if details:
                error = {"code": "validation_error", "message": "bad", "details": details}
                self._send(422, {"error": error})
            return bool(details)

        def _activity(self, body: dict[str, Any], size: int) -> None:
            if not state.activity_endpoint:
                self._send(404, {"error": {"code": "http_error", "message": "Not Found"}})
                return
            if state.max_activity_body is not None and size > state.max_activity_body:
                self._send(413, {"error": {"code": "payload_too_large", "message": "big"}})
                return
            events = body.get("events")
            if not isinstance(events, list) or not 1 <= len(events) <= 1000:
                self._send(422, {"error": {"code": "validation_error", "message": "events"}})
                return
            state.activity.append(body)
            accepted = duplicates = 0
            for event in events:
                uid = event.get("event_uid")
                if uid in state.activity_uids:
                    duplicates += 1
                else:
                    state.activity_uids.add(uid)
                    accepted += 1
            asset = state.agents[body["agent_id"]]
            self._send(
                200,
                {"asset_id": asset, "accepted": accepted, "duplicates": duplicates, "rejected": []},
            )

        def _reject_unknown_host_fields(self, path: str, body: dict[str, Any]) -> bool:
            if path == "/agents/register":
                host, prefix = body, ["body"]
            elif path == "/agents/heartbeat" and isinstance(body.get("host"), dict):
                host, prefix = body["host"], ["body", "host"]
            else:
                return False
            details = [
                {"loc": [*prefix, name], "msg": "Extra inputs", "type": "extra_forbidden"}
                for name in sorted(state.unknown_host_fields & set(host))
            ]
            if details:
                error = {"code": "validation_error", "message": "bad", "details": details}
                self._send(422, {"error": error})
            return bool(details)

        def _reject_unknown_item_fields(self, body: dict[str, Any]) -> bool:
            details = [
                {"loc": ["body", section, index, name], "msg": "Extra", "type": "extra_forbidden"}
                for section, name in sorted(state.unknown_item_fields)
                for index, item in enumerate(body.get(section) or [])
                if isinstance(item, dict) and name in item
            ]
            if details:
                error = {"code": "validation_error", "message": "bad", "details": details}
                self._send(422, {"error": error})
            return bool(details)

    return Handler


@pytest.fixture
def fake_api() -> Iterator[tuple[str, FakeApiState]]:
    state = FakeApiState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", state
    server.shutdown()
    server.server_close()


@pytest.fixture
def make_config(tmp_path: Path) -> Any:
    def factory(api_url: str, **overrides: Any) -> AgentConfig:
        overrides.setdefault("enrollment_key", ENROLLMENT_KEY)
        # Fase 6E: nunca las rutas reales del helper de aislamiento del equipo de pruebas.
        overrides.setdefault(
            "isolation",
            IsolationSettings(
                exchange_dir=tmp_path / "isolation", policy_file=tmp_path / "isolation.toml"
            ),
        )
        return AgentConfig(api_url=api_url, state_dir=tmp_path / "state", **overrides).validate()

    return factory


def make_client(config: AgentConfig) -> SentraClient:
    return SentraClient(config.api_url, timeout=2)


def make_store(config: AgentConfig) -> IdentityStore:
    return IdentityStore(config.state_dir)


class FakeKeychain:
    """Keychain en memoria (Fase 6C.5): los tests nunca tocan el Keychain real del equipo.

    También en macOS (CI): sin esto, cada IdentityStore escribiría en el keychain de login
    del usuario del runner.
    """

    def __init__(self) -> None:
        self.items: dict[str, str] = {}
        self.available = True
        self.calls: list[tuple[str, str]] = []

    def check(self) -> None:
        if not self.available:
            raise CredentialStoreUnavailableError("Keychain locked or not writable (test)")

    def get(self, account: str) -> str | None:
        self.check()
        self.calls.append(("get", account))
        return self.items.get(account)

    def set(self, account: str, secret: str) -> None:
        self.check()
        self.calls.append(("set", account))
        self.items[account] = secret

    def delete(self, account: str) -> None:
        self.check()
        self.calls.append(("delete", account))
        self.items.pop(account, None)


@pytest.fixture(autouse=True)
def fake_keychain(monkeypatch: pytest.MonkeyPatch) -> FakeKeychain:
    keychain = FakeKeychain()
    monkeypatch.setattr(credentials, "keychain_factory", lambda: keychain)
    return keychain


@pytest.fixture(autouse=True)
def _no_host_wireless(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """El agente de los tests no lee el Wi-Fi real del equipo (Fase 6C.5).

    Los resultados no deben depender de si el equipo de pruebas tiene nmcli, netsh o un
    adaptador; los tests del colector lo prueban con fixtures (marca `host_wireless`).
    """
    if request.node.get_closest_marker("host_wireless") is None:
        monkeypatch.setattr(wifi, "collect_wireless", lambda platform=None: None)


@pytest.fixture(autouse=True)
def _no_host_telemetry(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fase 6E: el agente de los tests no sondea los procesos ni servicios reales.

    Los tests de telemetría inyectan un TelemetryService con fuentes simuladas; los que
    quieran la real usan la marca `host_telemetry`.
    """
    if request.node.get_closest_marker("host_telemetry") is None:
        monkeypatch.setattr(runner, "default_telemetry", lambda config: None)
