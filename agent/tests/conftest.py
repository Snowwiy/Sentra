"""A small in-process HTTP server that follows the Sentra agent protocol.

It lets the agent tests exercise real HTTP, JSON and error handling without a database.
Backend behavior itself is covered by the backend test suite.
"""

import json
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from sentra_agent.client import SentraClient
from sentra_agent.config import AgentConfig
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
            elif path == "/agents/heartbeat":
                self._send(200, {"asset_id": state.agents[agent_id], "status": "online"})
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
        return AgentConfig(api_url=api_url, state_dir=tmp_path / "state", **overrides).validate()

    return factory


def make_client(config: AgentConfig) -> SentraClient:
    return SentraClient(config.api_url, timeout=2)


def make_store(config: AgentConfig) -> IdentityStore:
    return IdentityStore(config.state_dir)
