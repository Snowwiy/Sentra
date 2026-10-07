"""Minimal JSON client for the Sentra API using only the standard library."""

import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from uuid import UUID

from sentra_agent import __version__

# Statuses that describe a temporary condition on the server side: retry with backoff like a
# network failure instead of treating the request as permanently rejected.
#   408 request timeout, 409 concurrent first registration, 425/429 throttling.
_RETRYABLE_4XX = {408, 409, 425, 429}
# Upper bound for Retry-After so a misbehaving proxy cannot park the agent for days.
_MAX_RETRY_AFTER = 3600.0


class TransportError(Exception):
    """The API could not be reached (network down, DNS, timeout, 5xx). Worth retrying."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ApiError(Exception):
    """The API answered with a client error (4xx). Retrying the same request will not help."""

    def __init__(self, status: int, body: dict[str, Any]) -> None:
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body

    @property
    def code(self) -> str | None:
        """Machine-readable error code from the API's `{"error": {"code": ...}}` envelope."""
        error = self.body.get("error")
        return error.get("code") if isinstance(error, dict) else None


class SentraClient:
    def __init__(self, api_url: str, timeout: float) -> None:
        self._base = api_url.rstrip("/") + "/api/v1"
        self._timeout = timeout

    def _post(
        self, path: str, payload: dict[str, Any], extra_headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"sentra-agent/{__version__}",
        }
        headers.update(extra_headers or {})
        request = urllib.request.Request(  # noqa: S310  (scheme validated in AgentConfig)
            self._base + path,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        try:
            # The timeout covers connect and each socket read, so a hung server can never
            # block the agent loop indefinitely.
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                body: dict[str, Any] = json.loads(response.read() or b"{}")
                return body
        except urllib.error.HTTPError as error:
            body = _read_error_body(error)
            # 5xx means the server (or its database) is unhealthy: retry like a network error.
            if error.code >= 500 or error.code in _RETRYABLE_4XX:
                raise TransportError(
                    f"HTTP {error.code}: {body}", _retry_after(error.headers.get("Retry-After"))
                ) from error
            raise ApiError(error.code, body) from error
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError) as error:
            # ValueError: a proxy or captive portal answered 2xx with a non-JSON body.
            raise TransportError(str(error)) from error

    def register(
        self,
        agent_id: UUID,
        host: dict[str, Any],
        enrollment_key: str | None = None,
        *,
        enrollment_token: str | None = None,
    ) -> dict[str, Any]:
        # The one-time token, when present, is the credential; the shared key is legacy.
        headers = (
            {"X-Enrollment-Token": enrollment_token}
            if enrollment_token
            else {"X-Enrollment-Key": enrollment_key or ""}
        )
        return self._post("/agents/register", {"agent_id": str(agent_id), **host}, headers)

    def heartbeat(
        self, agent_id: UUID, token: str, host: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"agent_id": str(agent_id)}
        if host is not None:
            body["host"] = host
        return self._post("/agents/heartbeat", body, _bearer(token))

    def send_inventory(
        self, agent_id: UUID, token: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]:
        return self._post("/inventory", {"agent_id": str(agent_id), **snapshot}, _bearer(token))

    def send_events(
        self,
        agent_id: UUID,
        token: str,
        events: list[dict[str, Any]],
        coverage: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"agent_id": str(agent_id), "events": events}
        # Fase 5C.1: solo si hay algo que informar (un servidor anterior no conoce el campo).
        if coverage:
            body["coverage"] = coverage
        return self._post("/events", body, _bearer(token))

    def send_processes(
        self, agent_id: UUID, token: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]:
        return self._post("/processes", {"agent_id": str(agent_id), **snapshot}, _bearer(token))

    def send_telemetry(self, agent_id: UUID, token: str, sample: dict[str, Any]) -> dict[str, Any]:
        return self._post("/telemetry", {"agent_id": str(agent_id), **sample}, _bearer(token))


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _retry_after(value: str | None) -> float | None:
    """Parse Retry-After (delta-seconds or HTTP date) into seconds, clamped to a sane range."""
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            seconds = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
        except (TypeError, ValueError):
            return None
    return min(max(seconds, 0.0), _MAX_RETRY_AFTER)


def _read_error_body(error: urllib.error.HTTPError) -> dict[str, Any]:
    try:
        data = json.loads(error.read() or b"{}")
    except (ValueError, OSError):
        return {}
    return data if isinstance(data, dict) else {}
