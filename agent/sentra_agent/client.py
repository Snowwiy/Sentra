"""Minimal JSON client for the Sentra API using only the standard library."""

import gzip
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, BinaryIO
from uuid import UUID

from sentra_agent import __version__
from sentra_agent.config import (
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_REQUEST_DEADLINE,
    AgentConfig,
    insecure_url_reason,
)

# Statuses that describe a temporary condition on the server side: retry with backoff like a
# network failure instead of treating the request as permanently rejected.
#   408 request timeout, 409 concurrent first registration, 425/429 throttling.
_RETRYABLE_4XX = {408, 409, 425, 429}
# Upper bound for Retry-After so a misbehaving proxy cannot park the agent for days.
_MAX_RETRY_AFTER = 3600.0
# Fase 6E: los lotes de actividad se comprimen a partir de este tamaño. Por debajo, gzip
# apenas ahorra y cuesta CPU en el equipo.
GZIP_THRESHOLD = 8 * 1024


class TransportError(Exception):
    """The API could not be reached (network down, DNS, timeout, 5xx). Worth retrying."""

    def __init__(
        self, message: str, retry_after: float | None = None, status: int | None = None
    ) -> None:
        super().__init__(message)
        self.retry_after = retry_after
        # Fase 7D.2: código HTTP cuando lo hubo (429 = cuota del servidor, no una caída).
        self.status = status


class TlsError(TransportError):
    """Fallo de verificación TLS (certificado, cadena o nombre). No es "servidor caído":
    el diagnóstico lo dice aparte. Se reintenta como un fallo de red (un certificado
    renovado lo arregla), pero la verificación nunca se relaja."""


class RedirectError(TransportError):
    """El servidor (o algo en medio) respondió con una redirección (Fase 7D.1, H05).

    No se sigue nunca: reenviaría la cabecera Authorization o la credencial de enrolamiento
    a otra URL (otro host, o http:// en claro). Se trata como un fallo temporal con backoff
    y un mensaje que dice qué corregir; el agente no queda cortado en silencio.
    """

    def __init__(self, status: int, location: str | None) -> None:
        super().__init__(
            f"HTTP {status} redirect to {location or '(no Location)'} refused: the agent never"
            " follows redirects; set api_url to the final https:// address"
        )
        self.status = status
        self.location = location


class ResponseTooLargeError(TransportError):
    """La respuesta supera max_response_bytes: se corta la lectura sin cargarla entera."""


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


# Fase 6C.5: raíces de confianza que Apple mantiene en macOS. El Python de python.org trae su
# propio OpenSSL sin certificados (hasta ejecutar "Install Certificates.command"), así que
# sin esto toda conexión HTTPS fallaría la verificación. Se AÑADEN a las del Python: nunca se
# desactiva ni se relaja la verificación.
MACOS_SYSTEM_ROOTS = "/etc/ssl/cert.pem"


def tls_context(platform: str | None = None, roots: str = MACOS_SYSTEM_ROOTS) -> ssl.SSLContext:
    """Contexto TLS verificado (certificado y nombre) con las raíces del sistema."""
    context = ssl.create_default_context()
    if (platform or sys.platform) == "darwin" and os.path.isfile(roots):
        context.load_verify_locations(cafile=roots)
    return context


def tls_context_with(ca_bundle: Path | None) -> ssl.SSLContext:
    """tls_context() más una CA privada opcional. TLS 1.2 como mínimo."""
    context = tls_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_bundle is not None:
        context.load_verify_locations(cafile=str(ca_bundle))
    return context


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Devolver None hace que urllib entregue la 3xx como HTTPError en lugar de seguirla.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class SentraClient:
    def __init__(
        self,
        api_url: str,
        timeout: float,
        *,
        ca_bundle: Path | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        deadline: float = DEFAULT_REQUEST_DEADLINE,
    ) -> None:
        # Defensa en profundidad: la configuración ya lo valida, pero el cliente no envía
        # nunca una credencial por HTTP fuera de loopback aunque alguien lo cree a mano.
        reason = insecure_url_reason(api_url)
        if reason is not None:
            raise ValueError(reason)
        self._base = api_url.strip().rstrip("/") + "/api/v1"
        self._timeout = timeout
        self._deadline = max(deadline, timeout)
        self._max_bytes = max_response_bytes
        self._tls = tls_context_with(ca_bundle)
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._tls), _NoRedirect()
        )

    def _post(
        self,
        path: str,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
        compress_over: int | None = None,
    ) -> dict[str, Any]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"sentra-agent/{__version__}",
        }
        headers.update(extra_headers or {})
        data = json.dumps(payload).encode()
        if compress_over is not None and len(data) > compress_over:
            # mtime=0: el mismo lote produce los mismos bytes (reintentos reproducibles).
            data = gzip.compress(data, compresslevel=6, mtime=0)
            headers["Content-Encoding"] = "gzip"
        request = urllib.request.Request(  # noqa: S310  (scheme validated in AgentConfig)
            self._base + path,
            data=data,
            headers=headers,
            method="POST",
        )
        started = time.monotonic()
        try:
            # El timeout vale para conectar y para cada lectura del socket; el plazo total
            # (deadline) acota además la petición completa.
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = _read_bounded(response, self._max_bytes, started + self._deadline)
        except urllib.error.HTTPError as error:
            try:
                if 300 <= error.code < 400:
                    raise RedirectError(error.code, error.headers.get("Location")) from error
                body = _read_error_body(error, self._max_bytes)
                retry_after = _retry_after(error.headers.get("Retry-After"))
            finally:
                # HTTPError es también la respuesta abierta: quien la captura la cierra.
                error.close()
            # 5xx means the server (or its database) is unhealthy: retry like a network error.
            if error.code >= 500 or error.code in _RETRYABLE_4XX:
                raise TransportError(
                    f"HTTP {error.code}: {body}", retry_after, error.code
                ) from error
            raise ApiError(error.code, body) from error
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLError):
                raise TlsError(f"TLS verification failed: {error.reason}") from error
            raise TransportError(f"network error: {error.reason}") from error
        except ssl.SSLError as error:
            raise TlsError(f"TLS verification failed: {error}") from error
        except (TimeoutError, ConnectionError, OSError) as error:
            raise TransportError(f"network error: {error}") from error
        try:
            parsed = json.loads(raw or b"{}")
        except ValueError as error:
            # Un proxy o portal cautivo que responde 2xx con algo que no es JSON.
            raise TransportError("unexpected non-JSON response from the API") from error
        if not isinstance(parsed, dict):
            raise TransportError("unexpected JSON response from the API (not an object)")
        return parsed

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
        self,
        agent_id: UUID,
        token: str,
        host: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"agent_id": str(agent_id)}
        if host is not None:
            body["host"] = host
        # Fase 6E: campos opcionales `telemetry` e `isolation`. Un servidor anterior los
        # rechaza como desconocidos y el runner los quita (mecanismo _unknown_fields).
        for key, value in (extra or {}).items():
            if value is not None:
                body[key] = value
        return self._post("/agents/heartbeat", body, _bearer(token))

    def send_activity(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        """Fase 6E: lote de actividad del endpoint (gzip si pasa de GZIP_THRESHOLD)."""
        return self._post("/agents/activity", body, _bearer(token), compress_over=GZIP_THRESHOLD)

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

    def poll_commands(self, agent_id: UUID, token: str, max_commands: int = 5) -> dict[str, Any]:
        # Fase 5D: comandos de Response en cola para este agente (con su propio token).
        return self._post(
            "/agents/commands/poll",
            {"agent_id": str(agent_id), "max_commands": max_commands},
            _bearer(token),
        )

    def send_command_result(
        self, agent_id: UUID, token: str, request_id: UUID, body: dict[str, Any]
    ) -> dict[str, Any]:
        # request_id es un UUID ya validado: nunca se interpola texto del servidor en la URL.
        return self._post(
            f"/agents/commands/{UUID(str(request_id))}/result",
            {"agent_id": str(agent_id), **body},
            _bearer(token),
        )

    def rotate_credential(self, agent_id: UUID, token: str) -> dict[str, Any]:
        """Fase 7D.1: credencial nueva a cambio de la vigente (solo por HTTPS o loopback)."""
        return self._post("/agents/credentials/rotate", {"agent_id": str(agent_id)}, _bearer(token))

    def send_telemetry(self, agent_id: UUID, token: str, sample: dict[str, Any]) -> dict[str, Any]:
        return self._post("/telemetry", {"agent_id": str(agent_id), **sample}, _bearer(token))


def client_for(config: AgentConfig) -> SentraClient:
    """Cliente con los límites de transporte de la configuración (AgentConfig)."""
    return SentraClient(
        config.api_url,
        config.request_timeout_seconds,
        ca_bundle=config.ca_bundle,
        max_response_bytes=config.max_response_bytes,
        deadline=config.request_deadline_seconds,
    )


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


_CHUNK = 64 * 1024


def _read_bounded(stream: BinaryIO, limit: int, deadline: float) -> bytes:
    """Lee por trozos hasta `limit` bytes y antes del instante `deadline` (monotónico)."""
    chunks: list[bytes] = []
    total = 0
    while True:
        if time.monotonic() > deadline:
            raise TransportError("request deadline exceeded while reading the response")
        # read1 devuelve lo que ya llegó (una lectura de socket como mucho): así el plazo se
        # comprueba aunque el servidor envíe la respuesta byte a byte. read(n) esperaría a
        # tener n bytes completos.
        reader = getattr(stream, "read1", stream.read)
        chunk = reader(min(_CHUNK, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise ResponseTooLargeError(f"response larger than {limit} bytes; not read")


def _read_error_body(error: urllib.error.HTTPError, limit: int) -> dict[str, Any]:
    if error.fp is None:
        return {}
    try:
        data = json.loads(error.read(min(limit, 64 * 1024)) or b"{}")
    except (ValueError, OSError):
        return {}
    return data if isinstance(data, dict) else {}
