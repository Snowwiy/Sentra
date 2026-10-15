"""Cliente HTTPS del protocolo del sensor (solo stdlib, solo conexiones salientes).

El sensor nunca escucha: todas las conexiones las inicia él hacia el servidor, así funciona
tras NAT y sin abrir puertos en el site. El transporte es inyectable para probar sin red.
"""

import json
import ssl
import urllib.error
import urllib.request
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol

from sentra_sensor import __version__
from sentra_sensor.config import validate_server_url

API_PREFIX = "/api/v1"
# Tope de lectura de una respuesta: un proxy roto o malicioso no puede agotar la memoria.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
# Tope de Retry-After para que un intermediario no aparque el sensor durante días.
MAX_RETRY_AFTER = 3600.0


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    def request(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes, timeout: float
    ) -> HttpResponse:
        """Devuelve la respuesta (cualquier status). Errores de red: OSError."""
        ...


class TransportError(Exception):
    """No hubo respuesta HTTP utilizable (red, DNS, TLS, timeout, respuesta no JSON)."""


class TlsError(TransportError):
    """Fallo de verificación TLS. Se distingue para el diagnóstico: no es "servidor caído"."""


class ApiError(Exception):
    """El servidor respondió con un error HTTP (>= 400)."""

    def __init__(
        self, status: int, code: str | None, message: str, retry_after: float | None = None
    ) -> None:
        super().__init__(f"HTTP {status} {code or ''}: {message}".strip())
        self.status = status
        self.code = code
        self.retry_after = retry_after

    @property
    def retryable(self) -> bool:
        # 408/425/429 y 5xx describen un estado temporal: se reintenta con backoff.
        return self.status >= 500 or self.status in (408, 425, 429)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Una redirección reenviaría la cabecera Authorization a otra URL (potencialmente otro
    # host o http://). El protocolo no usa redirecciones: se tratan como error.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def build_ssl_context(ca_bundle: Path | None) -> ssl.SSLContext:
    """Verificación TLS SIEMPRE activa; `ca_bundle` solo añade una CA privada de confianza.

    No hay ninguna ruta de código que desactive la verificación ni la comprobación de host.
    """
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_bundle is not None:
        context.load_verify_locations(cafile=str(ca_bundle))
    return context


class UrllibTransport:
    def __init__(self, ca_bundle: Path | None = None) -> None:
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=build_ssl_context(ca_bundle)), _NoRedirect()
        )

    def request(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes, timeout: float
    ) -> HttpResponse:
        req = urllib.request.Request(  # noqa: S310  (esquema validado en validate_server_url)
            url, data=body, headers=dict(headers), method=method
        )
        try:
            with self._opener.open(req, timeout=timeout) as response:
                return HttpResponse(
                    response.status, dict(response.headers), response.read(MAX_RESPONSE_BYTES)
                )
        except urllib.error.HTTPError as error:
            data = error.read(MAX_RESPONSE_BYTES) if error.fp is not None else b""
            return HttpResponse(error.code, dict(error.headers or {}), data)
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLError):
                raise TlsError(f"TLS verification failed: {error.reason}") from error
            raise TransportError(f"network error: {error.reason}") from error
        except ssl.SSLError as error:
            raise TlsError(f"TLS verification failed: {error}") from error
        except (TimeoutError, ConnectionError, OSError) as error:
            raise TransportError(f"network error: {error}") from error


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - datetime.now(UTC)).total_seconds()
    return max(0.0, min(seconds, MAX_RETRY_AFTER))


def _job_path(job_id: str, action: str) -> str:
    # El job_id viene del servidor: se normaliza como UUID antes de interpolarlo en la URL.
    return f"/sensor/jobs/{uuid.UUID(str(job_id))}/{action}"


class SensorClient:
    def __init__(
        self,
        server_url: str,
        transport: Transport,
        timeout: float = 15.0,
        credential: str | None = None,
    ) -> None:
        self._base = validate_server_url(server_url) + API_PREFIX
        self._transport = transport
        self._timeout = timeout
        self._credential = credential

    def set_credential(self, credential: str) -> None:
        self._credential = credential

    def _post(
        self, path: str, payload: dict[str, Any], headers: Mapping[str, str] | None = None
    ) -> dict[str, Any]:
        all_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"sentra-sensor/{__version__}",
        }
        if headers is not None:
            all_headers.update(headers)
        elif self._credential is not None:
            all_headers["Authorization"] = f"Bearer {self._credential}"
        body = json.dumps(payload, separators=(",", ":")).encode()
        response = self._transport.request(
            "POST", self._base + path, all_headers, body, self._timeout
        )
        try:
            data = json.loads(response.body or b"{}")
        except ValueError:
            data = None
        if response.status >= 400:
            code: str | None = None
            message = ""
            if isinstance(data, dict) and isinstance(data.get("error"), dict):
                code = data["error"].get("code")
                message = str(data["error"].get("message") or "")[:200]
            retry_after = parse_retry_after(
                {k.lower(): v for k, v in response.headers.items()}.get("retry-after")
            )
            raise ApiError(response.status, code, message, retry_after)
        if not isinstance(data, dict):
            # p. ej. un portal cautivo que responde 200 con HTML.
            raise TransportError(f"unexpected non-JSON response (HTTP {response.status})")
        return data

    # --- protocolo --------------------------------------------------------------------

    def enroll(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._post("/sensor/enroll", body, {"X-Sensor-Enrollment-Token": token})

    def heartbeat(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._post("/sensor/heartbeat", body)

    def poll(self, max_jobs: int = 1) -> dict[str, Any]:
        return self._post("/sensor/jobs/poll", {"max_jobs": max_jobs})

    def start(self, job_id: str, attempt: int) -> dict[str, Any]:
        return self._post(_job_path(job_id, "start"), {"attempt": attempt})

    def results(self, job_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._post(_job_path(job_id, "results"), body)

    def complete(self, job_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._post(_job_path(job_id, "complete"), body)

    def rotate_credential(self) -> dict[str, Any]:
        return self._post("/sensor/credential/rotate", {})
