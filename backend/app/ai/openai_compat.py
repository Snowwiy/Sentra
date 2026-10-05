"""Proveedor compatible con la API de chat de OpenAI (POST {base}/chat/completions).

Cubre servidores locales (llama.cpp, vLLM, LM Studio, Ollama en modo /v1...) y proveedores
externos con el mismo protocolo, sin SDK ni dependencias nuevas (http.client de stdlib).

Decisiones:
- http.client y no urllib: no sigue redirecciones (una respuesta 30x no puede llevar los
  datos a otro host) e ignora HTTP(S)_PROXY del entorno (el destino es exactamente
  AI_BASE_URL);
- tres límites de tiempo: conexión, lectura por bloque y un plazo total que acota cada
  lectura con el tiempo restante, así un modelo lento nunca retiene un hilo más de
  AI_TIMEOUT_SECONDS;
- la respuesta se lee con tope de tamaño: un servidor roto no puede agotar la memoria;
- los errores nunca incluyen el cuerpo de la respuesta ni la clave;
- fail closed (4J.1): el constructor rechaza un destino no permitido y, tras conectar y
  ANTES de enviar datos, se comprueba la IP real del servidor. Un nombre "local" que resuelva
  fuera de loopback/AI_LOCAL_NETWORKS (DNS manipulado, /etc/hosts erróneo) no recibe nada;
- un único destino: si el modelo falla, el error se devuelve tal cual. No existe ningún
  fallback a otro proveedor (ni local ni cloud).
"""

import http.client
import json
import ssl
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from app.ai.config import AIConfig, is_authorized_local_ip, is_forbidden_ip, literal_ip
from app.ai.provider import (
    AIDestinationBlockedError,
    AIError,
    AIInvalidResponseError,
    AIProviderAuthError,
    AIProviderRateLimitedError,
    AIProviderUnavailableError,
    AIRequest,
    AIResponse,
    AITimeoutError,
)

# Ninguna respuesta legítima de un análisis se acerca a esto.
MAX_RESPONSE_BYTES = 512 * 1024
_CHUNK = 16 * 1024
# El health check debe ser barato: nunca bloquea la página de estado más de unos segundos.
HEALTH_CONNECT_TIMEOUT = 3.0
HEALTH_TOTAL_TIMEOUT = 5.0


@dataclass(frozen=True)
class ProviderHealth:
    reachable: bool
    latency_ms: int
    # Motivo legible si no responde (sin URL, clave ni cuerpo de la respuesta).
    detail: str | None = None


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(self, config: AIConfig) -> None:
        if not config.base_url or not config.model:
            raise ValueError("AI_BASE_URL and AI_MODEL are required")
        parts = urlsplit(config.base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("AI_BASE_URL must be an http(s) URL")
        # Defensa en profundidad: el servicio ya lo comprueba, pero así ningún llamador
        # futuro puede crear un proveedor hacia un destino bloqueado.
        blocked = config.destination_blocked_reason()
        if blocked:
            raise AIDestinationBlockedError(blocked)
        self.model = config.model
        self.location = config.location
        self._local_networks = config.local_networks
        self._https = parts.scheme == "https"
        self._host = parts.hostname
        self._port = parts.port or (443 if self._https else 80)
        self._base_path = parts.path.rstrip("/") or ""
        self._path = self._base_path + "/chat/completions"
        self._api_key = config.api_key
        self._json_mode = config.json_mode
        self._connect_timeout = config.connect_timeout_seconds
        self._read_timeout = config.read_timeout_seconds
        self._total_timeout = config.timeout_seconds

    def _payload(self, request: AIRequest) -> bytes:
        body: dict[str, Any] = {
            "model": self.model,
            # Instrucciones y datos en mensajes separados (ver docs, prompt injection).
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
            "temperature": request.temperature,
            "max_tokens": request.max_output_tokens,
            "stream": False,
        }
        if self._json_mode:
            body["response_format"] = {"type": "json_object"}
        return json.dumps(body, ensure_ascii=False).encode("utf-8")

    def _connection(self) -> http.client.HTTPConnection:
        if self._https:
            return http.client.HTTPSConnection(
                self._host,
                self._port,
                timeout=self._connect_timeout,
                context=ssl.create_default_context(),
            )
        return http.client.HTTPConnection(self._host, self._port, timeout=self._connect_timeout)

    def _check_peer(self, conn: http.client.HTTPConnection) -> None:
        """Verifica la IP real conectada ANTES de enviar la petición (anti DNS rebinding)."""
        try:
            peer = conn.sock.getpeername()[0] if conn.sock is not None else ""
        except OSError:
            peer = ""
        address = literal_ip(peer) if peer else None
        if address is None:
            raise AIDestinationBlockedError("The AI server address could not be verified")
        if self.location == "local":
            if not is_authorized_local_ip(address, self._local_networks):
                raise AIDestinationBlockedError(
                    "The local AI server resolved outside loopback and AI_LOCAL_NETWORKS"
                )
        elif is_forbidden_ip(address):
            raise AIDestinationBlockedError("The AI server resolved to a forbidden address")

    def _exchange(
        self,
        method: str,
        path: str,
        body: bytes | None,
        connect_timeout: float,
        total_timeout: float,
    ) -> tuple[int, bytes, int]:
        """Una petición HTTP acotada en tiempo y tamaño. Devuelve (status, cuerpo, ms)."""
        started = time.monotonic()
        deadline = started + total_timeout

        def remaining() -> float:
            left = deadline - time.monotonic()
            if left <= 0:
                raise AITimeoutError("The AI provider did not answer in time")
            return left

        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        # Sin AI_API_KEY (lo normal en un servidor local) no se envía Authorization.
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        conn = self._connection()
        try:
            try:
                conn.timeout = min(connect_timeout, remaining())
                conn.connect()
                self._check_peer(conn)
                if conn.sock is not None:
                    conn.sock.settimeout(min(self._read_timeout, remaining()))
                conn.request(method, path, body=body, headers=headers)
                response = conn.getresponse()
                raw = bytearray()
                while True:
                    if conn.sock is not None:
                        conn.sock.settimeout(min(self._read_timeout, remaining()))
                    chunk = response.read(_CHUNK)
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise AIInvalidResponseError("The AI provider response is too large")
            except TimeoutError:
                raise AITimeoutError("The AI provider did not answer in time") from None
            except (OSError, http.client.HTTPException) as exc:
                # Sin detalles del destino: el mensaje llega al navegador.
                raise AIProviderUnavailableError(
                    f"The AI provider is unavailable ({type(exc).__name__})"
                ) from None
        finally:
            conn.close()
        return response.status, bytes(raw), int((time.monotonic() - started) * 1000)

    def complete(self, request: AIRequest) -> AIResponse:
        status_code, raw, latency = self._exchange(
            "POST",
            self._path,
            self._payload(request),
            self._connect_timeout,
            self._total_timeout,
        )
        return self._parse(status_code, raw, latency)

    def check(self) -> ProviderHealth:
        """Health check sin datos de Sentra: GET {base}/models con timeouts cortos.

        Solo prueba que el servidor configurado responde; nunca envía telemetría ni prompts.
        Un 404 cuenta como disponible: algunos servidores locales no implementan /models.
        """
        started = time.monotonic()
        try:
            status_code, _, latency = self._exchange(
                "GET",
                self._base_path + "/models",
                None,
                min(self._connect_timeout, HEALTH_CONNECT_TIMEOUT),
                min(self._total_timeout, HEALTH_TOTAL_TIMEOUT),
            )
        except AIError as exc:
            return ProviderHealth(False, int((time.monotonic() - started) * 1000), exc.message)
        if status_code in (401, 403):
            return ProviderHealth(False, latency, "The AI provider rejected the server credentials")
        if status_code >= 500:
            return ProviderHealth(False, latency, f"The AI provider failed (HTTP {status_code})")
        return ProviderHealth(True, latency)

    def _parse(self, status_code: int, raw: bytes, latency_ms: int) -> AIResponse:
        if status_code in (401, 403):
            raise AIProviderAuthError("The AI provider rejected the server credentials")
        if status_code == 429:
            raise AIProviderRateLimitedError("The AI provider is rate limiting requests")
        if status_code >= 500:
            raise AIProviderUnavailableError(f"The AI provider failed (HTTP {status_code})")
        if status_code >= 400:
            raise AIProviderUnavailableError(f"The AI provider refused the request ({status_code})")
        try:
            body = json.loads(raw)
            content = body["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise AIInvalidResponseError("The AI provider returned an unexpected body") from None
        if not isinstance(content, str):
            raise AIInvalidResponseError("The AI provider returned an empty answer")
        usage = body.get("usage") if isinstance(body, dict) else None
        usage = usage if isinstance(usage, dict) else {}
        return AIResponse(
            content=content,
            model=str(body.get("model") or self.model)[:128],
            latency_ms=latency_ms,
            usage_input=_int(usage.get("prompt_tokens")),
            usage_output=_int(usage.get("completion_tokens")),
        )


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
