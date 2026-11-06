"""Abstracción de proveedor de IA (Fase 4J).

Sentra no se acopla a un proveedor: el servicio de insights solo conoce `AIProvider`, que
recibe una petición ya construida (instrucciones, contexto y pregunta separados) y devuelve
texto. La validación, el grounding y la persistencia ocurren fuera del proveedor, así que
cambiar de proveedor no puede relajar ninguna garantía.

Los errores son SentraError con códigos propios: la API responde con un mensaje claro y
nunca con el cuerpo de la respuesta del proveedor (podría contener eco de cabeceras o datos).
"""

from dataclasses import dataclass, field
from typing import Protocol

from fastapi import status

from app.core.exceptions import SentraError


@dataclass(frozen=True)
class AIRequest:
    # Instrucciones del sistema (política fija y versionada; nunca contienen datos).
    system: str
    # Documento JSON con el contexto de Sentra y la pregunta del analista. Los datos no
    # confiables viajan como valores JSON dentro de él, nunca concatenados a instrucciones.
    user: str
    max_output_tokens: int
    # Determinista en lo posible: el mismo contexto debe dar respuestas parecidas.
    temperature: float = 0.0


@dataclass(frozen=True)
class AIResponse:
    content: str
    model: str
    latency_ms: int
    # Uso informado por el proveedor (puede no existir en servidores locales).
    usage_input: int | None = None
    usage_output: int | None = None
    extra: dict[str, str] = field(default_factory=dict)
    # 7C-Fix2: por qué terminó la generación ("stop", "length"...) y cuántos caracteres de
    # razonamiento devolvió el servidor aparte (`reasoning_content`). Solo para diagnosticar
    # una respuesta inutilizable; el razonamiento nunca se guarda ni se registra.
    finish_reason: str | None = None
    reasoning_chars: int = 0


class AIProvider(Protocol):
    """Contrato mínimo de un proveedor. Solo análisis: no hay herramientas ni funciones."""

    name: str
    model: str

    def complete(self, request: AIRequest) -> AIResponse: ...


# --- Errores ---------------------------------------------------------------------------------


class AIError(SentraError):
    status_code = status.HTTP_502_BAD_GATEWAY
    code = "ai_error"


class AINotConfiguredError(AIError):
    # AI_ENABLED=false, falta URL/modelo o proveedor externo no permitido.
    status_code = status.HTTP_409_CONFLICT
    code = "ai_not_configured"


class AIDestinationBlockedError(AIError):
    # AI_BASE_URL (o la IP real a la que resolvió) no es un destino permitido: externo con
    # AI_ALLOW_EXTERNAL=false, IP privada no autorizada o dirección prohibida. Fail closed
    # (4J.1): no se envía nada y no se prueba ningún otro proveedor.
    status_code = status.HTTP_409_CONFLICT
    code = "ai_destination_blocked"


class AIProviderUnavailableError(AIError):
    code = "ai_provider_unavailable"


class AITimeoutError(AIError):
    status_code = status.HTTP_504_GATEWAY_TIMEOUT
    code = "ai_timeout"


class AIProviderRateLimitedError(AIError):
    # El PROVEEDOR limitó (429 suyo). Distinto del límite de Sentra (rate_limited, 429).
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = "ai_provider_rate_limited"


class AIProviderAuthError(AIError):
    # Clave rechazada por el proveedor: problema de configuración del servidor.
    code = "ai_provider_auth_failed"


class AIInvalidResponseError(AIError):
    # La respuesta no es JSON válido o no cumple el schema tras los reintentos.
    code = "ai_invalid_response"

    def __init__(self, message: str, reason: str = "invalid_json") -> None:
        # 7C-Fix2: motivo concreto (ver INVALID_REASONS). Va a la auditoría, al log y al
        # cliente en `details`; nunca el contenido de la respuesta.
        super().__init__(message, details=[{"reason": reason}])
        self.reason = reason


# 7C-Fix2: motivos de una respuesta inutilizable, del más al menos específico.
INVALID_REASONS = (
    # El servidor cortó por max_tokens mientras el modelo razonaba: no llegó a responder.
    "truncated_reasoning",
    # Cortado por max_tokens con la respuesta a medias (JSON incompleto).
    "truncated",
    # Terminó sin respuesta, solo con razonamiento.
    "reasoning_only",
    # Terminó sin contenido.
    "empty_answer",
    # Hay texto, pero no es un objeto JSON.
    "invalid_json",
    # Es JSON, pero no cumple el schema del análisis (RawInsight o el de la consola).
    "schema_mismatch",
    # Cuerpo HTTP sin la forma de la API de chat, o demasiado grande.
    "unexpected_body",
)


class AIUngroundedResponseError(AIError):
    # Las conclusiones dependían de evidencia inexistente: no se muestra como análisis.
    code = "ai_ungrounded_response"


class AIBusyError(AIError):
    # Demasiadas llamadas simultáneas al modelo (AI_MAX_CONCURRENT).
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "ai_busy"
