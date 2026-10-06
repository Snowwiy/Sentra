import logging
from typing import Any, cast

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.metrics import REGISTRY
from app.core.request_context import current_request_id

logger = logging.getLogger(__name__)


class SentraError(Exception):
    """Base class for domain errors that map to an HTTP response."""

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    code = "internal_error"

    def __init__(self, message: str, details: list[dict[str, Any]] | None = None) -> None:
        super().__init__(message)
        self.message = message
        # Contexto opcional y seguro para el cliente (p. ej. la versión actual en un 409 de
        # concurrencia, para que la UI pueda refrescar). Nunca datos internos ni secretos.
        self.details = details


class NotFoundError(SentraError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"


class UnauthorizedError(SentraError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unauthorized"


class ForbiddenError(SentraError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"


class AgentRevokedError(ForbiddenError):
    # Distinct code so the agent can tell "an operator revoked me" from "enrollment is
    # disabled" and log the right instruction; both are 403 and neither should be retried soon.
    code = "agent_revoked"


class NotAuthenticatedError(SentraError):
    # Sin sesión de dashboard válida (no hay cookie, caducó, fue revocada o el usuario está
    # desactivado). El frontend la trata igual en todos los casos: limpiar estado e ir a
    # /login. Es una clase aparte de UnauthorizedError para no anunciar "Bearer", que es el
    # esquema de los agentes, no el del navegador.
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "not_authenticated"


class InvalidCredentialsError(SentraError):
    # Login fallido. Mismo código y mensaje para usuario inexistente, contraseña incorrecta
    # o usuario desactivado: la respuesta no revela qué usuarios existen.
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "invalid_credentials"


class PermissionDeniedError(ForbiddenError):
    # Sesión válida, pero su rol no tiene el permiso que pide el endpoint.
    code = "permission_denied"


class CsrfError(ForbiddenError):
    # Petición mutable sin token CSRF válido o desde un Origin no autorizado.
    code = "csrf_failed"


class RateLimitedError(SentraError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"

    def __init__(self, message: str, retry_after: float, scope: str = "other") -> None:
        super().__init__(message)
        self.retry_after = max(int(retry_after) + 1, 1)
        # Ámbito del límite (login, agent_register, ai...) solo para la métrica de 429.
        self.scope = scope


class PolicyError(SentraError):
    # Usuario o contraseña que no cumple la política (core/passwords.py).
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "policy_violation"


class ConflictError(SentraError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


class LastAdminError(ConflictError):
    # La operación dejaría Sentra sin ningún admin activo.
    code = "last_admin"


class DiscoveryDisabledError(ConflictError):
    # DISCOVERY_ALLOWED_NETWORKS vacío: no hay nada que se pueda escanear.
    code = "discovery_disabled"


class IncidentConflictError(ConflictError):
    # Fase 4K: el incidente cambió desde que el cliente lo leyó (token `version` obsoleto).
    # `details` lleva la versión y el estado actuales para que la UI refresque y el operador
    # decida; nunca se sobrescribe en silencio el cambio de otro.
    code = "incident_conflict"


class IncidentStateError(ConflictError):
    # Transición no permitida por la state machine, o caso cerrado/fusionado que no admite
    # cambios. 409: el estado actual del caso es el que lo impide, no la forma de la petición.
    code = "incident_invalid_state"


class IncidentRelationError(SentraError):
    # Owner, activo, detección, alerta o incidente de merge que no existe o no es válido
    # para esta operación (usuario inactivo, viewer como owner, merge consigo mismo...).
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "incident_invalid_reference"


class IncidentAlreadyLinkedError(ConflictError):
    # La detección/alerta ya pertenece a un incidente activo: se ofrece adjuntar o abrir
    # ese caso en lugar de crear un duplicado (anti incident-flood).
    code = "incident_already_linked"


class AssetContextConflictError(ConflictError):
    # Fase 4L: el contexto del activo cambió desde que el cliente lo leyó (`version`
    # obsoleta). Mismo patrón que incident_conflict: nunca se sobrescribe en silencio.
    code = "asset_context_conflict"


class AssetTagLimitError(SentraError):
    # Se superaría el número máximo de etiquetas distintas de la plataforma (anti tag flood).
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "asset_tag_limit"


class VulnerabilityConflictError(ConflictError):
    # Fase 5B: el finding cambió desde que el cliente lo leyó (`version` obsoleta, p. ej. la
    # evaluación lo actualizó o lo cambió otro analista). `details` lleva versión y estado.
    code = "vulnerability_conflict"


class VulnerabilityStateError(ConflictError):
    # Acción no permitida desde el estado actual del finding (resolver uno ya resuelto,
    # reconocer un falso positivo...). 409: lo impide el estado, no la petición.
    code = "vulnerability_invalid_state"


class VulnerabilityEvidenceError(SentraError):
    # Resolver a mano un finding cuya evidencia dice vulnerable (confirmed/probable) sin
    # confirmarlo explícitamente con override_evidence y motivo.
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "vulnerability_evidence_vulnerable"


class CatalogError(SentraError):
    # Catálogo de vulnerabilidades rechazado (formato, tamaño, profundidad, registros...).
    # El código concreto (catalog_too_large, catalog_invalid_json...) va en `code`.
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "catalog_invalid"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CatalogChangedError(ConflictError):
    # El fichero confirmado no es el previsualizado (sha256 distinto): se vuelve a revisar.
    code = "catalog_changed"


class CatalogBusyError(ConflictError):
    # Otra importación del catálogo está en curso (API o CLI): una sola a la vez.
    code = "catalog_import_in_progress"


class DiscoveryTargetError(SentraError):
    # Target fuera de la allowlist, inválido, demasiado grande o de espacio no permitido.
    # 422 y no 403: el operador puede corregirlo eligiendo una red autorizada.
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "discovery_target_refused"


def _error(
    status_code: int,
    code: str,
    message: str,
    details: object = None,
    *,
    with_request_id: bool = False,
) -> JSONResponse:
    body: dict[str, object] = {"code": code, "message": message}
    if details is not None:
        body["details"] = details
    request_id = current_request_id() if with_request_id else None
    if request_id:
        # Fase 4M: en errores del servidor el operador necesita ir del mensaje que ve el
        # usuario a la traza del log; el id es lo único que se expone (nunca la traza).
        body["request_id"] = request_id
    response = JSONResponse(status_code=status_code, content={"error": body})
    if request_id:
        # Un 500 no pasa por el middleware que añade la cabecera (lo genera la capa externa).
        response.headers["X-Request-ID"] = request_id
    return response


async def _sentra_error_handler(_: Request, exc: Exception) -> JSONResponse:
    error = cast(SentraError, exc)
    response = _error(error.status_code, error.code, error.message, jsonable_encoder(error.details))
    if isinstance(error, UnauthorizedError):
        response.headers["WWW-Authenticate"] = "Bearer"
    if isinstance(error, RateLimitedError):
        response.headers["Retry-After"] = str(error.retry_after)
        REGISTRY.rate_limited(error.scope)
    return response


async def _validation_error_handler(_: Request, exc: Exception) -> JSONResponse:
    # Submitted values are deliberately not echoed back.
    details = [
        {"loc": err.get("loc"), "msg": err.get("msg"), "type": err.get("type")}
        for err in cast(RequestValidationError, exc).errors()
    ]
    return _error(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        "validation_error",
        "Request validation failed",
        jsonable_encoder(details),
    )


async def _http_error_handler(_: Request, exc: Exception) -> JSONResponse:
    error = cast(StarletteHTTPException, exc)
    return _error(error.status_code, "http_error", str(error.detail))


async def _database_unavailable_handler(request: Request, exc: Exception) -> JSONResponse:
    # OperationalError means the database could not serve the request (down, restarting,
    # connection dropped, timeout); a pool TimeoutError means every connection of the pool is
    # busy (load spike, slow queries). Both are transient, so answer 503: the agent treats 5xx
    # as "retry later" and buffers, and the dashboard can say the service is unavailable
    # instead of a generic internal error. Logged without a traceback because an outage would
    # otherwise flood the log with one identical stack per request.
    logger.warning(
        "Database unavailable",
        extra={"path": request.url.path, "error": type(exc.__cause__ or exc).__name__},
    )
    return _error(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "database_unavailable",
        "Database temporarily unavailable, retry later",
        with_request_id=True,
    )


async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Full details go to the logs only; clients never receive internal tracebacks.
    logger.exception("Unhandled error", extra={"path": request.url.path}, exc_info=exc)
    response = _error(
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        "internal_error",
        "Internal server error",
        with_request_id=True,
    )
    # La capa externa que genera el 500 no pasa por el middleware de cabeceras de seguridad.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(SentraError, _sentra_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_error_handler)
    app.add_exception_handler(OperationalError, _database_unavailable_handler)
    app.add_exception_handler(PoolTimeoutError, _database_unavailable_handler)
    app.add_exception_handler(Exception, _unhandled_error_handler)
