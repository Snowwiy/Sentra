import logging
from typing import cast

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


class SentraError(Exception):
    """Base class for domain errors that map to an HTTP response."""

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    code = "internal_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


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


class ConflictError(SentraError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


def _error(status_code: int, code: str, message: str, details: object = None) -> JSONResponse:
    body: dict[str, object] = {"code": code, "message": message}
    if details is not None:
        body["details"] = details
    return JSONResponse(status_code=status_code, content={"error": body})


async def _sentra_error_handler(_: Request, exc: Exception) -> JSONResponse:
    error = cast(SentraError, exc)
    response = _error(error.status_code, error.code, error.message)
    if isinstance(error, UnauthorizedError):
        response.headers["WWW-Authenticate"] = "Bearer"
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
    # connection dropped, timeout). That is transient, so answer 503: the agent treats 5xx as
    # "retry later" and buffers, and the dashboard can say the service is unavailable instead
    # of a generic internal error. Logged without a traceback because an outage would
    # otherwise flood the log with one identical stack per request.
    logger.warning(
        "Database unavailable",
        extra={"path": request.url.path, "error": type(exc.__cause__ or exc).__name__},
    )
    return _error(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "database_unavailable",
        "Database temporarily unavailable, retry later",
    )


async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Full details go to the logs only; clients never receive internal tracebacks.
    logger.exception("Unhandled error", extra={"path": request.url.path}, exc_info=exc)
    return _error(status.HTTP_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal server error")


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(SentraError, _sentra_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_error_handler)
    app.add_exception_handler(OperationalError, _database_unavailable_handler)
    app.add_exception_handler(Exception, _unhandled_error_handler)
