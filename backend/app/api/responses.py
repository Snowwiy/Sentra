"""Error responses for the OpenAPI document.

Every error answer uses the same envelope (core/exceptions.py). These declarations only
document which statuses each route can produce, so /docs and generated clients match what the
API really sends; they do not change behavior.
"""

from typing import Any

from app.schemas.common import ErrorResponse

_DESCRIPTIONS = {
    401: (
        "Missing or invalid credentials: agent/admin credential (`unauthorized`), no valid"
        " dashboard session (`not_authenticated`) or failed login (`invalid_credentials`)"
    ),
    403: (
        "Forbidden: enrollment disabled (`forbidden`), agent revoked (`agent_revoked`), role"
        " without the permission (`permission_denied`) or missing CSRF token (`csrf_failed`)"
    ),
    404: "Asset not found (`not_found`)",
    409: "Concurrent first registration of the same agent; retry (`conflict`)",
    429: "Too many attempts; retry after `Retry-After` seconds (`rate_limited`)",
    413: "Request body larger than MAX_REQUEST_BYTES (`payload_too_large`)",
    422: "Validation error (`validation_error`, with `details` per field)",
    503: "Database unavailable; retry later (`database_unavailable`)",
}

OpenApiResponses = dict[int | str, dict[str, Any]]


def error_responses(*statuses: int) -> OpenApiResponses:
    return {
        status: {"model": ErrorResponse, "description": _DESCRIPTIONS[status]}
        for status in statuses
    }
