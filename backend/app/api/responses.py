"""Error responses for the OpenAPI document.

Every error answer uses the same envelope (core/exceptions.py). These declarations only
document which statuses each route can produce, so /docs and generated clients match what the
API really sends; they do not change behavior.
"""

from typing import Any

from app.schemas.common import ErrorResponse

_DESCRIPTIONS = {
    401: "Missing or invalid credentials (`unauthorized`)",
    403: "Enrollment disabled (`forbidden`) or agent revoked by an operator (`agent_revoked`)",
    404: "Asset not found (`not_found`)",
    409: "Concurrent first registration of the same agent; retry (`conflict`)",
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
