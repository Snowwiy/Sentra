from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

NUL = "\x00"


class RequestModel(BaseModel):
    """Base for inbound payloads.

    Unknown fields are rejected so typos and contract drift fail loudly instead of being
    silently dropped; strings are trimmed so whitespace-only values fail min_length checks.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="after")
    @classmethod
    def _reject_nul(cls, value: object) -> object:
        # PostgreSQL cannot store U+0000 in text or JSONB columns. Without this check such a
        # string reaches the database and fails as an unhandled error (HTTP 500), which agents
        # read as "server unavailable": they back off and resend the same payload forever,
        # slowing their heartbeat until the asset looks offline. A 422 is final instead.
        # Applies to every string field of subclasses, including nested models.
        if isinstance(value, str) and NUL in value:
            raise ValueError("must not contain NUL (U+0000) characters")
        return value


class ResponseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ErrorBody(BaseModel):
    code: str = Field(examples=["validation_error"])
    message: str
    # Validation errors: one entry per failing field (`loc`, `msg`, `type`). Incident
    # conflicts (Fase 4K): the current version/status so the client can refresh.
    details: list[dict[str, Any]] | None = None


class ErrorResponse(BaseModel):
    """Body of every error answer (see core/exceptions.py), documented in the OpenAPI."""

    error: ErrorBody


Percentage = Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)]

# Largest value a PostgreSQL BIGINT column holds. Integers stored in BIGINT columns must be
# bounded here: Python ints are unbounded, so without this an oversized value reaches the
# database and fails as an unhandled overflow (HTTP 500) instead of a validation error (422).
BIGINT_MAX = 2**63 - 1
