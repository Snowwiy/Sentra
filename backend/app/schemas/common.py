from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class RequestModel(BaseModel):
    """Base for inbound payloads.

    Unknown fields are rejected so typos and contract drift fail loudly instead of being
    silently dropped; strings are trimmed so whitespace-only values fail min_length checks.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ResponseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


Percentage = Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)]

# Largest value a PostgreSQL BIGINT column holds. Integers stored in BIGINT columns must be
# bounded here: Python ints are unbounded, so without this an oversized value reaches the
# database and fails as an unhandled overflow (HTTP 500) instead of a validation error (422).
BIGINT_MAX = 2**63 - 1
