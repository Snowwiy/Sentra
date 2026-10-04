"""Shared query parameter types."""

from fastapi import Query

# PostgreSQL cannot store or compare text containing NUL (U+0000): a search term carrying it
# fails in the database (HTTP 500). Rejected here as 422, like NUL in request bodies.
_NO_NUL = r"^[^\x00]*$"


def text_query(max_length: int) -> object:
    """Optional free-text query parameter: bounded length, no NUL."""
    return Query(max_length=max_length, pattern=_NO_NUL)
