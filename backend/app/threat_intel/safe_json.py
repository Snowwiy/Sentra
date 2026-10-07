"""Lectura defensiva de JSON no confiable (importaciones y feeds de inteligencia).

Mismas defensas que el catálogo 5B (app/vulnerabilities/catalog.py), con códigos propios:
tamaño antes de parsear, profundidad medida con un recorrido lineal ANTES de json.loads (un
JSON muy anidado agotaría la pila), sin NaN/Infinity y sin claves duplicadas (ambiguas).
"""

import json
from typing import Any

from app.threat_intel.errors import IntelFormatError

MAX_DEPTH = 24


def check_depth(text: str, limit: int) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > limit:
                raise IntelFormatError("intel_too_deep", f"JSON nesting deeper than {limit}")
        elif char in "]}":
            depth -= 1


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IntelFormatError("intel_duplicate_key", "Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise IntelFormatError("intel_invalid_json", f"Non-finite number {name} is not allowed")


def loads(raw: bytes, max_bytes: int, max_depth: int = MAX_DEPTH) -> Any:
    """bytes UTF-8 -> objeto JSON, o IntelFormatError (sin devolver el contenido)."""
    if len(raw) > max_bytes:
        raise IntelFormatError("intel_too_large", f"Content exceeds {max_bytes} bytes")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise IntelFormatError("intel_invalid_json", "Content must be UTF-8 JSON") from None
    check_depth(text, max_depth)
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except IntelFormatError:
        raise
    except (ValueError, RecursionError):
        raise IntelFormatError("intel_invalid_json", "Content is not valid JSON") from None
