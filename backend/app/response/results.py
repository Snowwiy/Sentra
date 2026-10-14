"""Saneado y acotado de resultados de Response (Fase 5D).

Un resultado llega de un handler del servidor o de un agente (dato no confiable). Antes de
guardarlo se reduce a JSON simple y acotado: solo dict/list/str/int/float/bool/None, claves
de texto cortas, profundidad y longitudes limitadas, sin caracteres de control. El frontend
lo muestra siempre como texto (nunca como HTML), pero el servidor no depende de eso.

Si el resultado saneado supera RESPONSE_RESULT_MAX_KB se sustituye por un marcador
`truncated` en lugar de guardarlo a medias: un JSON cortado no es evidencia fiable.
"""

import json
import math
import re
from typing import Any

MAX_DEPTH = 6
MAX_KEY = 64
MAX_STRING = 2000
MAX_LIST = 500
MAX_KEYS = 200
SUMMARY_MAX = 500
# Controles C0/C1 salvo tabulador y salto de línea; también separadores Unicode de línea.
_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029]")


def clean_text(value: object, limit: int) -> str:
    return _CONTROL.sub("", str(value))[:limit]


def _clean(value: Any, depth: int) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        # BIGINT de PostgreSQL y números que el navegador representa sin perder precisión.
        return value if -(2**53) <= value <= 2**53 else str(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return clean_text(value, MAX_STRING)
    if depth >= MAX_DEPTH:
        return "…"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in list(value.items())[:MAX_KEYS]:
            out[clean_text(key, MAX_KEY)] = _clean(item, depth + 1)
        return out
    if isinstance(value, list | tuple):
        return [_clean(item, depth + 1) for item in list(value)[:MAX_LIST]]
    # Cualquier otro tipo (objetos, bytes...) se guarda como su representación de texto.
    return clean_text(value, MAX_STRING)


def bounded_result(summary: object, data: object, max_bytes: int) -> dict[str, Any]:
    """{"summary": str, "data": dict} saneado y dentro de max_bytes (JSON UTF-8)."""
    clean_summary = clean_text(summary or "", SUMMARY_MAX)
    clean_data = _clean(data if isinstance(data, dict) else {"value": data}, 0)
    size = len(json.dumps(clean_data, ensure_ascii=False).encode())
    if size > max_bytes:
        clean_data = {"truncated": True, "original_bytes": size, "max_bytes": max_bytes}
    return {"summary": clean_summary, "data": clean_data}
