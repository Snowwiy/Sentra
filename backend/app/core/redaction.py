"""Redacción central de secretos en logs y mensajes de error (Fase 4M).

No confundir con app/ai/redaction.py, que seudonimiza datos de negocio antes de enviarlos a
un modelo. Esto evita que credenciales lleguen a un log: los logs se copian a journald,
ficheros rotados, tickets y SIEM, donde una contraseña o un token quedan expuestos durante
años y a mucha más gente que la base de datos.

Dos defensas complementarias:
- por nombre de campo: cualquier valor cuya clave suene a secreto (password, token,
  cookie, csrf, api_key, authorization...) se sustituye entero;
- por forma del texto: contraseñas en URLs (postgresql://user:pass@host), cabeceras
  Authorization/Cookie, tokens con prefijo de Sentra y pares clave=valor sensibles dentro de
  mensajes o trazas de excepciones.

Es una red de seguridad, no un permiso para registrar secretos: el código sigue sin pasarlos
a los logs a propósito.
"""

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"

# Claves cuyo valor nunca se registra. Subcadenas, en minúsculas.
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "csrf",
    "credential",
    "enrollment_key",
    "admin_key",
    "private_key",
    "session_id",
    "database_url",
    "dsn",
)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # scheme://user:password@host -> scheme://user:[REDACTED]@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)[^\s@/]+(@)"), r"\1" + REDACTED + r"\2"),
    # Authorization: Bearer xxx / Basic xxx
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{8,}"), r"\1 " + REDACTED),
    # Tokens con prefijo propio de Sentra (sesión y enrollment).
    (re.compile(r"\bsentra_(s|et)_[A-Za-z0-9_\-]{8,}"), "sentra_" + r"\1_" + REDACTED),
    # Cabeceras sensibles volcadas como texto.
    (
        re.compile(
            r"(?i)\b(cookie|set-cookie|x-csrf-token|x-admin-key|x-enrollment-key|"
            r"x-enrollment-token|authorization)(\s*[:=]\s*)[^\r\n,;]+"
        ),
        r"\1\2" + REDACTED,
    ),
    # clave=valor o "clave": "valor" con nombre sensible.
    (
        re.compile(
            r"(?i)([\"']?\b[a-z0-9_\-]*(?:password|passwd|secret|token|api_key|apikey|"
            r"csrf)[a-z0-9_\-]*[\"']?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&}]+)"
        ),
        r"\1" + REDACTED,
    ),
)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def redact_text(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_item(key: Any, value: Any, depth: int) -> Any:
    # Los números y booleanos nunca son secretos: "output_tokens": 812 es una métrica.
    if isinstance(key, str) and is_sensitive_key(key) and not isinstance(value, int | float):
        return REDACTED if value is not None else None
    return redact_value(value, depth + 1)


def redact_value(value: Any, depth: int = 0) -> Any:
    """Copia de `value` con los secretos sustituidos (dicts, listas y texto)."""
    if depth > 6:
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {k: _redact_item(k, v, depth) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_value(v, depth + 1) for v in value]
    return value
