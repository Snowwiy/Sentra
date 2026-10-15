"""Redacción de secretos antes de que un dato entre en un snapshot de informe (Fase 5E).

Un informe se descarga, se reenvía y se archiva: lo que entra en él sale del control de
Sentra. Por eso, además de no seleccionar nunca columnas de credenciales (hash del token del
agente, hash de identidad de máquina, sesiones...), todo JSON libre que se copia (detalles de
detecciones, evidencia, resultados de Response) pasa por aquí:

- se eliminan las claves con nombre de credencial (password, token, secret, api_key,
  authorization, cookie, credential, enrollment...);
- en los textos se sustituyen cabeceras Authorization, "Bearer ..." y pares clave=valor de
  credenciales por "[redacted]".

Rutas, usuarios, hostnames e IPs NO se tocan: son datos operativos que un informe técnico
necesita (el resumen ejecutivo ya no los incluye por diseño).
"""

import re
from typing import Any

REDACTED = "[redacted]"
# Fragmentos de nombre de clave que nunca llegan a un informe. Más específicos que los de la
# auditoría ("key" a secas borraría component_key o dedup_key, que son datos útiles).
_SECRET_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "authorization",
    "auth_header",
    "cookie",
    "credential",
    "enrollment_key",
    "session_id",
    "csrf",
)
_SECRET_TEXT = re.compile(
    r"(?i)(authorization\s*[:=]\s*\S+(?:\s+\S+)?"
    r"|bearer\s+[A-Za-z0-9._~+/=-]{8,}"
    r"|(?:password|passwd|pwd|secret|token|api[_-]?key|enrollment[_-]?key)\s*[:=]\s*\S+)"
)
# Profundidad y tamaño máximos de un JSON copiado: un objeto hostil o enorme no infla el
# snapshot (los datos útiles de evidencia son pequeños).
MAX_DEPTH = 6
MAX_ITEMS = 50
MAX_TEXT = 1000


def is_secret_key(name: str) -> bool:
    lowered = name.lower()
    return any(fragment in lowered for fragment in _SECRET_KEY_FRAGMENTS)


def redact_text(value: str, limit: int = MAX_TEXT) -> str:
    cleaned = _SECRET_TEXT.sub(REDACTED, value.replace("\x00", ""))
    if len(cleaned) > limit:
        return cleaned[: limit - 1] + "…"
    return cleaned


def redact(value: Any, depth: int = 0) -> Any:
    """Copia JSON-segura y acotada de `value` sin claves ni textos de credenciales."""
    if depth > MAX_DEPTH:
        return "[truncated]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_ITEMS:
                out["_truncated"] = True
                break
            name = str(key)[:100]
            out[name] = REDACTED if is_secret_key(name) else redact(item, depth + 1)
        return out
    if isinstance(value, list | tuple):
        items = [redact(item, depth + 1) for item in list(value)[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            items.append("[truncated]")
        return items
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    return redact_text(str(value))
