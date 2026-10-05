"""Saneado de datos no confiables (eventos, procesos, nombres) antes de usarlos.

Todo lo que llega de un host puede estar manipulado: nombres de cuenta, rutas, nombres de
servicio. Aquí solo se acota y limpia el texto para guardarlo y mostrarlo; nunca se ejecuta,
nunca se pasa a una shell y la UI lo pinta como texto (React escapa), nunca como HTML.
"""

import re
from typing import Any

# Caracteres de control (incluidos saltos de línea y secuencias ANSI) fuera: un título o un
# log no deben poder "romper" líneas ni inyectar secuencias de terminal.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
MAX_VALUE = 512
MAX_FIELDS = 24


def clean(value: object, limit: int = MAX_VALUE) -> str:
    """Texto de una línea, sin caracteres de control y acotado."""
    text = _CONTROL.sub(" ", str(value))
    return " ".join(text.split())[:limit]


def clean_or_none(value: object, limit: int = MAX_VALUE) -> str | None:
    """Como `clean`, pero None para vacío o "-" (el "sin valor" de Windows)."""
    if value is None:
        return None
    text = clean(value, limit)
    return text if text and text != "-" else None


def bounded_data(data: dict[str, Any]) -> dict[str, Any]:
    """Copia acotada de un diccionario de evidencia: escalares limpios, sin None.

    La evidencia se guarda en JSONB y se devuelve por la API: así nunca crece sin límite ni
    lleva estructuras anidadas arbitrarias venidas del host.
    """
    result: dict[str, Any] = {}
    for key, value in list(data.items())[:MAX_FIELDS]:
        if value is None:
            continue
        if isinstance(value, bool | int | float):
            result[clean(key, 64)] = value
        elif isinstance(value, list | tuple):
            result[clean(key, 64)] = [clean(item, 128) for item in list(value)[:20]]
        else:
            result[clean(key, 64)] = clean(value)
    return result


def principal(value: object) -> str | None:
    """Nombre de cuenta normalizado para agrupar: sin dominio y en minúsculas.

    "PC-01\\Admin", "admin" y "CN=Admin,OU=..." se tratan como la misma cuenta dentro de un
    activo. Puede juntar una cuenta local y una de dominio con el mismo nombre: se acepta
    porque siempre se compara dentro del mismo activo y, cuando hay SID, se usa el SID.
    """
    text = clean_or_none(value, 255)
    if text is None:
        return None
    if text.upper().startswith("CN="):
        text = text[3:].split(",", 1)[0]
    text = text.rsplit("\\", 1)[-1]
    text = text.split("@", 1)[0] if "@" in text and not text.startswith("@") else text
    text = text.strip().lower()
    return text or None


def sid(value: object) -> str | None:
    """SID normalizado (mayúsculas), o None si no tiene forma de SID o es el SID nulo."""
    text = clean_or_none(value, 184)
    if text is None or not text.upper().startswith("S-1-") or text.upper() == "S-1-0-0":
        return None
    return text.upper()
