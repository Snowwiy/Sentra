"""Validación y saneado de los campos que llegan de fuentes externas (datos no confiables).

Todo lo que sale de aquí es texto de una línea, acotado y sin caracteres de control, o un
valor tipado (IP normalizada, puerto en rango, fecha UTC). Nada se interpreta: un mensaje que
contenga una URL, un comando o un "ignora las instrucciones anteriores" se guarda como texto
y la UI lo muestra como texto (React escapa); nunca se sigue, se ejecuta ni se pasa a la IA
como instrucción.
"""

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any

from app.detection.text import bounded_tree, clean

_MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")
_TAG = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,47}$")
_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")
_IDENT = re.compile(r"^[A-Za-z0-9_.:/@-]{1,128}$")
MAX_TAGS = 16
MAX_MITRE = 8


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def identity_hash(*parts: object) -> str:
    """Identidad estable de un registro a partir de sus partes (para deduplicar)."""
    return sha256_text(json.dumps(parts, separators=(",", ":"), default=str, ensure_ascii=True))


def text(value: object, limit: int = 255) -> str | None:
    """Texto limpio de una línea o None si queda vacío (o es "-", el "sin valor" de Syslog)."""
    if value is None or isinstance(value, dict | list):
        return None
    cleaned = clean(value, limit)
    return cleaned if cleaned and cleaned != "-" else None


def ip(value: object) -> str | None:
    """IP normalizada (forma comprimida) o None si no es una dirección válida."""
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    candidate = value.strip()
    # IPv6 con zona (fe80::1%eth0): la zona no identifica nada fuera del host.
    candidate = candidate.split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return None


def port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.strip().isdigit() and len(value.strip()) <= 5:
        number = int(value.strip())
    else:
        return None
    return number if 0 <= number <= 65_535 else None


def hostname(value: object) -> str | None:
    cleaned = text(value, 253)
    if cleaned is None or not _HOSTNAME.fullmatch(cleaned):
        return None
    return cleaned.lower().rstrip(".")


def ident(value: object, limit: int = 128) -> str | None:
    """Identificador del origen (id de alerta, uid, sid): solo caracteres seguros."""
    if isinstance(value, bool) or value is None:
        return None
    raw = str(value).strip()[:limit]
    return raw if _IDENT.fullmatch(raw) else None


def tags(values: object) -> list[str]:
    out: list[str] = []
    if not isinstance(values, list | tuple):
        return out
    for item in values:
        if not isinstance(item, str):
            continue
        tag = item.strip().lower().replace(" ", "_")[:48]
        if _TAG.fullmatch(tag) and tag not in out:
            out.append(tag)
        if len(out) >= MAX_TAGS:
            break
    return out


def mitre(values: object) -> list[str]:
    """Técnicas ATT&CK con formato válido (T1234 o T1234.001). Un texto libre se descarta."""
    items = values if isinstance(values, list | tuple) else [values]
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            continue
        code = item.strip().upper()
        if _MITRE.fullmatch(code) and code not in out:
            out.append(code)
        if len(out) >= MAX_MITRE:
            break
    return out


def timestamp(value: object) -> datetime | None:
    """Fecha ISO 8601 (o epoch en segundos) a UTC. Sin zona horaria NO se adivina: None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        try:
            return datetime.fromtimestamp(float(value), UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or len(value) > 64:
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    # Suricata y Wazuh escriben la zona sin dos puntos (+0000): fromisoformat la acepta desde
    # Python 3.11, pero normalizamos por claridad.
    match = re.match(r"^(.*[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)([+-]\d{2})(\d{2})$", candidate)
    if match:
        candidate = f"{match.group(1)}{match.group(2)}:{match.group(3)}"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def url_path(value: object) -> str | None:
    """Ruta de una URL sin query string ni fragmento (pueden llevar tokens o credenciales)."""
    if not isinstance(value, str):
        return None
    return text(value.split("?", 1)[0].split("#", 1)[0], 512)


def data(values: dict[str, Any]) -> dict[str, Any]:
    """Campos propios del conector, acotados (claves, elementos, longitud, profundidad)."""
    return bounded_tree({k: v for k, v in values.items() if v is not None}, depth=3)


def excerpt(raw: str, limit: int) -> str | None:
    """Extracto del registro para la evidencia: sin caracteres de control y acotado."""
    if limit <= 0:
        return None
    return clean(raw, limit) or None
