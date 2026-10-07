"""Importación de un SUBSET seguro de STIX 2.x (2.0 y 2.1). Puro, sin base de datos.

Qué se acepta (docs/stix-support.md):
- un bundle ({"type": "bundle", "objects": [...]}) o un sobre TAXII ({"objects": [...]});
- objetos `indicator` con `pattern_type` "stix" (o sin él, STIX 2.0) cuyo patrón es UNA
  comparación de igualdad de la lista blanca, por ejemplo:
      [ipv4-addr:value = '203.0.113.7']
      [domain-name:value = 'example.com']
      [file:hashes.'SHA-256' = 'aa...']
  Cualquier otro patrón (AND/OR, operadores, observaciones, calificadores WITHIN/REPEATS,
  MATCHES, otros objetos) se cuenta como "unsupported_pattern" y NO se importa;
- `malware`, `threat-actor`, `campaign` e `intrusion-set` solo como metadatos (nombre), y
  relaciones `indicates` indicador -> esos objetos. No hay motor de grafos.

Seguridad:
- el patrón NUNCA se evalúa ni compila como código: se reconoce con una expresión regular
  anclada de la lista blanca y el valor se extrae como literal (con sus escapes \\' y \\\\);
- límites de tamaño, número de objetos, profundidad y longitud de cada texto;
- etiquetas, nombres y descripciones son texto no confiable: se guardan acotados y la UI los
  pinta como texto (una etiqueta "<script>" es solo una cadena);
- la clasificación sale de `indicator_types` (2.1) o `labels` (2.0) de la propia fuente. Si
  no declara nada, el indicador queda "unknown": aparecer en un bundle no lo hace malicioso.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.threat_intel import safe_json
from app.threat_intel.errors import IntelFormatError, IntelRecordError
from app.threat_intel.indicators import confidence_from_score, normalize
from app.threat_intel.kev import clean_text
from app.threat_intel.records import IndicatorRecord, InvalidRecord, ParsedIntel
from app.vulnerabilities.catalog import safe_reference

FORMAT = "stix-2"
_ID = re.compile(r"^[a-z][a-z0-9-]{1,40}--[0-9a-fA-F-]{36}$")
_TAG = re.compile(r"^[^\x00-\x1f\x7f]{1,64}$")
MAX_PATTERN = 1024
MAX_TAGS = 20
MAX_REFERENCES = 20
MAX_RELATED = 10
CONTEXT_TYPES = frozenset({"malware", "threat-actor", "campaign", "intrusion-set"})

# Lista blanca de rutas de objeto -> tipo de indicador de Sentra.
_PATHS: Mapping[str, str] = {
    "ipv4-addr:value": "ipv4",
    "ipv6-addr:value": "ipv6",
    "domain-name:value": "domain",
    "url:value": "url",
    "email-addr:value": "email",
    "file:hashes.'sha-256'": "sha256",
    "file:hashes.sha256": "sha256",
    "file:hashes.'sha256'": "sha256",
    "file:hashes.'sha-1'": "sha1",
    "file:hashes.sha1": "sha1",
    "file:hashes.'sha1'": "sha1",
    "file:hashes.md5": "md5",
    "file:hashes.'md5'": "md5",
}
# [ruta = 'literal'] y nada más. La ruta se valida después contra _PATHS. El literal admite
# los escapes de STIX (\' y \\) y ningún otro carácter de control.
_PATTERN = re.compile(
    r"^\[\s*(?P<path>[a-z0-9-]+:[a-z0-9_.'-]+)\s*=\s*'(?P<value>(?:[^'\\\x00-\x1f]|\\['\\])*)'\s*\]$",
    re.IGNORECASE,
)
_MALICIOUS = frozenset({"malicious-activity", "compromised", "attribution"})
_SUSPICIOUS = frozenset({"anomalous-activity", "anonymization"})


@dataclass(frozen=True)
class StixLimits:
    max_bytes: int
    max_objects: int
    max_depth: int = safe_json.MAX_DEPTH


def parse_pattern(pattern: str) -> tuple[str, str] | None:
    """(tipo, valor) si el patrón está en la lista blanca; None si no está soportado."""
    if len(pattern) > MAX_PATTERN:
        return None
    match = _PATTERN.match(pattern.strip())
    if match is None:
        return None
    kind = _PATHS.get(match.group("path").lower())
    if kind is None:
        return None
    value = match.group("value").replace("\\'", "'").replace("\\\\", "\\")
    if kind in ("ipv4", "ipv6") and "/" in value:
        kind = "cidr"
    return kind, value


def _timestamp(value: object, field: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise IntelRecordError("invalid_record", f"{field} must be a STIX timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise IntelRecordError("invalid_record", f"{field} is not a valid timestamp") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _strings(value: object, limit: int, pattern: re.Pattern[str] = _TAG) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise IntelRecordError("invalid_record", "expected a list of strings")
    result: list[str] = []
    for item in value[:limit]:
        if isinstance(item, str) and pattern.match(item.strip()):
            text = clean_text(item, 64)
            if text and text not in result:
                result.append(text)
    return result


def classification(types: list[str]) -> str:
    lowered = {t.lower() for t in types}
    if lowered & _MALICIOUS:
        return "malicious"
    if lowered & _SUSPICIOUS:
        return "suspicious"
    if "benign" in lowered:
        return "benign"
    return "unknown"


def _references(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    urls: list[str] = []
    for item in value[:MAX_REFERENCES]:
        url = item.get("url") if isinstance(item, dict) else None
        if not isinstance(url, str):
            continue
        try:
            urls.append(safe_reference(url))
        except ValueError:
            continue  # una referencia rara no invalida el indicador: se descarta sola
    return urls


def _indicator(obj: dict[str, Any], related: list[tuple[str, str]]) -> IndicatorRecord | None:
    """IndicatorRecord, None si el patrón no está soportado, o IntelRecordError."""
    pattern_type = obj.get("pattern_type", "stix")
    pattern = obj.get("pattern")
    if pattern_type != "stix" or not isinstance(pattern, str):
        return None
    parsed = parse_pattern(pattern)
    if parsed is None:
        return None
    kind, value = parsed
    normalized = normalize(kind, value)
    types = _strings(obj.get("indicator_types"), MAX_TAGS) or _strings(obj.get("labels"), MAX_TAGS)
    raw_confidence = obj.get("confidence")
    score: int | None = None
    if raw_confidence is not None:
        if (
            not isinstance(raw_confidence, int)
            or isinstance(raw_confidence, bool)
            or not 0 <= raw_confidence <= 100
        ):
            raise IntelRecordError("invalid_record", "confidence must be an integer 0-100")
        score = raw_confidence
    revoked = obj.get("revoked", False)
    if not isinstance(revoked, bool):
        raise IntelRecordError("invalid_record", "revoked must be a boolean")
    name = clean_text(obj.get("name"), 200) if isinstance(obj.get("name"), str) else None
    description = obj.get("description")
    text = clean_text(description, 1000) if isinstance(description, str) else None
    if name and text:
        text = f"{name}: {text}"[:1000]
    return IndicatorRecord(
        indicator_type=normalized.indicator_type,
        value=normalized.value,
        original=normalized.original,
        network=normalized.network,
        classification=classification(types),
        # Sin confidence declarada: "medium" (valor por defecto prudente). El original queda
        # en confidence_score = None para no inventar una cifra.
        confidence=confidence_from_score(score) if score is not None else "medium",
        confidence_score=score,
        valid_from=_timestamp(obj.get("valid_from"), "valid_from"),
        valid_until=_timestamp(obj.get("valid_until"), "valid_until"),
        revoked=revoked,
        first_seen=_timestamp(obj.get("created"), "created"),
        last_seen=_timestamp(obj.get("modified"), "modified"),
        tags=tuple(_strings(obj.get("labels"), MAX_TAGS)),
        description=text,
        references=tuple(_references(obj.get("external_references"))),
        related=tuple(related[:MAX_RELATED]),
        external_id=obj.get("id") if isinstance(obj.get("id"), str) else None,
        pattern=pattern.strip()[:MAX_PATTERN],
    )


def parse(raw: bytes, limits: StixLimits) -> ParsedIntel:
    document = safe_json.loads(raw, limits.max_bytes, limits.max_depth)
    if not isinstance(document, dict) or not isinstance(document.get("objects"), list):
        raise IntelFormatError("intel_invalid_format", "Not a STIX 2.x bundle")
    if document.get("type", "bundle") != "bundle":
        raise IntelFormatError("intel_invalid_format", "Not a STIX 2.x bundle")
    objects = document["objects"]
    if len(objects) > limits.max_objects:
        raise IntelFormatError("intel_too_many_records", f"More than {limits.max_objects} objects")
    parsed = ParsedIntel(format=FORMAT)
    spec = document.get("spec_version")
    parsed.source_version = clean_text(spec, 16) if isinstance(spec, str) else None

    # Primera pasada: nombres de los objetos de contexto y relaciones "indicates".
    names: dict[str, tuple[str, str]] = {}
    links: dict[str, list[str]] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        obj_type, obj_id = obj.get("type"), obj.get("id")
        if not isinstance(obj_id, str) or not _ID.match(obj_id):
            continue
        if obj_type in CONTEXT_TYPES and isinstance(obj.get("name"), str):
            name = clean_text(obj["name"], 200)
            if name:
                names[obj_id] = (str(obj_type), name)
        elif obj_type == "relationship" and obj.get("relationship_type") == "indicates":
            source, target = obj.get("source_ref"), obj.get("target_ref")
            if isinstance(source, str) and isinstance(target, str):
                links.setdefault(source, []).append(target)

    seen: set[tuple[str, str]] = set()
    for index, obj in enumerate(objects):
        if not isinstance(obj, dict):
            parsed.add_invalid(
                InvalidRecord(index, "invalid_record", "object must be a JSON object")
            )
            continue
        obj_type = obj.get("type")
        obj_id = obj.get("id")
        reference = obj_id[:128] if isinstance(obj_id, str) else None
        if obj_type != "indicator":
            if obj_type not in CONTEXT_TYPES and obj_type not in (
                "relationship",
                "identity",
                "marking-definition",
            ):
                parsed.add_unsupported(f"object_type:{str(obj_type)[:32]}")
            continue
        if not isinstance(obj_id, str) or not _ID.match(obj_id):
            parsed.add_invalid(InvalidRecord(index, "invalid_record", "indicator without valid id"))
            continue
        related = [names[target] for target in links.get(obj_id, []) if target in names]
        try:
            record = _indicator(obj, related)
        except IntelRecordError as exc:
            parsed.add_invalid(InvalidRecord(index, exc.code, str(exc), reference))
            continue
        if record is None:
            parsed.add_unsupported("unsupported_pattern")
            continue
        if record.key in seen:
            # Dos indicadores del mismo bundle con el mismo valor: se queda el primero.
            parsed.add_unsupported("duplicate_indicator")
            continue
        seen.add(record.key)
        parsed.indicators.append(record)
    return parsed
