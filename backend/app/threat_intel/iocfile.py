"""Formato JSON propio de importación de IOCs: sentra-ioc/1. Puro, sin base de datos.

    {
      "format": "sentra-ioc/1",
      "indicators": [
        {"type": "ipv4", "value": "203.0.113.7", "classification": "malicious",
         "confidence": "high", "valid_until": "2026-12-31T00:00:00Z",
         "tags": ["botnet"], "description": "...", "references": ["https://..."]}
      ]
    }

`classification` es OBLIGATORIA: Sentra nunca asume "malicious" por el mero hecho de que un
valor aparezca en un fichero. `confidence` es opcional (por defecto "medium"). Ver
docs/threat-intel-sources.md.
"""

from datetime import UTC, datetime
from typing import Any

from app.threat_intel import safe_json
from app.threat_intel.errors import IntelFormatError, IntelRecordError
from app.threat_intel.indicators import CLASSIFICATIONS, CONFIDENCES, normalize
from app.threat_intel.kev import clean_text
from app.threat_intel.records import IndicatorRecord, InvalidRecord, ParsedIntel
from app.threat_intel.stix import MAX_REFERENCES, MAX_TAGS, StixLimits, _strings
from app.vulnerabilities.catalog import safe_reference

FORMAT = "sentra-ioc/1"
_KEYS = frozenset(
    {
        "type",
        "value",
        "classification",
        "confidence",
        "valid_from",
        "valid_until",
        "revoked",
        "first_seen",
        "last_seen",
        "tags",
        "description",
        "references",
        "id",
    }
)


def _timestamp(value: object, field: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise IntelRecordError("invalid_record", f"{field} must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise IntelRecordError("invalid_record", f"{field} is not a valid timestamp") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _record(item: Any) -> IndicatorRecord:
    if not isinstance(item, dict):
        raise IntelRecordError("invalid_record", "indicator must be an object")
    unknown = set(item) - _KEYS
    if unknown:
        raise IntelRecordError("invalid_record", "unknown keys in indicator")
    normalized = normalize(str(item.get("type")), item.get("value"))
    classification = item.get("classification")
    if classification not in CLASSIFICATIONS:
        raise IntelRecordError(
            "invalid_classification", "classification is required (malicious, suspicious...)"
        )
    confidence = item.get("confidence", "medium")
    if confidence not in CONFIDENCES:
        raise IntelRecordError("invalid_record", "confidence must be low, medium or high")
    revoked = item.get("revoked", False)
    if not isinstance(revoked, bool):
        raise IntelRecordError("invalid_record", "revoked must be a boolean")
    refs_raw = item.get("references") or []
    if not isinstance(refs_raw, list):
        raise IntelRecordError("invalid_record", "references must be a list")
    references: list[str] = []
    for url in refs_raw[:MAX_REFERENCES]:
        try:
            references.append(safe_reference(url))
        except ValueError:
            raise IntelRecordError("invalid_reference", "references must be http(s) URLs") from None
    description = item.get("description")
    if description is not None and not isinstance(description, str):
        raise IntelRecordError("invalid_record", "description must be text")
    external = item.get("id")
    return IndicatorRecord(
        indicator_type=normalized.indicator_type,
        value=normalized.value,
        original=normalized.original,
        network=normalized.network,
        classification=classification,
        confidence=confidence,
        valid_from=_timestamp(item.get("valid_from"), "valid_from"),
        valid_until=_timestamp(item.get("valid_until"), "valid_until"),
        revoked=revoked,
        first_seen=_timestamp(item.get("first_seen"), "first_seen"),
        last_seen=_timestamp(item.get("last_seen"), "last_seen"),
        tags=tuple(_strings(item.get("tags"), MAX_TAGS)),
        description=clean_text(description, 1000),
        references=tuple(references),
        external_id=clean_text(external, 128) if isinstance(external, str) else None,
    )


def parse(raw: bytes, limits: StixLimits) -> ParsedIntel:
    document = safe_json.loads(raw, limits.max_bytes, limits.max_depth)
    if not isinstance(document, dict) or document.get("format") != FORMAT:
        raise IntelFormatError("intel_invalid_format", f"Unsupported format (expected {FORMAT})")
    if set(document) - {"format", "indicators", "description"}:
        raise IntelFormatError("intel_invalid_format", "Unknown top-level keys")
    items = document.get("indicators")
    if not isinstance(items, list):
        raise IntelFormatError("intel_invalid_format", "'indicators' must be a list")
    if len(items) > limits.max_objects:
        raise IntelFormatError("intel_too_many_records", f"More than {limits.max_objects} records")
    parsed = ParsedIntel(format=FORMAT)
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(items):
        try:
            record = _record(item)
        except IntelRecordError as exc:
            ref = item.get("value") if isinstance(item, dict) else None
            # El valor del IOC se muestra acotado: ayuda a corregir el fichero y no es un secreto.
            parsed.add_invalid(
                InvalidRecord(index, exc.code, str(exc), str(ref)[:128] if ref else None)
            )
            continue
        if record.key in seen:
            parsed.add_unsupported("duplicate_indicator")
            continue
        seen.add(record.key)
        parsed.indicators.append(record)
    return parsed
