"""Parser del catálogo CISA Known Exploited Vulnerabilities (JSON oficial). Puro.

Semántica (docs/threat-intelligence.md): que un CVE esté en KEV significa "CISA tiene
evidencia de explotación activa de esta vulnerabilidad en el mundo". NO significa que un
activo de Sentra haya sido explotado ni que sea vulnerable: eso lo decide el matcher 5B con
el inventario. `knownRansomwareCampaignUse` se guarda tal cual ("Known"/"Unknown"):
"Unknown" NO quiere decir "sin ransomware" ni "seguro".

El feed se valida entero antes de tocar la base de datos. Campos desconocidos se ignoran
(CISA puede añadir columnas); los conocidos se acotan y sanean como texto no confiable.
"""

import re
import unicodedata
from collections.abc import Iterator
from datetime import UTC, date, datetime
from typing import Any

from app.threat_intel import safe_json
from app.threat_intel.errors import IntelFormatError, IntelRecordError
from app.threat_intel.records import InvalidRecord, ParsedIntel, VulnIntelRecord

FORMAT = "cisa-kev"
DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REFERENCE_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_CWE = re.compile(r"^(?:CWE-\d{1,6}|NVD-CWE-Other|NVD-CWE-noinfo)$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# KEV tiene ~1 500 entradas; esto deja mucho margen sin aceptar un fichero absurdo.
MAX_RECORDS = 100_000


def clean_text(value: object, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise IntelRecordError("invalid_record", "expected a text value")
    text = unicodedata.normalize("NFC", value.replace("\x00", ""))
    text = " ".join(_CONTROL.sub("", text).split())
    return text[:limit] or None


def _date(value: object, field: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise IntelRecordError("invalid_record", f"{field} must be a date")
    try:
        return date.fromisoformat(value[:10]).isoformat()
    except ValueError:
        raise IntelRecordError("invalid_record", f"{field} is not a valid date") from None


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _record(item: Any) -> VulnIntelRecord:
    if not isinstance(item, dict):
        raise IntelRecordError("invalid_record", "entry must be an object")
    cve = item.get("cveID")
    if not isinstance(cve, str) or not CVE.match(cve.strip().upper()):
        raise IntelRecordError("invalid_cve", "entry has no valid cveID")
    cve = cve.strip().upper()
    added = _date(item.get("dateAdded"), "dateAdded")
    if added is None:
        raise IntelRecordError("invalid_record", "dateAdded is required")
    ransomware = clean_text(item.get("knownRansomwareCampaignUse"), 16)
    cwes_raw = item.get("cwes") or []
    if not isinstance(cwes_raw, list):
        raise IntelRecordError("invalid_record", "cwes must be a list")
    cwes = [c.strip() for c in cwes_raw[:20] if isinstance(c, str) and _CWE.match(c.strip())]
    data = {
        "date_added": added,
        "due_date": _date(item.get("dueDate"), "dueDate"),
        "required_action": clean_text(item.get("requiredAction"), 600),
        # Valor literal de CISA ("Known" / "Unknown"). "Unknown" no es "no".
        "known_ransomware_use": ransomware.lower() if ransomware else None,
        "vendor_project": clean_text(item.get("vendorProject"), 128),
        "product": clean_text(item.get("product"), 128),
        "vulnerability_name": clean_text(item.get("vulnerabilityName"), 300),
        "short_description": clean_text(item.get("shortDescription"), 1000),
        "notes": clean_text(item.get("notes"), 1000),
        "cwes": cwes,
    }
    published = datetime.fromisoformat(added).replace(tzinfo=UTC)
    return VulnIntelRecord(
        kind="kev", cve_id=cve, data=data, external_id=cve, published_at=published
    )


def parse(raw: bytes, max_bytes: int, max_records: int = MAX_RECORDS) -> ParsedIntel:
    """Valida el feed completo. IntelFormatError si la estructura no es la de KEV."""
    document = safe_json.loads(raw, max_bytes)
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise IntelFormatError("intel_invalid_format", "Not a CISA KEV catalog")
    items = document["vulnerabilities"]
    if len(items) > max_records:
        raise IntelFormatError("intel_too_many_records", f"More than {max_records} records")
    parsed = ParsedIntel(format=FORMAT, complete=True)
    version = document.get("catalogVersion")
    parsed.source_version = clean_text(version, 64) if isinstance(version, str) else None
    parsed.published_at = _timestamp(document.get("dateReleased"))
    seen: set[str] = set()
    for index, item in enumerate(items):
        try:
            record = _record(item)
        except IntelRecordError as exc:
            ref = item.get("cveID") if isinstance(item, dict) else None
            parsed.add_invalid(
                InvalidRecord(index, exc.code, str(exc), str(ref)[:64] if ref else None)
            )
            continue
        if record.cve_id in seen:
            parsed.add_unsupported("duplicate_cve")
            continue
        seen.add(record.cve_id)
        parsed.vulnerabilities.append(record)
    # Un feed "completo" con todo inválido desactivaría todos los CVEs: se rechaza entero.
    if items and not parsed.vulnerabilities:
        raise IntelFormatError("intel_invalid_format", "No valid KEV entries in the feed")
    return parsed


def iter_records(parsed: ParsedIntel) -> Iterator[VulnIntelRecord]:
    yield from parsed.vulnerabilities
