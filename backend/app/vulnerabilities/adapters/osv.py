"""Adapter de OSV (https://ossf.github.io/osv-schema/) para paquetes de distribución. Puro.

Solo los ecosistemas que Sentra inventaría de verdad (agente Linux con dpkg o rpm):
- Debian:<versión> (dpkg). OSV usa el paquete FUENTE ("openssh"); el agente informa paquetes
  binarios ("openssh-server"), así que la coincidencia se limita a "probable" y solo casa
  cuando el binario se llama igual que el fuente (source_package);
- Ubuntu:<versión>[:LTS] (dpkg). Los USN traen la lista de binarios
  (ecosystem_specific.binaries) y se usa esa;
- AlmaLinux:<versión>, Rocky Linux:<versión> y Red Hat:enterprise_linux:<versión> (rpm),
  con nombres de paquete binario.

Lo que NO aplica y se descarta contando el motivo (`ecosystem_not_inventoried`): PyPI, npm,
Maven, Go, crates.io, NuGet, RubyGems, Packagist, Hex, Pub, Alpine/Wolfi/Chainguard (apk),
SUSE/openSUSE, Mageia, Photon OS, Android, GitHub Actions, Linux (kernel upstream)... El
software de Windows no tiene ecosistema OSV (el agente lo inventaría desde el registro) y
macOS tampoco (Homebrew no publica en OSV): para ellos la fuente es NVD.

El agente no informa todavía la versión de la distribución: el matcher mantiene
`distro_release_unknown` (como mucho "probable") aunque el rango venga de Debian 12.
"""

import io
import re
import unicodedata
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from app.threat_intel import safe_json
from app.threat_intel.errors import IntelFormatError
from app.vulnerabilities.adapters import (
    Converted,
    Invalid,
    Skipped,
    SourceFormatError,
    SourceRecord,
    Tombstone,
)
from app.vulnerabilities.catalog import safe_reference

FORMAT = "osv"
DEFAULT_URL = "https://osv-vulnerabilities.storage.googleapis.com"
REFERENCE_URL = "https://google.github.io/osv.dev/data/"
# Ecosistemas que se pueden descargar (all.zip por ecosistema) porque Sentra los inventaría.
DOWNLOAD_ECOSYSTEMS = ("Debian", "Ubuntu", "AlmaLinux", "Rocky Linux", "Red Hat")
MAX_ENTRY_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_RANGES = 200
MAX_PACKAGES = 100

_ID = re.compile(r"^[A-Za-z][A-Za-z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{1,60}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_CWE = re.compile(r"^(?:CWE-\d{1,6}|NVD-CWE-Other|NVD-CWE-noinfo)$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_RELEASE = re.compile(r"^\d{1,4}(?:\.\d{1,4})?$")
# Severidad cualitativa de las propias distribuciones (Ubuntu priority, Red Hat/Alma/Rocky).
_QUALITATIVE = {
    "negligible": "informational",
    "low": "low",
    "moderate": "medium",
    "medium": "medium",
    "important": "high",
    "high": "high",
    "critical": "critical",
}
_SUMMARY_SEVERITY = re.compile(r"^(Critical|Important|Moderate|Low):\s")
_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def download_url(base: str, ecosystem: str) -> str:
    """all.zip de un ecosistema bajo la base oficial (o la de VULN_SOURCE_URLS)."""
    return f"{base.rstrip('/')}/{quote(ecosystem)}/all.zip"


@dataclass(frozen=True)
class Target:
    ecosystem: str  # deb | rpm
    distro: str
    source_names: bool


def target(ecosystem: object) -> Target | None:
    """Ecosistema OSV -> (deb|rpm, distribución). None si Sentra no lo inventaría."""
    if not isinstance(ecosystem, str):
        return None
    parts = ecosystem.split(":")
    base = parts[0]
    release = parts[1] if len(parts) > 1 and _RELEASE.match(parts[1]) else None
    if base == "Debian":
        return Target("deb", f"debian:{release}" if release else "debian", True)
    if base == "Ubuntu":
        if release:
            return Target("deb", f"ubuntu:{release}", True)
        if len(parts) > 2 and parts[1] == "Pro" and _RELEASE.match(parts[2]):
            return Target("deb", f"ubuntu:pro:{parts[2]}", True)
        return Target("deb", "ubuntu", True)
    if base == "AlmaLinux":
        return Target("rpm", f"almalinux:{release}" if release else "almalinux", False)
    if base == "Rocky Linux":
        return Target("rpm", f"rocky:{release}" if release else "rocky", False)
    if base == "Red Hat" and len(parts) > 2 and parts[1] == "enterprise_linux":
        major = parts[2] if _RELEASE.match(parts[2]) else None
        return Target("rpm", f"rhel:{major}" if major else "rhel", False)
    return None


def _text(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFC", value.replace("\x00", ""))
    text = _CONTROL.sub("", text).strip()
    return text[:limit] or None


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    # OSV publica nanosegundos ("...09:47:30.250301196Z"): Python acepta hasta microsegundos.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _ranges(affected: dict[str, Any]) -> list[dict[str, str]]:
    """Eventos introduced/fixed/last_affected de rangos ECOSYSTEM -> rangos declarativos."""
    ranges: list[dict[str, str]] = []
    for range_ in affected.get("ranges") or []:
        if not isinstance(range_, dict) or range_.get("type") != "ECOSYSTEM":
            # GIT/SEMVER no describen versiones de paquetes de distribución.
            continue
        low: str | None = None
        open_ = False
        for event in range_.get("events") or []:
            if not isinstance(event, dict):
                continue
            if isinstance(event.get("introduced"), str):
                low, open_ = event["introduced"], True
            elif open_ and isinstance(event.get("fixed"), str):
                ranges.append(_bounds(low, "lt", event["fixed"]))
                open_ = False
            elif open_ and isinstance(event.get("last_affected"), str):
                ranges.append(_bounds(low, "lte", event["last_affected"]))
                open_ = False
        if open_:
            # Sin versión corregida: afectadas todas desde "introduced".
            ranges.append({"gte": low if low and low != "0" else "0"})
    if not ranges:
        listed = [v for v in affected.get("versions") or [] if isinstance(v, str)]
        ranges = [{"eq": v} for v in listed[:MAX_RANGES]]
    return ranges


def _bounds(low: str | None, op: str, high: str) -> dict[str, str]:
    bounds = {op: high}
    if low and low != "0":
        bounds["gte"] = low
    return bounds


def _severity(document: dict[str, Any]) -> str | None:
    """Severidad cualitativa publicada por la fuente (nunca calculada a partir del vector)."""
    found: list[str] = []
    for entry in document.get("severity") or []:
        if isinstance(entry, dict) and entry.get("type") == "Ubuntu":
            found.append(str(entry.get("score", "")).lower())
    for affected in document.get("affected") or []:
        specific = affected.get("database_specific") if isinstance(affected, dict) else None
        cves = ((specific or {}).get("cves_map") or {}).get("cves") or []
        for cve in cves if isinstance(cves, list) else []:
            for entry in (cve.get("severity") or []) if isinstance(cve, dict) else []:
                if isinstance(entry, dict) and entry.get("type") == "Ubuntu":
                    found.append(str(entry.get("score", "")).lower())
    specific = document.get("database_specific")
    if isinstance(specific, dict) and isinstance(specific.get("severity"), str):
        found.append(specific["severity"].lower())
    summary = document.get("summary")
    if isinstance(summary, str):
        match = _SUMMARY_SEVERITY.match(summary)
        if match:
            found.append(match.group(1).lower())
    mapped = [_QUALITATIVE[s] for s in found if s in _QUALITATIVE]
    return max(mapped, key=lambda s: _RANK[s]) if mapped else None


def _cvss(document: dict[str, Any]) -> dict[str, Any] | None:
    """Vector CVSS publicado (sin puntuación: OSV no la trae y Sentra no la calcula)."""
    for wanted in ("CVSS_V3", "CVSS_V4"):
        for entry in document.get("severity") or []:
            if not isinstance(entry, dict) or entry.get("type") != wanted:
                continue
            vector = entry.get("score")
            if not isinstance(vector, str) or len(vector) > 256:
                continue
            for version in ("3.1", "3.0", "4.0"):
                if vector.startswith(f"CVSS:{version}/"):
                    return {"version": version, "vector": vector}
    return None


def _aliases(document: dict[str, Any], own: str) -> list[str]:
    values: set[str] = set()
    for field in ("aliases", "upstream", "related"):
        for value in document.get(field) or []:
            if isinstance(value, str) and _ID.match(value.strip()) and value.strip() != own:
                values.add(value.strip().upper() if value.upper().startswith("CVE-") else value)
    # CVE primero (el primer alias CVE es el que enlaza con KEV/EPSS) y como mucho 20.
    return sorted(values, key=lambda v: (not _CVE.match(v), v))[:20]


def convert(
    document: object,
    index: int,
    retrieved_at: datetime,
    content_sha256: str | None,
    *,
    prefer_cve_records: bool = False,
) -> Converted:
    if not isinstance(document, dict):
        return Skipped(index, None, "invalid_entry")
    raw_id = document.get("id")
    osv_id = raw_id.strip() if isinstance(raw_id, str) else ""
    if not _ID.match(osv_id) or len(osv_id) > 64:
        return Skipped(index, None, "invalid_entry")
    if osv_id.upper().startswith("CVE-"):
        osv_id = osv_id.upper()
    if document.get("withdrawn"):
        return Tombstone(index, osv_id, "osv_withdrawn")
    if prefer_cve_records and osv_id.startswith("USN-"):
        # El all.zip de Ubuntu trae también un registro por CVE (UBUNTU-CVE-*): un USN con
        # varios CVE solo enlazaría KEV/EPSS del primero y duplicaría findings.
        upstream = document.get("upstream") or []
        if any(isinstance(u, str) and u.startswith("UBUNTU-CVE-") for u in upstream):
            return Skipped(index, osv_id, "superseded_by_cve_record")
    groups: dict[tuple[str, str, bool, str], dict[str, Any]] = {}
    ecosystems: set[str] = set()
    ignored = 0
    for affected in document.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict):
            continue
        destination = target(package.get("ecosystem"))
        name = package.get("name")
        if destination is None or not isinstance(name, str):
            ignored += 1
            continue
        ranges = _ranges(affected)
        if not ranges:
            ignored += 1
            continue
        ecosystems.add(str(package.get("ecosystem"))[:40])
        names = [name]
        source_names = destination.source_names
        specific = affected.get("ecosystem_specific")
        binaries = specific.get("binaries") if isinstance(specific, dict) else None
        if isinstance(binaries, list):
            listed = [
                str(b["binary_name"])
                for b in binaries
                if isinstance(b, dict) and isinstance(b.get("binary_name"), str)
            ]
            if listed:
                # Ubuntu: paquetes binarios publicados por la propia distribución.
                names, source_names = sorted(set(listed)), False
        key = (destination.ecosystem, destination.distro, source_names, repr(ranges))
        group = groups.setdefault(
            key,
            {
                "type": "package",
                "product": name[:128],
                "packages": [],
                "ranges": ranges[:MAX_RANGES],
                "distro": destination.distro,
                "source_package": source_names,
                "platforms": ["linux"],
            },
        )
        for package_name in names:
            entry = {"ecosystem": destination.ecosystem, "name": package_name.lower()}
            if entry not in group["packages"] and len(group["packages"]) < MAX_PACKAGES:
                group["packages"].append(entry)
        if len(ranges) == 1 and set(ranges[0]) <= {"lt", "gte"} and "lt" in ranges[0]:
            group["fixed_version"] = ranges[0]["lt"][:128]
    if not groups:
        return Skipped(index, osv_id, "ecosystem_not_inventoried")
    details = _text(document.get("details"), 10_000)
    summary = _text(document.get("summary"), 300)
    published = _timestamp(document.get("published"))
    modified = _timestamp(document.get("modified"))
    references: list[str] = []
    for reference in document.get("references") or []:
        url = reference.get("url") if isinstance(reference, dict) else None
        try:
            clean = safe_reference(url) if isinstance(url, str) else None
        except ValueError:
            clean = None
        if clean is not None and clean not in references:
            references.append(clean)
    specific = document.get("database_specific")
    cwe_ids = specific.get("cwe_ids") if isinstance(specific, dict) else None
    cwe = sorted({c for c in cwe_ids or [] if isinstance(c, str) and _CWE.match(c)})[:20]
    aliases = _aliases(document, osv_id)
    severity = _severity(document)
    data: dict[str, Any] = {
        "id": osv_id,
        "aliases": aliases,
        "title": summary or _first_sentence(details) or osv_id,
        "description": details,
        "severity": severity,
        "cvss": _cvss(document),
        "published_at": published.isoformat() if published else None,
        "modified_at": modified.isoformat() if modified else None,
        "references": references[:200],
        "cwe": cwe,
        "affected": list(groups.values())[:500],
        "metadata": {"osv_ecosystems": ",".join(sorted(ecosystems))[:200]},
    }
    provenance = {
        "adapter": "osv",
        "format": FORMAT,
        "upstream_id": osv_id,
        "retrieved_at": retrieved_at.isoformat(),
        "content_sha256": content_sha256,
        "attributes": {
            "description": "osv",
            "references": "osv",
            "cvss": "osv_vector" if data["cvss"] else None,
            "severity": "osv_distribution_rating" if severity else None,
            "affected": "osv_ecosystem_ranges",
            "published": "osv",
            "modified": "osv",
            "exploitation": "threat_intel:cisa_kev",
            "epss": "threat_intel:first_epss",
        },
        "dropped": {"affected_not_inventoried": ignored},
    }
    cves = [a for a in aliases if _CVE.match(a)]
    return SourceRecord(
        index, osv_id, data, provenance, severity_from=cves if severity is None else []
    )


def _first_sentence(text: str | None) -> str | None:
    if not text:
        return None
    sentence = " ".join(text.split())
    cut = sentence.find(". ")
    if 0 < cut < 200:
        return sentence[: cut + 1]
    return sentence[:197].rsplit(" ", 1)[0] + "..." if len(sentence) > 200 else sentence


# --- Contenedores: JSON suelto, lista o all.zip --------------------------------------------------


def iter_documents(
    raw: bytes, max_bytes: int, max_records: int
) -> Iterator[tuple[int, object | Invalid]]:
    """(índice, documento OSV | Invalid). SourceFormatError si el contenedor entero falla."""
    if raw[:4] == b"PK\x03\x04":
        yield from _iter_zip(raw, max_bytes, max_records)
        return
    try:
        document = safe_json.loads(raw, max_bytes, MAX_DEPTH)
    except IntelFormatError as exc:
        code = "too_large" if exc.code == "intel_too_large" else "invalid_json"
        raise SourceFormatError(code, "OSV content is not complete, valid JSON") from None
    if isinstance(document, dict) and isinstance(document.get("vulns"), list):
        items: list[object] = document["vulns"]
    elif isinstance(document, list):
        items = document
    elif isinstance(document, dict):
        items = [document]
    else:
        raise SourceFormatError("invalid_format", "OSV content must be an object or a list")
    if len(items) > max_records:
        raise SourceFormatError("too_many_records", f"More than {max_records} OSV records")
    yield from enumerate(items)


def _iter_zip(
    raw: bytes, max_bytes: int, max_records: int
) -> Iterator[tuple[int, object | Invalid]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise SourceFormatError(
            "invalid_archive", "The OSV archive is corrupt or truncated"
        ) from None
    with archive:
        entries = [i for i in archive.infolist() if not i.is_dir()]
        if len(entries) > max_records:
            raise SourceFormatError("too_many_records", f"More than {max_records} OSV records")
        total = 0
        for index, info in enumerate(entries):
            if not info.filename.endswith(".json"):
                yield index, Invalid(index, None, "unexpected_entry", "not a JSON file")
                continue
            if info.file_size > MAX_ENTRY_BYTES:
                yield index, Invalid(index, None, "entry_too_large", "record file too large")
                continue
            try:
                with archive.open(info) as handle:
                    # Se lee como mucho el límite + 1: el tamaño declarado puede mentir.
                    data = handle.read(MAX_ENTRY_BYTES + 1)
            except (zipfile.BadZipFile, OSError, EOFError):
                raise SourceFormatError(
                    "invalid_archive", "The OSV archive is corrupt or truncated"
                ) from None
            total += len(data)
            if len(data) > MAX_ENTRY_BYTES:
                yield index, Invalid(index, None, "entry_too_large", "record file too large")
                continue
            if total > max_bytes:
                # Bomba de descompresión: el total descomprimido también está acotado.
                raise SourceFormatError(
                    "too_large", f"OSV archive expands beyond {max_bytes} bytes"
                )
            try:
                yield index, safe_json.loads(data, MAX_ENTRY_BYTES, MAX_DEPTH)
            except IntelFormatError:
                yield index, Invalid(index, None, "invalid_json", "record is not valid JSON")
