"""Adapter de NVD CVE API 2.0 (y de sus ficheros de datos JSON 2.0). Puro.

Formato: https://nvd.nist.gov/developers/vulnerabilities. Una respuesta de la API y un fichero
de datos 2.0 tienen la misma forma: {resultsPerPage, startIndex, totalResults, format:
"NVD_CVE", version: "2.0", timestamp, vulnerabilities: [{cve: {...}}]}.

Protecciones (el contenido es dato no confiable):
- JSON estricto con tamaño y profundidad acotados (threat_intel.safe_json); un JSON truncado
  no se parsea y la página entera se rechaza;
- coherencia de la paginación: startIndex pedido, len(vulnerabilities) == resultsPerPage y
  totalResults estable; el llamador comprueba al final recibidos == totalResults;
- cada CVE se convierte por separado: uno malformado se descarta con su índice y código.

Qué se toma de NVD (ATTRIBUTE_SOURCES["nvd"]): id, descripción en inglés, referencias http(s),
CVSS (Primary de NVD; si no hay, Secondary del CNA; v3.1 > v4.0 > v3.0 > v2), CWE, fechas y
configuraciones CPE 2.3 con sus rangos. Lo que NO se toma: los campos cisa* (la explotación
conocida la aporta la fuente CISA KEV de Threat Intelligence; copiarla duplicaría el dato y
podría contar dos veces en el riesgo).
"""

import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from app.threat_intel import safe_json
from app.threat_intel.errors import IntelFormatError
from app.vulnerabilities import cpe as cpe_mod
from app.vulnerabilities.adapters import (
    Converted,
    Skipped,
    SourceFormatError,
    SourceRecord,
    Tombstone,
)
from app.vulnerabilities.catalog import safe_reference, severity_from_score

FORMAT = "nvd-cve-2.0"
DEFAULT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REFERENCE_URL = "https://nvd.nist.gov/developers/vulnerabilities"
MAX_RESULTS_PER_PAGE = 2000
# NVD limita lastModStartDate/lastModEndDate a 120 días consecutivos.
MAX_WINDOW = timedelta(days=120)
# Límite público de NVD: 5 peticiones por 30 s sin API key y 50 con ella.
RATE_WINDOW_SECONDS = 30.0
RATE_WITHOUT_KEY = 5
RATE_WITH_KEY = 50
MAX_DEPTH = 32

_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_CWE = re.compile(r"^(?:CWE-\d{1,6}|NVD-CWE-Other|NVD-CWE-noinfo)$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Preferencia de métricas: versión y después Primary (NVD) antes que Secondary (CNA).
_METRICS = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
_SEVERITY = {
    "none": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}
# Condición que no se puede verificar nunca: un nodo negado de NVD ("no ejecutándose en X").
NEGATED_CONDITION = "cpe:2.3:a:sentra:negated_configuration:*:*:*:*:*:*:*:*"
MAX_REFERENCES = 200
MAX_CONDITIONS = 100


@dataclass
class NvdPage:
    results_per_page: int
    start_index: int
    total_results: int
    timestamp: datetime | None
    items: list[Any]


def parse_page(raw: bytes, max_bytes: int) -> NvdPage:
    """Valida la envoltura de una página o fichero 2.0. SourceFormatError si no es coherente."""
    try:
        document = safe_json.loads(raw, max_bytes, MAX_DEPTH)
    except IntelFormatError as exc:
        code = "too_large" if exc.code == "intel_too_large" else "invalid_json"
        raise SourceFormatError(
            code, "NVD content is not complete, valid JSON (truncated or corrupt)"
        ) from None
    if not isinstance(document, dict):
        raise SourceFormatError("invalid_format", "NVD content must be a JSON object")
    if document.get("format", "NVD_CVE") != "NVD_CVE" or not str(
        document.get("version", "2.0")
    ).startswith("2."):
        raise SourceFormatError("invalid_format", "Not an NVD CVE API 2.0 document")
    items = document.get("vulnerabilities")
    numbers = [document.get(k) for k in ("resultsPerPage", "startIndex", "totalResults")]
    if not isinstance(items, list) or not all(
        isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in numbers
    ):
        raise SourceFormatError("invalid_format", "NVD document lacks pagination or results")
    per_page, start, total = (int(n) for n in numbers)  # type: ignore[arg-type]
    if len(items) != per_page or start + per_page > total:
        # resultsPerPage es lo que NVD dice que envía en ESTA página: si no coincide, la
        # respuesta llegó incompleta (corte de un proxy, error del servidor).
        raise SourceFormatError(
            "incomplete_response", "NVD page does not contain the announced number of results"
        )
    return NvdPage(per_page, start, total, _timestamp(document.get("timestamp")), items)


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # NVD publica las fechas en UTC sin zona.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _text(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFC", value.replace("\x00", ""))
    text = _CONTROL.sub("", text).strip()
    return text[:limit] or None


def _title(cve_id: str, description: str | None) -> str:
    """NVD no publica título: la primera frase de la descripción (acotada)."""
    if not description:
        return cve_id
    sentence = " ".join(description.split())
    cut = sentence.find(". ")
    if 0 < cut < 200:
        sentence = sentence[: cut + 1]
    if len(sentence) > 200:
        sentence = sentence[:197].rsplit(" ", 1)[0] + "..."
    return sentence


def _metric(metrics: dict[str, Any]) -> tuple[dict[str, Any], str, dict[str, Any]] | None:
    for name, version in _METRICS:
        entries = metrics.get(name)
        if not isinstance(entries, list):
            continue
        ranked = sorted(
            (e for e in entries if isinstance(e, dict) and isinstance(e.get("cvssData"), dict)),
            key=lambda e: 0 if e.get("type") == "Primary" else 1,
        )
        if ranked:
            return ranked[0], version, ranked[0]["cvssData"]
    return None


def _cvss(metrics: object) -> tuple[str, dict[str, Any], dict[str, Any]] | None:
    """(severidad, cvss, procedencia) de la métrica preferida; None si NVD no tiene ninguna."""
    if not isinstance(metrics, dict):
        return None
    chosen = _metric(metrics)
    if chosen is None:
        return None
    entry, version, data = chosen
    score = data.get("baseScore")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10:
        return None
    vector = data.get("vectorString")
    raw_severity = data.get("baseSeverity") or entry.get("baseSeverity")
    severity = _SEVERITY.get(str(raw_severity).lower()) if raw_severity else None
    cvss: dict[str, Any] = {"version": version, "score": float(score)}
    if isinstance(vector, str) and len(vector) <= 256:
        cvss["vector"] = vector
    provenance = {
        "source": _text(entry.get("source"), 120),
        "type": entry.get("type") if entry.get("type") in ("Primary", "Secondary") else None,
        "version": version,
    }
    return severity or severity_from_score(float(score), version), cvss, provenance


def _match(raw: dict[str, Any]) -> dict[str, Any]:
    match: dict[str, Any] = {"criteria": raw.get("criteria")}
    for source, target in (
        ("versionStartIncluding", "version_start_including"),
        ("versionStartExcluding", "version_start_excluding"),
        ("versionEndIncluding", "version_end_including"),
        ("versionEndExcluding", "version_end_excluding"),
    ):
        if raw.get(source) not in (None, ""):
            match[target] = raw[source]
    return match


def _affected(configurations: object) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Configuraciones -> entradas `cpe` agrupadas por producto y condiciones AND."""
    stats = {"hardware_only": 0, "invalid_cpe": 0}
    groups: dict[tuple[str, tuple[str, ...]], list[dict[str, Any]]] = {}
    names: dict[str, tuple[str, str]] = {}
    for configuration in configurations if isinstance(configurations, list) else []:
        if not isinstance(configuration, dict):
            continue
        nodes = [n for n in configuration.get("nodes") or [] if isinstance(n, dict)]
        conjunctive = configuration.get("operator") == "AND"
        for position, node in enumerate(nodes):
            matches = [m for m in node.get("cpeMatch") or [] if isinstance(m, dict)]
            # En un AND, lo que exigen los OTROS nodos son condiciones de este; un nodo
            # negado nunca se puede verificar (queda como condición sin verificar).
            conditions: list[str] = []
            if conjunctive:
                for other_position, other in enumerate(nodes):
                    if other_position == position:
                        continue
                    for m in other.get("cpeMatch") or []:
                        if isinstance(m, dict) and isinstance(m.get("criteria"), str):
                            conditions.append(m["criteria"])
            if node.get("negate"):
                conditions.append(NEGATED_CONDITION)
            for raw in matches:
                if not raw.get("vulnerable") or not isinstance(raw.get("criteria"), str):
                    continue
                try:
                    parsed = cpe_mod.parse(raw["criteria"])
                except cpe_mod.CpeError:
                    stats["invalid_cpe"] += 1
                    continue
                if parsed.part == "h":
                    # Hardware: el inventario de los agentes no describe hardware.
                    stats["hardware_only"] += 1
                    continue
                group_key = (parsed.key, tuple(sorted(set(conditions))))
                match_entry = _match(raw)
                bucket = groups.setdefault(group_key, [])
                if match_entry not in bucket:
                    bucket.append(match_entry)
                names[parsed.key] = (parsed.vendor, parsed.product)
    affected: list[dict[str, Any]] = []
    for (cpe_key, condition_cpes), matches in sorted(groups.items()):
        vendor, product = names[cpe_key]
        entry: dict[str, Any] = {
            "type": "cpe",
            "product": cpe_mod.unescape(product)[:128],
            "vendor": cpe_mod.unescape(vendor)[:128],
            "cpe_match": matches,
            "conditions": list(condition_cpes),
        }
        ends = {m.get("version_end_excluding") for m in matches}
        if len(matches) == 1 and len(ends) == 1 and None not in ends:
            entry["fixed_version"] = str(next(iter(ends)))[:128]
        affected.append(entry)
    return affected, stats


def convert(
    item: object, index: int, retrieved_at: datetime, content_sha256: str | None
) -> Converted:
    """Un elemento de `vulnerabilities` -> registro normalizado, retirada o descarte."""
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return Skipped(index, None, "invalid_entry")
    cve_id = str(cve.get("id") or "").strip().upper()
    if not _CVE.match(cve_id):
        return Skipped(index, None, "invalid_entry")
    status = str(cve.get("vulnStatus") or "")
    if status == "Rejected":
        return Tombstone(index, cve_id, "nvd_rejected")
    description = next(
        (
            _text(d.get("value"), 10_000)
            for d in cve.get("descriptions") or []
            if isinstance(d, dict) and d.get("lang") == "en"
        ),
        None,
    )
    scored = _cvss(cve.get("metrics"))
    if scored is None:
        # Sin métrica (Received, Awaiting Analysis...) no hay severidad que no sea inventada:
        # se descarta hasta que NVD la publique (llegará en una sincronización incremental).
        return Skipped(index, cve_id, "nvd_not_scored")
    severity, cvss, cvss_provenance = scored
    references: list[str] = []
    dropped = 0
    for reference in cve.get("references") or []:
        url = reference.get("url") if isinstance(reference, dict) else None
        try:
            clean = safe_reference(url) if isinstance(url, str) else None
        except ValueError:
            clean = None
        if clean is None:
            dropped += 1
        elif clean not in references:
            references.append(clean)
    truncated = max(len(references) - MAX_REFERENCES, 0)
    cwe = sorted(
        {
            str(d.get("value"))
            for w in cve.get("weaknesses") or []
            if isinstance(w, dict)
            for d in w.get("description") or []
            if isinstance(d, dict) and _CWE.match(str(d.get("value")))
        }
    )[:20]
    affected, stats = _affected(cve.get("configurations"))
    published = _timestamp(cve.get("published"))
    modified = _timestamp(cve.get("lastModified"))
    data: dict[str, Any] = {
        "id": cve_id,
        "title": _title(cve_id, description),
        "description": description,
        "severity": severity,
        "cvss": cvss,
        "published_at": published.isoformat() if published else None,
        "modified_at": modified.isoformat() if modified else None,
        "references": references[:MAX_REFERENCES],
        "cwe": cwe,
        "affected": affected,
        "metadata": {
            "nvd_status": status[:40] or None,
            "source_identifier": _text(cve.get("sourceIdentifier"), 120),
        },
    }
    provenance: dict[str, Any] = {
        "adapter": "nvd",
        "format": FORMAT,
        "upstream_id": cve_id,
        "retrieved_at": retrieved_at.isoformat(),
        "content_sha256": content_sha256,
        "attributes": {
            "description": "nvd",
            "title": "nvd_description_first_sentence",
            "references": "nvd",
            "cvss": cvss_provenance,
            "severity": f"nvd_cvss_{cvss_provenance['version']}",
            "cwe": "nvd",
            "affected": "nvd_configurations",
            "published": "nvd",
            "modified": "nvd",
            "exploitation": "threat_intel:cisa_kev",
            "epss": "threat_intel:first_epss",
        },
        "dropped": {
            "references_invalid": dropped,
            "references_truncated": truncated,
            **stats,
        },
    }
    return SourceRecord(index, cve_id, data, provenance)


def iter_records(
    page: NvdPage, retrieved_at: datetime, content_sha256: str | None, offset: int = 0
) -> Iterator[Converted]:
    for position, item in enumerate(page.items):
        yield convert(item, offset + position, retrieved_at, content_sha256)


# --- Consultas incrementales a la API ----------------------------------------------------------


def _iso(moment: datetime) -> str:
    # Formato que documenta NVD: 2021-08-04T13:00:00.000+00:00 (UTC explícito).
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def windows(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    """Ventanas consecutivas de como mucho 120 días entre start y end."""
    result: list[tuple[datetime, datetime]] = []
    current = start
    while current < end:
        upper = min(current + MAX_WINDOW, end)
        result.append((current, upper))
        current = upper
    return result


def page_url(
    base: str,
    *,
    start_index: int,
    per_page: int,
    window: tuple[datetime, datetime] | None,
) -> str:
    params: dict[str, str] = {
        "resultsPerPage": str(min(max(per_page, 1), MAX_RESULTS_PER_PAGE)),
        "startIndex": str(max(start_index, 0)),
    }
    if window is not None:
        params["lastModStartDate"] = _iso(window[0])
        params["lastModEndDate"] = _iso(window[1])
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}{urlencode(params)}"
