"""Parser del CSV diario de FIRST EPSS (Exploit Prediction Scoring System). Streaming.

Semántica: `epss` es la probabilidad (0-1) de que se observe actividad de explotación de un
CVE en los próximos 30 días según el modelo de FIRST; `percentile` es su posición frente al
resto de CVEs puntuados. NO es la severidad (eso es CVSS), NO es "% de vulnerabilidad" del
activo y NO es la probabilidad de que el activo esté comprometido. La UI lo muestra como
"probabilidad de explotación EPSS".

El fichero (~300 000 filas) se procesa línea a línea desde un fichero binario (gzip o texto):
nunca se carga entero en memoria. Formato:
    #model_version:v2025.03.14,score_date:2025-03-15T00:00:00+0000
    cve,epss,percentile
    CVE-1999-0001,0.01141,0.77824

Historial (decisión documentada en docs/threat-intel-sources.md): EPSS cambia cada día para
casi todos los CVEs, así que NO se guarda cada valor diario. Se guarda el valor actual y, en
`data.previous`, el último valor ANTERIOR a un cambio material; además cada cambio material
deja una fila en threat_intel_changes. Cambio material = cambio de banda (ver BANDS) o una
variación absoluta de al menos MATERIAL_DELTA.
"""

import csv
import gzip
import io
import math
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import IO, cast

from app.threat_intel.errors import IntelFormatError, IntelRecordError
from app.threat_intel.records import InvalidRecord, ParsedIntel, VulnIntelRecord

FORMAT = "first-epss"
DEFAULT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
REFERENCE_URL = "https://www.first.org/epss/"
CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_HEADER_META = re.compile(r"^#model_version:([^,]{1,64}),score_date:(\S{8,40})$")
MAX_LINE = 256
MAX_RECORDS = 2_000_000
# Bandas de probabilidad (umbrales inferiores de "elevated" y "high"). La UI, la prioridad
# 5B y el riesgo 4I usan estas mismas bandas: nunca se definen en otro sitio.
ELEVATED = 0.1
HIGH = 0.5
BANDS = (ELEVATED, HIGH)
MATERIAL_DELTA = 0.1


def band(score: float | None) -> str:
    if score is None:
        return "none"
    if score >= HIGH:
        return "high"
    if score >= ELEVATED:
        return "elevated"
    return "low"


def is_material(previous: float | None, current: float | None) -> bool:
    """¿Cambio que merece historial y reevaluar prioridades? (no cada variación diaria)."""
    if previous is None or current is None:
        return previous != current
    return band(previous) != band(current) or abs(current - previous) >= MATERIAL_DELTA


@dataclass
class EpssHeader:
    model_version: str | None = None
    score_date: datetime | None = None


def _score_date(value: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _probability(value: str, field: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise IntelRecordError("invalid_record", f"{field} is not a number") from None
    if not math.isfinite(number) or number < 0 or number > 1:
        raise IntelRecordError("invalid_record", f"{field} must be between 0 and 1")
    return round(number, 5)


def open_text(handle: IO[bytes]) -> IO[str]:
    """Texto UTF-8 desde gzip o CSV plano (lo decide la cabecera mágica, no la extensión)."""
    # BufferedReader solo para mirar la cabecera sin consumirla (peek).
    buffered = io.BufferedReader(cast("io.RawIOBase", handle))
    magic = buffered.peek(2)[:2]
    # newline="": el módulo csv gestiona los saltos de línea (CRLF incluido).
    if magic == b"\x1f\x8b":
        return io.TextIOWrapper(
            gzip.GzipFile(fileobj=buffered), encoding="utf-8", errors="strict", newline=""
        )
    return io.TextIOWrapper(buffered, encoding="utf-8", errors="strict", newline="")


def iter_rows(
    handle: IO[bytes], parsed: ParsedIntel, max_records: int = MAX_RECORDS
) -> Iterator[VulnIntelRecord]:
    """Genera los registros válidos; los inválidos se cuentan en `parsed`.

    Errores estructurales (no es EPSS, cabecera ausente, demasiadas filas, gzip corrupto)
    lanzan IntelFormatError a mitad de la iteración: quien consume lo hace dentro de una
    transacción y la deshace entera (nada parcial queda guardado).
    """
    header = EpssHeader()
    text = open_text(handle)
    try:
        first = text.readline(MAX_LINE + 1).strip()
        meta = _HEADER_META.match(first)
        if meta:
            header.model_version = meta.group(1)
            header.score_date = _score_date(meta.group(2))
            first = text.readline(MAX_LINE + 1).strip()
        if first.replace(" ", "").lower() != "cve,epss,percentile":
            raise IntelFormatError("intel_invalid_format", "Not a FIRST EPSS CSV")
        parsed.source_version = header.model_version
        parsed.published_at = header.score_date
        data = {
            "model_version": header.model_version,
            "score_date": header.score_date.date().isoformat() if header.score_date else None,
        }
        count = 0
        for index, row in enumerate(csv.reader(_bounded_lines(text))):
            if not row:
                continue
            count += 1
            if count > max_records:
                raise IntelFormatError("intel_too_many_records", f"More than {max_records} rows")
            try:
                if len(row) != 3:
                    raise IntelRecordError("invalid_record", "expected 3 columns")
                cve = row[0].strip().upper()
                if not CVE.match(cve):
                    raise IntelRecordError("invalid_cve", "invalid CVE identifier")
                score = _probability(row[1].strip(), "epss")
                percentile = _probability(row[2].strip(), "percentile")
            except IntelRecordError as exc:
                ref = row[0][:64] if row else None
                parsed.add_invalid(InvalidRecord(index, exc.code, str(exc), ref))
                continue
            yield VulnIntelRecord(
                kind="epss",
                cve_id=cve,
                data=dict(data),
                epss_score=score,
                epss_percentile=percentile,
                external_id=cve,
                published_at=header.score_date,
            )
    except (OSError, EOFError, UnicodeDecodeError, csv.Error, gzip.BadGzipFile) as exc:
        raise IntelFormatError(
            "intel_invalid_format", f"Unreadable EPSS file ({type(exc).__name__})"
        ) from None


def _bounded_lines(text: IO[str]) -> Iterator[str]:
    """Líneas con tope de longitud: una "línea" de GB sin saltos no llega a memoria."""
    while True:
        line = text.readline(MAX_LINE + 1)
        if not line:
            return
        if len(line) > MAX_LINE and not line.endswith("\n"):
            raise IntelFormatError("intel_invalid_format", "EPSS line too long")
        yield line
