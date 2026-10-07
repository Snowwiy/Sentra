"""Adapters de fuentes de inteligencia (ThreatIntelProvider). Sin base de datos.

Cada adapter declara lo que es (nombre, categoría, si necesita red, capacidades, intervalo
por defecto) y cómo convertir lo descargado o importado en registros normalizados
(records.py). La persistencia, los locks, la auditoría y el historial son comunes
(sync.py/store.py): un adapter nuevo no toca rutas ni servicios.

Implementados en 5C:
- cisa_kev: catálogo oficial CISA KEV (JSON, completo: lo que desaparece se marca inactivo);
- first_epss: CSV diario de FIRST EPSS (completo, por streaming);
- local_import: importación manual de IOCs (sentra-ioc/1 o STIX 2.x); nunca usa la red.

Previstos (contrato documentado en docs/threat-intel-sources.md, sin implementar): TAXII
2.1, avisos de fabricante, proveedores comerciales opcionales. Ninguno es requisito.
"""

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import IO, Literal

from app.threat_intel import epss, iocfile, kev, stix
from app.threat_intel.errors import IntelFormatError
from app.threat_intel.records import ParsedIntel, VulnIntelRecord

Category = Literal[
    "vulnerability", "ioc", "advisory", "exploitation", "reputation", "campaign", "other"
]
CATEGORIES: tuple[str, ...] = (
    "vulnerability",
    "ioc",
    "advisory",
    "exploitation",
    "reputation",
    "campaign",
    "other",
)
TRUST_LEVELS: tuple[str, ...] = ("official", "trusted", "community", "local")
IMPORT_FORMATS: tuple[str, ...] = ("sentra-ioc", "stix")


@dataclass
class ParsedFeed:
    """Lo que entrega un adapter: metadatos + registros (en lista o en streaming)."""

    parsed: ParsedIntel
    stream: Iterator[VulnIntelRecord] | None = None

    def vulnerabilities(self) -> Iterator[VulnIntelRecord]:
        if self.stream is not None:
            yield from self.stream
        else:
            yield from self.parsed.vulnerabilities


@dataclass(frozen=True)
class ThreatIntelProvider:
    name: str
    title: str
    category: str
    network_required: bool
    # vulnerability_intel, indicators, conditional_requests, manual_import, complete_feed.
    capabilities: tuple[str, ...]
    default_interval_hours: int | None
    default_stale_hours: int | None
    default_url: str | None = None
    # Tipo de registro de vulnerability_intel que produce (kev | epss). None: indicadores.
    intel_kind: str | None = None
    reference_url: str | None = None
    # Convierte un fichero descargado (binario) en registros. None: no descarga nada.
    parse_download: Callable[[IO[bytes], int, int], ParsedFeed] | None = field(
        default=None, repr=False
    )


def _parse_kev(handle: IO[bytes], max_bytes: int, max_records: int) -> ParsedFeed:
    raw = handle.read(max_bytes + 1)
    return ParsedFeed(kev.parse(raw, max_bytes, min(max_records, kev.MAX_RECORDS)))


def _parse_epss(handle: IO[bytes], max_bytes: int, max_records: int) -> ParsedFeed:
    parsed = ParsedIntel(format=epss.FORMAT, complete=True)
    # Generador perezoso: el CSV se lee mientras se escribe en staging (store.py).
    stream = epss.iter_rows(handle, parsed, min(max_records, epss.MAX_RECORDS))
    return ParsedFeed(parsed, stream)


PROVIDERS: dict[str, ThreatIntelProvider] = {
    "cisa_kev": ThreatIntelProvider(
        name="cisa_kev",
        title="CISA Known Exploited Vulnerabilities",
        category="exploitation",
        network_required=True,
        capabilities=("vulnerability_intel", "conditional_requests", "complete_feed"),
        default_interval_hours=24,
        default_stale_hours=120,
        default_url=kev.DEFAULT_URL,
        intel_kind="kev",
        reference_url=kev.REFERENCE_URL,
        parse_download=_parse_kev,
    ),
    "first_epss": ThreatIntelProvider(
        name="first_epss",
        title="FIRST EPSS",
        category="exploitation",
        network_required=True,
        capabilities=("vulnerability_intel", "conditional_requests", "complete_feed"),
        default_interval_hours=24,
        default_stale_hours=120,
        default_url=epss.DEFAULT_URL,
        intel_kind="epss",
        reference_url=epss.REFERENCE_URL,
        parse_download=_parse_epss,
    ),
    "local_import": ThreatIntelProvider(
        name="local_import",
        title="Importación local (sentra-ioc/1, STIX 2.x)",
        category="ioc",
        network_required=False,
        capabilities=("indicators", "manual_import"),
        default_interval_hours=None,
        default_stale_hours=None,
    ),
}


def get_provider(name: str) -> ThreatIntelProvider:
    provider = PROVIDERS.get(name)
    if provider is None:
        raise IntelFormatError("unknown_provider", f"Unknown provider {name}")
    return provider


def parse_import(fmt: str, raw: bytes, max_bytes: int, max_records: int) -> ParsedFeed:
    """Fichero local de indicadores (API o CLI): sentra-ioc/1 o un bundle STIX 2.x."""
    limits = stix.StixLimits(max_bytes=max_bytes, max_objects=max_records)
    if fmt == "stix":
        return ParsedFeed(stix.parse(raw, limits))
    if fmt == "sentra-ioc":
        return ParsedFeed(iocfile.parse(raw, limits))
    raise IntelFormatError("intel_invalid_format", f"Unsupported import format {fmt}")


def parse_vulnerability_import(
    provider: str, handle: IO[bytes], max_bytes: int, max_records: int
) -> ParsedFeed:
    """Importación manual offline de un fichero KEV/EPSS descargado aparte (CLI).

    Permite tener KEV y EPSS en un servidor sin Internet: alguien descarga el fichero oficial
    en otro equipo y lo importa aquí. Pasa por el mismo parser que la sincronización.
    """
    target = get_provider(provider)
    if target.parse_download is None:
        raise IntelFormatError("intel_invalid_format", "This provider has no feed format")
    return target.parse_download(handle, max_bytes, max_records)
