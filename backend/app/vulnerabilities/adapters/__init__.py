"""Adapters de fuentes oficiales del catálogo de vulnerabilidades (Fase 6C.4). Puros.

Cada adapter convierte el formato oficial de una fuente en registros normalizados con la misma
forma que sentra-vuln-catalog/1 (catalog.SourceVulnerabilityIn): así pasan por la misma
validación, staging, importación por lotes, cola de reevaluación y auditoría que un catálogo
local, sin tocar el matcher ni el motor. Nada aquí usa la red ni la base de datos: la descarga
la hace app/vulnerabilities/source_sync.py con el cliente seguro de Threat Intelligence.

- nvd: NVD CVE API 2.0 (páginas de la API y ficheros de datos JSON 2.0 descargados);
- osv: OSV (registros sueltos, listas o el all.zip de un ecosistema) de las distribuciones que
  Sentra inventaría (Debian/Ubuntu dpkg, AlmaLinux/Rocky/Red Hat rpm);
- local_catalog: el formato sentra-vuln-catalog/1 de la Fase 5B (catalog.py);
- KEV y EPSS siguen siendo de Threat Intelligence (app/threat_intel): se leen de sus tablas por
  CVE, nunca se copian al catálogo.

Qué fuente aporta cada atributo: ATTRIBUTE_SOURCES (también en la API y en
docs/vulnerability-sources.md).
"""

from dataclasses import dataclass, field
from typing import Any

# Atributos del catálogo y quién los aporta en cada adapter. "threat_intel" = se leen en
# tiempo de consulta de las fuentes KEV/EPSS de la Fase 5C (sin copia ni doble conteo).
ATTRIBUTES = (
    "cve",
    "description",
    "references",
    "cvss",
    "product_identifier",
    "affected_versions",
    "exploitation",
    "epss",
    "published",
    "modified",
    "local_updated",
)
ATTRIBUTE_SOURCES: dict[str, dict[str, str]] = {
    "nvd": {
        "cve": "nvd: cve.id",
        "description": "nvd: cve.descriptions (en)",
        "references": "nvd: cve.references (solo http/https)",
        "cvss": "nvd: cve.metrics (Primary de NVD; si no, Secondary del CNA)",
        "product_identifier": "nvd: configurations (CPE 2.3) + identificador declarado",
        "affected_versions": "nvd: cpeMatch versionStart*/versionEnd* o versión del CPE",
        "exploitation": "threat_intel: cisa_kev (no se usan los campos cisa* de NVD)",
        "epss": "threat_intel: first_epss",
        "published": "nvd: cve.published",
        "modified": "nvd: cve.lastModified",
        "local_updated": "sentra: vulnerabilities.updated_at",
    },
    "osv": {
        "cve": "osv: aliases/upstream/related (CVE)",
        "description": "osv: details/summary",
        "references": "osv: references (solo http/https)",
        "cvss": "osv: severity (vector); la puntuación no se calcula",
        "product_identifier": "osv: affected.package (ecosistema + paquete)",
        "affected_versions": "osv: affected.ranges ECOSYSTEM (introduced/fixed/last_affected)",
        "exploitation": "threat_intel: cisa_kev",
        "epss": "threat_intel: first_epss",
        "published": "osv: published",
        "modified": "osv: modified",
        "local_updated": "sentra: vulnerabilities.updated_at",
    },
    "local_catalog": {
        "cve": "catálogo local: id/aliases",
        "description": "catálogo local",
        "references": "catálogo local",
        "cvss": "catálogo local",
        "product_identifier": "catálogo local: names/publishers/packages/os/cpe_match",
        "affected_versions": "catálogo local: ranges",
        "exploitation": "threat_intel: cisa_kev",
        "epss": "threat_intel: first_epss",
        "published": "catálogo local: published_at",
        "modified": "catálogo local: modified_at",
        "local_updated": "sentra: vulnerabilities.updated_at",
    },
}


class SourceFormatError(ValueError):
    """Error estructural del fichero o respuesta: se rechaza entero (nada se aplica)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class SourceRecord:
    """Registro convertido (aún sin validar con SourceVulnerabilityIn)."""

    index: int
    external_id: str
    data: dict[str, Any]
    provenance: dict[str, Any]
    # CVEs cuya severidad puede tomarse de otra fuente ya importada (OSV sin severidad propia).
    severity_from: list[str] = field(default_factory=list)


@dataclass
class Tombstone:
    """La fuente retira un registro (NVD Rejected, OSV withdrawn): se vacían sus afectados."""

    index: int
    external_id: str
    reason: str


@dataclass
class Skipped:
    """Registro que Sentra no puede usar (no es un error del fichero): se cuenta por motivo."""

    index: int
    external_id: str | None
    reason: str


Converted = SourceRecord | Tombstone | Skipped


@dataclass
class Invalid:
    index: int
    external_id: str | None
    code: str
    message: str
