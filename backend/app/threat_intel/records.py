"""Registros normalizados que producen los parsers y consume store.py (sin base de datos)."""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Registros inválidos devueltos en una previsualización (el total va aparte).
MAX_INVALID_SHOWN = 100


def content_hash(payload: dict[str, Any]) -> str:
    """Huella estable del contenido funcional (detecta reimportaciones sin cambios)."""
    text = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IndicatorRecord:
    indicator_type: str
    value: str
    original: str
    classification: str
    confidence: str
    network: str | None = None
    confidence_score: int | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    revoked: bool = False
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: tuple[str, ...] = ()
    description: str | None = None
    references: tuple[str, ...] = ()
    related: tuple[tuple[str, str], ...] = ()
    external_id: str | None = None
    pattern: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.indicator_type, self.value)

    def fingerprint(self) -> str:
        return content_hash(
            {
                "classification": self.classification,
                "confidence": self.confidence,
                "confidence_score": self.confidence_score,
                "valid_from": self.valid_from,
                "valid_until": self.valid_until,
                "revoked": self.revoked,
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
                "tags": sorted(self.tags),
                "description": self.description,
                "references": sorted(self.references),
                "related": sorted(self.related),
                "external_id": self.external_id,
                "pattern": self.pattern,
            }
        )


@dataclass(frozen=True)
class VulnIntelRecord:
    kind: str  # kev | epss
    cve_id: str
    data: dict[str, Any]
    epss_score: float | None = None
    epss_percentile: float | None = None
    external_id: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None

    def fingerprint(self) -> str:
        return content_hash(
            {
                "data": self.data,
                "epss_score": self.epss_score,
                "epss_percentile": self.epss_percentile,
                "published_at": self.published_at,
                "modified_at": self.modified_at,
            }
        )


@dataclass(frozen=True)
class InvalidRecord:
    index: int
    code: str
    message: str
    # Identificador del objeto (STIX id, CVE...) si se pudo leer; nunca el contenido.
    reference: str | None = None


@dataclass
class ParsedIntel:
    """Resultado de parsear un fichero o feed completo."""

    format: str
    indicators: list[IndicatorRecord] = field(default_factory=list)
    vulnerabilities: list[VulnIntelRecord] = field(default_factory=list)
    invalid: list[InvalidRecord] = field(default_factory=list)
    invalid_total: int = 0
    # Objetos válidos pero fuera del subset soportado (patrones STIX complejos, tipos STIX
    # no soportados): se cuentan, no se guardan ni se interpretan.
    unsupported: dict[str, int] = field(default_factory=dict)
    # Versión/fecha que declara la propia fuente (catalogVersion de KEV, modelo de EPSS...).
    source_version: str | None = None
    published_at: datetime | None = None
    # Un feed COMPLETO (KEV, EPSS) describe todo el estado de la fuente: lo que no viene se
    # marca inactivo. Una importación parcial (lote de IOCs) nunca desactiva nada.
    complete: bool = False

    def add_invalid(self, record: InvalidRecord) -> None:
        self.invalid_total += 1
        if len(self.invalid) < MAX_INVALID_SHOWN:
            self.invalid.append(record)

    def add_unsupported(self, reason: str) -> None:
        self.unsupported[reason] = self.unsupported.get(reason, 0) + 1

    @property
    def total(self) -> int:
        return len(self.indicators) + len(self.vulnerabilities)
