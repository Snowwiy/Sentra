"""Fuentes del catálogo de vulnerabilidades (Fase 5B): de dónde salen los bytes a importar.

Hoy solo hay fuentes LOCALES: un fichero que el admin sube por la API o indica a la CLI.
Sentra no descarga nada. Un conector futuro (NVD, OSV, avisos de fabricante...) será otra
implementación de `VulnerabilitySource` que produzca el mismo formato sentra-vuln-catalog/1:
pasará por la misma validación, previsualización, importación y auditoría, sin tocar el
matcher ni el motor. Activarlo será una decisión explícita (y una fase propia).
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from app.vulnerabilities.catalog import CatalogFormatError


class VulnerabilitySource(Protocol):
    """Origen de un catálogo: entrega como mucho `max_bytes` bytes o falla."""

    @property
    def kind(self) -> str: ...

    def read(self, max_bytes: int) -> bytes: ...


@dataclass(frozen=True)
class UploadedSource:
    """Catálogo recibido por la API (texto JSON del cuerpo de la petición)."""

    content: str
    kind: str = "imported_catalog"

    def read(self, max_bytes: int) -> bytes:
        data = self.content.encode("utf-8")
        if len(data) > max_bytes:
            raise CatalogFormatError("catalog_too_large", f"Catalog exceeds {max_bytes} bytes")
        return data


@dataclass(frozen=True)
class LocalFileSource:
    """Fichero local indicado por un admin a la CLI. Nunca una URL ni un patrón."""

    path: Path
    kind: str = "imported_catalog"

    def read(self, max_bytes: int) -> bytes:
        if not self.path.is_file():
            raise CatalogFormatError("catalog_not_found", "Catalog file not found")
        # Se lee como mucho max_bytes + 1: un fichero enorme nunca se carga entero.
        with self.path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise CatalogFormatError("catalog_too_large", f"Catalog exceeds {max_bytes} bytes")
        return data
