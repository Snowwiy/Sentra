"""Contratos de los selectores contextuales (Fase 7C.3, docs/contextual-selectors.md).

El usuario escribe un nombre, una IP, una MAC, una etiqueta o un número de caso; la API
devuelve candidatos con su id público ya resuelto y dice si la coincidencia es única o
ambigua. La UI nunca pide al usuario que copie un UUID.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from app.schemas.common import ResponseModel

LookupKind = Literal["asset", "detection", "incident"]
# exact: una sola coincidencia exacta (se puede elegir sola); ambiguous: varias exactas, el
# usuario tiene que elegir; partial: solo coincidencias parciales; none: nada.
LookupResolution = Literal["exact", "ambiguous", "partial", "none"]
# Campo por el que coincidió (la UI lo resalta para que se vea por qué aparece).
MatchField = Literal[
    "label",
    "name",
    "hostname",
    "dns",
    "ip",
    "mac",
    "tag",
    "model",
    "rule",
    "title",
    "number",
    "id",
]


class LookupItem(ResponseModel):
    kind: LookupKind
    id: UUID
    label: str
    # Línea secundaria legible: IP · tipo · site (activo), regla · activo (detección)...
    secondary: str | None
    match_field: MatchField
    exact: bool
    archived: bool = False
    site_name: str | None = None
    ip: str | None = None
    mac: str | None = None
    device_type: str | None = None
    status: str | None = None
    severity: str | None = None
    # Activo relacionado (detecciones): para enlazar y para el contexto de la consola.
    asset_id: UUID | None = None
    asset_label: str | None = None
    last_seen_at: datetime | None = None


class LookupResult(ResponseModel):
    kind: LookupKind
    query: str
    resolution: LookupResolution
    items: list[LookupItem]
    # Hay más coincidencias de las devueltas: afinar la búsqueda.
    truncated: bool
