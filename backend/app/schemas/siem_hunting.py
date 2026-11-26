"""Contratos de hunting e investigación SIEM (Fase 7F.6, docs/fase-7f-correlation.md).

La búsqueda es un filtro TIPADO: cada campo tiene su forma validada y se traduce a una
condición fija en SQLAlchemy. No hay lenguaje de consulta, ni SQL, ni expresiones regulares
del usuario: nada de lo que se escribe aquí llega a la base de datos como código.
"""

import ipaddress
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.schemas.common import RequestModel, ResponseModel
from app.schemas.siem import SiemEventDetail, SiemEventRead

Token = Annotated[str, Field(pattern=r"^[a-z0-9_.]{1,48}$")]
Severity = Literal["informational", "low", "medium", "high", "critical", "unknown"]
Verdict = Literal["attributed", "multiple", "ambiguous", "hostname_hint", "insufficient_evidence"]
Origin = Literal["imported", "correlated", "probable_match", "insufficient_evidence"]
# Identificadores de la fuente (regla, firma, id externo, flow): texto acotado sin controles.
Ident = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[^\x00-\x1f\x7f]+$")]


def _network(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Not an IP address or CIDR") from exc
    # Un /0 (o /1...) es "todo": no filtra nada y obliga a recorrer la ventana entera.
    if network.prefixlen < (8 if network.version == 4 else 16):
        raise ValueError("CIDR too broad")
    return network.compressed


class SiemSearchFilter(RequestModel):
    """Filtro de hunting. `since` y `until` son obligatorios: toda búsqueda tiene ventana."""

    since: datetime
    until: datetime
    site_id: UUID | None = None
    source_ids: list[UUID] = Field(default_factory=list, max_length=20)
    source_types: list[Annotated[str, Field(pattern=r"^[a-z0-9_]{1,24}$")]] = Field(
        default_factory=list, max_length=10
    )
    event_types: list[Token] = Field(default_factory=list, max_length=20)
    categories: list[Token] = Field(default_factory=list, max_length=10)
    severities: list[Severity] = Field(default_factory=list, max_length=6)
    # IP o CIDR (≥ /8 en IPv4, ≥ /16 en IPv6). `ip` busca en origen o destino.
    ip: str | None = Field(default=None, max_length=64)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Annotated[str, Field(pattern=r"^[a-z0-9]{1,16}$")] | None = None
    # Igualdad sin distinguir mayúsculas (nunca patrones).
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    username: str | None = Field(default=None, min_length=1, max_length=128)
    rule_id: Ident | None = None
    signature_id: Ident | None = None
    external_id: Ident | None = None
    flow_ref: Ident | None = None
    mitre_technique: Annotated[str, Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")] | None = None
    asset_id: UUID | None = None
    verdicts: list[Verdict] = Field(default_factory=list, max_length=5)
    origins: list[Origin] = Field(default_factory=list, max_length=4)
    # Texto contenido en el mensaje (sin comodines: % y _ se buscan literalmente).
    text: str | None = Field(default=None, min_length=3, max_length=100)

    @field_validator("ip", "source_ip", "destination_ip")
    @classmethod
    def _valid_network(cls, value: str | None) -> str | None:
        return _network(value)

    @field_validator("hostname", "username", "text")
    @classmethod
    def _no_controls(cls, value: str | None) -> str | None:
        if value is not None and any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("Control characters are not allowed")
        return value

    @model_validator(mode="after")
    def _window(self) -> "SiemSearchFilter":
        if self.since.tzinfo is None or self.until.tzinfo is None:
            raise ValueError("since and until need a time zone")
        if self.until <= self.since:
            raise ValueError("until must be after since")
        return self


class SiemSearchRequest(SiemSearchFilter):
    limit: int = Field(default=50, ge=1, le=200)
    # Cursor opaco devuelto por la página anterior (orden: más reciente primero).
    cursor: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9_=-]+$")
    # Recuento total acotado (más caro que la página): solo si se pide.
    count: bool = False


class SiemSearchResult(ResponseModel):
    items: list[SiemEventRead]
    next_cursor: str | None
    # Recuento si se pidió; `count_capped` = hay al menos ese número (SIEM_SEARCH_COUNT_CAP).
    count: int | None = None
    count_capped: bool = False
    took_ms: int


class SiemSavedSearchCreate(RequestModel):
    name: str = Field(min_length=1, max_length=100, pattern=r"^[^\x00-\x1f\x7f]+$")
    query: SiemSearchFilter


class SiemSavedSearchRead(ResponseModel):
    search_id: UUID
    name: str
    query: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class SiemSavedSearchList(ResponseModel):
    items: list[SiemSavedSearchRead]


# --- Investigación ---------------------------------------------------------------------------


class SiemRelatedDetection(ResponseModel):
    """Detección nativa de un activo candidato en la ventana del evento.

    `match`: `topic` (misma técnica MITRE o mismo tema) o `time_only` (solo coincide el
    tiempo: contexto, nunca prueba de relación)."""

    detection_id: UUID
    asset_id: UUID
    asset_name: str
    rule_id: str
    title: str
    severity: str
    first_seen_at: datetime
    last_seen_at: datetime
    match: Literal["topic", "time_only"]
    explanation: str


class SiemRelatedEvent(ResponseModel):
    event_id: UUID
    source_name: str
    source_type: str
    event_type: str
    timestamp: datetime
    direction: Literal["outgoing", "incoming"]
    method: str
    confidence: str
    explanation: str


class SiemRelated(ResponseModel):
    event_id: UUID
    events: list[SiemRelatedEvent]
    detections: list[SiemRelatedDetection]
    window_minutes: int
    note: str


class SiemTimelineItem(ResponseModel):
    kind: Literal["siem_event", "detection"]
    ref: UUID
    at: datetime
    title: str
    severity: str
    source: str


class SiemTimeline(ResponseModel):
    asset_id: UUID
    since: datetime
    until: datetime
    items: list[SiemTimelineItem]
    truncated: bool


class SiemExportRequest(RequestModel):
    event_ids: list[UUID] = Field(min_length=1, max_length=5000)
    reason: str | None = Field(default=None, max_length=300, pattern=r"^[^\x00-\x1f\x7f]*$")


class SiemEvidenceExport(ResponseModel):
    """Paquete de evidencia: eventos completos y hashes para verificar su integridad.

    `events_sha256` es el SHA-256 del JSON canónico de `events` (claves ordenadas, sin
    espacios); cada evento conserva además el `evidence_hash` del registro original."""

    format: Literal["sentra-siem-evidence/1"]
    exported_at: datetime
    exported_by: str
    reason: str | None
    events: list[SiemEventDetail]
    missing: list[UUID]
    events_sha256: str


class SiemCaseAttach(RequestModel):
    note: str | None = Field(default=None, max_length=500, pattern=r"^[^\x00-\x1f\x7f]*$")


class IncidentSiemEventRead(ResponseModel):
    event_id: UUID
    available: bool
    source_name: str
    source_type: str
    event_type: str
    timestamp: datetime
    evidence_hash: str
    snapshot: dict[str, Any]
    snapshot_sha256: str
    note: str | None
    attached_at: datetime
    attached_by: str


class IncidentSiemEventList(ResponseModel):
    items: list[IncidentSiemEventRead]
