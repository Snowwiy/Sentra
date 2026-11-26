"""Contratos de la integración SIEM (Fase 7F): protocolo del sensor y API del dashboard.

Lo que llega del sensor se valida con modelos cerrados (extra=forbid) y límites explícitos.
El registro en sí (`raw`) es texto acotado y NO se interpreta aquí: lo normaliza el conector
de la fuente en el servidor (app/siem/normalizers), que es quien decide qué es válido.
"""

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field

from app.schemas.common import RequestModel, ResponseModel

ALIAS_PATTERN = r"^[a-z0-9_-]{1,32}$"
CODE_PATTERN = r"^[a-z0-9_]{1,48}$"
MAX_RECORDS_HARD = 5000
MAX_RAW_CHARS_HARD = 65_536

SourceState = Literal["disabled", "configured", "healthy", "degraded", "offline", "error"]
InputState = Literal["starting", "running", "degraded", "error", "stopped", "not_declared"]
ReceiverState = Literal["disabled", "not_configured", "starting", "running", "degraded", "error"]
Transport = Literal["sensor", "upload"]
Counter = Annotated[int, Field(ge=0, le=2**53)]
Code = Annotated[str, Field(pattern=CODE_PATTERN)]


# --- protocolo del sensor ------------------------------------------------------------------


class SiemRecordIn(RequestModel):
    """Un registro recibido o leído por el sensor. `raw` es el texto original (Syslog) o la
    línea JSON ya saneada (sin payloads) por el lector de ficheros del sensor."""

    # El registro se guarda tal cual llegó (su hash es evidencia): sin recortar espacios.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    raw: str = Field(min_length=1, max_length=MAX_RAW_CHARS_HARD)
    record_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,80}$")
    collected_at: AwareDatetime
    transport: Literal["udp", "tcp", "tls", "file"]
    peer_ip: str | None = Field(default=None, max_length=45)
    peer_port: int | None = Field(default=None, ge=0, le=65_535)
    file_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    offset: int | None = Field(default=None, ge=0, le=2**53)


class SiemBatchStatsIn(RequestModel):
    """Contadores del receptor desde el lote anterior (deltas). Solo números y estados."""

    received: Counter = 0
    dropped_oversize: Counter = 0
    dropped_peer: Counter = 0
    dropped_rate: Counter = 0
    malformed: Counter = 0
    connections_rejected: Counter = 0
    spool_dropped: Counter = 0
    truncations: Counter = 0
    rotations: Counter = 0


class SiemBatchIn(RequestModel):
    batch_id: UUID
    source_id: UUID
    input: str = Field(pattern=ALIAS_PATTERN)
    config_revision: int | None = Field(default=None, ge=0, le=2**31)
    records: list[SiemRecordIn] = Field(max_length=MAX_RECORDS_HARD)
    stats: SiemBatchStatsIn | None = None


class SiemBatchAccepted(ResponseModel):
    batch_id: UUID
    duplicate: bool
    records: int
    accepted: int
    duplicates: int
    rejected: int
    reject_reasons: dict[str, int]


class SiemInputHealthIn(RequestModel):
    name: str = Field(pattern=ALIAS_PATTERN)
    source_id: UUID | None = None
    state: InputState
    error_code: Code | None = None
    degraded_reasons: list[Code] = Field(default_factory=list, max_length=8)
    received: Counter | None = None
    dropped: Counter | None = None
    malformed: Counter | None = None
    connections: Counter | None = None
    last_record_at: AwareDatetime | None = None


class SiemHealthIn(RequestModel):
    """Estado de los receptores SIEM en el heartbeat. Solo alias, contadores y estados."""

    state: ReceiverState
    # Revisión de `config.siem` que el sensor tiene aplicada (para no dar por "no declarada"
    # una entrada que el sensor aún no ha recibido).
    config_revision: int | None = Field(default=None, ge=0, le=2**31)
    inputs: list[SiemInputHealthIn] = Field(default_factory=list, max_length=32)
    spool_items: Counter | None = None
    spool_bytes: Counter | None = None
    spool_dropped: Counter | None = None


class SensorSiemSource(ResponseModel):
    source_id: UUID
    input: str
    source_type: str
    revision: int


class SensorSiemConfig(ResponseModel):
    """Bloque `config.siem` del heartbeat. Solo para sensores que declaran siem.ingest."""

    enabled: bool
    revision: int
    sources: list[SensorSiemSource]
    max_records_per_batch: int
    max_batch_bytes: int
    max_record_bytes: int
    flush_interval_seconds: int
    spool_max_mb: int
    spool_max_age_hours: int


# --- API del dashboard ---------------------------------------------------------------------


class SiemConnectorRead(ResponseModel):
    source_type: str
    title: str
    version: str
    transports: list[str]
    sensor_input: str | None
    description: str
    severity_policy: dict[str, str]
    severity_policy_doc: str
    event_types: list[str]
    sensitive_fields: list[str]
    validation: str
    formats: list[str]


class SiemConnectorList(ResponseModel):
    items: list[SiemConnectorRead]


class SiemSourceConfigIn(RequestModel):
    """Configuración aprobada de una fuente. Sin secretos: ninguna fuente guarda credenciales.

    - severity_policy: ajuste de la política del conector (solo sus claves).
    - event_types: lista blanca de tipos de evento (vacía = todos los que el conector sabe).
    """

    severity_policy: dict[
        Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:-]{1,32}$")],
        Literal["informational", "low", "medium", "high", "critical", "unknown"],
    ] = Field(default_factory=dict, max_length=32)
    event_types: list[Annotated[str, Field(pattern=r"^[a-z0-9_.]{1,48}$")]] = Field(
        default_factory=list, max_length=64
    )


class SiemSourceCreate(RequestModel):
    site_id: UUID
    name: str = Field(min_length=1, max_length=100, pattern=r"^[^\x00-\x1f\x7f]+$")
    source_type: str = Field(pattern=r"^[a-z0-9_]{1,24}$")
    transport: Transport
    sensor_id: UUID | None = None
    input_name: str | None = Field(default=None, pattern=ALIAS_PATTERN)
    enabled: bool = False
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    max_events_per_minute: int | None = Field(default=None, ge=1, le=600_000)
    config: SiemSourceConfigIn = Field(default_factory=SiemSourceConfigIn)


class SiemSourceUpdate(RequestModel):
    expected_revision: int = Field(ge=0)
    name: str | None = Field(
        default=None, min_length=1, max_length=100, pattern=r"^[^\x00-\x1f\x7f]+$"
    )
    enabled: bool | None = None
    sensor_id: UUID | None = None
    input_name: str | None = Field(default=None, pattern=ALIAS_PATTERN)
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    clear_retention: bool = False
    max_events_per_minute: int | None = Field(default=None, ge=1, le=600_000)
    config: SiemSourceConfigIn | None = None


class SiemImportRequest(RequestModel):
    """Importación manual: el contenido de un fichero exportado (una línea por registro).

    El tamaño lo acota MAX_REQUEST_BYTES (middleware) y el número de líneas
    SIEM_UPLOAD_MAX_RECORDS. Reimportar el mismo contenido es un duplicado (idempotente).
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    content: str = Field(min_length=1, max_length=16 * 1024 * 1024)
    filename: str | None = Field(default=None, max_length=200, pattern=r"^[^\x00-\x1f\x7f/\\]+$")


class SiemSourceRead(ResponseModel):
    source_id: UUID
    name: str
    source_type: str
    connector_title: str | None
    connector_version: str
    transport: str
    site_id: UUID
    site_name: str
    sensor_id: UUID | None
    sensor_name: str | None
    input_name: str | None
    enabled: bool
    revision: int
    status: SourceState
    status_reasons: list[str]
    config: dict[str, Any]
    effective_severity_policy: dict[str, str]
    retention_days: int | None
    effective_retention_days: int | None
    max_events_per_minute: int
    events_received: int
    events_accepted: int
    events_rejected: int
    events_duplicate: int
    events_dropped: int
    last_success_at: datetime | None
    last_event_at: datetime | None
    lag_seconds: int | None
    last_error_code: str | None
    last_error_at: datetime | None
    reported_state: str | None
    reported_at: datetime | None
    created_by: str | None
    updated_by: str | None
    created_at: datetime
    updated_at: datetime


class SiemSourceList(ResponseModel):
    items: list[SiemSourceRead]


class SiemAssetRef(ResponseModel):
    asset_id: UUID
    name: str


class SiemAttributionCandidate(ResponseModel):
    asset_id: UUID | None
    asset_name: str | None
    # source | destination | reporter | host
    role: str
    # ip_in_site | reporter_ip | agent_ip | hostname_match
    method: str
    confidence: str
    value: str


class SiemAttribution(ResponseModel):
    """Atribución conservadora (app/siem/identity.py). `verdict`: attributed (un activo),
    multiple (varios activos con roles distintos), ambiguous (una IP compartida por varios
    activos), hostname_hint (solo coincide el nombre: pista, no identidad) o
    insufficient_evidence (nada lo identifica).

    `origin` (solo alertas): imported (alerta externa con activo), correlated (corroborada
    por el NDR de Sentra), probable_match (probablemente la misma que una detección nativa de
    Sentra: no se crea otra) o insufficient_evidence (sin activo atribuible: no hay señal)."""

    verdict: str
    candidates: list[SiemAttributionCandidate]
    ambiguous: int = 0
    origin: str | None = None


class SiemEventLinkRead(ResponseModel):
    """Relación explicada con otra evidencia. `kind`: ndr_flow, ndr_anomaly, siem_event."""

    kind: str
    target_ref: str
    method: str
    confidence: str
    explanation: str
    created_at: datetime


class SiemEventRead(ResponseModel):
    event_id: UUID
    schema_version: int
    normalization_version: str
    source_id: UUID
    source_name: str
    source_type: str
    site_id: UUID
    event_type: str
    category: str
    timestamp: datetime
    collected_at: datetime | None
    received_at: datetime
    time_quality: str
    severity: str
    source_severity: str | None
    confidence: str
    hostname: str | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    username: str | None
    process_name: str | None
    action: str | None
    outcome: str | None
    signature_id: str | None
    rule_id: str | None
    message: str | None
    tags: list[str]
    mitre_techniques: list[str]
    external_id: str | None
    flow_ref: str | None
    raw_reference: str
    evidence_hash: str
    asset: SiemAssetRef | None
    attribution: SiemAttribution | None


class SiemEventDetail(SiemEventRead):
    raw_excerpt: str | None
    data: dict[str, Any] | None
    # Fase 7F.3: correlaciones con flujos y anomalías NDR y con otros eventos SIEM.
    links: list[SiemEventLinkRead] = Field(default_factory=list)


class SiemEventList(ResponseModel):
    items: list[SiemEventRead]
    total: int
    limit: int
    offset: int
    # True si `total` es una cota (la búsqueda cuenta como mucho COUNT_CAP filas).
    total_capped: bool = False


class SiemCount(ResponseModel):
    key: str
    count: int


class SiemOverview(ResponseModel):
    window_hours: int
    sources_total: int
    sources_by_status: dict[str, int]
    events: int
    rejected: int
    duplicates: int
    by_source_type: list[SiemCount]
    by_severity: list[SiemCount]
    by_category: list[SiemCount]
    lagging_sources: int
    last_event_received_at: datetime | None
