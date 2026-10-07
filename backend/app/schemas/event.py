import re
from datetime import UTC, datetime
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from app.models.event import EventLevel
from app.schemas.common import BIGINT_MAX, NUL, RequestModel, ResponseModel
from app.schemas.telemetry import MAX_FUTURE_SKEW

MAX_EVENTS_PER_BATCH = 500
MAX_MESSAGE_LENGTH = 4000
# Campos estructurados por evento (Fase 4H). El agente envía una lista cerrada (unos pocos
# campos por id); los límites protegen la API de un agente manipulado igualmente.
MAX_DATA_FIELDS = 16
MAX_DATA_VALUE_LENGTH = 512
# Nombres de campo de Windows: "TargetUserName", "param1", "Threat Name"...
_DATA_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9 _.\-]{0,63}$")
# Fase 5C.1: tipo normalizado de los eventos Linux (auth_failure, sudo_command...).
EVENT_TYPE_PATTERN = r"^[a-z][a-z0-9_]{0,47}$"
# Cobertura de eventos que informa el agente: fuente -> estado. Valores cerrados para que un
# agente manipulado no pueda escribir texto libre que la UI muestre.
COVERAGE_STATES = frozenset({"active", "unavailable", "no_permission", "error", "disabled"})
_COVERAGE_SOURCE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
MAX_COVERAGE_SOURCES = 16


class EventIn(RequestModel):
    source: str = Field(min_length=1, max_length=32, examples=["windows_eventlog"])
    channel: str = Field(min_length=1, max_length=255, examples=["System"])
    record_id: int = Field(ge=0, le=BIGINT_MAX)
    # Id de evento de Windows. Fase 5C.1: opcional, los eventos Linux no tienen (null).
    event_code: int | None = Field(default=None, ge=0, le=2**31 - 1)
    event_type: str | None = Field(default=None, pattern=EVENT_TYPE_PATTERN)
    provider: str = Field(min_length=1, max_length=255)
    level: EventLevel
    # Long messages are truncated by the agent; the bound protects the API either way.
    message: str = Field(max_length=MAX_MESSAGE_LENGTH)
    # Host name the event was recorded on (Windows <Computer>); optional for older agents.
    computer: str | None = Field(default=None, max_length=255)
    # Opcional (agentes desde la Fase 4H): EventData/UserData de una lista cerrada por id.
    data: dict[str, str] | None = Field(default=None, max_length=MAX_DATA_FIELDS)
    occurred_at: AwareDatetime

    @field_validator("data")
    @classmethod
    def _check_data(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        # El validador común de NUL solo mira campos de texto, no claves ni valores de un
        # diccionario: aquí se comprueba todo, porque acaba en una columna JSONB.
        if not value:
            return None
        clean: dict[str, str] = {}
        for key, item in value.items():
            if not _DATA_KEY.match(key):
                raise ValueError(f"invalid data field name: {key[:64]!r}")
            if NUL in item:
                raise ValueError("must not contain NUL (U+0000) characters")
            if len(item) > MAX_DATA_VALUE_LENGTH:
                raise ValueError(f"data value too long (max {MAX_DATA_VALUE_LENGTH})")
            clean[key] = item.strip()
        return clean

    @field_validator("occurred_at")
    @classmethod
    def _normalize(cls, value: datetime) -> datetime:
        value = value.astimezone(UTC)
        if value > datetime.now(UTC) + MAX_FUTURE_SKEW:
            raise ValueError("occurred_at is too far in the future")
        return value


class EventBatch(RequestModel):
    agent_id: UUID
    # Fase 5C.1: puede ir vacío si el lote solo informa la cobertura (p. ej. el journal no
    # se puede leer): así "sin permiso" no se confunde con "0 eventos".
    events: list[EventIn] = Field(max_length=MAX_EVENTS_PER_BATCH)
    coverage: dict[str, str] | None = Field(default=None, max_length=MAX_COVERAGE_SOURCES)

    @field_validator("coverage")
    @classmethod
    def _check_coverage(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if not value:
            return None
        for key, state in value.items():
            if not _COVERAGE_SOURCE.match(key):
                raise ValueError(f"invalid coverage source: {key[:32]!r}")
            if state not in COVERAGE_STATES:
                raise ValueError(f"invalid coverage state for {key}")
        return value

    @model_validator(mode="after")
    def _not_empty(self) -> "EventBatch":
        if not self.events and not self.coverage:
            raise ValueError("a batch needs events or coverage")
        return self


class EventBatchAccepted(ResponseModel):
    asset_id: UUID
    received: int
    stored: int  # lower than `received` when some events were already stored (resend)


class EventRead(ResponseModel):
    event_id: UUID
    asset_id: UUID
    hostname: str
    source: str
    channel: str
    event_code: int | None
    # Fase 5C.1: tipo normalizado (Linux); null en Windows.
    event_type: str | None = None
    provider: str
    level: EventLevel
    message: str
    record_id: int
    computer: str | None
    # Campos estructurados enviados por el agente (Fase 4H); null en agentes anteriores.
    data: dict[str, str] | None = None
    occurred_at: datetime


class EventList(ResponseModel):
    items: list[EventRead]
    # Number of items in this page. Event tables grow large, so they are not counted.
    total: int
    # True when more events match after this page (use `offset` to read them).
    has_more: bool = False
