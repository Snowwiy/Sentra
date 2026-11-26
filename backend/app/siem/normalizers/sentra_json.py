"""Conector `sentra_json`: eventos que ya siguen el contrato normalizado de Sentra (7F.1).

Pensado para scripts propios o exportaciones convertidas: una línea JSON por evento con los
nombres del contrato (docs/fase-7f-architecture.md). La validación es estricta: una clave
desconocida rechaza el registro (`invalid_schema`) y las que intentan fijar el site o la
fuente (`site_id`, `source_id`) se rechazan con un motivo propio: el site sale siempre de la
fuente registrada, nunca del contenido.
"""

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.siem import fields
from app.siem.catalog import (
    INPUT_FILE,
    TRANSPORT_SENSOR,
    TRANSPORT_UPLOAD,
    Connector,
    NormalizeContext,
    register,
)
from app.siem.contract import (
    CATEGORIES,
    CONFIDENCES,
    OUTCOMES,
    SEVERITIES,
    NormalizedEvent,
    RawRecord,
    RecordRejectedError,
)

VERSION = "1.0.0"
FORBIDDEN_KEYS = frozenset({"site_id", "source_id", "site", "sensor_id"})


class _Event(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=2000)

    event_id: str | None = Field(default=None, max_length=128)
    event_type: str = Field(pattern=r"^[a-z0-9_.]{1,48}$")
    category: str
    timestamp: str | None = None
    severity: str = "unknown"
    confidence: str = "unknown"
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = Field(default=None, pattern=r"^[a-z0-9_-]{1,16}$")
    username: str | None = None
    process_name: str | None = None
    action: str | None = Field(default=None, pattern=r"^[a-z0-9_-]{1,32}$")
    outcome: str | None = None
    signature_id: str | None = None
    rule_id: str | None = None
    message: str | None = None
    tags: list[str] = Field(default_factory=list, max_length=32)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=16)


def normalize(record: RawRecord, ctx: NormalizeContext) -> NormalizedEvent:
    try:
        value: Any = json.loads(record.raw)
    except ValueError as exc:
        raise RecordRejectedError("invalid_json") from exc
    if not isinstance(value, dict):
        raise RecordRejectedError("invalid_json")
    if FORBIDDEN_KEYS & set(value):
        raise RecordRejectedError("forbidden_field")
    try:
        event = _Event.model_validate(value)
    except ValidationError as exc:
        raise RecordRejectedError("invalid_schema") from exc
    if (
        event.category not in CATEGORIES
        or event.severity not in SEVERITIES
        or event.confidence not in CONFIDENCES
        or (event.outcome is not None and event.outcome not in OUTCOMES)
    ):
        raise RecordRejectedError("invalid_schema")
    if not ctx.allows(event.event_type):
        raise RecordRejectedError("event_type_not_allowed")
    observed = fields.timestamp(event.timestamp) if event.timestamp else None
    if event.timestamp and observed is None:
        raise RecordRejectedError("invalid_timestamp")
    # Sin event_id propio, la identidad es el contenido: el mismo registro importado dos
    # veces es un duplicado.
    identity = (
        fields.identity_hash("id", event.event_id)
        if event.event_id
        else fields.identity_hash("raw", record.raw)
    )
    return NormalizedEvent(
        event_type=event.event_type,
        category=event.category,
        identity=identity,
        observed_at=observed,
        severity=event.severity,
        source_severity=event.severity,
        confidence=event.confidence,
        hostname=fields.hostname(event.hostname),
        src_ip=fields.ip(event.source_ip),
        dst_ip=fields.ip(event.destination_ip),
        src_port=fields.port(event.source_port),
        dst_port=fields.port(event.destination_port),
        protocol=event.protocol,
        username=fields.text(event.username, 128),
        process_name=fields.text(event.process_name, 255),
        action=event.action,
        outcome=event.outcome,
        signature_id=fields.ident(event.signature_id, 64),
        rule_id=fields.ident(event.rule_id, 64),
        message=fields.text(event.message, 1000),
        tags=fields.tags(event.tags),
        mitre_techniques=fields.mitre(event.mitre_techniques),
        external_id=fields.ident(event.event_id),
        excerpt=fields.excerpt(record.raw, ctx.raw_store_bytes),
    )


CONNECTOR = register(
    Connector(
        source_type="sentra_json",
        title="Sentra JSON (contrato normalizado)",
        version=VERSION,
        transports=(TRANSPORT_UPLOAD, TRANSPORT_SENSOR),
        sensor_input=INPUT_FILE,
        description=(
            "Una línea JSON por evento con los campos del contrato sentra.siem.event. Para"
            " scripts propios o exportaciones ya convertidas."
        ),
        normalize=normalize,
        severity_policy={},
        severity_policy_doc=(
            "La severidad viene ya en la escala de Sentra (informational..critical); un valor"
            " fuera de la escala rechaza el registro."
        ),
        sensitive_fields=("username", "hostname", "message"),
        validation="Contrato propio de Sentra: probado con los fixtures de backend/tests.",
        formats=("json_lines",),
    )
)
