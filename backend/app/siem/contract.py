"""Contrato del evento normalizado `sentra.siem.event` (versión SCHEMA_VERSION).

Es el único formato que el resto de Sentra lee: los conectores traducen su formato de origen
a `NormalizedEvent` y nada más. Reglas del contrato (docs/fase-7f-architecture.md):

- Un campo que el origen no trae queda a None. No se inventan valores para cumplir el
  esquema (p. ej. no se pone "unknown" en una IP ni la hora del servidor como si fuera la del
  evento: `time_quality` dice de dónde sale la hora).
- Severidades y categorías son enumeradas. La traducción de la severidad de cada producto la
  decide una política explícita y visible por fuente (catalog.py), nunca una suposición.
- `identity` identifica el registro dentro de la fuente para deduplicar: el mismo registro
  recibido dos veces (reintentos, relectura de un fichero) produce la misma identidad.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SCHEMA_VERSION = 1
SCHEMA_NAME = "sentra.siem.event"

SEVERITIES = ("informational", "low", "medium", "high", "critical", "unknown")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES[:-1])}
CATEGORIES = (
    "authentication",
    "network",
    "dns",
    "http",
    "tls",
    "dhcp",
    "ssh",
    "file",
    "system",
    "administrative",
    "detection",
    "other",
)
CONFIDENCES = ("low", "medium", "high", "unknown")
OUTCOMES = ("success", "failure", "unknown")
# De dónde sale `observed_at`: del propio evento, del receptor (el evento no traía hora) o
# recortada (el evento decía estar en el futuro más allá del desfase tolerado).
TIME_QUALITIES = ("source", "receiver", "clamped")
TRANSPORTS = ("udp", "tcp", "tls", "file", "upload")


class RecordRejectedError(Exception):
    """Registro que no se puede normalizar. `reason` es un código enumerado (se cuenta por
    fuente y lote); nunca lleva contenido del registro."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class RawRecord:
    """Un registro tal como llegó (texto acotado) y los metadatos de su transporte.

    `peer_ip` es la dirección de quien lo envió al receptor: en UDP no está autenticada, así
    que nunca se usa como identidad del dispositivo, solo como contexto.
    """

    raw: str
    transport: str
    reference: str
    record_id: str | None = None
    collected_at: datetime | None = None
    peer_ip: str | None = None
    peer_port: int | None = None


@dataclass
class NormalizedEvent:
    event_type: str
    category: str
    identity: str
    observed_at: datetime | None = None
    severity: str = "unknown"
    source_severity: str | None = None
    confidence: str = "unknown"
    hostname: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    username: str | None = None
    process_name: str | None = None
    action: str | None = None
    outcome: str | None = None
    signature_id: str | None = None
    rule_id: str | None = None
    message: str | None = None
    tags: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    external_id: str | None = None
    flow_ref: str | None = None
    # Extracto saneado del registro para la evidencia (sin payloads, ya acotado).
    excerpt: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        """Comprobación final del contrato: un normalizador con un bug no puede guardar un
        valor fuera de las enumeraciones."""
        if self.category not in CATEGORIES:
            raise RecordRejectedError("invalid_category")
        if self.severity not in SEVERITIES:
            raise RecordRejectedError("invalid_severity")
        if self.confidence not in CONFIDENCES:
            raise RecordRejectedError("invalid_confidence")
        if self.outcome is not None and self.outcome not in OUTCOMES:
            raise RecordRejectedError("invalid_outcome")
