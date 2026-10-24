"""Contratos de telemetría avanzada de endpoint y árbol de procesos (Fase 6E.3/6E.4).

Ver docs/fase-6e-contracts.md (protocolo del agente) y docs/process-tree.md (API de lectura).
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from app.schemas.common import RequestModel, ResponseModel

ActivityCategory = Literal[
    "process",
    "network",
    "service",
    "scheduled_task",
    "persistence",
    "auth",
    "dns",
    "protection",
    "firewall",
    "agent_health",
]
CollectorState = Literal["active", "unavailable", "permission_denied", "disabled", "error"]
INSTANCE_KEY = r"^[0-9a-f]{32}$"


class ActivityEventIn(RequestModel):
    event_uid: UUID
    seq: int = Field(ge=0, le=2**62)
    category: ActivityCategory
    action: str = Field(min_length=1, max_length=24)
    occurred_at: AwareDatetime
    source: str = Field(min_length=1, max_length=24)
    instance_key: str | None = Field(default=None, pattern=INSTANCE_KEY)
    data: dict[str, Any] = Field(default_factory=dict)


class ActivityStats(BaseModel):
    """Estado de la cola y de los colectores del agente. Ignora claves nuevas (un agente
    más moderno puede añadir contadores sin que el lote se rechace)."""

    model_config = ConfigDict(extra="ignore")

    queued: int | None = Field(default=None, ge=0, le=100_000_000)
    dropped_total: int | None = Field(default=None, ge=0, le=2**50)
    dropped_since_last: int | None = Field(default=None, ge=0, le=2**50)
    oldest_queued_at: AwareDatetime | None = None
    process_poll_seconds: float | None = Field(default=None, ge=0, le=86_400)
    collectors: dict[str, CollectorState] = Field(default_factory=dict, max_length=24)


class ActivityBatchIn(RequestModel):
    agent_id: UUID
    batch_id: UUID
    boot_id: str = Field(min_length=1, max_length=64)
    # Cada evento se valida por separado: uno mal formado se rechaza solo, no el lote.
    events: list[dict[str, Any]] = Field(min_length=1, max_length=1000)
    stats: ActivityStats | None = None


class ActivityRejected(ResponseModel):
    index: int
    code: str


class ActivityAccepted(ResponseModel):
    asset_id: UUID
    accepted: int
    duplicates: int
    rejected: list[ActivityRejected]


class ActivityEventRead(ResponseModel):
    id: int
    event_uid: UUID
    category: ActivityCategory
    action: str
    source: str
    instance_key: str | None
    data: dict[str, Any]
    occurred_at: datetime
    received_at: datetime


class ActivityList(ResponseModel):
    asset_id: UUID
    items: list[ActivityEventRead]
    next_before_id: int | None


class ProcessNode(ResponseModel):
    instance_key: str
    pid: int
    ppid: int | None
    parent_instance_key: str | None
    parent_relation: str | None
    name: str | None
    exe: str | None
    cmdline: str | None
    username: str | None
    sha256: str | None
    signer: str | None
    integrity: str | None
    source: str
    started_at: datetime | None
    ended_at: datetime | None
    running: bool
    children_count: int


class ProcessTree(ResponseModel):
    """Un nivel del árbol (carga perezosa): raíces o hijos de `parent`."""

    asset_id: UUID
    parent: str | None
    at: datetime | None
    nodes: list[ProcessNode]
    truncated: bool


class ProcessInstanceDetail(ResponseModel):
    asset_id: UUID
    process: ProcessNode
    # Del padre inmediato hacia la raíz (como máximo 32 niveles).
    ancestors: list[ProcessNode]
    connections: list[ActivityEventRead]


class TelemetryStatus(ResponseModel):
    asset_id: UUID
    enabled: bool
    reported_at: datetime | None
    stats: dict[str, Any] | None
    last_event_at: datetime | None
    events_last_hour: int
    # Retraso entre que ocurre un evento en el host y llega al servidor (última hora).
    ingest_lag_p50_seconds: float | None
    ingest_lag_p95_seconds: float | None
    cmdline_policy: Literal["off", "redacted", "full"]
