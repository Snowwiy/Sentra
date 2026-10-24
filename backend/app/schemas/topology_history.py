"""Contratos de la API de historial de topología y cambios de red (Fase 6E.1).

Ver docs/topology-history.md. `nodes` y `links` de un snapshot son el estado compacto
guardado en ese momento (no se recalculan con el inventario actual).
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.schemas.common import RequestModel, ResponseModel

SnapshotQuality = Literal["complete", "partial", "degraded"]
ChangeType = Literal[
    "device_appeared",
    "device_not_observed",
    "device_disappeared",
    "device_retired",
    "ip_changed",
    "mac_changed",
    "name_changed",
    "vendor_changed",
    "gateway_changed",
    "role_changed",
    "classification_changed",
    "connectivity_changed",
    "link_added",
    "link_not_observed",
    "link_removed",
    "link_port_changed",
    "link_vlan_changed",
    "link_kind_changed",
    "link_confidence_changed",
    "wifi_association_changed",
    "wifi_ap_changed",
]
ChangeStatus = Literal["detected", "confirmed", "dismissed"]
SubjectType = Literal["node", "link"]
_PLAIN = r"^[^\x00-\x1f\x7f]*$"


class TopologySnapshotRead(ResponseModel):
    id: UUID
    site_id: UUID
    sequence: int
    content_hash: str
    node_count: int
    link_count: int
    quality: SnapshotQuality
    quality_reasons: list[str]
    taken_at: datetime
    confirmed_at: datetime
    confirmations: int
    preserved: bool


class TopologySnapshotList(ResponseModel):
    items: list[TopologySnapshotRead]
    # Cursor de la página siguiente (secuencia del último elemento), null si no hay más.
    next_before_sequence: int | None


class TopologySnapshotDetail(TopologySnapshotRead):
    nodes: dict[str, Any]
    links: dict[str, Any]
    degraded_nodes: list[str]


class TopologyDiffSummary(ResponseModel):
    total: int
    by_type: dict[str, int]


class TopologyDiff(ResponseModel):
    site_id: UUID
    from_snapshot: TopologySnapshotRead
    to_snapshot: TopologySnapshotRead
    summary: TopologyDiffSummary
    # Cada cambio: change_type, subject_type, subject_key, subject_label, before, after,
    # confidence y evidence (misma forma que NetworkChangeRead sin campos de revisión).
    changes: list[dict[str, Any]]


class NetworkChangeRead(ResponseModel):
    id: UUID
    site_id: UUID
    change_type: ChangeType
    subject_type: SubjectType
    subject_key: str
    subject_label: str | None
    asset_id: UUID | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    evidence: list[dict[str, Any]]
    source: str
    confidence: Literal["high", "medium", "low"]
    status: ChangeStatus
    review_note: str | None
    reviewed_by: str | None
    reviewed_at: datetime | None
    detected_at: datetime
    preserved: bool
    version: int


class NetworkChangeList(ResponseModel):
    total: int
    items: list[NetworkChangeRead]


class NetworkChangeReview(RequestModel):
    status: ChangeStatus
    note: str | None = Field(default=None, max_length=500, pattern=_PLAIN)
    version: int = Field(ge=1, le=2**31 - 1)


class TopologyHistoryEntry(ResponseModel):
    """Un periodo en el que el nodo o enlace tuvo los mismos valores (o no existía)."""

    snapshot_id: UUID
    sequence: int
    since: datetime
    until: datetime
    present: bool
    value: dict[str, Any] | None


class TopologyHistory(ResponseModel):
    site_id: UUID
    subject_type: SubjectType
    subject_key: str
    entries: list[TopologyHistoryEntry]
