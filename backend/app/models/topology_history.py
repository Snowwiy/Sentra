"""Historial de topología y cambios de red (Fase 6E.1, docs/topology-history.md).

Dos tablas sobre el motor de 6D:

- topology_snapshots: una fila por ESTADO distinto del grafo de un site (no por
  reconstrucción). Cada reconstrucción calcula el contenido compacto y su hash; si coincide con
  el último snapshot solo se actualiza `confirmed_at`. Así el historial crece con los cambios
  de la red y no con el intervalo del programador.
- network_changes: cada diferencia entre dos snapshots consecutivos (o de identidad) con su
  evidencia, fuente, confianza y revisión humana. Es evidencia SOC: no se borra salvo por la
  retención configurada y nunca si está preservada (vinculada a un incidente o investigación).

Los snapshots guardan referencias al inventario (claves de nodo) y los valores observados en
ese momento (nombre, IP, MAC...): no se recalculan después, porque son el estado de entonces.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# Calidad de la evidencia de un snapshot. Solo `complete` permite concluir que algo dejó de
# existir; `partial` (grafo recortado por los topes) y `degraded` (alguna fuente de evidencia
# falló en su última consulta) solo permiten registrar lo que SÍ se observó.
SNAPSHOT_QUALITIES = ("complete", "partial", "degraded")

CHANGE_TYPES = (
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
)
CHANGE_STATUSES = ("detected", "confirmed", "dismissed")
SUBJECT_TYPES = ("node", "link")
CHANGE_CONFIDENCES = ("high", "medium", "low")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class TopologySnapshot(Base):
    __tablename__ = "topology_snapshots"
    __table_args__ = (
        UniqueConstraint("site_id", "sequence", name="uq_topology_snapshots_site_sequence"),
        Index("ix_topology_snapshots_site_taken", "site_id", "taken_at"),
        Index("ix_topology_snapshots_build", "build_id"),
        CheckConstraint(_in("quality", SNAPSHOT_QUALITIES), name="ck_topology_snapshots_quality"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    # Número creciente por site: ordena el historial sin depender del reloj.
    sequence: Mapped[int] = mapped_column(Integer)
    # SHA-256 del contenido canónico (nodes + links): igualdad = mismo estado de red.
    content_hash: Mapped[str] = mapped_column(String(64))
    # Reconstrucción que lo produjo (SET NULL: la retención de builds no borra la historia).
    build_id: Mapped[int | None] = mapped_column(
        ForeignKey("topology_builds.id", ondelete="SET NULL")
    )
    # {node_id: {...valores compactos...}} y {link_key: {...}}; ver app/topology/history.py.
    nodes: Mapped[dict[str, Any]] = mapped_column(JSONB)
    links: Mapped[dict[str, Any]] = mapped_column(JSONB)
    node_count: Mapped[int] = mapped_column(Integer)
    link_count: Mapped[int] = mapped_column(Integer)
    quality: Mapped[str] = mapped_column(String(16))
    # Motivos de una calidad distinta de complete y nodos cuya evidencia falló.
    quality_detail: Mapped[dict[str, Any]] = mapped_column(JSONB)
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Última reconstrucción que obtuvo exactamente este estado.
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    confirmations: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    preserved: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    preserve_reason: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class NetworkChange(Base):
    __tablename__ = "network_changes"
    __table_args__ = (
        Index("ix_network_changes_site_detected", "site_id", "detected_at"),
        Index("ix_network_changes_subject", "site_id", "subject_key", "detected_at"),
        Index("ix_network_changes_type", "site_id", "change_type", "detected_at"),
        Index("ix_network_changes_asset", "asset_id"),
        Index("ix_network_changes_from_snapshot", "from_snapshot_id"),
        Index("ix_network_changes_to_snapshot", "to_snapshot_id"),
        CheckConstraint(_in("change_type", CHANGE_TYPES), name="ck_network_changes_type"),
        CheckConstraint(_in("status", CHANGE_STATUSES), name="ck_network_changes_status"),
        CheckConstraint(_in("subject_type", SUBJECT_TYPES), name="ck_network_changes_subject"),
        CheckConstraint(
            _in("confidence", CHANGE_CONFIDENCES), name="ck_network_changes_confidence"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    change_type: Mapped[str] = mapped_column(String(32))
    subject_type: Mapped[str] = mapped_column(String(8))
    # Clave de nodo (asset:<uuid>, network_device:<uuid>...) o link_key del enlace.
    subject_key: Mapped[str] = mapped_column(String(96))
    subject_label: Mapped[str | None] = mapped_column(String(255))
    # Activo afectado si el sujeto es (o toca) un activo: filtra el historial por activo.
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    before: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # [{"source", "detail", "observed_at"}] acotada (máx. 8 entradas).
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    # topology_diff | identity | dhcp | discovery: quién lo detectó.
    source: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[str] = mapped_column(String(8))
    status: Mapped[str] = mapped_column(String(16), default="detected", server_default="detected")
    review_note: Mapped[str | None] = mapped_column(String(500))
    reviewed_by: Mapped[str | None] = mapped_column(String(64))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    from_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("topology_snapshots.id", ondelete="SET NULL")
    )
    to_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("topology_snapshots.id", ondelete="SET NULL")
    )
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    preserved: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
