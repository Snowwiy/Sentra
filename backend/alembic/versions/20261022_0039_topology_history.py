"""Historial de topología y cambios de red (Fase 6E.1)

Revision ID: 0039
Revises: 0038
Create Date: 2026-10-22

Cambios (ver app/models/topology_history.py y docs/topology-history.md):
- topology_snapshots: un estado distinto del grafo por fila (hash del contenido canónico),
  con calidad de la evidencia (complete/partial/degraded) y marca de preservación.
- network_changes: cambios entre snapshots consecutivos con evidencia, fuente, confianza y
  revisión humana.
- topology_links.absent_builds / absent_since / removed_at: contador de reconstrucciones sin
  derivar el enlace, para concluir link_removed solo tras varias ausencias con fuente sana.

Datos: no se crea ningún snapshot en la migración; el primero lo toma la siguiente
reconstrucción (línea base, sin cambios). Los enlaces ya ausentes empiezan con
absent_builds = 0: su eliminación se concluye solo con reconstrucciones posteriores.

DOWNGRADE: elimina el historial (snapshots y cambios, incluidos sus estados de revisión, que
quedan en la auditoría) y las tres columnas de topology_links. Los enlaces y su revisión de
6D se conservan.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0039"
down_revision: str | None = "0038"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())

QUALITIES = ("complete", "partial", "degraded")
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


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _ts(name: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(name: str, target: str, ondelete: str, nullable: bool = True) -> sa.Column[object]:
    return sa.Column(
        name, sa.BigInteger(), sa.ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "topology_snapshots",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        _fk("build_id", "topology_builds.id", "SET NULL"),
        sa.Column("nodes", _JSONB, nullable=False),
        sa.Column("links", _JSONB, nullable=False),
        sa.Column("node_count", sa.Integer(), nullable=False),
        sa.Column("link_count", sa.Integer(), nullable=False),
        sa.Column("quality", sa.String(16), nullable=False),
        sa.Column("quality_detail", _JSONB, nullable=False),
        _ts("taken_at"),
        _ts("confirmed_at"),
        sa.Column("confirmations", sa.Integer(), server_default="1", nullable=False),
        sa.Column("preserved", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("preserve_reason", sa.String(200)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("site_id", "sequence", name="uq_topology_snapshots_site_sequence"),
        sa.CheckConstraint(_in("quality", QUALITIES), name="ck_topology_snapshots_quality"),
    )
    op.create_index(
        "ix_topology_snapshots_site_taken", "topology_snapshots", ["site_id", "taken_at"]
    )
    op.create_index("ix_topology_snapshots_build", "topology_snapshots", ["build_id"])

    op.create_table(
        "network_changes",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        sa.Column("change_type", sa.String(32), nullable=False),
        sa.Column("subject_type", sa.String(8), nullable=False),
        sa.Column("subject_key", sa.String(96), nullable=False),
        sa.Column("subject_label", sa.String(255)),
        _fk("asset_id", "assets.id", "SET NULL"),
        sa.Column("before", _JSONB),
        sa.Column("after", _JSONB),
        sa.Column("evidence", _JSONB, nullable=False),
        sa.Column("source", sa.String(24), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("status", sa.String(16), server_default="detected", nullable=False),
        sa.Column("review_note", sa.String(500)),
        sa.Column("reviewed_by", sa.String(64)),
        _ts("reviewed_at", nullable=True),
        _fk("from_snapshot_id", "topology_snapshots.id", "SET NULL"),
        _fk("to_snapshot_id", "topology_snapshots.id", "SET NULL"),
        _ts("detected_at"),
        sa.Column("preserved", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.CheckConstraint(_in("change_type", CHANGE_TYPES), name="ck_network_changes_type"),
        sa.CheckConstraint(
            _in("status", ("detected", "confirmed", "dismissed")), name="ck_network_changes_status"
        ),
        sa.CheckConstraint(
            _in("subject_type", ("node", "link")), name="ck_network_changes_subject"
        ),
        sa.CheckConstraint(
            _in("confidence", ("high", "medium", "low")), name="ck_network_changes_confidence"
        ),
    )
    op.create_index(
        "ix_network_changes_site_detected", "network_changes", ["site_id", "detected_at"]
    )
    op.create_index(
        "ix_network_changes_subject", "network_changes", ["site_id", "subject_key", "detected_at"]
    )
    op.create_index(
        "ix_network_changes_type", "network_changes", ["site_id", "change_type", "detected_at"]
    )
    op.create_index("ix_network_changes_asset", "network_changes", ["asset_id"])
    op.create_index("ix_network_changes_from_snapshot", "network_changes", ["from_snapshot_id"])
    op.create_index("ix_network_changes_to_snapshot", "network_changes", ["to_snapshot_id"])

    op.add_column(
        "topology_links",
        sa.Column("absent_builds", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column("topology_links", _ts("absent_since", nullable=True))
    op.add_column("topology_links", _ts("removed_at", nullable=True))


def downgrade() -> None:
    op.drop_column("topology_links", "removed_at")
    op.drop_column("topology_links", "absent_since")
    op.drop_column("topology_links", "absent_builds")
    op.drop_table("network_changes")
    op.drop_table("topology_snapshots")
