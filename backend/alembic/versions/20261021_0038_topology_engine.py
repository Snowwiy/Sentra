"""Motor de topología y diagnóstico SNMP por equipo (Fase 6D)

Revision ID: 0038
Revises: 0037
Create Date: 2026-10-21

Cambios (ver app/models/topology.py, app/models/network.py y docs/topology-engine.md):
- topology_links: enlaces derivados de evidencia verificable (LLDP/CDP, tablas de switches,
  asociaciones WLAN, gateways de agentes) con clase, confianza, evidencia acotada, presencia
  y revisión humana. Los nodos no se guardan: son referencias al inventario existente.
- topology_builds: historial de reconstrucciones por site; un índice único parcial impide dos
  reconstrucciones simultáneas del mismo site.
- network_devices.snmp_status: diagnóstico SNMP del equipo en la taxonomía de Sentra
  (unverified, compatible, no_response, unreachable, auth_failed, unsupported_version,
  malformed_response, collector_error). Nunca un nombre de excepción.
- network_devices.monitoring_paused_at / monitoring_pause_reason: pausa automática de las
  consultas periódicas tras fallos repetidos que indican que no hay SNMP utilizable (sin
  reintentos indefinidos contra equipos incompatibles).

Datos: snmp_status empieza en "unverified", salvo los equipos que ya tuvieron alguna consulta
correcta (last_success_at no nulo), que pasan a "compatible": esa respuesta ya está demostrada
y mostrarlos como "sin verificar" hasta la siguiente consulta sería engañoso. Los equipos con
consultas fallidas previas no se pausan retroactivamente: la pausa solo la decide el
programador con fallos nuevos.

DOWNGRADE: elimina las tablas de topología (se pierden los enlaces derivados, que se pueden
reconstruir, y las revisiones humanas de enlaces, que quedan en la auditoría) y las columnas
de diagnóstico SNMP (un equipo pausado vuelve a consultarse en su intervalo).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0038"
down_revision: str | None = "0037"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())


def _ts(name: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(name: str, target: str, ondelete: str, nullable: bool = True) -> sa.Column[object]:
    return sa.Column(
        name, sa.BigInteger(), sa.ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "topology_links",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        sa.Column("link_key", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("medium", sa.String(16), server_default="unknown", nullable=False),
        sa.Column("relation", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("source_node", sa.String(96), nullable=False),
        _fk("source_asset_id", "assets.id", "CASCADE"),
        _fk("source_device_id", "network_devices.id", "CASCADE"),
        _fk("source_ap_id", "wlan_access_points.id", "CASCADE"),
        _fk("source_interface_id", "network_interfaces.id", "SET NULL"),
        sa.Column("source_port", sa.String(255)),
        sa.Column("target_node", sa.String(96), nullable=False),
        _fk("target_asset_id", "assets.id", "CASCADE"),
        _fk("target_device_id", "network_devices.id", "CASCADE"),
        _fk("target_ap_id", "wlan_access_points.id", "CASCADE"),
        sa.Column("target_port", sa.String(255)),
        sa.Column("target_external_label", sa.String(255)),
        sa.Column("target_external", _JSONB),
        sa.Column("evidence", _JSONB, nullable=False),
        sa.Column("evidence_sources", _JSONB, nullable=False),
        sa.Column("present", sa.Boolean(), server_default="true", nullable=False),
        _ts("first_seen_at"),
        _ts("last_seen_at"),
        _ts("last_evidence_at", nullable=True),
        sa.Column("review_state", sa.String(16), server_default="unreviewed", nullable=False),
        sa.Column("review_note", sa.String(500)),
        sa.Column("reviewed_by", sa.String(64)),
        _ts("reviewed_at", nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("site_id", "link_key", name="uq_topology_links_site_key"),
        sa.CheckConstraint(
            "kind IN ('physical', 'logical', 'observed', 'candidate', 'unknown')",
            name="ck_topology_links_kind",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')", name="ck_topology_links_confidence"
        ),
        sa.CheckConstraint(
            "review_state IN ('unreviewed', 'accepted', 'rejected')",
            name="ck_topology_links_review_state",
        ),
    )
    op.create_index(
        "ix_topology_links_site_present", "topology_links", ["site_id", "present", "kind"]
    )
    op.create_index("ix_topology_links_source_node", "topology_links", ["site_id", "source_node"])
    op.create_index("ix_topology_links_target_node", "topology_links", ["site_id", "target_node"])
    for column in (
        "source_asset_id",
        "target_asset_id",
        "source_device_id",
        "target_device_id",
        "source_ap_id",
        "target_ap_id",
        "source_interface_id",
    ):
        name = column.removesuffix("_id")
        op.create_index(f"ix_topology_links_{name}", "topology_links", [column])

    op.create_table(
        "topology_builds",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("requested_by", sa.String(64)),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("counts", _JSONB),
        sa.Column("error_code", sa.String(32)),
        _ts("started_at"),
        _ts("finished_at", nullable=True),
        sa.Column("duration_ms", sa.Integer()),
        sa.CheckConstraint(
            "status IN ('running', 'succeeded', 'failed')", name="ck_topology_builds_status"
        ),
    )
    op.create_index("ix_topology_builds_site", "topology_builds", ["site_id", "started_at"])
    op.create_index(
        "uq_topology_builds_running",
        "topology_builds",
        ["site_id"],
        unique=True,
        postgresql_where=sa.text("status = 'running'"),
    )

    op.add_column(
        "network_devices",
        sa.Column("snmp_status", sa.String(24), server_default="unverified", nullable=False),
    )
    op.add_column("network_devices", _ts("monitoring_paused_at", nullable=True))
    op.add_column("network_devices", sa.Column("monitoring_pause_reason", sa.String(32)))
    op.execute(
        "UPDATE network_devices SET snmp_status = 'compatible' WHERE last_success_at IS NOT NULL"
    )


def downgrade() -> None:
    op.drop_column("network_devices", "monitoring_pause_reason")
    op.drop_column("network_devices", "monitoring_paused_at")
    op.drop_column("network_devices", "snmp_status")
    op.drop_index("uq_topology_builds_running", table_name="topology_builds")
    op.drop_index("ix_topology_builds_site", table_name="topology_builds")
    op.drop_table("topology_builds")
    op.drop_table("topology_links")
