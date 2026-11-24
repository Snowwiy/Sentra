"""Fase 7E.2: anomalías de red NDR (ARP, MITM, DNS, DHCP) y asociaciones IP-MAC

Revision ID: 0054
Revises: 0053
Create Date: 2026-11-24

Cambios (docs/fase-7e-migrations.md):
- `ndr_anomalies`: hallazgos de las reglas NDR con veredicto (observed, suspicious, probable,
  confirmed), estado de triaje y evidencia acotada. Única activa por (site, regla, clave).
- `ndr_ip_mac_bindings`: asociaciones IP-MAC observadas por ARP y DHCP, base de las reglas
  de suplantación ARP y de la puerta de enlace.

Datos: ninguno. Las reglas empiezan a evaluar los lotes que lleguen después de actualizar; lo
ya guardado en 0053 no se reevalúa.

DOWNGRADE: elimina ambas tablas (se pierden las anomalías NDR y su triaje).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0054"
down_revision: str | None = "0053"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ndr_anomalies",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("sensor_id", sa.BigInteger(), nullable=True),
        sa.Column("rule_id", sa.String(length=24), nullable=False),
        sa.Column("rule_version", sa.SmallInteger(), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("verdict", sa.String(length=12), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="open", nullable=False),
        sa.Column("dedup_key", sa.String(length=160), nullable=False),
        sa.Column("subject_ip", sa.String(length=45), nullable=True),
        sa.Column("subject_mac", sa.String(length=17), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("summary", sa.String(length=1000), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("occurrences", sa.Integer(), server_default="1", nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status_by", sa.String(length=64), nullable=True),
        sa.Column("status_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status_note", sa.String(length=500), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "verdict IN ('observed', 'suspicious', 'probable', 'confirmed')",
            name=op.f("ck_ndr_anomalies_verdict"),
        ),
        sa.CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved', 'false_positive')",
            name=op.f("ck_ndr_anomalies_status"),
        ),
        sa.ForeignKeyConstraint(
            ["sensor_id"],
            ["sensors.id"],
            name=op.f("fk_ndr_anomalies_sensor_id_sensors"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.id"],
            name=op.f("fk_ndr_anomalies_site_id_sites"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ndr_anomalies")),
        sa.UniqueConstraint("public_id", name=op.f("uq_ndr_anomalies_public_id")),
    )
    op.create_index(
        "uq_ndr_anomalies_active_key",
        "ndr_anomalies",
        ["site_id", "rule_id", "dedup_key"],
        unique=True,
        postgresql_where=sa.text("status IN ('open', 'acknowledged')"),
    )
    op.create_index("ix_ndr_anomalies_site_last_seen", "ndr_anomalies", ["site_id", "last_seen"])
    op.create_index("ix_ndr_anomalies_status_last_seen", "ndr_anomalies", ["status", "last_seen"])
    op.create_index("ix_ndr_anomalies_sensor_id", "ndr_anomalies", ["sensor_id"])
    op.create_index("ix_ndr_anomalies_subject_ip", "ndr_anomalies", ["site_id", "subject_ip"])

    op.create_table(
        "ndr_ip_mac_bindings",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("vlan_key", sa.Integer(), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("mac", sa.String(length=17), nullable=False),
        sa.Column("source", sa.String(length=8), nullable=False),
        sa.Column("gateway", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("count", sa.BigInteger(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.id"],
            name=op.f("fk_ndr_ip_mac_bindings_site_id_sites"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ndr_ip_mac_bindings")),
        sa.UniqueConstraint("site_id", "vlan_key", "ip", "mac", name="uq_ndr_ip_mac_bindings_key"),
    )
    op.create_index(
        "ix_ndr_ip_mac_bindings_site_ip", "ndr_ip_mac_bindings", ["site_id", "ip", "last_seen"]
    )
    op.create_index("ix_ndr_ip_mac_bindings_site_mac", "ndr_ip_mac_bindings", ["site_id", "mac"])
    op.create_index("ix_ndr_ip_mac_bindings_last_seen", "ndr_ip_mac_bindings", ["last_seen"])


def downgrade() -> None:
    op.drop_table("ndr_ip_mac_bindings")
    op.drop_table("ndr_anomalies")
