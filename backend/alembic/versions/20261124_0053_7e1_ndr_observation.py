"""Fase 7E.1: observación pasiva de red (NDR)

Revision ID: 0053
Revises: 0052
Create Date: 2026-11-24

Cambios (docs/fase-7e-migrations.md):
- `ndr_capture_configs`: captura aprobada por un admin para cada sensor (alias de interfaz,
  límites, metadatos permitidos y punto de observación confirmado).
- `ndr_batches`: recibos de lotes (deduplicación at-least-once y salud de la captura).
- `ndr_flows`: flujos bidireccionales (solo metadatos; uid estable por flujo y sensor).
- `ndr_protocol_observations`: metadatos ARP/DNS/DHCP/SNI agregados por clave natural.

Datos: ninguno. Las tablas nacen vacías; ningún sensor captura hasta que un admin apruebe
una configuración, así que actualizar no cambia el comportamiento de ningún sensor.

DOWNGRADE: elimina las cuatro tablas. Se pierden las configuraciones de captura aprobadas y
todo lo observado por NDR (flujos y metadatos); ningún dato de otras fases.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0053"
down_revision: str | None = "0052"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _ts(name: str, nullable: bool = False, default: bool = False) -> sa.Column:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        server_default=sa.text("now()") if default else None,
        nullable=nullable,
    )


def upgrade() -> None:
    op.create_table(
        "ndr_capture_configs",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("sensor_id", sa.BigInteger(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("interfaces", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("observation_point", sa.String(length=200), nullable=True),
        sa.Column("promiscuous", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("snaplen", sa.Integer(), server_default="512", nullable=False),
        sa.Column("max_flows", sa.Integer(), server_default="20000", nullable=False),
        sa.Column("max_packets_per_second", sa.Integer(), server_default="20000", nullable=False),
        sa.Column("max_cpu_percent", sa.SmallInteger(), server_default="40", nullable=False),
        sa.Column("export_interval_seconds", sa.Integer(), server_default="60", nullable=False),
        sa.Column("flow_idle_timeout_seconds", sa.Integer(), server_default="120", nullable=False),
        sa.Column(
            "flow_active_timeout_seconds", sa.Integer(), server_default="300", nullable=False
        ),
        sa.Column("arp_metadata", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("dhcp_metadata", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("dns_metadata", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("tls_metadata", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("updated_by", sa.String(length=64), nullable=True),
        _ts("created_at", default=True),
        _ts("updated_at", default=True),
        sa.ForeignKeyConstraint(
            ["sensor_id"],
            ["sensors.id"],
            name=op.f("fk_ndr_capture_configs_sensor_id_sensors"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.id"],
            name=op.f("fk_ndr_capture_configs_site_id_sites"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ndr_capture_configs")),
        sa.UniqueConstraint("public_id", name=op.f("uq_ndr_capture_configs_public_id")),
        sa.UniqueConstraint("sensor_id", name="uq_ndr_capture_configs_sensor_id"),
    )
    op.create_index("ix_ndr_capture_configs_site_id", "ndr_capture_configs", ["site_id"])

    op.create_table(
        "ndr_batches",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("batch_id", sa.Uuid(), nullable=False),
        sa.Column("sensor_id", sa.BigInteger(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("interface", sa.String(length=32), nullable=False),
        sa.Column("config_revision", sa.Integer(), nullable=False),
        sa.Column("backend", sa.String(length=16), nullable=True),
        _ts("window_start"),
        _ts("window_end"),
        _ts("received_at"),
        sa.Column("part", sa.Integer(), nullable=False),
        sa.Column("parts", sa.Integer(), nullable=False),
        sa.Column("flows", sa.Integer(), nullable=False),
        sa.Column("observations", sa.Integer(), nullable=False),
        sa.Column("stats", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["sensor_id"],
            ["sensors.id"],
            name=op.f("fk_ndr_batches_sensor_id_sensors"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.id"],
            name=op.f("fk_ndr_batches_site_id_sites"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ndr_batches")),
        sa.UniqueConstraint("sensor_id", "batch_id", name="uq_ndr_batches_sensor_batch"),
    )
    op.create_index("ix_ndr_batches_site_received", "ndr_batches", ["site_id", "received_at"])
    op.create_index("ix_ndr_batches_received_at", "ndr_batches", ["received_at"])

    op.create_table(
        "ndr_flows",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("sensor_id", sa.BigInteger(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("interface", sa.String(length=32), nullable=False),
        sa.Column("uid", sa.String(length=32), nullable=False),
        sa.Column("ip_version", sa.SmallInteger(), nullable=False),
        sa.Column("transport", sa.String(length=8), nullable=False),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("vlan", sa.SmallInteger(), nullable=True),
        sa.Column("src_mac", sa.String(length=17), nullable=True),
        sa.Column("dst_mac", sa.String(length=17), nullable=True),
        _ts("first_seen"),
        _ts("last_seen"),
        sa.Column("packets_out", sa.BigInteger(), nullable=False),
        sa.Column("packets_in", sa.BigInteger(), nullable=False),
        sa.Column("bytes_out", sa.BigInteger(), nullable=False),
        sa.Column("bytes_in", sa.BigInteger(), nullable=False),
        sa.Column("tcp_flags_out", sa.SmallInteger(), nullable=False),
        sa.Column("tcp_flags_in", sa.SmallInteger(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("final", sa.Boolean(), nullable=False),
        sa.Column("segments", sa.Integer(), nullable=False),
        sa.Column("flags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("retransmissions", sa.Integer(), nullable=False),
        sa.Column("fragments", sa.Integer(), nullable=False),
        sa.Column("icmp_type", sa.SmallInteger(), nullable=True),
        sa.Column("app_hints", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        _ts("updated_at"),
        sa.ForeignKeyConstraint(
            ["sensor_id"],
            ["sensors.id"],
            name=op.f("fk_ndr_flows_sensor_id_sensors"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["site_id"], ["sites.id"], name=op.f("fk_ndr_flows_site_id_sites"), ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ndr_flows")),
        sa.UniqueConstraint("sensor_id", "uid", name="uq_ndr_flows_sensor_uid"),
    )
    op.create_index("ix_ndr_flows_site_last_seen", "ndr_flows", ["site_id", "last_seen"])
    op.create_index("ix_ndr_flows_site_src", "ndr_flows", ["site_id", "src_ip", "last_seen"])
    op.create_index("ix_ndr_flows_site_dst", "ndr_flows", ["site_id", "dst_ip", "last_seen"])
    op.create_index("ix_ndr_flows_last_seen", "ndr_flows", ["last_seen"])

    op.create_table(
        "ndr_protocol_observations",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("sensor_id", sa.BigInteger(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("interface", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=True),
        sa.Column("peer_ip", sa.String(length=45), nullable=True),
        sa.Column("mac", sa.String(length=17), nullable=True),
        sa.Column("name", sa.String(length=253), nullable=True),
        sa.Column("vlan", sa.SmallInteger(), nullable=True),
        sa.Column("count", sa.BigInteger(), nullable=False),
        _ts("first_seen"),
        _ts("last_seen"),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "kind IN ('arp', 'dns', 'dhcp', 'tls')",
            name=op.f("ck_ndr_protocol_observations_kind"),
        ),
        sa.ForeignKeyConstraint(
            ["sensor_id"],
            ["sensors.id"],
            name=op.f("fk_ndr_protocol_observations_sensor_id_sensors"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.id"],
            name=op.f("fk_ndr_protocol_observations_site_id_sites"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ndr_protocol_observations")),
        sa.UniqueConstraint(
            "sensor_id", "kind", "key_hash", name="uq_ndr_protocol_observations_key"
        ),
    )
    op.create_index(
        "ix_ndr_protocol_observations_site_kind",
        "ndr_protocol_observations",
        ["site_id", "kind", "last_seen"],
    )
    op.create_index(
        "ix_ndr_protocol_observations_site_ip", "ndr_protocol_observations", ["site_id", "ip"]
    )
    op.create_index(
        "ix_ndr_protocol_observations_site_mac", "ndr_protocol_observations", ["site_id", "mac"]
    )
    op.create_index(
        "ix_ndr_protocol_observations_last_seen", "ndr_protocol_observations", ["last_seen"]
    )


def downgrade() -> None:
    op.drop_table("ndr_protocol_observations")
    op.drop_table("ndr_flows")
    op.drop_table("ndr_batches")
    op.drop_table("ndr_capture_configs")
