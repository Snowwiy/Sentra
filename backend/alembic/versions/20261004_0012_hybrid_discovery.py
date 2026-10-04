"""Hybrid monitoring: assets without agent, network discovery, exposed ports

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

monitoring_method = postgresql.ENUM(
    "discovered", "agentless", "agent", name="asset_monitoring_method", create_type=False
)
port_state = postgresql.ENUM("open", "closed", name="port_state", create_type=False)
job_status = postgresql.ENUM(
    "running", "completed", "cancelled", "failed", name="discovery_job_status", create_type=False
)
job_trigger = postgresql.ENUM("manual", "scheduled", name="discovery_trigger", create_type=False)
asset_status = postgresql.ENUM(name="asset_status", create_type=False)

NEW_RULES = (
    "asset_discovered",
    "unknown_device",
    "asset_disappeared",
    "port_exposed",
    "port_closed",
    "monitoring_lost",
)
OLD_RULES = (
    "asset_offline",
    "high_cpu",
    "high_ram",
    "disk_critical",
    "service_stopped",
    "event_burst",
    "admin_changed",
    "critical_event",
)
NEW_CATEGORIES = ("exposure", "network")
OLD_CATEGORIES = ("service", "software", "account")
NEW_KINDS = ("port_opened", "port_closed", "appeared", "disappeared")
OLD_KINDS = (
    "added",
    "removed",
    "started",
    "stopped",
    "start_type_changed",
    "version_changed",
    "enabled",
    "disabled",
    "admin_granted",
    "admin_revoked",
)
# create_type=False: created explicitly below (create_table would create them again).
# Reported by agents: optional for assets that only exist on the network.
AGENT_COLUMNS = (
    ("agent_id", sa.Uuid()),
    ("hostname", sa.String(length=255)),
    ("os_name", sa.String(length=64)),
    ("os_version", sa.String(length=128)),
    ("architecture", sa.String(length=32)),
    ("agent_version", sa.String(length=64)),
)


def upgrade() -> None:
    # Unused in this transaction, so ADD VALUE is allowed inside it (PostgreSQL 12+).
    for rule in NEW_RULES:
        op.execute(f"ALTER TYPE alert_rule ADD VALUE IF NOT EXISTS '{rule}'")
    for category in NEW_CATEGORIES:
        op.execute(f"ALTER TYPE change_category ADD VALUE IF NOT EXISTS '{category}'")
    for kind in NEW_KINDS:
        op.execute(f"ALTER TYPE change_kind ADD VALUE IF NOT EXISTS '{kind}'")

    bind = op.get_bind()
    for enum_type in (monitoring_method, port_state, job_status, job_trigger):
        enum_type.create(bind, checkfirst=True)

    # Existing assets all run an agent: the server default classifies them. Dropping NOT
    # NULL is metadata only; existing rows and agents are unaffected.
    op.add_column(
        "assets",
        sa.Column("monitoring_method", monitoring_method, server_default="agent", nullable=False),
    )
    for name, type_ in AGENT_COLUMNS:
        op.alter_column("assets", name, existing_type=type_, nullable=True)
    op.add_column("assets", sa.Column("mac_address", sa.String(length=17), nullable=True))
    op.add_column("assets", sa.Column("reverse_dns", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("vendor", sa.String(length=128), nullable=True))
    op.add_column("assets", sa.Column("device_type", sa.String(length=32), nullable=True))
    op.add_column("assets", sa.Column("device_type_reason", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("discovery_sources", postgresql.JSONB(), nullable=True))
    op.add_column("assets", sa.Column("discovery_network", sa.String(length=64), nullable=True))
    op.add_column("assets", sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "assets", sa.Column("last_network_seen_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("assets", sa.Column("network_status", asset_status, nullable=True))
    op.add_column(
        "assets",
        sa.Column("network_misses", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "assets", sa.Column("exposure_baseline_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index("ix_assets_primary_ip", "assets", ["primary_ip"])
    op.create_index("ix_assets_mac_address", "assets", ["mac_address"])

    op.create_table(
        "asset_ports",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("state", port_state, nullable=False),
        sa.Column("service_hint", sa.String(length=32), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("misses", sa.Integer(), server_default="0", nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_asset_ports_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_ports")),
        sa.UniqueConstraint("asset_id", "protocol", "port", name="uq_asset_ports_asset_port"),
    )

    op.create_table(
        "discovery_jobs",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("target", sa.String(length=64), nullable=False),
        sa.Column("trigger", job_trigger, nullable=False),
        sa.Column("status", job_status, nullable=False),
        sa.Column("baseline", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hosts_scanned", sa.Integer(), nullable=False),
        sa.Column("hosts_alive", sa.Integer(), nullable=False),
        sa.Column("hosts_new", sa.Integer(), nullable=False),
        sa.Column("open_ports", sa.Integer(), nullable=False),
        sa.Column("probes", sa.Integer(), nullable=False),
        sa.Column("error_count", sa.Integer(), nullable=False),
        sa.Column("errors", postgresql.JSONB(), nullable=True),
        sa.Column("parameters", postgresql.JSONB(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_discovery_jobs")),
        sa.UniqueConstraint("public_id", name=op.f("uq_discovery_jobs_public_id")),
    )
    op.create_index(
        "uq_discovery_jobs_running_target",
        "discovery_jobs",
        ["target"],
        unique=True,
        postgresql_where=sa.text("status = 'running'"),
    )
    op.create_index("ix_discovery_jobs_started", "discovery_jobs", ["started_at"])


def _rebuild_enum(type_name: str, table: str, column: str, values: Sequence[str]) -> None:
    listed = ", ".join(f"'{value}'" for value in values)
    op.execute(f"ALTER TYPE {type_name} RENAME TO {type_name}_old")
    op.execute(f"CREATE TYPE {type_name} AS ENUM ({listed})")
    op.execute(
        f"ALTER TABLE {table} ALTER COLUMN {column} TYPE {type_name}"
        f" USING {column}::text::{type_name}"
    )
    op.execute(f"DROP TYPE {type_name}_old")


def downgrade() -> None:
    bind = op.get_bind()
    # ⚠️ Data that cannot exist before 0012 is deleted: assets without an agent (with their
    # ports, changes and alerts, by cascade), discovery alerts and changes of agent assets.
    bind.execute(sa.text("DELETE FROM assets WHERE agent_id IS NULL"))
    bind.execute(
        sa.text("DELETE FROM alerts WHERE rule::text = ANY(:rules)"), {"rules": list(NEW_RULES)}
    )
    bind.execute(
        sa.text("DELETE FROM asset_changes WHERE category::text = ANY(:c) OR kind::text = ANY(:k)"),
        {"c": list(NEW_CATEGORIES), "k": list(NEW_KINDS)},
    )

    op.drop_index("ix_discovery_jobs_started", table_name="discovery_jobs")
    op.drop_index("uq_discovery_jobs_running_target", table_name="discovery_jobs")
    op.drop_table("discovery_jobs")
    op.drop_table("asset_ports")
    op.drop_index("ix_assets_mac_address", table_name="assets")
    op.drop_index("ix_assets_primary_ip", table_name="assets")
    for column in (
        "exposure_baseline_at",
        "network_misses",
        "network_status",
        "last_network_seen_at",
        "discovered_at",
        "discovery_network",
        "discovery_sources",
        "device_type_reason",
        "device_type",
        "vendor",
        "reverse_dns",
        "mac_address",
        "monitoring_method",
    ):
        op.drop_column("assets", column)
    for name, type_ in AGENT_COLUMNS:
        op.alter_column("assets", name, existing_type=type_, nullable=False)
    for enum_type in (job_trigger, job_status, port_state, monitoring_method):
        enum_type.drop(bind, checkfirst=True)

    # The partial unique index on alerts references the enum column: rebuild around it.
    op.drop_index("uq_alerts_active_asset_rule", table_name="alerts")
    _rebuild_enum("alert_rule", "alerts", "rule", OLD_RULES)
    op.create_index(
        "uq_alerts_active_asset_rule",
        "alerts",
        ["asset_id", "rule"],
        unique=True,
        postgresql_where=sa.text("status <> 'resolved'"),
    )
    _rebuild_enum("change_category", "asset_changes", "category", OLD_CATEGORIES)
    _rebuild_enum("change_kind", "asset_changes", "kind", OLD_KINDS)
