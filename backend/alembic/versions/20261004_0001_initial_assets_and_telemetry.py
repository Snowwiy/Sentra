"""Initial schema: assets and telemetry samples

Revision ID: 0001
Revises:
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

asset_status = sa.Enum("online", "offline", "unknown", name="asset_status")


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("os_name", sa.String(length=64), nullable=False),
        sa.Column("os_version", sa.String(length=128), nullable=False),
        sa.Column("architecture", sa.String(length=32), nullable=False),
        sa.Column("primary_ip", sa.String(length=45), nullable=False),
        sa.Column("agent_version", sa.String(length=64), nullable=False),
        sa.Column("status", asset_status, nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
        sa.UniqueConstraint("public_id", name=op.f("uq_assets_public_id")),
        sa.UniqueConstraint("agent_id", name=op.f("uq_assets_agent_id")),
    )

    op.create_table(
        "telemetry_samples",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("cpu_percent", sa.Float(), nullable=False),
        sa.Column("ram_percent", sa.Float(), nullable=False),
        sa.Column("disk_percent", sa.Float(), nullable=False),
        sa.Column("uptime_seconds", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_telemetry_samples_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_telemetry_samples")),
    )
    op.create_index(
        "ix_telemetry_samples_asset_recorded",
        "telemetry_samples",
        ["asset_id", "recorded_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_telemetry_samples_asset_recorded", table_name="telemetry_samples")
    op.drop_table("telemetry_samples")
    op.drop_table("assets")
    asset_status.drop(op.get_bind(), checkfirst=True)
