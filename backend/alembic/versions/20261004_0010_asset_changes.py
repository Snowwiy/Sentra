"""Inventory changes detected between snapshots

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

change_category = postgresql.ENUM("service", "software", "account", name="change_category")
change_kind = postgresql.ENUM(
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
    name="change_kind",
)


def upgrade() -> None:
    op.create_table(
        "asset_changes",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("category", change_category, nullable=False),
        sa.Column("kind", change_kind, nullable=False),
        sa.Column("item", sa.String(length=512), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_asset_changes_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_changes")),
        sa.UniqueConstraint("public_id", name=op.f("uq_asset_changes_public_id")),
    )
    op.create_index("ix_asset_changes_asset_detected", "asset_changes", ["asset_id", "detected_at"])
    op.create_index("ix_asset_changes_detected", "asset_changes", ["detected_at"])


def downgrade() -> None:
    op.drop_index("ix_asset_changes_detected", table_name="asset_changes")
    op.drop_index("ix_asset_changes_asset_detected", table_name="asset_changes")
    op.drop_table("asset_changes")
    bind = op.get_bind()
    change_kind.drop(bind, checkfirst=True)
    change_category.drop(bind, checkfirst=True)
