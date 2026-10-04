"""System events reported by agents

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

event_level = sa.Enum("info", "warning", "error", "critical", name="event_level")


def upgrade() -> None:
    op.create_table(
        "system_events",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("channel", sa.String(length=255), nullable=False),
        sa.Column("record_id", sa.BigInteger(), nullable=False),
        sa.Column("event_code", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=255), nullable=False),
        sa.Column("level", event_level, nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_system_events_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_system_events")),
        sa.UniqueConstraint("public_id", name=op.f("uq_system_events_public_id")),
        sa.UniqueConstraint("asset_id", "channel", "record_id", name="uq_system_events_record"),
    )
    op.create_index("ix_system_events_asset_occurred", "system_events", ["asset_id", "occurred_at"])
    op.create_index("ix_system_events_occurred", "system_events", ["occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_system_events_occurred", table_name="system_events")
    op.drop_index("ix_system_events_asset_occurred", table_name="system_events")
    op.drop_table("system_events")
    event_level.drop(op.get_bind(), checkfirst=True)
