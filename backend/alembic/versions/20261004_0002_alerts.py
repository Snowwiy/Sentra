"""Alerts table

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

alert_rule = sa.Enum("asset_offline", "high_cpu", "high_ram", "disk_critical", name="alert_rule")
alert_severity = sa.Enum("info", "warning", "critical", name="alert_severity")
alert_status = sa.Enum("open", "resolved", name="alert_status")


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("rule", alert_rule, nullable=False),
        sa.Column("severity", alert_severity, nullable=False),
        sa.Column("status", alert_status, nullable=False),
        sa.Column("message", sa.String(length=500), nullable=False),
        sa.Column("value", sa.Float(), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name=op.f("fk_alerts_asset_id_assets"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
        sa.UniqueConstraint("public_id", name=op.f("uq_alerts_public_id")),
    )
    op.create_index("ix_alerts_status_opened", "alerts", ["status", "opened_at"])
    # Partial unique index: the deduplication guarantee for open alerts (see models/alert.py).
    op.create_index(
        "uq_alerts_open_asset_rule",
        "alerts",
        ["asset_id", "rule"],
        unique=True,
        postgresql_where=sa.text("status = 'open'"),
    )


def downgrade() -> None:
    op.drop_index("uq_alerts_open_asset_rule", table_name="alerts")
    op.drop_index("ix_alerts_status_opened", table_name="alerts")
    op.drop_table("alerts")
    bind = op.get_bind()
    for enum in (alert_status, alert_severity, alert_rule):
        enum.drop(bind, checkfirst=True)
