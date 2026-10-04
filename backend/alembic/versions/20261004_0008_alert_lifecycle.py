"""Alert lifecycle: acknowledged status, details, occurrences and event-based rules

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_RULES = ("service_stopped", "event_burst", "admin_changed", "critical_event")
OLD_RULES = ("asset_offline", "high_cpu", "high_ram", "disk_critical")


def upgrade() -> None:
    # New enum values. PostgreSQL 12+ accepts ADD VALUE inside the migration transaction as
    # long as the value is not used in that same transaction; nothing below uses them (the
    # new index predicate is written against 'resolved').
    op.execute("ALTER TYPE alert_status ADD VALUE IF NOT EXISTS 'acknowledged'")
    for rule in NEW_RULES:
        op.execute(f"ALTER TYPE alert_rule ADD VALUE IF NOT EXISTS '{rule}'")

    # All nullable or with a server default: metadata-only changes, existing alerts unchanged.
    op.add_column("alerts", sa.Column("details", postgresql.JSONB(), nullable=True))
    op.add_column("alerts", sa.Column("source_event_id", sa.BigInteger(), nullable=True))
    op.create_foreign_key(
        op.f("fk_alerts_source_event_id_system_events"),
        "alerts",
        "system_events",
        ["source_event_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column(
        "alerts", sa.Column("occurrences", sa.Integer(), server_default="1", nullable=False)
    )
    op.add_column(
        "alerts", sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("alerts", sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True))

    # Deduplication now covers acknowledged alerts too ("active" = not resolved).
    op.drop_index("uq_alerts_open_asset_rule", table_name="alerts")
    op.create_index(
        "uq_alerts_active_asset_rule",
        "alerts",
        ["asset_id", "rule"],
        unique=True,
        postgresql_where=sa.text("status <> 'resolved'"),
    )
    op.create_index("ix_alerts_asset_opened", "alerts", ["asset_id", "opened_at"])
    # Lookup used by the ON DELETE SET NULL trigger when retention deletes events. Without it
    # every deleted event scans the whole alerts table (51 s per 5000-event batch measured
    # with 100k alerts). Partial: most alerts have no source event.
    op.create_index(
        "ix_alerts_source_event",
        "alerts",
        ["source_event_id"],
        postgresql_where=sa.text("source_event_id IS NOT NULL"),
    )


def downgrade() -> None:
    # PostgreSQL cannot drop enum values, so the types are rebuilt. Alerts of the new rules
    # cannot be represented before 0008 and are deleted; acknowledged ones become open.
    op.get_bind().execute(
        sa.text("DELETE FROM alerts WHERE rule::text = ANY(:rules)"), {"rules": list(NEW_RULES)}
    )
    op.execute("UPDATE alerts SET status = 'open' WHERE status::text = 'acknowledged'")

    op.drop_index("ix_alerts_source_event", table_name="alerts")
    op.drop_index("ix_alerts_asset_opened", table_name="alerts")
    op.drop_index("uq_alerts_active_asset_rule", table_name="alerts")
    op.drop_column("alerts", "acknowledged_at")
    op.drop_column("alerts", "last_triggered_at")
    op.drop_column("alerts", "occurrences")
    op.drop_constraint(
        op.f("fk_alerts_source_event_id_system_events"), "alerts", type_="foreignkey"
    )
    op.drop_column("alerts", "source_event_id")
    op.drop_column("alerts", "details")

    for type_name, column, values in (
        ("alert_status", "status", ("open", "resolved")),
        ("alert_rule", "rule", OLD_RULES),
    ):
        listed = ", ".join(f"'{value}'" for value in values)
        op.execute(f"ALTER TYPE {type_name} RENAME TO {type_name}_old")
        op.execute(f"CREATE TYPE {type_name} AS ENUM ({listed})")
        op.execute(
            f"ALTER TABLE alerts ALTER COLUMN {column} TYPE {type_name}"
            f" USING {column}::text::{type_name}"
        )
        op.execute(f"DROP TYPE {type_name}_old")

    op.create_index(
        "uq_alerts_open_asset_rule",
        "alerts",
        ["asset_id", "rule"],
        unique=True,
        postgresql_where=sa.text("status = 'open'"),
    )
