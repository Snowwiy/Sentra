"""Idempotency key for telemetry samples

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Nullable: existing rows and older agents have no sample_id. PostgreSQL treats NULLs as
    # distinct in unique indexes, so they never conflict.
    op.add_column("telemetry_samples", sa.Column("sample_id", sa.Uuid(), nullable=True))
    op.create_index(
        "uq_telemetry_samples_asset_sample",
        "telemetry_samples",
        ["asset_id", "sample_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_telemetry_samples_asset_sample", table_name="telemetry_samples")
    op.drop_column("telemetry_samples", "sample_id")
