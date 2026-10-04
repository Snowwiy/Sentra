"""Computer name of host events

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Nullable: events stored before (and sent by older agents) have no computer name.
    op.add_column("system_events", sa.Column("computer", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("system_events", "computer")
