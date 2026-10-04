"""Agent token revocation and issue time

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Both nullable and without defaults: adding them is a metadata-only change in PostgreSQL
    # (no table rewrite) and existing agents keep working untouched.
    op.add_column(
        "assets", sa.Column("agent_token_revoked_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "assets", sa.Column("agent_token_issued_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("assets", "agent_token_issued_at")
    op.drop_column("assets", "agent_token_revoked_at")
