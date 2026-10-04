"""Per-agent token hash

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Nullable: assets registered before agent authentication have no token. Their agents get
    # 401 on the next call and enroll again, which sets the hash.
    op.add_column("assets", sa.Column("agent_token_hash", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "agent_token_hash")
