"""One-time agent enrollment tokens

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Only token hashes are stored; nothing here can be used to enroll an agent.
    op.create_table(
        "agent_enrollment_tokens",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("max_uses", sa.Integer(), server_default="1", nullable=False),
        sa.Column("use_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expected_platform", sa.String(length=32), nullable=True),
        sa.Column("expected_hostname", sa.String(length=255), nullable=True),
        sa.Column("note", sa.String(length=200), nullable=True),
        sa.Column("created_via", sa.String(length=16), nullable=False),
        sa.Column("last_asset_id", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(
            ["last_asset_id"],
            ["assets.id"],
            name=op.f("fk_agent_enrollment_tokens_last_asset_id_assets"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_enrollment_tokens")),
        sa.UniqueConstraint("public_id", name=op.f("uq_agent_enrollment_tokens_public_id")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_agent_enrollment_tokens_token_hash")),
    )
    op.create_index("ix_agent_enrollment_tokens_created", "agent_enrollment_tokens", ["created_at"])
    op.create_index(
        op.f("ix_agent_enrollment_tokens_last_asset_id"),
        "agent_enrollment_tokens",
        ["last_asset_id"],
    )


def downgrade() -> None:
    # Tokens issued under 0013 stop existing; agents already enrolled keep their own tokens.
    op.drop_index(
        op.f("ix_agent_enrollment_tokens_last_asset_id"), table_name="agent_enrollment_tokens"
    )
    op.drop_index("ix_agent_enrollment_tokens_created", table_name="agent_enrollment_tokens")
    op.drop_table("agent_enrollment_tokens")
