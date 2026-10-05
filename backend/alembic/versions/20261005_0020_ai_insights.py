"""AI Security Insights (Fase 4J)

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-05

Añade la tabla ai_insights: resultados validados de los análisis de IA (con referencias de
evidencia resueltas), su huella de datos para caché y estado stale, y métricas técnicas. No
guarda prompts, contexto enviado ni claves. No modifica ninguna tabla existente.

El downgrade borra ai_insights (análisis derivados que se pueden regenerar); el resto de
datos queda intacto.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_insights",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=True),
        sa.Column("detection_id", sa.BigInteger(), nullable=True),
        sa.Column("risk_snapshot_id", sa.BigInteger(), nullable=True),
        sa.Column("question", sa.String(length=500), nullable=True),
        sa.Column("cache_key", sa.String(length=64), nullable=False),
        sa.Column("data_version", sa.String(length=64), nullable=False),
        sa.Column("prompt_version", sa.String(length=48), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("input_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("evidence_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("dropped_refs", sa.Integer(), server_default="0", nullable=False),
        sa.Column("context_items", sa.Integer(), server_default="0", nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("input_chars", sa.Integer(), nullable=True),
        sa.Column("output_chars", sa.Integer(), nullable=True),
        sa.Column("usage_input", sa.Integer(), nullable=True),
        sa.Column("usage_output", sa.Integer(), nullable=True),
        sa.Column("requested_by", sa.String(length=64), nullable=False),
        sa.Column("requested_by_user_id", sa.BigInteger(), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_ai_insights_asset_id_assets"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["detection_id"],
            ["detections.id"],
            name=op.f("fk_ai_insights_detection_id_detections"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["risk_snapshot_id"],
            ["risk_snapshots.id"],
            name=op.f("fk_ai_insights_risk_snapshot_id_risk_snapshots"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            name=op.f("fk_ai_insights_requested_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_insights")),
        sa.UniqueConstraint("public_id", name=op.f("uq_ai_insights_public_id")),
    )
    op.create_index("ix_ai_insights_cache", "ai_insights", ["cache_key", "generated_at"])
    op.create_index("ix_ai_insights_generated", "ai_insights", ["generated_at"])
    op.create_index(
        "ix_ai_insights_asset",
        "ai_insights",
        ["asset_id", "generated_at"],
        postgresql_where=sa.text("asset_id IS NOT NULL"),
    )
    op.create_index(
        "ix_ai_insights_detection",
        "ai_insights",
        ["detection_id"],
        postgresql_where=sa.text("detection_id IS NOT NULL"),
    )
    op.create_index(
        "ix_ai_insights_snapshot",
        "ai_insights",
        ["risk_snapshot_id"],
        postgresql_where=sa.text("risk_snapshot_id IS NOT NULL"),
    )
    op.create_index(
        "ix_ai_insights_user",
        "ai_insights",
        ["requested_by_user_id"],
        postgresql_where=sa.text("requested_by_user_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_table("ai_insights")
