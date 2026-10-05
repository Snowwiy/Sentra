"""Gestor de modelos locales (Fase 4J.2)

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-05

Añade tres tablas nuevas: ai_local_models (modelos registrados con su metadata verificada),
ai_model_benchmarks (mediciones reales) y ai_local_settings (fila única con el runtime y el
modelo activo). No modifica ninguna tabla existente: ai_insights (4J) queda intacta.

El downgrade borra solo estas tablas. Los ficheros de modelo del disco nunca se tocan.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_local_models",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("family", sa.String(length=64), nullable=True),
        sa.Column("architecture", sa.String(length=64), nullable=True),
        sa.Column("parameter_count", sa.BigInteger(), nullable=True),
        sa.Column("quantization", sa.String(length=32), nullable=True),
        sa.Column("file_size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("native_context", sa.Integer(), nullable=True),
        sa.Column("layer_count", sa.Integer(), nullable=True),
        sa.Column("kv_head_count", sa.Integer(), nullable=True),
        sa.Column("head_dim", sa.Integer(), nullable=True),
        sa.Column("expert_count", sa.Integer(), nullable=True),
        sa.Column("runtime", sa.String(length=24), nullable=False),
        sa.Column("runtime_model_id", sa.String(length=256), nullable=False),
        sa.Column("local_path", sa.String(length=1024), nullable=True),
        sa.Column("split_count", sa.SmallInteger(), server_default="1", nullable=False),
        sa.Column("metadata_source", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=256), nullable=True),
        sa.Column("license", sa.String(length=64), nullable=True),
        sa.Column("checksum_sha256", sa.String(length=64), nullable=True),
        sa.Column("checksum_status", sa.String(length=16), server_default="none", nullable=False),
        sa.Column("registered_by", sa.String(length=64), nullable=False),
        sa.Column("installed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_selected_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_local_models")),
        sa.UniqueConstraint("public_id", name=op.f("uq_ai_local_models_public_id")),
    )
    op.create_index(
        "uq_ai_local_models_runtime_model",
        "ai_local_models",
        ["runtime", "runtime_model_id"],
        unique=True,
    )
    op.create_index(
        "uq_ai_local_models_path",
        "ai_local_models",
        ["local_path"],
        unique=True,
        postgresql_where=sa.text("local_path IS NOT NULL"),
    )
    op.create_index("ix_ai_local_models_installed", "ai_local_models", ["installed_at"])

    op.create_table(
        "ai_model_benchmarks",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("model_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("runtime", sa.String(length=24), nullable=False),
        sa.Column("measurement", sa.String(length=16), nullable=True),
        sa.Column("max_tokens", sa.Integer(), nullable=False),
        sa.Column("configured_context", sa.Integer(), nullable=True),
        sa.Column("load_ms", sa.Integer(), nullable=True),
        sa.Column("ttft_ms", sa.Integer(), nullable=True),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("prompt_tps", sa.Float(), nullable=True),
        sa.Column("generation_tps", sa.Float(), nullable=True),
        sa.Column("peak_ram_bytes", sa.BigInteger(), nullable=True),
        sa.Column("peak_vram_bytes", sa.BigInteger(), nullable=True),
        sa.Column("performance_class", sa.String(length=16), nullable=True),
        sa.Column("error", sa.String(length=64), nullable=True),
        sa.Column("requested_by", sa.String(length=64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["model_id"],
            ["ai_local_models.id"],
            name=op.f("fk_ai_model_benchmarks_model_id_ai_local_models"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_model_benchmarks")),
        sa.UniqueConstraint("public_id", name=op.f("uq_ai_model_benchmarks_public_id")),
    )
    op.create_index(
        "ix_ai_model_benchmarks_model", "ai_model_benchmarks", ["model_id", "started_at"]
    )

    op.create_table(
        "ai_local_settings",
        sa.Column("id", sa.SmallInteger(), nullable=False),
        sa.Column("runtime", sa.String(length=24), nullable=True),
        sa.Column("active_model_id", sa.BigInteger(), nullable=True),
        sa.Column("updated_by", sa.String(length=64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("id = 1", name=op.f("ck_ai_local_settings_single_row")),
        sa.ForeignKeyConstraint(
            ["active_model_id"],
            ["ai_local_models.id"],
            name=op.f("fk_ai_local_settings_active_model_id_ai_local_models"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_local_settings")),
    )
    op.create_index(
        op.f("ix_ai_local_settings_active_model_id"), "ai_local_settings", ["active_model_id"]
    )


def downgrade() -> None:
    op.drop_table("ai_local_settings")
    op.drop_table("ai_model_benchmarks")
    op.drop_table("ai_local_models")
