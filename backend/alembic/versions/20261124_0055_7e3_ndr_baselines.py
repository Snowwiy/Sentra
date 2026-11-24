"""Fase 7E.3: líneas base de comportamiento NDR y cursores del job ndr-engine

Revision ID: 0055
Revises: 0054
Create Date: 2026-11-24

Cambios (docs/fase-7e-migrations.md):
- `ndr_baselines`: media y varianza (Welford) por equipo y métrica horaria.
- `ndr_engine_cursors`: posición de cada tarea del job ndr-engine (horas ya agregadas).

Datos: ninguno. Las líneas base empiezan a aprender con la primera hora completa posterior a
la actualización; hasta NDR_BASELINE_MIN_SAMPLES muestras no se evalúa nada.

DOWNGRADE: elimina ambas tablas (se pierde lo aprendido; vuelve a aprender al subir).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0055"
down_revision: str | None = "0054"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ndr_baselines",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("entity_ip", sa.String(length=45), nullable=False),
        sa.Column("metric", sa.String(length=32), nullable=False),
        sa.Column("samples", sa.Integer(), nullable=False),
        sa.Column("mean", sa.Float(), nullable=False),
        sa.Column("m2", sa.Float(), nullable=False),
        sa.Column("last_value", sa.Float(), nullable=True),
        sa.Column("last_bucket", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.id"],
            name=op.f("fk_ndr_baselines_site_id_sites"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ndr_baselines")),
        sa.UniqueConstraint("site_id", "entity_ip", "metric", name="uq_ndr_baselines_key"),
    )
    op.create_index("ix_ndr_baselines_updated_at", "ndr_baselines", ["updated_at"])
    op.create_table(
        "ndr_engine_cursors",
        sa.Column("name", sa.String(length=32), nullable=False),
        sa.Column("position", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_ndr_engine_cursors")),
    )


def downgrade() -> None:
    op.drop_table("ndr_engine_cursors")
    op.drop_table("ndr_baselines")
