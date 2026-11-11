"""Fase 7D.2: cubos de cuota de ingesta por agente (H06)

Revision ID: 0052
Revises: 0051
Create Date: 2026-11-09

Cambios (docs/fase-7d2.md):
- Tabla `ingest_quota_buckets`: estado de los cubos de tokens que limitan la ingesta de
  cada agente autenticado y la global (core/ingest_quota.py). Solo la usa la API con
  RATE_LIMIT_BACKEND=database (o auto en producción).

Datos: ninguno. La tabla nace vacía y no toca ninguna tabla existente; un cubo ausente equivale
a un cubo lleno, así que el primer minuto tras actualizar ningún agente queda limitado.

Sin claves foráneas (estado efímero, ver el modelo): el test de índices de FK no aplica.

DOWNGRADE: elimina la tabla. Solo se pierde el estado de las cuotas (los cubos vuelven a
estar llenos) y los contadores de rechazos recientes del panel; ningún dato de monitorización.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0052"
down_revision: str | None = "0051"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # IF NOT EXISTS: idempotente si la tabla ya existe (p. ej. una restauración parcial de
    # esquema tras un rollback manual). PostgreSQL ya hace el DDL transaccional, así que una
    # ejecución interrumpida no deja la tabla a medias.
    op.create_table(
        "ingest_quota_buckets",
        sa.Column("bucket_key", sa.String(length=96), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("tokens", sa.Float(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("rejected_total", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("last_rejected_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("bucket_key", name=op.f("pk_ingest_quota_buckets")),
        if_not_exists=True,
    )
    op.create_index(
        "ix_ingest_quota_buckets_agent_rejected",
        "ingest_quota_buckets",
        ["agent_id"],
        postgresql_where=sa.text("last_rejected_at IS NOT NULL"),
        if_not_exists=True,
    )
    op.create_index(
        "ix_ingest_quota_buckets_updated_at",
        "ingest_quota_buckets",
        ["updated_at"],
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("ix_ingest_quota_buckets_updated_at", table_name="ingest_quota_buckets")
    op.drop_index("ix_ingest_quota_buckets_agent_rejected", table_name="ingest_quota_buckets")
    op.drop_table("ingest_quota_buckets")
