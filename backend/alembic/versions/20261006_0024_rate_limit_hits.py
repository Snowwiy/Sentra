"""Rate limiting compartido en PostgreSQL (Fase 4M)

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-06

Por qué hace falta persistencia: los limitadores eran memoria del proceso. Con varios
workers de uvicorn cada uno llevaba su contador (el límite real se multiplicaba por el número
de workers) y un reinicio los vaciaba. Una tabla en la base que Sentra ya usa resuelve las
dos cosas sin añadir Redis ni otro servicio.

Añade solo la tabla rate_limit_hits (estado efímero: cada fila caduca con la ventana de su
limitador). No toca ninguna tabla existente.

DOWNGRADE: borra la tabla. Solo se pierden contadores de intentos en curso (los bloqueos
temporales activos se levantan antes de tiempo); ningún dato de negocio ni de auditoría.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_hits",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("scope", sa.String(32), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column(
            "hit_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_rate_limit_hits_lookup", "rate_limit_hits", ["scope", "key_hash", "hit_at"])
    op.create_index("ix_rate_limit_hits_hit_at", "rate_limit_hits", ["hit_at"])


def downgrade() -> None:
    op.drop_index("ix_rate_limit_hits_hit_at", table_name="rate_limit_hits")
    op.drop_index("ix_rate_limit_hits_lookup", table_name="rate_limit_hits")
    op.drop_table("rate_limit_hits")
