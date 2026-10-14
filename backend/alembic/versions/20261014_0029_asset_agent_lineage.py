"""Linaje de agentes por activo (Fase 5C.2, ciclo de vida y reconciliación)

Revision ID: 0029
Revises: 0028
Create Date: 2026-10-14

Añade solo la tabla asset_agent_lineage: una fila por cada asociación activo↔agente que
termina en una reconciliación manual (el agente se movió a otro activo, o el activo histórico
recibió otro agente y el anterior queda como histórico sin credencial).

Por qué hace falta: en 5C.1 reconciliar sobrescribía assets.agent_id del activo histórico y
el agent_id anterior solo quedaba en la auditoría. Sin él no se puede saber qué agente generó
el historial del activo ni reconocer como duplicado fuerte a un agente antiguo que vuelve.

Índices: asset_id y related_asset_id (claves foráneas: test_every_foreign_key_is_indexed y
borrado en cascada sin recorrer la tabla) y agent_id (búsqueda de linaje en duplicados).

No toca tablas existentes ni reescribe filas. Stale, candidatos a limpieza y escaneos
perdidos se derivan de columnas que ya existen (network_misses, last_network_seen_at,
last_seen_at): no se añade ninguna columna derivable.

DOWNGRADE: borra la tabla. Se pierde el linaje registrado por reconciliaciones hechas con
0029 (la auditoría agent_asset_reconciled / agent_reassigned conserva los mismos ids).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "asset_agent_lineage",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "asset_id",
            sa.BigInteger(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_reason", sa.String(16), nullable=False),
        sa.Column(
            "related_asset_id",
            sa.BigInteger(),
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reconciliation_id", sa.Uuid(), nullable=False),
        sa.Column("agent_version", sa.String(64), nullable=True),
        sa.Column("actor", sa.String(64), nullable=False),
    )
    op.create_index("ix_asset_agent_lineage_asset", "asset_agent_lineage", ["asset_id"])
    op.create_index("ix_asset_agent_lineage_agent", "asset_agent_lineage", ["agent_id"])
    op.create_index("ix_asset_agent_lineage_related", "asset_agent_lineage", ["related_asset_id"])


def downgrade() -> None:
    op.drop_index("ix_asset_agent_lineage_related", table_name="asset_agent_lineage")
    op.drop_index("ix_asset_agent_lineage_agent", table_name="asset_agent_lineage")
    op.drop_index("ix_asset_agent_lineage_asset", table_name="asset_agent_lineage")
    op.drop_table("asset_agent_lineage")
