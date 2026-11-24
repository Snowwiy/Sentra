"""Fase 7E.4: atribución de anomalías NDR a activos y enlace con el motor de detección

Revision ID: 0056
Revises: 0055
Create Date: 2026-11-24

Cambios (docs/fase-7e-migrations.md):
- `ndr_anomalies.asset_id`: activo del site al que se atribuye la anomalía (FK SET NULL, con
  índice).
- `ndr_anomalies.signaled_rank`: veredicto para el que ya se emitió una señal NDR_ANOMALY al
  motor de detección (0 = ninguna).

Datos: las anomalías existentes quedan sin activo y sin señal; las nuevas ocurrencias las
atribuyen. No se emiten señales retroactivas.

DOWNGRADE: elimina ambas columnas y el índice (se pierde la atribución; las detecciones
NET-NDR-001 ya creadas se conservan).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0056"
down_revision: str | None = "0055"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("ndr_anomalies", sa.Column("asset_id", sa.BigInteger(), nullable=True))
    op.add_column(
        "ndr_anomalies",
        sa.Column("signaled_rank", sa.SmallInteger(), server_default="0", nullable=False),
    )
    op.create_foreign_key(
        op.f("fk_ndr_anomalies_asset_id_assets"),
        "ndr_anomalies",
        "assets",
        ["asset_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_ndr_anomalies_asset_id", "ndr_anomalies", ["asset_id"])


def downgrade() -> None:
    op.drop_index("ix_ndr_anomalies_asset_id", table_name="ndr_anomalies")
    op.drop_constraint(
        op.f("fk_ndr_anomalies_asset_id_assets"), "ndr_anomalies", type_="foreignkey"
    )
    op.drop_column("ndr_anomalies", "signaled_rank")
    op.drop_column("ndr_anomalies", "asset_id")
