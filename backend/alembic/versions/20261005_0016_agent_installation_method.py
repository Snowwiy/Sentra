"""Método de instalación informado por el agente (Fase 4F: servicio Windows)

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-05

Depende de la 0015 de la Fase 4E (identificación de dispositivos), que se aplica antes.
Solo añade una columna nullable: los activos existentes quedan con null ("No reportado")
hasta que su agente vuelva a informar.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "assets", sa.Column("agent_installation_method", sa.String(length=32), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("assets", "agent_installation_method")
