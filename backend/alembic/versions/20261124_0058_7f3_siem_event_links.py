"""Fase 7F.3: enlaces explicados entre eventos SIEM y evidencia de Sentra (NDR, detecciones)

Revision ID: 0058
Revises: 0057
Create Date: 2026-11-24

Cambios (docs/fase-7f-migrations.md):
- `siem_event_links`: relación de un evento SIEM con un flujo NDR, una anomalía NDR, otro
  evento SIEM o una detección, con método y confianza. Sin clave foránea al destino (los
  flujos NDR se purgan con su propia retención); el enlace se borra con su evento.

Datos: tabla nueva y vacía; nada existente cambia.

DOWNGRADE: elimina la tabla (se pierden las correlaciones calculadas; los eventos SIEM, los
flujos NDR y las detecciones se conservan).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0058"
down_revision: str | None = "0057"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "siem_event_links",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("target_id", sa.BigInteger(), nullable=False),
        sa.Column("target_ref", sa.String(length=64), nullable=False),
        sa.Column("method", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["event_id"], ["siem_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id", "kind", "target_id", name="uq_siem_event_links_target"),
    )
    op.create_index("ix_siem_event_links_event_id", "siem_event_links", ["event_id"])
    op.create_index("ix_siem_event_links_site_id", "siem_event_links", ["site_id"])
    op.create_index("ix_siem_event_links_target", "siem_event_links", ["kind", "target_id"])
    op.create_index(
        "ix_siem_event_links_site_created", "siem_event_links", ["site_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_table("siem_event_links")
