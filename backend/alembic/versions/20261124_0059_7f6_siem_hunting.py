"""Fase 7F.6: búsquedas guardadas, eventos SIEM como evidencia de incidentes e índice de hunting

Revision ID: 0059
Revises: 0058
Create Date: 2026-11-24

Cambios (docs/fase-7f-migrations.md):
- `siem_saved_searches`: búsquedas de hunting guardadas, privadas de su autor (filtro tipado
  en JSONB, nunca SQL).
- `incident_siem_events`: eventos SIEM añadidos a un incidente, con una copia acotada y su
  hash para que la evidencia sobreviva a la retención de eventos (SET NULL al purgar).
- Índice parcial `ix_siem_events_site_username` para buscar por usuario.

Datos: tablas nuevas y vacías y un índice; nada existente cambia. Con muchos eventos, el
índice tarda en crearse (se crea dentro de la transacción de la migración).

DOWNGRADE: elimina el índice y las dos tablas (se pierden las búsquedas guardadas y las copias
de evidencia SIEM de los incidentes; los incidentes y los eventos SIEM se conservan).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0059"
down_revision: str | None = "0058"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "siem_saved_searches",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("owner_user_id", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("query", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint("owner_user_id", "name", name="uq_siem_saved_searches_owner_name"),
    )
    op.create_index("ix_siem_saved_searches_owner", "siem_saved_searches", ["owner_user_id"])
    op.create_table(
        "incident_siem_events",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=True),
        sa.Column("event_public_id", sa.Uuid(), nullable=False),
        sa.Column("source_name", sa.String(length=100), nullable=False),
        sa.Column("source_type", sa.String(length=24), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("snapshot_sha256", sa.String(length=64), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("attached_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attached_by_user_id", sa.BigInteger(), nullable=True),
        sa.Column("attached_by", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["siem_events.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["attached_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "event_public_id", name="uq_incident_siem_events_event"),
    )
    op.create_index("ix_incident_siem_events_incident_id", "incident_siem_events", ["incident_id"])
    op.create_index(
        "ix_incident_siem_events_event",
        "incident_siem_events",
        ["event_id"],
        postgresql_where=sa.text("event_id IS NOT NULL"),
    )
    op.create_index(
        "ix_incident_siem_events_attached_by",
        "incident_siem_events",
        ["attached_by_user_id"],
        postgresql_where=sa.text("attached_by_user_id IS NOT NULL"),
    )
    op.create_index(
        "ix_siem_events_site_username",
        "siem_events",
        ["site_id", "username", "observed_at"],
        postgresql_where=sa.text("username IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_siem_events_site_username", table_name="siem_events")
    op.drop_table("incident_siem_events")
    op.drop_table("siem_saved_searches")
