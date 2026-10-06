"""Asset Context (Fase 4L)

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-05

Añade el contexto operacional y de negocio de los activos sin tocar los datos existentes:
- tablas nuevas: asset_context (1:1 con assets, fila opcional), asset_tags y
  asset_context_changes (historial por campo);
- tipos ENUM nuevos: asset_role, asset_environment, asset_data_sensitivity,
  asset_network_zone;
- incident_assets: columnas nullable context_snapshot y resolved_context_snapshot (los
  vínculos existentes quedan con NULL).

No hay backfill: un activo sin fila en asset_context se lee como "todo unknown", que es
exactamente lo que Sentra sabe de él. La criticidad sigue en assets.criticality (0019) y no
se modifica. Activos, detecciones, riesgo, incidentes, IA, usuarios y agentes no cambian.

DOWNGRADE (pérdida de datos explícita): borra TODO el Asset Context (rol, entorno,
responsable, departamento, sensibilidad, zona, exposición a Internet, justificación de la
criticidad, procedencia), todas las etiquetas, el historial de cambios de contexto y los
snapshots de contexto de los incidentes. Se conservan: assets.criticality, la auditoría
(audit_events asset_*_changed) y todo lo demás.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLES = (
    "workstation",
    "server",
    "domain_controller",
    "database",
    "web_server",
    "application_server",
    "security_server",
    "network_device",
    "router",
    "switch",
    "firewall",
    "wireless_ap",
    "printer",
    "iot",
    "mobile",
    "virtual_machine",
    "container_host",
    "unknown",
    "other",
)
ENVIRONMENTS = ("production", "staging", "development", "testing", "lab", "personal", "unknown")
SENSITIVITIES = ("unknown", "public", "internal", "confidential", "restricted")
ZONES = ("unknown", "user", "server", "management", "dmz", "guest", "iot", "security", "lab")
TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    bind = op.get_bind()
    role = postgresql.ENUM(*ROLES, name="asset_role", create_type=False)
    environment = postgresql.ENUM(*ENVIRONMENTS, name="asset_environment", create_type=False)
    sensitivity = postgresql.ENUM(*SENSITIVITIES, name="asset_data_sensitivity", create_type=False)
    zone = postgresql.ENUM(*ZONES, name="asset_network_zone", create_type=False)
    for enum_type in (role, environment, sensitivity, zone):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "asset_context",
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("role", role, server_default="unknown", nullable=False),
        sa.Column("environment", environment, server_default="unknown", nullable=False),
        sa.Column("data_sensitivity", sensitivity, server_default="unknown", nullable=False),
        sa.Column("network_zone", zone, server_default="unknown", nullable=False),
        sa.Column("internet_exposed", sa.Boolean(), nullable=True),
        sa.Column("owner", sa.String(length=128), nullable=True),
        sa.Column("department", sa.String(length=64), nullable=True),
        sa.Column("criticality_rationale", sa.String(length=200), nullable=True),
        sa.Column("criticality_updated_at", TZ, nullable=True),
        sa.Column("criticality_updated_by", sa.String(length=64), nullable=True),
        sa.Column("provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("updated_at", TZ, nullable=False),
        sa.Column("updated_by", sa.String(length=64), nullable=True),
        sa.Column("updated_by_user_id", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("asset_id", name=op.f("pk_asset_context")),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_asset_context_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_user_id"],
            ["users.id"],
            name=op.f("fk_asset_context_updated_by_user_id_users"),
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_asset_context_internet_exposed",
        "asset_context",
        ["internet_exposed"],
        postgresql_where=sa.text("internet_exposed IS NOT NULL"),
    )
    op.create_index("ix_asset_context_department", "asset_context", [sa.text("lower(department)")])
    op.create_index(
        "ix_asset_context_updated_by",
        "asset_context",
        ["updated_by_user_id"],
        postgresql_where=sa.text("updated_by_user_id IS NOT NULL"),
    )

    op.create_table(
        "asset_tags",
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("tag", sa.String(length=32), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.PrimaryKeyConstraint("asset_id", "tag", name=op.f("pk_asset_tags")),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_asset_tags_asset_id_assets"),
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_asset_tags_tag", "asset_tags", ["tag"])

    op.create_table(
        "asset_context_changes",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("changed_at", TZ, nullable=False),
        sa.Column("field", sa.String(length=32), nullable=False),
        sa.Column("old_value", sa.String(length=300), nullable=True),
        sa.Column("new_value", sa.String(length=300), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_context_changes")),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_asset_context_changes_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name=op.f("fk_asset_context_changes_actor_user_id_users"),
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_asset_context_changes_asset", "asset_context_changes", ["asset_id", "changed_at"]
    )
    op.create_index(
        "ix_asset_context_changes_actor",
        "asset_context_changes",
        ["actor_user_id"],
        postgresql_where=sa.text("actor_user_id IS NOT NULL"),
    )

    op.add_column(
        "incident_assets",
        sa.Column("context_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "incident_assets",
        sa.Column(
            "resolved_context_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
    )


def downgrade() -> None:
    # ⚠️ Pérdida de datos documentada en el docstring y en docs/asset-context.md.
    op.drop_column("incident_assets", "resolved_context_snapshot")
    op.drop_column("incident_assets", "context_snapshot")
    op.drop_table("asset_context_changes")
    op.drop_table("asset_tags")
    op.drop_table("asset_context")
    bind = op.get_bind()
    for name in ("asset_network_zone", "asset_data_sensitivity", "asset_environment", "asset_role"):
        postgresql.ENUM(name=name).drop(bind, checkfirst=True)
