"""Asociaciones manuales de identidad (Fase 7B.2)

Revision ID: 0049
Revises: 0048
Create Date: 2026-10-26

Cambios (ver app/models/identity_link.py y docs/device-identity-wifi.md):
- asset_identity_links: un admin asocia un registro alias (MAC privada que rotó, duplicado
  descubierto) o un cliente Wi-Fi a un activo conocido, con motivo, evidencia y el estado
  anterior para deshacerlo. Revocar no borra la fila.

Índices: uno por FK (site, destino, alias, cliente Wi-Fi), exigido por test_migrations.

Datos: tabla nueva vacía. No hay backfill: nada se asocia sin una decisión de un admin.

DOWNGRADE: elimina la tabla. Los alias archivados por una asociación siguen archivados (el
archivado es del ciclo de vida 5C.1 y se restaura desde la ficha del activo) y los clientes
Wi-Fi asociados conservan su activo con base `manual` hasta el siguiente informe.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0049"
down_revision: str | None = "0048"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "asset_identity_links",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column(
            "site_id",
            sa.BigInteger(),
            sa.ForeignKey("sites.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column(
            "target_asset_id",
            sa.BigInteger(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "alias_asset_id", sa.BigInteger(), sa.ForeignKey("assets.id", ondelete="SET NULL")
        ),
        sa.Column(
            "wlan_client_id",
            sa.BigInteger(),
            sa.ForeignKey("wlan_clients.id", ondelete="SET NULL"),
        ),
        sa.Column("mac", sa.String(17)),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("evidence", _JSONB, nullable=False),
        sa.Column("previous_state", _JSONB, nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_by", sa.String(64)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoke_reason", sa.String(500)),
        sa.CheckConstraint(
            "kind IN ('asset_alias', 'wlan_client')", name="ck_asset_identity_links_kind"
        ),
        sa.CheckConstraint(
            "(kind = 'asset_alias' AND wlan_client_id IS NULL)"
            " OR (kind = 'wlan_client' AND alias_asset_id IS NULL)",
            name="ck_asset_identity_links_subject",
        ),
    )
    op.create_index("ix_asset_identity_links_target", "asset_identity_links", ["target_asset_id"])
    op.create_index("ix_asset_identity_links_alias", "asset_identity_links", ["alias_asset_id"])
    op.create_index(
        "ix_asset_identity_links_wlan_client", "asset_identity_links", ["wlan_client_id"]
    )
    op.create_index("ix_asset_identity_links_site", "asset_identity_links", ["site_id"])


def downgrade() -> None:
    op.drop_table("asset_identity_links")
