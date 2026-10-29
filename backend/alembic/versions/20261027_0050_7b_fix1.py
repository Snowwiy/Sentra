"""Fase 7B-Fix1: servicio modificado y origen de la observación de un puerto

Revision ID: 0050
Revises: 0049
Create Date: 2026-10-27

Cambios (docs/fase-7b-fix1.md):
- change_kind: valor nuevo `image_changed`. El inventario del agente 0.6.2 trae la línea de
  comandos de cada servicio; si cambia en un servicio que ya existía, es un "servicio
  modificado" (posible secuestro de servicio) y se registra como cambio propio.
- asset_ports.observed_from: desde dónde se comprobó por última vez que el puerto estaba
  abierto. `self` = el escáner corre en el propio equipo (el servidor de Sentra sondeando su
  propia IP: ese tráfico no atraviesa el firewall de Windows y no demuestra acceso desde la
  LAN); `remote` = desde otro equipo. NULL = anterior a esta migración (sin dato).

Índices: ninguna FK nueva.

Datos: columna nueva nula; se rellena en el siguiente descubrimiento. Sin backfill: no se
puede saber a posteriori desde dónde se observó un puerto.

DOWNGRADE: elimina la columna. Los cambios `image_changed` se borran (el valor no existe
antes de 0050) y el tipo enumerado se reconstruye sin él.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0050"
down_revision: str | None = "0049"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_KINDS = (
    "added",
    "removed",
    "started",
    "stopped",
    "start_type_changed",
    "version_changed",
    "enabled",
    "disabled",
    "admin_granted",
    "admin_revoked",
    "port_opened",
    "port_closed",
    "appeared",
    "disappeared",
    "reclassified",
)


def upgrade() -> None:
    # Valor nuevo sin usar en esta transacción: ADD VALUE se permite dentro (PG 12+).
    op.execute("ALTER TYPE change_kind ADD VALUE IF NOT EXISTS 'image_changed'")
    op.add_column("asset_ports", sa.Column("observed_from", sa.String(8), nullable=True))
    op.create_check_constraint(
        "ck_asset_ports_observed_from",
        "asset_ports",
        "observed_from IS NULL OR observed_from IN ('self', 'remote')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_asset_ports_observed_from", "asset_ports", type_="check")
    op.drop_column("asset_ports", "observed_from")
    op.execute("DELETE FROM asset_changes WHERE kind::text = 'image_changed'")
    listed = ", ".join(f"'{value}'" for value in OLD_KINDS)
    op.execute("ALTER TYPE change_kind RENAME TO change_kind_old")
    op.execute(f"CREATE TYPE change_kind AS ENUM ({listed})")
    op.execute(
        "ALTER TABLE asset_changes ALTER COLUMN kind TYPE change_kind USING kind::text::change_kind"
    )
    op.execute("DROP TYPE change_kind_old")
