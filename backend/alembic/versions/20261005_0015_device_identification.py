"""Identificación de dispositivos: nombre, fabricante, modelo, SO probable, confianza y evidencias

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-05

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

confidence = postgresql.ENUM("low", "medium", "high", name="classification_confidence")
# Misma enum sin CREATE TYPE implícito: se crea explícitamente antes de añadir la columna.
confidence_column = postgresql.ENUM(name="classification_confidence", create_type=False)

NEW_COLUMNS: tuple[tuple[str, sa.types.TypeEngine[object]], ...] = (
    ("device_name", sa.String(length=255)),
    ("name_source", sa.String(length=16)),
    ("device_vendor", sa.String(length=128)),
    ("device_model", sa.String(length=128)),
    ("probable_os", sa.String(length=64)),
    ("classification_confidence", confidence_column),
    ("classification_evidence", postgresql.JSONB()),
    ("identity_observations", postgresql.JSONB()),
)

# Valores de los enums de cambios anteriores a 0015 (para reconstruirlos al bajar).
OLD_CATEGORIES = ("service", "software", "account", "exposure", "network")
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
)


def upgrade() -> None:
    # Valores nuevos sin usar en esta transacción: ADD VALUE se permite dentro (PG 12+).
    op.execute("ALTER TYPE change_category ADD VALUE IF NOT EXISTS 'identity'")
    op.execute("ALTER TYPE change_kind ADD VALUE IF NOT EXISTS 'reclassified'")
    confidence.create(op.get_bind(), checkfirst=True)
    for name, type_ in NEW_COLUMNS:
        op.add_column("assets", sa.Column(name, type_, nullable=True))

    # Tipos anteriores a la 4E → tipos nuevos. "windows"/"linux" eran sistemas operativos,
    # no tipos de dispositivo: con agente es un equipo (pc); sin agente venía de puertos de
    # Windows, así que pasa a "pc" con SO probable Windows. classification_confidence queda
    # null a propósito: marca "clasificado antes de la 4E", y la primera reclasificación
    # con el motor nuevo no se registra como cambio (evita una avalancha de historial).
    # "network_device" solo lo ponía el gateway por defecto del servidor: se guarda como
    # observación para que recalcular (heartbeat, CLI reclassify-assets) no lo pierda antes
    # del siguiente scan.
    op.execute(
        "UPDATE assets SET identity_observations = '{\"gateway\": true}'::jsonb"
        " WHERE device_type = 'network_device'"
    )
    op.execute("UPDATE assets SET device_type = 'router' WHERE device_type = 'network_device'")
    op.execute(
        "UPDATE assets SET probable_os = 'Windows'"
        " WHERE device_type = 'windows' AND agent_id IS NULL"
    )
    op.execute("UPDATE assets SET device_type = 'pc' WHERE device_type IN ('windows', 'linux')")


def _rebuild_enum(type_name: str, table: str, column: str, values: Sequence[str]) -> None:
    listed = ", ".join(f"'{value}'" for value in values)
    op.execute(f"ALTER TYPE {type_name} RENAME TO {type_name}_old")
    op.execute(f"CREATE TYPE {type_name} AS ENUM ({listed})")
    op.execute(
        f"ALTER TABLE {table} ALTER COLUMN {column} TYPE {type_name}"
        f" USING {column}::text::{type_name}"
    )
    op.execute(f"DROP TYPE {type_name}_old")


def downgrade() -> None:
    # ⚠️ Se pierde el historial de reclasificaciones (no existe antes de 0015) y la
    # identificación; los tipos vuelven a los cuatro valores antiguos cuando se puede.
    op.execute(
        "DELETE FROM asset_changes WHERE category::text = 'identity' OR kind::text = 'reclassified'"
    )
    op.execute(
        "UPDATE assets SET device_type = CASE"
        " WHEN device_type IN ('router', 'access_point', 'network_switch') THEN 'network_device'"
        " WHEN device_type = 'printer' THEN 'printer'"
        " WHEN device_type IN ('pc', 'laptop', 'server', 'virtual_machine')"
        "  AND coalesce(os_name, probable_os) ILIKE '%windows%' THEN 'windows'"
        " WHEN device_type IN ('pc', 'laptop', 'server', 'virtual_machine')"
        "  AND coalesce(os_name, probable_os) ILIKE '%linux%' THEN 'linux'"
        " ELSE NULL END"
    )
    for name, _ in reversed(NEW_COLUMNS):
        op.drop_column("assets", name)
    confidence.drop(op.get_bind(), checkfirst=True)
    _rebuild_enum("change_category", "asset_changes", "category", OLD_CATEGORIES)
    _rebuild_enum("change_kind", "asset_changes", "kind", OLD_KINDS)
