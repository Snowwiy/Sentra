"""Identidad automática con procedencia y etiqueta personalizada de activos (Corrección 6C)

Revision ID: 0037
Revises: 0036
Create Date: 2026-10-19

Cambios (ver app/models/asset.py, app/models/site.py y docs/asset-identity-labels.md):
- assets.observed_names: nombres observados con procedencia y clase (agent, device, dhcp,
  dns, generic). Lo rellena el motor de identificación en el siguiente dato de cada activo
  (discovery, heartbeat) o con `python -m app.cli reclassify-assets`.
- assets.custom_label (+ versión, autor y fecha): nombre visible que pone una persona. Nunca
  lo escribe el discovery, el agente ni el motor de identificación. Un CHECK impide guardar
  una etiqueta vacía (el servicio ya la normaliza; es defensa en profundidad).
- sensor_observations.identity: nombres que publica el host (mDNS, NetBIOS, SSDP/UPnP)
  según un sensor >= 0.5.0 en discovery_advanced v2.

Datos: no se toca ningún valor existente. identity_observations sigue con la misma forma;
las claves nuevas (seen_at, reverse_dns_confirmed) se añaden al llegar datos nuevos.

DOWNGRADE: elimina las columnas nuevas. Se pierden las etiquetas personalizadas (quedan en la
auditoría como asset_label_changed), los nombres observados (se recalculan solos con el
motor anterior) y los nombres que enviaron los sensores en jobs ya aplicados.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0037"
down_revision: str | None = "0036"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.add_column("assets", sa.Column("observed_names", _JSONB))
    op.add_column("assets", sa.Column("custom_label", sa.String(64)))
    op.add_column(
        "assets",
        sa.Column("custom_label_version", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column("assets", sa.Column("custom_label_updated_at", sa.DateTime(timezone=True)))
    op.add_column("assets", sa.Column("custom_label_updated_by", sa.String(64)))
    op.create_check_constraint(
        "ck_assets_custom_label_not_blank",
        "assets",
        "custom_label IS NULL OR length(btrim(custom_label)) > 0",
    )
    op.add_column("sensor_observations", sa.Column("identity", _JSONB))


def downgrade() -> None:
    op.drop_column("sensor_observations", "identity")
    op.drop_constraint("ck_assets_custom_label_not_blank", "assets", type_="check")
    for column in (
        "custom_label_updated_by",
        "custom_label_updated_at",
        "custom_label_version",
        "custom_label",
        "observed_names",
    ):
        op.drop_column("assets", column)
