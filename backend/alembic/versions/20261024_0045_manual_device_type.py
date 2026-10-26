"""Tipo de dispositivo manual (Fase 7A.4)

Revision ID: 0045
Revises: 0044
Create Date: 2026-10-24

Cambios (ver app/models/asset.py y docs/device-intelligence.md):
- assets.manual_device_type / manual_device_type_at / manual_device_type_by: tipo que fija un
  admin cuando la identificación automática no acierta. Manda sobre la inferencia sin borrar
  sus evidencias.

Datos: columnas nuevas vacías; ningún activo cambia de tipo al migrar. Los tipos nuevos
(ip_camera, dvr_nvr, network_device) no necesitan migración: assets.device_type es texto y
se recalcula con cada dato nuevo.

DOWNGRADE: elimina las columnas; los tipos manuales se pierden y vuelve el automático en el
siguiente recálculo. Si hay activos con tipo ip_camera, dvr_nvr o network_device, la versión
anterior los muestra como tipo desconocido hasta el siguiente discovery.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0045"
down_revision: str | None = "0044"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("manual_device_type", sa.String(32)))
    op.add_column("assets", sa.Column("manual_device_type_at", sa.DateTime(timezone=True)))
    op.add_column("assets", sa.Column("manual_device_type_by", sa.String(64)))


def downgrade() -> None:
    op.drop_column("assets", "manual_device_type_by")
    op.drop_column("assets", "manual_device_type_at")
    op.drop_column("assets", "manual_device_type")
