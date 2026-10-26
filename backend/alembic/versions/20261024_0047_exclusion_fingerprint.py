"""Excepciones de detección con huella y puerto (Fase 7A.8)

Revision ID: 0047
Revises: 0046
Create Date: 2026-10-24

Cambios (ver app/models/endpoint.py y docs/powershell-detections.md):
- detection_exclusions.field admite script_path y script_sha256 (contexto del 4104 que envía
  el agente 0.6.0);
- detection_exclusions.require_sha256: hash que además debe coincidir (una excepción de ruta
  deja de aplicar si el script cambia);
- detection_exclusions.port: puerto que además debe coincidir (excepciones de NET-001/NET-002
  para un proceso concreto en un puerto concreto).

Datos: las excepciones existentes no cambian (columnas nuevas nulas).

DOWNGRADE: borra las excepciones con los campos nuevos (no caben en la restricción anterior;
quedan en la auditoría) y elimina las dos columnas.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0047"
down_revision: str | None = "0046"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_FIELDS = ("exe", "name", "sha256", "signer", "parent_name", "remote_address")
FIELDS = (*OLD_FIELDS, "script_path", "script_sha256")


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def upgrade() -> None:
    op.add_column("detection_exclusions", sa.Column("require_sha256", sa.String(64)))
    op.add_column("detection_exclusions", sa.Column("port", sa.Integer()))
    op.drop_constraint("ck_detection_exclusions_field", "detection_exclusions", type_="check")
    op.create_check_constraint(
        "ck_detection_exclusions_field", "detection_exclusions", _in("field", FIELDS)
    )
    op.create_check_constraint(
        "ck_detection_exclusions_require_sha256",
        "detection_exclusions",
        "require_sha256 IS NULL OR require_sha256 ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "ck_detection_exclusions_port",
        "detection_exclusions",
        "port IS NULL OR port BETWEEN 1 AND 65535",
    )


def downgrade() -> None:
    op.execute("DELETE FROM detection_exclusions WHERE field IN ('script_path', 'script_sha256')")
    op.drop_constraint("ck_detection_exclusions_port", "detection_exclusions", type_="check")
    op.drop_constraint(
        "ck_detection_exclusions_require_sha256", "detection_exclusions", type_="check"
    )
    op.drop_constraint("ck_detection_exclusions_field", "detection_exclusions", type_="check")
    op.create_check_constraint(
        "ck_detection_exclusions_field", "detection_exclusions", _in("field", OLD_FIELDS)
    )
    op.drop_column("detection_exclusions", "port")
    op.drop_column("detection_exclusions", "require_sha256")
