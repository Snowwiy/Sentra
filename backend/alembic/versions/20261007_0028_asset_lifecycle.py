"""Agent & asset lifecycle + eventos Linux (Fase 5C.1, hotfix)

Revision ID: 0028
Revises: 0027
Create Date: 2026-10-07

Añade a `assets`:
- archived_at / archived_by / archive_reason: archivado persistente. Un activo archivado
  conserva todo su historial (telemetría, eventos, detecciones, riesgo, vulnerabilidades,
  threat intel, incidentes, auditoría) pero no aparece por defecto ni cuenta en el resumen;
- lifecycle_version: control de concurrencia optimista de archivar, restaurar, borrar y
  reconciliar (409 si el activo cambió desde que la UI lo cargó). Columna propia porque
  updated_at cambia con cada heartbeat;
- ever_managed: el activo tuvo agente alguna vez. Se rellena con agent_id IS NOT NULL (antes
  de esta fase un activo no podía perder su agente). Un activo que fue Managed nunca se
  puede borrar físicamente desde la UI;
- machine_id_hash (+ índice): identidad estable de la máquina, ya derivada en el agente
  (HMAC-SHA256 de /etc/machine-id o MachineGuid); el valor en claro nunca llega al servidor;
- event_coverage / event_coverage_at: estado de las fuentes de eventos que informa el agente
  (journal, sshd, sudo, auditd...), para Risk y la pestaña Eventos;
- índice de lower(hostname) para las sugerencias de duplicados.

En `system_events`:
- event_code pasa a admitir NULL: los eventos Linux (journal) no tienen id de evento y no
  deben fingir uno de Windows;
- event_type: tipo normalizado (auth_failure, sudo_command, service_failed...) de los eventos
  Linux; NULL en los de Windows.

No borra ni reescribe filas existentes salvo el relleno de ever_managed.

DOWNGRADE: elimina las columnas nuevas. Se PIERDE el estado de archivado (los activos
archivados vuelven a ser visibles y a contar; ninguno se borra), el motivo y quién archivó,
la identidad de máquina (se vuelve a recibir con el siguiente heartbeat si se reaplica la
migración), la cobertura de eventos y el tipo normalizado de los eventos Linux. Los eventos
Linux se conservan con event_code = 0 (la columna vuelve a ser NOT NULL). La historia de
reconciliaciones sigue en la auditoría (audit_events no cambia).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assets", sa.Column("archived_by", sa.String(64), nullable=True))
    op.add_column("assets", sa.Column("archive_reason", sa.String(500), nullable=True))
    op.add_column(
        "assets",
        sa.Column("lifecycle_version", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "assets",
        sa.Column("ever_managed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("assets", sa.Column("machine_id_hash", sa.String(64), nullable=True))
    op.add_column(
        "assets",
        sa.Column("event_coverage", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "assets", sa.Column("event_coverage_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.execute("UPDATE assets SET ever_managed = true WHERE agent_id IS NOT NULL")
    op.create_index("ix_assets_machine_id_hash", "assets", ["machine_id_hash"])
    op.create_index("ix_assets_hostname_lower", "assets", [sa.text("lower(hostname)")])

    op.alter_column("system_events", "event_code", existing_type=sa.Integer(), nullable=True)
    op.add_column("system_events", sa.Column("event_type", sa.String(48), nullable=True))


def downgrade() -> None:
    op.drop_column("system_events", "event_type")
    # Los eventos Linux no tienen id: 0 es el único valor que no se confunde con un id real
    # de Windows (los ids de evento empiezan en 1).
    op.execute("UPDATE system_events SET event_code = 0 WHERE event_code IS NULL")
    op.alter_column("system_events", "event_code", existing_type=sa.Integer(), nullable=False)

    op.drop_index("ix_assets_hostname_lower", table_name="assets")
    op.drop_index("ix_assets_machine_id_hash", table_name="assets")
    for column in (
        "event_coverage_at",
        "event_coverage",
        "machine_id_hash",
        "ever_managed",
        "lifecycle_version",
        "archive_reason",
        "archived_by",
        "archived_at",
    ):
        op.drop_column("assets", column)
