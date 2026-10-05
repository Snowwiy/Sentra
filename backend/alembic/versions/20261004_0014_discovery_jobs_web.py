"""Discovery desde el dashboard: estado queued, progreso, cancelación y resultados del job

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-04

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_STATUSES = ("running", "completed", "cancelled", "failed")
INDEX = "uq_discovery_jobs_running_target"

NEW_COLUMNS: tuple[tuple[str, sa.types.TypeEngine[object], str | None], ...] = (
    ("requested_via", sa.String(length=16), None),
    ("hosts_total", sa.Integer(), "0"),
    ("ports_opened", sa.Integer(), "0"),
    ("ports_closed", sa.Integer(), "0"),
    ("cancel_requested_at", sa.DateTime(timezone=True), None),
    ("heartbeat_at", sa.DateTime(timezone=True), None),
    ("stop_reason", sa.String(length=32), None),
    ("progress", postgresql.JSONB(), None),
    ("new_asset_ids", postgresql.JSONB(), None),
)


def upgrade() -> None:
    # El índice parcial nuevo usa 'queued' en su predicado. PostgreSQL no permite usar un
    # valor de enum añadido dentro de la misma transacción, así que ADD VALUE se confirma
    # aparte (autocommit) antes de recrear el índice.
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TYPE discovery_job_status ADD VALUE IF NOT EXISTS 'queued' BEFORE 'running'"
        )

    for name, type_, default in NEW_COLUMNS:
        # server_default solo para rellenar filas existentes; el modelo pone el valor.
        op.add_column(
            "discovery_jobs",
            sa.Column(name, type_, nullable=default is None, server_default=default),
        )
        if default is not None:
            op.alter_column("discovery_jobs", name, server_default=None)

    # Un job en cola también ocupa su red: así dos peticiones simultáneas desde el
    # dashboard (o el scheduler mientras hay uno en cola) no escanean la misma red dos veces.
    op.drop_index(INDEX, table_name="discovery_jobs")
    op.create_index(
        INDEX,
        "discovery_jobs",
        ["target"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )


def downgrade() -> None:
    # ⚠️ Un job en cola no existe antes de 0014: se marca como fallido (nunca se ejecutó).
    op.execute(
        "UPDATE discovery_jobs SET status = 'failed', completed_at = now() WHERE status = 'queued'"
    )
    op.drop_index(INDEX, table_name="discovery_jobs")
    for name, _, _ in reversed(NEW_COLUMNS):
        op.drop_column("discovery_jobs", name)
    listed = ", ".join(f"'{value}'" for value in OLD_STATUSES)
    op.execute("ALTER TYPE discovery_job_status RENAME TO discovery_job_status_old")
    op.execute(f"CREATE TYPE discovery_job_status AS ENUM ({listed})")
    op.execute(
        "ALTER TABLE discovery_jobs ALTER COLUMN status TYPE discovery_job_status"
        " USING status::text::discovery_job_status"
    )
    op.execute("DROP TYPE discovery_job_status_old")
    op.create_index(
        INDEX,
        "discovery_jobs",
        ["target"],
        unique=True,
        postgresql_where=sa.text("status = 'running'"),
    )
