"""Reporting y exportación de evidencia (Fase 5E)

Revision ID: 0031
Revises: 0030
Create Date: 2026-10-14

Tablas nuevas (ver app/models/report.py y docs/reporting.md):
- reports: trabajo de generación (pending/running/succeeded/failed/cancelled/expired),
  petición normalizada (tipo, formato, rango UTC, filtros, alcance), hora de corte de los
  datos, snapshot estructurado acotado con su SHA-256 y resumen determinista;
- report_artifacts: metadata del fichero final (ruta relativa generada por el servidor,
  tamaño y SHA-256). El fichero vive en REPORT_OUTPUT_DIR, nunca en la base de datos.

Índices: el de la clave foránea de cada tabla (test_every_foreign_key_is_indexed), el parcial
de la cola del worker (solo filas vivas) y dos únicos parciales que garantizan en la base de
datos que un doble clic no crea dos informes: uno por clave de idempotencia de cada usuario y
uno por petición idéntica mientras está viva.

No modifica tablas existentes. DOWNGRADE: borra las dos tablas (se pierde el historial de
informes; las entradas report_* de audit_events se conservan). Los ficheros de
REPORT_OUTPUT_DIR no se tocan: se borran a mano si se desea.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIVE = "status IN ('pending', 'running')"


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("report_type", sa.String(32), nullable=False),
        sa.Column("template_version", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("classification", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column(
            "created_by_user_id",
            sa.BigInteger(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cutoff_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("time_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("time_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timezone", sa.String(32), nullable=False),
        sa.Column("filters", postgresql.JSONB(), nullable=False),
        sa.Column("scope", postgresql.JSONB(), nullable=False),
        sa.Column("summary", postgresql.JSONB(), nullable=True),
        sa.Column("snapshot", postgresql.JSONB(), nullable=True),
        sa.Column("snapshot_sha256", sa.String(64), nullable=True),
        sa.Column("snapshot_bytes", sa.Integer(), nullable=True),
        sa.Column("idempotency_key", sa.String(64), nullable=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.SmallInteger(), nullable=False),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(500), nullable=True),
        sa.Column("expired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expired_by", sa.String(64), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
    )
    op.create_index("ix_reports_created", "reports", ["created_at"])
    op.create_index("ix_reports_type_created", "reports", ["report_type", "created_at"])
    op.create_index("ix_reports_status_created", "reports", ["status", "created_at"])
    op.create_index("ix_reports_user_created", "reports", ["created_by_user_id", "created_at"])
    op.create_index(
        "ix_reports_active",
        "reports",
        ["status", "lease_until"],
        postgresql_where=sa.text(ACTIVE),
    )
    op.create_index(
        "uq_reports_idempotency",
        "reports",
        ["created_by_user_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.create_index(
        "uq_reports_active_request",
        "reports",
        ["request_hash"],
        unique=True,
        postgresql_where=sa.text(ACTIVE),
    )

    op.create_table(
        "report_artifacts",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column(
            "report_id",
            sa.BigInteger(),
            sa.ForeignKey("reports.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("filename", sa.String(160), nullable=False),
        sa.Column("content_type", sa.String(64), nullable=False),
        sa.Column("storage_key", sa.String(200), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("uq_report_artifacts_report", "report_artifacts", ["report_id"], unique=True)


def downgrade() -> None:
    op.drop_table("report_artifacts")
    op.drop_table("reports")
