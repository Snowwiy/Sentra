"""Analyst Tool Engine (Fase 7A.1-7A.3)

Revision ID: 0044
Revises: 0043
Create Date: 2026-10-24

Cambios (ver app/models/tool.py y docs/analyst-tool-engine.md):
- tool_executions: una fila por petición a una herramienta del registro cerrado (lecturas,
  investigaciones y acciones), con entrada validada y su SHA-256, salida acotada con su
  SHA-256, evidencia, procedencia, estado, plazos, aprobación humana y la ejecución de
  Response en la que delegó.

Datos: tabla nueva vacía. Nada se ejecuta solo: cada fila nace de una petición de un usuario.

DOWNGRADE: elimina la tabla y con ella el historial de herramientas (la auditoría `tool_*`
se conserva en audit_events). Exportarlo antes si se necesita como evidencia.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0044"
down_revision: str | None = "0043"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())
STATUSES = (
    "previewed",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "timed_out",
    "rejected",
    "expired",
)
ACTIVE = "status IN ('previewed', 'running')"


def _ts(name: str, nullable: bool = True) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(name: str, table: str) -> sa.Column[object]:
    return sa.Column(name, sa.BigInteger(), sa.ForeignKey(f"{table}.id", ondelete="SET NULL"))


def upgrade() -> None:
    op.create_table(
        "tool_executions",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("correlation_id", sa.Uuid(), nullable=False),
        sa.Column("tool_id", sa.String(64), nullable=False),
        sa.Column("tool_version", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(16), nullable=False),
        sa.Column("risk_level", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("invoker", sa.String(16), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        _fk("actor_user_id", "users"),
        sa.Column("input", _JSONB, nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("output", _JSONB),
        sa.Column("output_sha256", sa.String(64)),
        sa.Column("output_bytes", sa.Integer()),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("summary", sa.String(500)),
        sa.Column("evidence", _JSONB),
        sa.Column("provenance", _JSONB),
        sa.Column("error_code", sa.String(64)),
        sa.Column("error_message", sa.String(500)),
        sa.Column("target_type", sa.String(16)),
        sa.Column("target_public_id", sa.Uuid()),
        sa.Column("target_label", sa.String(255)),
        _fk("site_id", "sites"),
        _fk("asset_id", "assets"),
        _fk("incident_id", "incidents"),
        _fk("response_execution_id", "response_executions"),
        sa.Column("idempotency_key", sa.String(64)),
        sa.Column("approved_by", sa.String(64)),
        _fk("approved_by_user_id", "users"),
        _ts("approved_at"),
        sa.Column("approval_note", sa.String(500)),
        sa.Column("cancelled_by", sa.String(64)),
        sa.Column("backend_pid", sa.Integer()),
        _ts("created_at", nullable=False),
        _ts("started_at"),
        _ts("finished_at"),
        _ts("deadline_at"),
        sa.Column("duration_ms", sa.Integer()),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "status IN (" + ", ".join(f"'{s}'" for s in STATUSES) + ")",
            name="ck_tool_executions_status",
        ),
        sa.CheckConstraint("invoker IN ('user')", name="ck_tool_executions_invoker"),
    )
    op.create_index("ix_tool_executions_created", "tool_executions", ["created_at"])
    op.create_index("ix_tool_executions_actor", "tool_executions", ["actor_user_id", "created_at"])
    op.create_index("ix_tool_executions_tool", "tool_executions", ["tool_id", "created_at"])
    op.create_index("ix_tool_executions_asset", "tool_executions", ["asset_id", "created_at"])
    for name, column in (
        ("ix_tool_executions_incident", "incident_id"),
        ("ix_tool_executions_site", "site_id"),
        ("ix_tool_executions_response", "response_execution_id"),
        ("ix_tool_executions_approver", "approved_by_user_id"),
    ):
        op.create_index(
            name,
            "tool_executions",
            [column],
            postgresql_where=sa.text(f"{column} IS NOT NULL"),
        )
    op.create_index(
        "ix_tool_executions_active",
        "tool_executions",
        ["status", "deadline_at"],
        postgresql_where=sa.text(ACTIVE),
    )
    op.create_index(
        "uq_tool_executions_running_dedupe",
        "tool_executions",
        ["actor_user_id", "tool_id", "input_sha256"],
        unique=True,
        postgresql_where=sa.text("status = 'running'"),
    )
    op.create_index(
        "uq_tool_executions_idempotency",
        "tool_executions",
        ["actor_user_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_table("tool_executions")
