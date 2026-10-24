"""Aislamiento seguro (Fase 6E.7)

Revision ID: 0043
Revises: 0042
Create Date: 2026-10-22

Cambios (ver app/models/isolation.py y docs/safe-isolation.md):
- isolation_sessions: sesiones de aislamiento con su estado, duración, confirmaciones y lo
  que el helper local informó haber aplicado. Una viva como mucho por activo.
- assets.isolation_status / isolation_status_at: estado del helper según el heartbeat.
- alert_rule: valor nuevo 'isolation_state' (discrepancia entre servidor y equipo).

Datos: tablas y columnas nuevas vacías. ISOLATION_ENABLED=false por defecto: ningún equipo se
aísla sin activarlo aquí Y en la política local del helper.

DOWNGRADE: antes de bajar, levantar cualquier aislamiento vivo (el helper lo revierte solo al
caducar aunque el servidor no responda). Elimina la tabla, las columnas y las alertas
'isolation_state' (el valor del enum queda, PostgreSQL no permite quitarlo; es inocuo).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0043"
down_revision: str | None = "0042"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())
STATES = (
    "requested",
    "approved",
    "applying",
    "isolated",
    "reverting",
    "restored",
    "failed",
    "expired",
    "unknown",
)
ACTIVE = "status IN ('requested', 'approved', 'applying', 'isolated', 'reverting', 'unknown')"


def _ts(name: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _execution_fk(name: str) -> sa.Column[object]:
    return sa.Column(
        name, sa.BigInteger(), sa.ForeignKey("response_executions.id", ondelete="SET NULL")
    )


def upgrade() -> None:
    # ADD VALUE en la transacción de la migración: válido en PostgreSQL 12+ si el valor no se
    # usa en esta misma transacción (no se usa).
    op.execute("ALTER TYPE alert_rule ADD VALUE IF NOT EXISTS 'isolation_state'")

    op.create_table(
        "isolation_sessions",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("asset_id", sa.BigInteger(), sa.ForeignKey("assets.id", ondelete="SET NULL")),
        sa.Column("asset_public_id", sa.Uuid(), nullable=False),
        sa.Column("asset_label", sa.String(255), nullable=False),
        sa.Column("agent_id", sa.Uuid()),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("duration_minutes", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(64), nullable=False),
        _ts("requested_at"),
        sa.Column("approved_by", sa.String(64)),
        _ts("approved_at", nullable=True),
        _ts("expires_at"),
        _ts("applied_at", nullable=True),
        sa.Column("released_by", sa.String(64)),
        sa.Column("release_reason", sa.String(500)),
        _ts("released_at", nullable=True),
        _ts("ended_at", nullable=True),
        sa.Column("method", sa.String(32)),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("allowed", _JSONB, nullable=False),
        sa.Column("rules", _JSONB, nullable=False),
        sa.Column("error_code", sa.String(64)),
        _execution_fk("isolate_execution_id"),
        _execution_fk("release_execution_id"),
        sa.Column("reported_state", sa.String(16)),
        _ts("reported_at", nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "status IN (" + ", ".join(f"'{s}'" for s in STATES) + ")",
            name="ck_isolation_sessions_status",
        ),
    )
    op.create_index(
        "ix_isolation_sessions_asset", "isolation_sessions", ["asset_id", "requested_at"]
    )
    op.create_index(
        "uq_isolation_sessions_active_asset",
        "isolation_sessions",
        ["asset_id"],
        unique=True,
        postgresql_where=sa.text(ACTIVE),
    )
    op.create_index(
        "ix_isolation_sessions_isolate_execution", "isolation_sessions", ["isolate_execution_id"]
    )
    op.create_index(
        "ix_isolation_sessions_release_execution", "isolation_sessions", ["release_execution_id"]
    )
    op.create_index(
        "ix_isolation_sessions_expires",
        "isolation_sessions",
        ["expires_at"],
        postgresql_where=sa.text(ACTIVE),
    )
    op.add_column("assets", sa.Column("isolation_status", _JSONB))
    op.add_column("assets", _ts("isolation_status_at", nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    # Las alertas 'isolation_state' no pueden existir antes de la 0043.
    bind.execute(sa.text("DELETE FROM alerts WHERE rule::text = 'isolation_state'"))
    op.drop_column("assets", "isolation_status_at")
    op.drop_column("assets", "isolation_status")
    op.drop_table("isolation_sessions")
