"""Response Engine y Playbooks (Fase 5D)

Revision ID: 0030
Revises: 0029
Create Date: 2026-10-14

Tablas nuevas (ver app/models/response.py y docs/response-engine.md):
- playbooks / playbook_versions: definiciones declarativas versionadas (inmutables);
- playbook_runs: ejecuciones de playbook con la copia exacta de los pasos usados;
- response_executions: cada acción pedida (manual o paso de playbook), estado y resultado;
- agent_commands: comandos estructurados (tipo allowlisted) para un agente concreto, con TTL
  obligatorio, lease de entrega y contador de entregas.

Columnas nuevas en assets (nullable, sin reescritura de filas):
- agent_capabilities (JSONB): tipos de comando que el agente declara; null = agente anterior;
- agent_capabilities_at.

Índices: los de cada clave foránea (test_every_foreign_key_is_indexed), los parciales de
barrido (solo filas vivas) y dos únicos parciales que garantizan idempotencia en la base de
datos aunque lleguen dos peticiones a la vez: una ejecución viva por acción+objetivo, una
ejecución por paso de playbook y una por clave de idempotencia de cada usuario.

Los playbooks built-in no se siembran aquí: viven en código (app/response/playbooks.py) y se
crean al leer el catálogo, así una versión nueva de Sentra puede añadir su versión siguiente.

DOWNGRADE: borra las cinco tablas y las dos columnas. Se pierde el historial de Response (las
entradas de audit_events response_* y playbook_* se conservan).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIVE = "status IN ('pending', 'approval_required', 'queued', 'running')"


def upgrade() -> None:
    op.add_column("assets", sa.Column("agent_capabilities", postgresql.JSONB(), nullable=True))
    op.add_column(
        "assets", sa.Column("agent_capabilities_at", sa.DateTime(timezone=True), nullable=True)
    )

    op.create_table(
        "playbooks",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("key", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("builtin", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("current_version", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column(
            "created_by_user_id",
            sa.BigInteger(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
    )
    op.create_index(
        "ix_playbooks_created_by",
        "playbooks",
        ["created_by_user_id"],
        postgresql_where=sa.text("created_by_user_id IS NOT NULL"),
    )

    op.create_table(
        "playbook_versions",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "playbook_id",
            sa.BigInteger(),
            sa.ForeignKey("playbooks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("steps", postgresql.JSONB(), nullable=False),
        sa.Column("risk_level", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "uq_playbook_versions", "playbook_versions", ["playbook_id", "version"], unique=True
    )

    op.create_table(
        "playbook_runs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column(
            "playbook_id",
            sa.BigInteger(),
            sa.ForeignKey("playbooks.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("playbook_key", sa.String(64), nullable=False),
        sa.Column("playbook_name", sa.String(120), nullable=False),
        sa.Column("playbook_version", sa.Integer(), nullable=False),
        sa.Column("steps", postgresql.JSONB(), nullable=False),
        sa.Column("risk_level", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("current_step", sa.Integer(), nullable=False),
        sa.Column("target_public_id", sa.Uuid(), nullable=False),
        sa.Column("target_label", sa.String(255), nullable=False),
        sa.Column(
            "asset_id",
            sa.BigInteger(),
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "incident_id",
            sa.BigInteger(),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("detection_public_id", sa.Uuid(), nullable=True),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.BigInteger(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reason", sa.String(500), nullable=True),
        sa.Column("idempotency_key", sa.String(64), nullable=True),
        sa.Column("dedupe_key", sa.String(200), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
    )
    op.create_index("ix_playbook_runs_playbook", "playbook_runs", ["playbook_id", "created_at"])
    op.create_index("ix_playbook_runs_asset", "playbook_runs", ["asset_id", "created_at"])
    op.create_index(
        "ix_playbook_runs_incident",
        "playbook_runs",
        ["incident_id"],
        postgresql_where=sa.text("incident_id IS NOT NULL"),
    )
    op.create_index(
        "ix_playbook_runs_actor",
        "playbook_runs",
        ["actor_user_id"],
        postgresql_where=sa.text("actor_user_id IS NOT NULL"),
    )
    op.create_index(
        "ix_playbook_runs_active",
        "playbook_runs",
        ["status"],
        postgresql_where=sa.text("status = 'running'"),
    )
    op.create_index("ix_playbook_runs_created", "playbook_runs", ["created_at"])
    op.create_index(
        "uq_playbook_runs_active_dedupe",
        "playbook_runs",
        ["dedupe_key"],
        unique=True,
        postgresql_where=sa.text("dedupe_key IS NOT NULL AND status = 'running'"),
    )
    op.create_index(
        "uq_playbook_runs_idempotency",
        "playbook_runs",
        ["actor_user_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )

    op.create_table(
        "response_executions",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("correlation_id", sa.Uuid(), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("risk_level", sa.String(16), nullable=False),
        sa.Column("requires_agent", sa.Boolean(), nullable=False),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target_public_id", sa.Uuid(), nullable=False),
        sa.Column("target_label", sa.String(255), nullable=False),
        sa.Column(
            "asset_id",
            sa.BigInteger(),
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "incident_id",
            sa.BigInteger(),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("detection_public_id", sa.Uuid(), nullable=True),
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("parameters", postgresql.JSONB(), nullable=False),
        sa.Column("result", postgresql.JSONB(), nullable=True),
        sa.Column("result_summary", sa.String(500), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(500), nullable=True),
        sa.Column("blockers", postgresql.JSONB(), nullable=True),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.BigInteger(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reason", sa.String(500), nullable=True),
        sa.Column("confirmed", sa.Boolean(), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=True),
        sa.Column("dedupe_key", sa.String(200), nullable=True),
        sa.Column(
            "playbook_run_id",
            sa.BigInteger(),
            sa.ForeignKey("playbook_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("step_index", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
    )
    op.create_index(
        "ix_response_executions_asset", "response_executions", ["asset_id", "created_at"]
    )
    op.create_index(
        "ix_response_executions_incident",
        "response_executions",
        ["incident_id"],
        postgresql_where=sa.text("incident_id IS NOT NULL"),
    )
    op.create_index(
        "ix_response_executions_actor",
        "response_executions",
        ["actor_user_id"],
        postgresql_where=sa.text("actor_user_id IS NOT NULL"),
    )
    op.create_index(
        "uq_response_executions_run_step",
        "response_executions",
        ["playbook_run_id", "step_index"],
        unique=True,
        postgresql_where=sa.text("playbook_run_id IS NOT NULL"),
    )
    op.create_index("ix_response_executions_created", "response_executions", ["created_at"])
    op.create_index(
        "ix_response_executions_deadline",
        "response_executions",
        ["deadline_at"],
        postgresql_where=sa.text(ACTIVE),
    )
    op.create_index(
        "uq_response_executions_active_dedupe",
        "response_executions",
        ["dedupe_key"],
        unique=True,
        postgresql_where=sa.text(f"dedupe_key IS NOT NULL AND {ACTIVE}"),
    )
    op.create_index(
        "uq_response_executions_idempotency",
        "response_executions",
        ["actor_user_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )

    op.create_table(
        "agent_commands",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("request_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column(
            "execution_id",
            sa.BigInteger(),
            sa.ForeignKey("response_executions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.BigInteger(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("command_type", sa.String(48), nullable=False),
        sa.Column("params", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivery_count", sa.Integer(), nullable=False),
        sa.Column("max_deliveries", sa.Integer(), nullable=False),
    )
    op.create_index(
        "ix_agent_commands_asset_status", "agent_commands", ["asset_id", "status", "created_at"]
    )
    op.create_index("ix_agent_commands_execution", "agent_commands", ["execution_id"])
    op.create_index(
        "ix_agent_commands_open",
        "agent_commands",
        ["status", "expires_at"],
        postgresql_where=sa.text("status IN ('queued', 'delivered')"),
    )


def downgrade() -> None:
    op.drop_table("agent_commands")
    op.drop_table("response_executions")
    op.drop_table("playbook_runs")
    op.drop_table("playbook_versions")
    op.drop_table("playbooks")
    op.drop_column("assets", "agent_capabilities_at")
    op.drop_column("assets", "agent_capabilities")
