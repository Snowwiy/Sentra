"""Tareas de caso y solicitudes de control de red (Fase 7A.6)

Revision ID: 0046
Revises: 0045
Create Date: 2026-10-24

Cambios (ver app/models/case_operations.py y docs/case-operations.md):
- incident_tasks: trabajo humano delegado dentro de un incidente, con responsable, estado,
  evidencia referenciada y resultado obligatorio al terminar.
- network_control_requests: restricciones de red propuestas (puerto, servicio, dirección,
  dominio, acceso a sitio web, subida de ficheros) con su aprobación o rechazo por un admin,
  el punto de control evaluado y, si se aplicó fuera de Sentra, quién y cuándo.

Datos: tablas nuevas vacías. Nada se crea solo: cada fila nace de una petición de un usuario.

DOWNGRADE: elimina las dos tablas con sus tareas y solicitudes (la actividad del caso y la
auditoría se conservan). Exportarlas antes si se necesitan como evidencia.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0046"
down_revision: str | None = "0045"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())
TASK_KINDS = (
    "investigate_port",
    "verify_service",
    "review_vulnerability",
    "analyze_evidence",
    "investigate_script",
    "review_network_activity",
    "request_policy",
    "verify_remediation",
    "prepare_block_rule",
    "document_exception",
    "other",
)
TASK_STATUSES = ("open", "in_progress", "blocked", "done", "cancelled")
CONTROL_TYPES = (
    "block_port",
    "block_service",
    "block_address",
    "block_domain",
    "restrict_site_access",
    "prevent_upload",
)
CONTROL_STATUSES = ("pending_approval", "approved", "rejected", "cancelled", "expired")
ENFORCEMENT_STATUSES = ("not_evaluated", "no_enforcement_point", "applied_manually")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _ts(name: str, nullable: bool = True) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(
    name: str, table: str, ondelete: str = "SET NULL", nullable: bool = True
) -> sa.Column[object]:
    return sa.Column(
        name,
        sa.BigInteger(),
        sa.ForeignKey(f"{table}.id", ondelete=ondelete),
        nullable=nullable,
    )


def upgrade() -> None:
    op.create_table(
        "incident_tasks",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("incident_id", "incidents", "CASCADE", nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("status", sa.String(16), nullable=False),
        _fk("asset_id", "assets"),
        _fk("assignee_user_id", "users"),
        sa.Column("assignee", sa.String(64)),
        _ts("assigned_at"),
        _fk("created_by_user_id", "users"),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("evidence", _JSONB, nullable=False),
        sa.Column("result", sa.Text()),
        _ts("due_at"),
        _ts("created_at", nullable=False),
        _ts("updated_at", nullable=False),
        _ts("started_at"),
        _ts("completed_at"),
        sa.Column("completed_by", sa.String(64)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(_in("kind", TASK_KINDS), name="ck_incident_tasks_kind"),
        sa.CheckConstraint(_in("status", TASK_STATUSES), name="ck_incident_tasks_status"),
        sa.CheckConstraint(
            "status <> 'done' OR (result IS NOT NULL AND length(result) > 0)",
            name="ck_incident_tasks_done_result",
        ),
    )
    op.create_index("ix_incident_tasks_incident", "incident_tasks", ["incident_id", "created_at"])
    op.create_index(
        "ix_incident_tasks_assignee_open",
        "incident_tasks",
        ["assignee_user_id", "status"],
        postgresql_where=sa.text("assignee_user_id IS NOT NULL"),
    )
    op.create_index(
        "ix_incident_tasks_creator",
        "incident_tasks",
        ["created_by_user_id"],
        postgresql_where=sa.text("created_by_user_id IS NOT NULL"),
    )
    op.create_index(
        "ix_incident_tasks_asset",
        "incident_tasks",
        ["asset_id"],
        postgresql_where=sa.text("asset_id IS NOT NULL"),
    )

    op.create_table(
        "network_control_requests",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("incident_id", "incidents", "CASCADE", nullable=False),
        _fk("task_id", "incident_tasks"),
        sa.Column("control_type", sa.String(32), nullable=False),
        sa.Column("target", _JSONB, nullable=False),
        sa.Column("direction", sa.String(8)),
        _fk("asset_id", "assets"),
        _fk("site_id", "sites"),
        sa.Column("scope_label", sa.String(255), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("enforcement_status", sa.String(24), nullable=False),
        sa.Column("enforcement", _JSONB),
        _ts("expires_at"),
        _fk("requested_by_user_id", "users"),
        sa.Column("requested_by", sa.String(64), nullable=False),
        _ts("created_at", nullable=False),
        _ts("updated_at", nullable=False),
        _fk("decided_by_user_id", "users"),
        sa.Column("decided_by", sa.String(64)),
        _ts("decided_at"),
        sa.Column("decision_note", sa.String(1000)),
        _fk("applied_by_user_id", "users"),
        sa.Column("applied_by", sa.String(64)),
        _ts("applied_at"),
        sa.Column("applied_note", sa.String(1000)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(_in("control_type", CONTROL_TYPES), name="ck_network_controls_type"),
        sa.CheckConstraint(_in("status", CONTROL_STATUSES), name="ck_network_controls_status"),
        sa.CheckConstraint(
            _in("enforcement_status", ENFORCEMENT_STATUSES),
            name="ck_network_controls_enforcement",
        ),
        sa.CheckConstraint(
            "direction IS NULL OR direction IN ('inbound', 'outbound', 'both')",
            name="ck_network_controls_direction",
        ),
    )
    op.create_index(
        "ix_network_controls_incident", "network_control_requests", ["incident_id", "created_at"]
    )
    op.create_index(
        "ix_network_controls_open",
        "network_control_requests",
        ["status", "expires_at"],
        postgresql_where=sa.text("status IN ('pending_approval', 'approved')"),
    )
    for name, column in (
        ("ix_network_controls_task", "task_id"),
        ("ix_network_controls_asset", "asset_id"),
        ("ix_network_controls_site", "site_id"),
        ("ix_network_controls_requester", "requested_by_user_id"),
        ("ix_network_controls_decider", "decided_by_user_id"),
        ("ix_network_controls_applier", "applied_by_user_id"),
    ):
        op.create_index(
            name,
            "network_control_requests",
            [column],
            postgresql_where=sa.text(f"{column} IS NOT NULL"),
        )


def downgrade() -> None:
    op.drop_table("network_control_requests")
    op.drop_table("incident_tasks")
