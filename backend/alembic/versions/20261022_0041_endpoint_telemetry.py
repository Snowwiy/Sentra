"""Telemetría avanzada de endpoint, árbol de procesos y excepciones de reglas (Fase 6E.3-6E.5)

Revision ID: 0041
Revises: 0040
Create Date: 2026-10-22

Cambios (ver app/models/endpoint.py, docs/process-tree.md y docs/behavioral-detection.md):
- endpoint_activity: eventos de actividad del agente 0.5.0, únicos por (activo, event_uid).
- process_instances: instancias de proceso por instance_key (no por PID).
- detection_exclusions: excepciones auditadas y revocables de reglas integradas.
- assets.telemetry_status / telemetry_status_at: estado de la cola y colectores del agente.

Datos: tablas nuevas y vacías; las columnas de assets quedan a null hasta el primer lote de
un agente 0.5.0. Los agentes anteriores no cambian de comportamiento.

DOWNGRADE: elimina las tres tablas y las dos columnas. Se pierde la actividad recibida, el
árbol de procesos y las excepciones (su creación y revocación quedan en la auditoría).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0041"
down_revision: str | None = "0040"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())

CATEGORIES = (
    "process",
    "network",
    "service",
    "scheduled_task",
    "persistence",
    "auth",
    "dns",
    "protection",
    "firewall",
    "agent_health",
)
RELATIONS = ("observed", "inferred", "missing", "pid_reused")
FIELDS = ("exe", "name", "sha256", "signer", "parent_name", "remote_address")


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _ts(name: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _asset_fk(nullable: bool = False) -> sa.Column[object]:
    return sa.Column(
        "asset_id",
        sa.BigInteger(),
        sa.ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=nullable,
    )


def upgrade() -> None:
    op.create_table(
        "endpoint_activity",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        _asset_fk(),
        sa.Column("event_uid", sa.Uuid(), nullable=False),
        sa.Column("boot_id", sa.String(64), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("source", sa.String(24), nullable=False),
        sa.Column("instance_key", sa.String(32)),
        sa.Column("data", _JSONB, nullable=False),
        _ts("occurred_at"),
        _ts("received_at"),
        sa.UniqueConstraint("asset_id", "event_uid", name="uq_endpoint_activity_event"),
        sa.CheckConstraint(_in("category", CATEGORIES), name="ck_endpoint_activity_category"),
    )
    op.create_index(
        "ix_endpoint_activity_asset_time", "endpoint_activity", ["asset_id", "occurred_at"]
    )
    op.create_index(
        "ix_endpoint_activity_asset_category",
        "endpoint_activity",
        ["asset_id", "category", "occurred_at"],
    )
    op.create_index(
        "ix_endpoint_activity_instance", "endpoint_activity", ["asset_id", "instance_key"]
    )
    op.create_index("ix_endpoint_activity_received", "endpoint_activity", ["received_at"])

    op.create_table(
        "process_instances",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        _asset_fk(),
        sa.Column("instance_key", sa.String(32), nullable=False),
        sa.Column("boot_id", sa.String(64), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("ppid", sa.Integer()),
        sa.Column("parent_instance_key", sa.String(32)),
        sa.Column("parent_relation", sa.String(16)),
        sa.Column("name", sa.String(255)),
        sa.Column("exe", sa.String(1024)),
        sa.Column("cmdline", sa.Text()),
        sa.Column("username", sa.String(255)),
        sa.Column("sha256", sa.String(64)),
        sa.Column("signer", sa.String(255)),
        sa.Column("integrity", sa.String(16)),
        sa.Column("source", sa.String(24), nullable=False),
        _ts("started_at", nullable=True),
        _ts("ended_at", nullable=True),
        _ts("first_seen_at"),
        _ts("last_seen_at"),
        sa.UniqueConstraint("asset_id", "instance_key", name="uq_process_instances_key"),
        sa.CheckConstraint(
            "parent_relation IS NULL OR " + _in("parent_relation", RELATIONS),
            name="ck_process_instances_parent_relation",
        ),
    )
    op.create_index(
        "ix_process_instances_parent", "process_instances", ["asset_id", "parent_instance_key"]
    )
    op.create_index("ix_process_instances_started", "process_instances", ["asset_id", "started_at"])
    op.create_index("ix_process_instances_seen", "process_instances", ["last_seen_at"])

    op.create_table(
        "detection_exclusions",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("rule_id", sa.String(64), nullable=False),
        _asset_fk(nullable=True),
        sa.Column("field", sa.String(16), nullable=False),
        sa.Column("value", sa.String(1024), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        _ts("created_at"),
        _ts("expires_at", nullable=True),
        _ts("revoked_at", nullable=True),
        sa.Column("revoked_by", sa.String(64)),
        sa.Column("hits", sa.Integer(), server_default="0", nullable=False),
        _ts("last_hit_at", nullable=True),
        sa.CheckConstraint(_in("field", FIELDS), name="ck_detection_exclusions_field"),
    )
    op.create_index("ix_detection_exclusions_rule", "detection_exclusions", ["rule_id"])
    op.create_index("ix_detection_exclusions_asset", "detection_exclusions", ["asset_id"])

    op.add_column("assets", sa.Column("telemetry_status", _JSONB))
    op.add_column("assets", _ts("telemetry_status_at", nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "telemetry_status_at")
    op.drop_column("assets", "telemetry_status")
    op.drop_table("detection_exclusions")
    op.drop_table("process_instances")
    op.drop_table("endpoint_activity")
