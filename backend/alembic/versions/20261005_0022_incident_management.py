"""Gestión de incidentes SOC (Fase 4K)

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-05

Añade el módulo de incidentes sin tocar los datos existentes:
- tablas nuevas: incidents, incident_assets, incident_detections, incident_alerts,
  incident_notes, incident_activity, incident_feedback;
- tipos ENUM nuevos: incident_status, incident_level, incident_confidence,
  incident_resolution; secuencia incident_number_seq (INC-000001...);
- ai_insights: columna nullable incident_id (FK SET NULL) + índice parcial. Las filas
  existentes quedan con NULL; nada más cambia en 4J/4J.1/4J.2;
- audit_events: índice ix_audit_events_target (solo índice, sin cambiar filas).

Detecciones, alertas, riesgo, usuarios, agentes y activos NO se modifican.

DOWNGRADE (pérdida de datos explícita): borra TODOS los incidentes, sus relaciones, notas,
actividad, feedback de falsos positivos y la numeración INC; borra los insights de IA de
tipo incidente (kind incident_*) porque sin la columna incident_id ya no serían
interpretables. La auditoría (audit_events con acciones incident_*) se conserva.
Detecciones, alertas, activos y riesgo no se tocan.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATUSES = ("open", "triage", "investigating", "contained", "resolved", "closed", "merged")
LEVELS = ("low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
RESOLUTIONS = (
    "true_positive",
    "false_positive",
    "benign_activity",
    "duplicate",
    "accepted_risk",
    "other",
)
TZ = sa.DateTime(timezone=True)


def _user_fk(table: str, column: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column], ["users.id"], name=op.f(f"fk_{table}_{column}_users"), ondelete="SET NULL"
    )


def _incident_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["incident_id"],
        ["incidents.id"],
        name=op.f(f"fk_{table}_incident_id_incidents"),
        ondelete="CASCADE",
    )


def _partial(name: str, table: str, columns: list[str], where: str, unique: bool = False) -> None:
    op.create_index(name, table, columns, unique=unique, postgresql_where=sa.text(where))


def upgrade() -> None:
    bind = op.get_bind()
    status = postgresql.ENUM(*STATUSES, name="incident_status", create_type=False)
    level = postgresql.ENUM(*LEVELS, name="incident_level", create_type=False)
    confidence = postgresql.ENUM(*CONFIDENCES, name="incident_confidence", create_type=False)
    resolution = postgresql.ENUM(*RESOLUTIONS, name="incident_resolution", create_type=False)
    for enum_type in (status, level, confidence, resolution):
        enum_type.create(bind, checkfirst=True)
    op.execute("CREATE SEQUENCE IF NOT EXISTS incident_number_seq")

    op.create_table(
        "incidents",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column(
            "number",
            sa.BigInteger(),
            server_default=sa.text("nextval('incident_number_seq')"),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", level, nullable=False),
        sa.Column("priority", level, nullable=False),
        sa.Column("status", status, nullable=False),
        sa.Column("confidence", confidence, nullable=True),
        sa.Column("owner_user_id", sa.BigInteger(), nullable=True),
        sa.Column("assigned_at", TZ, nullable=True),
        sa.Column("assigned_by_user_id", sa.BigInteger(), nullable=True),
        sa.Column("created_by_user_id", sa.BigInteger(), nullable=True),
        sa.Column("updated_by_user_id", sa.BigInteger(), nullable=True),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("updated_at", TZ, nullable=False),
        sa.Column("first_seen_at", TZ, nullable=True),
        sa.Column("last_seen_at", TZ, nullable=True),
        sa.Column("last_activity_at", TZ, nullable=False),
        sa.Column("triaged_at", TZ, nullable=True),
        sa.Column("resolved_at", TZ, nullable=True),
        sa.Column("resolved_by_user_id", sa.BigInteger(), nullable=True),
        sa.Column("closed_at", TZ, nullable=True),
        sa.Column("resolution_category", resolution, nullable=True),
        sa.Column("resolution_summary", sa.String(length=2000), nullable=True),
        sa.Column("duplicate_of_id", sa.BigInteger(), nullable=True),
        sa.Column("merged_into_id", sa.BigInteger(), nullable=True),
        sa.Column("merged_at", TZ, nullable=True),
        sa.Column("risk_score_snapshot", sa.SmallInteger(), nullable=True),
        sa.Column("risk_level_snapshot", sa.String(length=16), nullable=True),
        sa.Column("risk_confidence_snapshot", sa.String(length=16), nullable=True),
        sa.Column("risk_snapshot_at", TZ, nullable=True),
        sa.Column("risk_snapshot_id", sa.BigInteger(), nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
        sa.UniqueConstraint("public_id", name=op.f("uq_incidents_public_id")),
        sa.UniqueConstraint("number", name=op.f("uq_incidents_number")),
        _user_fk("incidents", "owner_user_id"),
        _user_fk("incidents", "assigned_by_user_id"),
        _user_fk("incidents", "created_by_user_id"),
        _user_fk("incidents", "updated_by_user_id"),
        _user_fk("incidents", "resolved_by_user_id"),
        sa.ForeignKeyConstraint(
            ["duplicate_of_id"],
            ["incidents.id"],
            name=op.f("fk_incidents_duplicate_of_id_incidents"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["merged_into_id"],
            ["incidents.id"],
            name=op.f("fk_incidents_merged_into_id_incidents"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["risk_snapshot_id"],
            ["risk_snapshots.id"],
            name=op.f("fk_incidents_risk_snapshot_id_risk_snapshots"),
            ondelete="SET NULL",
        ),
    )
    # La secuencia pertenece a la columna: se borra con la tabla.
    op.execute("ALTER SEQUENCE incident_number_seq OWNED BY incidents.number")
    op.create_index("ix_incidents_last_activity", "incidents", ["last_activity_at"])
    op.create_index(
        "ix_incidents_status_last_activity", "incidents", ["status", "last_activity_at"]
    )
    op.create_index("ix_incidents_created", "incidents", ["created_at"])
    op.create_index("ix_incidents_created_by", "incidents", ["created_by_user_id"])
    _partial(
        "ix_incidents_owner",
        "incidents",
        ["owner_user_id", "last_activity_at"],
        "owner_user_id IS NOT NULL",
    )
    for column, name in (
        ("merged_into_id", "ix_incidents_merged_into"),
        ("duplicate_of_id", "ix_incidents_duplicate_of"),
        ("assigned_by_user_id", "ix_incidents_assigned_by"),
        ("updated_by_user_id", "ix_incidents_updated_by"),
        ("resolved_by_user_id", "ix_incidents_resolved_by"),
        ("risk_snapshot_id", "ix_incidents_risk_snapshot"),
    ):
        _partial(name, "incidents", [column], f"{column} IS NOT NULL")

    op.create_table(
        "incident_assets",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=True),
        sa.Column("asset_public_id", sa.Uuid(), nullable=False),
        sa.Column("asset_name", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("added_at", TZ, nullable=False),
        sa.Column("added_by_user_id", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_assets")),
        _incident_fk("incident_assets"),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_incident_assets_asset_id_assets"),
            ondelete="SET NULL",
        ),
        _user_fk("incident_assets", "added_by_user_id"),
    )
    _partial(
        "uq_incident_assets_asset",
        "incident_assets",
        ["incident_id", "asset_id"],
        "asset_id IS NOT NULL",
        unique=True,
    )
    _partial("ix_incident_assets_asset", "incident_assets", ["asset_id"], "asset_id IS NOT NULL")
    _partial(
        "ix_incident_assets_added_by",
        "incident_assets",
        ["added_by_user_id"],
        "added_by_user_id IS NOT NULL",
    )

    op.create_table(
        "incident_detections",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("detection_id", sa.BigInteger(), nullable=True),
        sa.Column("detection_public_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("attached_at", TZ, nullable=False),
        sa.Column("attached_by_user_id", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_detections")),
        _incident_fk("incident_detections"),
        sa.ForeignKeyConstraint(
            ["detection_id"],
            ["detections.id"],
            name=op.f("fk_incident_detections_detection_id_detections"),
            ondelete="SET NULL",
        ),
        _user_fk("incident_detections", "attached_by_user_id"),
    )
    _partial(
        "uq_incident_detections_detection",
        "incident_detections",
        ["incident_id", "detection_id"],
        "detection_id IS NOT NULL",
        unique=True,
    )
    _partial(
        "ix_incident_detections_detection",
        "incident_detections",
        ["detection_id"],
        "detection_id IS NOT NULL",
    )
    op.create_index("ix_incident_detections_rule", "incident_detections", ["rule_id"])
    _partial(
        "ix_incident_detections_attached_by",
        "incident_detections",
        ["attached_by_user_id"],
        "attached_by_user_id IS NOT NULL",
    )

    op.create_table(
        "incident_alerts",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("alert_id", sa.BigInteger(), nullable=True),
        sa.Column("alert_public_id", sa.Uuid(), nullable=False),
        sa.Column("rule", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("message", sa.String(length=500), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("attached_at", TZ, nullable=False),
        sa.Column("attached_by_user_id", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_alerts")),
        _incident_fk("incident_alerts"),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_incident_alerts_alert_id_alerts"),
            ondelete="SET NULL",
        ),
        _user_fk("incident_alerts", "attached_by_user_id"),
    )
    _partial(
        "uq_incident_alerts_alert",
        "incident_alerts",
        ["incident_id", "alert_id"],
        "alert_id IS NOT NULL",
        unique=True,
    )
    _partial("ix_incident_alerts_alert", "incident_alerts", ["alert_id"], "alert_id IS NOT NULL")
    _partial(
        "ix_incident_alerts_attached_by",
        "incident_alerts",
        ["attached_by_user_id"],
        "attached_by_user_id IS NOT NULL",
    )

    op.create_table(
        "incident_notes",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("author_user_id", sa.BigInteger(), nullable=True),
        sa.Column("author", sa.String(length=64), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_notes")),
        sa.UniqueConstraint("public_id", name=op.f("uq_incident_notes_public_id")),
        _incident_fk("incident_notes"),
        _user_fk("incident_notes", "author_user_id"),
    )
    op.create_index(
        "ix_incident_notes_incident_created", "incident_notes", ["incident_id", "created_at"]
    )
    _partial(
        "ix_incident_notes_author",
        "incident_notes",
        ["author_user_id"],
        "author_user_id IS NOT NULL",
    )

    op.create_table(
        "incident_activity",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("occurred_at", TZ, nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("actor_user_id", sa.BigInteger(), nullable=True),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("entity_type", sa.String(length=16), nullable=True),
        sa.Column("entity_id", sa.String(length=64), nullable=True),
        sa.Column("summary", sa.String(length=300), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_activity")),
        _incident_fk("incident_activity"),
        _user_fk("incident_activity", "actor_user_id"),
    )
    op.create_index(
        "ix_incident_activity_incident_occurred",
        "incident_activity",
        ["incident_id", "occurred_at", "id"],
    )
    op.create_index("ix_incident_activity_occurred", "incident_activity", ["occurred_at"])
    _partial(
        "ix_incident_activity_actor",
        "incident_activity",
        ["actor_user_id"],
        "actor_user_id IS NOT NULL",
    )

    op.create_table(
        "incident_feedback",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("detection_id", sa.BigInteger(), nullable=True),
        sa.Column("detection_public_id", sa.Uuid(), nullable=True),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=True),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=2000), nullable=True),
        sa.Column("created_by_user_id", sa.BigInteger(), nullable=True),
        sa.Column("created_at", TZ, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_feedback")),
        _incident_fk("incident_feedback"),
        sa.ForeignKeyConstraint(
            ["detection_id"],
            ["detections.id"],
            name=op.f("fk_incident_feedback_detection_id_detections"),
            ondelete="SET NULL",
        ),
        _user_fk("incident_feedback", "created_by_user_id"),
    )
    op.create_index("ix_incident_feedback_incident", "incident_feedback", ["incident_id"])
    op.create_index("ix_incident_feedback_rule", "incident_feedback", ["rule_id", "created_at"])
    _partial(
        "ix_incident_feedback_detection",
        "incident_feedback",
        ["detection_id"],
        "detection_id IS NOT NULL",
    )
    _partial(
        "ix_incident_feedback_user",
        "incident_feedback",
        ["created_by_user_id"],
        "created_by_user_id IS NOT NULL",
    )

    # 4J: análisis de IA sobre un incidente (columna nueva, nullable: filas previas intactas).
    op.add_column("ai_insights", sa.Column("incident_id", sa.BigInteger(), nullable=True))
    op.create_foreign_key(
        op.f("fk_ai_insights_incident_id_incidents"),
        "ai_insights",
        "incidents",
        ["incident_id"],
        ["id"],
        ondelete="SET NULL",
    )
    _partial(
        "ix_ai_insights_incident",
        "ai_insights",
        ["incident_id", "generated_at"],
        "incident_id IS NOT NULL",
    )
    op.create_index(
        "ix_audit_events_target", "audit_events", ["target_type", "target_id", "created_at"]
    )


def downgrade() -> None:
    # ⚠️ Pérdida de datos documentada en el docstring y en docs/incident-management.md.
    op.drop_index("ix_audit_events_target", table_name="audit_events")
    # Insights de incidente: sin incident_id no tendrían a qué referirse.
    op.execute("DELETE FROM ai_insights WHERE kind LIKE 'incident\\_%'")
    op.drop_index("ix_ai_insights_incident", table_name="ai_insights")
    op.drop_constraint(
        op.f("fk_ai_insights_incident_id_incidents"), "ai_insights", type_="foreignkey"
    )
    op.drop_column("ai_insights", "incident_id")
    for table in (
        "incident_feedback",
        "incident_activity",
        "incident_notes",
        "incident_alerts",
        "incident_detections",
        "incident_assets",
        "incidents",
    ):
        op.drop_table(table)
    op.execute("DROP SEQUENCE IF EXISTS incident_number_seq")
    bind = op.get_bind()
    for name in ("incident_resolution", "incident_confidence", "incident_level", "incident_status"):
        postgresql.ENUM(name=name).drop(bind, checkfirst=True)
