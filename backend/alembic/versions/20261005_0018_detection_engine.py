"""Motor de detección y correlación (Fase 4H)

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-05

Crea detections, detection_evidence, detection_signals y detection_baselines; añade la
columna opcional system_events.data (campos estructurados de eventos) y el valor
'security_detection' a alert_rule. No modifica ni borra activos, eventos, alertas,
telemetría, usuarios, sesiones ni auditoría.

El downgrade borra las tablas del motor, la columna data y las alertas security_detection
(no pueden existir antes de la 0018); el resto de datos queda intacto.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SEVERITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
STATUSES = ("open", "acknowledged", "resolved")
# alert_rule tal como queda en la 0017 (para reconstruirlo en el downgrade).
RULES_0017 = (
    "asset_offline",
    "high_cpu",
    "high_ram",
    "disk_critical",
    "service_stopped",
    "event_burst",
    "admin_changed",
    "critical_event",
    "asset_discovered",
    "unknown_device",
    "asset_disappeared",
    "port_exposed",
    "port_closed",
    "monitoring_lost",
)


def upgrade() -> None:
    # No se usa en esta transacción, así que ADD VALUE se permite dentro (PostgreSQL 12+).
    op.execute("ALTER TYPE alert_rule ADD VALUE IF NOT EXISTS 'security_detection'")
    op.add_column(
        "system_events",
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    severity = postgresql.ENUM(*SEVERITIES, name="detection_severity", create_type=False)
    confidence = postgresql.ENUM(*CONFIDENCES, name="detection_confidence", create_type=False)
    status = postgresql.ENUM(*STATUSES, name="detection_status", create_type=False)
    bind = op.get_bind()
    for enum_type in (severity, confidence, status):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "detections",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("dedup_key", sa.String(length=255), nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("confidence", confidence, nullable=False),
        sa.Column("status", status, nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.String(length=1000), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("mitre_tactic", sa.String(length=16), nullable=True),
        sa.Column("mitre_technique", sa.String(length=16), nullable=True),
        sa.Column("mitre_subtechnique", sa.String(length=16), nullable=True),
        sa.Column("occurrence_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(length=64), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(length=64), nullable=True),
        sa.Column("resolution_note", sa.String(length=500), nullable=True),
        sa.Column("alert_id", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_detections_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_detections_alert_id_alerts"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detections")),
        sa.UniqueConstraint("public_id", name=op.f("uq_detections_public_id")),
    )
    op.create_index(
        "uq_detections_active_key",
        "detections",
        ["asset_id", "rule_id", "dedup_key"],
        unique=True,
        postgresql_where=sa.text("status <> 'resolved'"),
    )
    op.create_index("ix_detections_last_seen", "detections", ["last_seen_at"])
    op.create_index("ix_detections_status_last_seen", "detections", ["status", "last_seen_at"])
    op.create_index("ix_detections_asset_last_seen", "detections", ["asset_id", "last_seen_at"])
    op.create_index("ix_detections_rule_last_seen", "detections", ["rule_id", "last_seen_at"])
    op.create_index("ix_detections_first_seen", "detections", ["first_seen_at"])
    op.create_index(
        "ix_detections_resolved_at",
        "detections",
        ["resolved_at"],
        postgresql_where=sa.text("status = 'resolved'"),
    )
    op.create_index(
        "ix_detections_alert",
        "detections",
        ["alert_id"],
        postgresql_where=sa.text("alert_id IS NOT NULL"),
    )

    op.create_table(
        "detection_evidence",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("detection_id", sa.BigInteger(), nullable=False),
        sa.Column("signal_id", sa.BigInteger(), nullable=True),
        sa.Column("signal_kind", sa.String(length=48), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=True),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=64), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.String(length=500), nullable=False),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["detection_id"],
            ["detections.id"],
            name=op.f("fk_detection_evidence_detection_id_detections"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detection_evidence")),
        sa.UniqueConstraint("detection_id", "signal_id", name="uq_detection_evidence_signal"),
    )
    op.create_index(
        "ix_detection_evidence_detection_occurred",
        "detection_evidence",
        ["detection_id", "occurred_at"],
    )

    op.create_table(
        "detection_signals",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(length=48), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=64), nullable=True),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_detection_signals_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detection_signals")),
    )
    op.create_index(
        "ix_detection_signals_asset_kind_occurred",
        "detection_signals",
        ["asset_id", "kind", "occurred_at"],
    )
    op.create_index(
        "ix_detection_signals_pending",
        "detection_signals",
        ["id"],
        postgresql_where=sa.text("evaluated_at IS NULL"),
    )
    op.create_index("ix_detection_signals_created", "detection_signals", ["created_at"])

    op.create_table(
        "detection_baselines",
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("key", sa.String(length=512), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_detection_baselines_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("asset_id", "kind", "key", name=op.f("pk_detection_baselines")),
    )


def downgrade() -> None:
    op.drop_table("detection_baselines")
    op.drop_table("detection_signals")
    op.drop_table("detection_evidence")
    op.drop_table("detections")
    bind = op.get_bind()
    for name in ("detection_status", "detection_confidence", "detection_severity"):
        postgresql.ENUM(name=name).drop(bind, checkfirst=True)
    op.drop_column("system_events", "data")

    # ⚠️ Las alertas security_detection no pueden existir antes de la 0018.
    bind.execute(sa.text("DELETE FROM alerts WHERE rule::text = 'security_detection'"))
    # PostgreSQL no permite quitar un valor de un ENUM: se reconstruye el tipo. El índice
    # único parcial depende de la columna y se recrea igual que en la 0012.
    op.drop_index("uq_alerts_active_asset_rule", table_name="alerts")
    listed = ", ".join(f"'{value}'" for value in RULES_0017)
    op.execute("ALTER TYPE alert_rule RENAME TO alert_rule_old")
    op.execute(f"CREATE TYPE alert_rule AS ENUM ({listed})")
    op.execute("ALTER TABLE alerts ALTER COLUMN rule TYPE alert_rule USING rule::text::alert_rule")
    op.execute("DROP TYPE alert_rule_old")
    op.create_index(
        "uq_alerts_active_asset_rule",
        "alerts",
        ["asset_id", "rule"],
        unique=True,
        postgresql_where=sa.text("status <> 'resolved'"),
    )
