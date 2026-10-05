"""Risk Engine (Fase 4I)

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-05

Añade assets.criticality (por defecto 'medium'), las tablas asset_risk, risk_snapshots y
risk_contributions, un índice para leer detecciones resueltas recientes por activo y el valor
'risk_critical' a alert_rule. Encola el primer cálculo de todos los activos existentes
(asset_risk con dirty_at). No modifica ni borra activos, detecciones, alertas, eventos,
telemetría, usuarios ni auditoría.

El downgrade borra las tablas de riesgo, la columna criticality y las alertas risk_critical
(no pueden existir antes de la 0019); el resto de datos queda intacto.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CRITICALITIES = ("low", "medium", "high", "critical")
LEVELS = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
# alert_rule tal como queda en la 0018 (para reconstruirlo en el downgrade).
RULES_0018 = (
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
    "security_detection",
)


def upgrade() -> None:
    # No se usa en esta transacción, así que ADD VALUE se permite dentro (PostgreSQL 12+).
    op.execute("ALTER TYPE alert_rule ADD VALUE IF NOT EXISTS 'risk_critical'")

    bind = op.get_bind()
    criticality = postgresql.ENUM(*CRITICALITIES, name="asset_criticality", create_type=False)
    level = postgresql.ENUM(*LEVELS, name="risk_level", create_type=False)
    confidence = postgresql.ENUM(*CONFIDENCES, name="risk_confidence", create_type=False)
    for enum_type in (criticality, level, confidence):
        enum_type.create(bind, checkfirst=True)

    # Con server_default: las filas existentes quedan en 'medium' sin reescribir nada a mano.
    op.add_column(
        "assets",
        sa.Column("criticality", criticality, server_default="medium", nullable=False),
    )

    op.create_table(
        "asset_risk",
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("score", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("level", level, server_default="informational", nullable=False),
        sa.Column("confidence", confidence, server_default="low", nullable=False),
        sa.Column("formula_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("top_factor", sa.String(length=255), nullable=True),
        sa.Column("contributions", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("last_snapshot_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_snapshot_score", sa.SmallInteger(), nullable=True),
        sa.Column("dirty_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_alert_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_asset_risk_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("asset_id", name=op.f("pk_asset_risk")),
    )
    op.create_index("ix_asset_risk_score", "asset_risk", ["score"])
    op.create_index("ix_asset_risk_level", "asset_risk", ["level"])
    op.create_index(
        "ix_asset_risk_dirty",
        "asset_risk",
        ["dirty_at"],
        postgresql_where=sa.text("dirty_at IS NOT NULL"),
    )
    op.create_index("ix_asset_risk_calculated", "asset_risk", ["calculated_at"])

    op.create_table(
        "risk_snapshots",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("score", sa.SmallInteger(), nullable=False),
        sa.Column("level", level, nullable=False),
        sa.Column("confidence", confidence, nullable=False),
        sa.Column("previous_score", sa.SmallInteger(), nullable=True),
        sa.Column("previous_level", level, nullable=True),
        sa.Column("transition", sa.String(length=8), nullable=True),
        sa.Column("reason", sa.String(length=32), nullable=False),
        sa.Column("formula_version", sa.Integer(), nullable=False),
        sa.Column("top_factor", sa.String(length=255), nullable=True),
        sa.Column("breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_risk_snapshots_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_snapshots")),
        sa.UniqueConstraint("public_id", name=op.f("uq_risk_snapshots_public_id")),
    )
    op.create_index(
        "ix_risk_snapshots_asset_calculated", "risk_snapshots", ["asset_id", "calculated_at"]
    )
    op.create_index("ix_risk_snapshots_calculated", "risk_snapshots", ["calculated_at"])

    op.create_table(
        "risk_contributions",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_id", sa.BigInteger(), nullable=False),
        sa.Column("position", sa.SmallInteger(), nullable=False),
        sa.Column("factor", sa.String(length=16), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("points", sa.Float(), nullable=False),
        sa.Column("nominal_points", sa.Float(), nullable=True),
        sa.Column("detection_id", sa.BigInteger(), nullable=True),
        sa.Column("detection_public_id", sa.Uuid(), nullable=True),
        sa.Column("rule_id", sa.String(length=32), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["risk_snapshots.id"],
            name=op.f("fk_risk_contributions_snapshot_id_risk_snapshots"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["detection_id"],
            ["detections.id"],
            name=op.f("fk_risk_contributions_detection_id_detections"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_contributions")),
    )
    op.create_index(
        "ix_risk_contributions_snapshot", "risk_contributions", ["snapshot_id", "position"]
    )
    op.create_index(
        "ix_risk_contributions_detection",
        "risk_contributions",
        ["detection_id"],
        postgresql_where=sa.text("detection_id IS NOT NULL"),
    )

    # Entrada del Risk Engine: detecciones resueltas recientes de un activo (memoria de
    # resolución). Las activas ya las cubre uq_detections_active_key (asset_id, ...).
    op.create_index(
        "ix_detections_asset_resolved",
        "detections",
        ["asset_id", "resolved_at"],
        postgresql_where=sa.text("status = 'resolved'"),
    )

    # Primer cálculo de los activos existentes: solo se encola; lo hace el job al arrancar.
    op.execute("INSERT INTO asset_risk (asset_id, dirty_at) SELECT id, now() FROM assets")


def downgrade() -> None:
    op.drop_index("ix_detections_asset_resolved", table_name="detections")
    op.drop_table("risk_contributions")
    op.drop_table("risk_snapshots")
    op.drop_table("asset_risk")
    op.drop_column("assets", "criticality")
    bind = op.get_bind()
    for name in ("risk_confidence", "risk_level", "asset_criticality"):
        postgresql.ENUM(name=name).drop(bind, checkfirst=True)

    # ⚠️ Las alertas risk_critical no pueden existir antes de la 0019.
    bind.execute(sa.text("DELETE FROM alerts WHERE rule::text = 'risk_critical'"))
    # PostgreSQL no permite quitar un valor de un ENUM: se reconstruye el tipo. El índice
    # único parcial depende de la columna y se recrea igual que en la 0012.
    op.drop_index("uq_alerts_active_asset_rule", table_name="alerts")
    listed = ", ".join(f"'{value}'" for value in RULES_0018)
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
