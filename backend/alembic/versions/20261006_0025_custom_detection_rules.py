"""Reglas de detección personalizadas y Sigma (Fase 5A)

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-06

Añade:
- detection_rules: estado actual de cada regla custom/Sigma (las built-in siguen en código);
- detection_rule_versions: versiones completas e inmutables (definición, textos, YAML Sigma);
- detection_rule_stats: contadores del motor por regla (también built-in);
- detection_rule_matches: estado temporal de las reglas con umbral (se purga con las señales);
- secuencia detection_rule_uid_seq para los identificadores estables (SENTRA-CUSTOM-000001);
- detections.rule_source y detections.rule_category (las filas existentes quedan "builtin").

No modifica ni reescribe detecciones, evidencia, riesgo, incidentes, activos, IA, sesiones
ni rate limits.

DOWNGRADE: borra las cuatro tablas, la secuencia y las dos columnas nuevas de detections. Se
PIERDEN las reglas personalizadas, su historial de versiones y sus estadísticas. Las
detecciones que generaron se conservan (rule_id y rule_version siguen ahí), pero dejan de
tener texto de regla asociado. No ejecutar el downgrade en una base real sin exportar antes
las reglas (GET /detection-rules/{id}/export) o tener un backup (scripts de la Fase 4M).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SEVERITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")


def upgrade() -> None:
    severity = postgresql.ENUM(*SEVERITIES, name="detection_severity", create_type=False)
    confidence = postgresql.ENUM(*CONFIDENCES, name="detection_confidence", create_type=False)
    tz = sa.DateTime(timezone=True)

    op.execute("CREATE SEQUENCE detection_rule_uid_seq START 1")

    op.create_table(
        "detection_rules",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("rule_uid", sa.String(32), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("sigma_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("compile_status", sa.String(16), nullable=False),
        sa.Column("current_version", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("logsource", sa.String(32), nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("confidence", confidence, nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("mitre_technique", sa.String(16), nullable=True),
        sa.Column("created_at", tz, nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("updated_at", tz, nullable=False),
        sa.Column("updated_by", sa.String(64), nullable=False),
        sa.Column("last_compiled_at", tz, nullable=False),
        sa.Column("retired_at", tz, nullable=True),
        sa.UniqueConstraint("rule_uid", name="uq_detection_rules_rule_uid"),
        sa.UniqueConstraint("sigma_id", name="uq_detection_rules_sigma_id"),
    )
    op.create_index("ix_detection_rules_status", "detection_rules", ["status"])
    op.create_index("ix_detection_rules_updated", "detection_rules", ["updated_at"])
    op.create_index("ix_detection_rules_logsource", "detection_rules", ["logsource"])

    op.create_table(
        "detection_rule_versions",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "rule_id",
            sa.BigInteger(),
            sa.ForeignKey("detection_rules.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", tz, nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("change_note", sa.String(200), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.String(2000), nullable=False),
        sa.Column("why", sa.String(1000), nullable=False),
        sa.Column("recommendations", postgresql.JSONB(), nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("confidence", confidence, nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("mitre_tactic", sa.String(16), nullable=True),
        sa.Column("mitre_technique", sa.String(16), nullable=True),
        sa.Column("mitre_subtechnique", sa.String(16), nullable=True),
        sa.Column("tags", postgresql.JSONB(), nullable=False),
        sa.Column("definition", postgresql.JSONB(), nullable=False),
        sa.Column("compiled", postgresql.JSONB(), nullable=False),
        sa.Column("compile_status", sa.String(16), nullable=False),
        sa.Column("compile_issues", postgresql.JSONB(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("sigma_yaml", sa.Text(), nullable=True),
        sa.Column("sigma_metadata", postgresql.JSONB(), nullable=True),
        sa.UniqueConstraint("rule_id", "version", name="uq_detection_rule_version"),
    )

    op.create_table(
        "detection_rule_stats",
        sa.Column("rule_uid", sa.String(32), primary_key=True),
        sa.Column("evaluations", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("matches", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("errors", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("consecutive_errors", sa.Integer(), server_default="0", nullable=False),
        sa.Column("slow_evaluations", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("eval_time_us", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("last_evaluated_at", tz, nullable=True),
        sa.Column("last_matched_at", tz, nullable=True),
        sa.Column("last_error_at", tz, nullable=True),
        sa.Column("last_error", sa.String(200), nullable=True),
    )

    op.create_table(
        "detection_rule_matches",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "rule_id",
            sa.BigInteger(),
            sa.ForeignKey("detection_rules.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column(
            "asset_id",
            sa.BigInteger(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("group_key", sa.String(255), nullable=False),
        sa.Column("signal_id", sa.BigInteger(), nullable=False),
        sa.Column("occurred_at", tz, nullable=False),
        sa.Column("created_at", tz, nullable=False),
        sa.UniqueConstraint("rule_id", "rule_version", "signal_id", name="uq_rule_match_signal"),
    )
    op.create_index(
        "ix_rule_matches_window",
        "detection_rule_matches",
        ["rule_id", "rule_version", "asset_id", "group_key", "occurred_at"],
    )
    op.create_index("ix_rule_matches_created", "detection_rule_matches", ["created_at"])
    op.create_index("ix_rule_matches_asset", "detection_rule_matches", ["asset_id"])

    # Columna con DEFAULT constante: en PostgreSQL 11+ no reescribe la tabla de detecciones.
    op.add_column(
        "detections",
        sa.Column("rule_source", sa.String(16), server_default="builtin", nullable=False),
    )
    op.add_column("detections", sa.Column("rule_category", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("detections", "rule_category")
    op.drop_column("detections", "rule_source")
    op.drop_index("ix_rule_matches_asset", table_name="detection_rule_matches")
    op.drop_index("ix_rule_matches_created", table_name="detection_rule_matches")
    op.drop_index("ix_rule_matches_window", table_name="detection_rule_matches")
    op.drop_table("detection_rule_matches")
    op.drop_table("detection_rule_stats")
    op.drop_table("detection_rule_versions")
    op.drop_index("ix_detection_rules_logsource", table_name="detection_rules")
    op.drop_index("ix_detection_rules_updated", table_name="detection_rules")
    op.drop_index("ix_detection_rules_status", table_name="detection_rules")
    op.drop_table("detection_rules")
    op.execute("DROP SEQUENCE IF EXISTS detection_rule_uid_seq")
