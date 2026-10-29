"""Atribución verificable de detecciones (Fase 7B.1)

Revision ID: 0048
Revises: 0047
Create Date: 2026-10-26

Cambios (ver app/models/attribution.py y docs/detection-attribution.md):
- maintenance_operations: operaciones de mantenimiento autorizadas de UN activo, con ventana
  cerrada, caducidad, cuentas, intérprete y padre esperados, aprobación explícita,
  revocación y versiones (supersedes_id). Nunca se borran desde la API.
- maintenance_artifacts: scripts y binarios (SHA-256 obligatorio + ruta canónica) y servicios
  (nombre + ImagePath exacto + cuenta) que autoriza cada versión de una operación.
- detection_attribution_events: historial de solo inserción de veredictos (sistema y
  analista). `confirmed_malicious` solo con source = analyst (restricción CHECK).
- detections: attribution_verdict, attribution (JSONB), attribution_operation_id (FK con
  índice) y attribution_at.

Índices: toda FK lleva índice (test_migrations); además (asset_id, window_start, window_end)
para buscar las operaciones de un activo en una ventana y sha256 de los artefactos.

Datos: tablas nuevas vacías y columnas nulas. No hay backfill: las detecciones existentes
quedan sin veredicto hasta que se evalúan (al recibir evidencia nueva, al aprobar una
operación de su activo o con POST /detections/{id}/attribution/evaluate). Ningún dato
histórico se modifica ni se borra.

DOWNGRADE: elimina las tres tablas y las cuatro columnas (se pierden las operaciones y el
historial de veredictos; la auditoría `maintenance_operation_*` y `detection_attribution_*`
se conserva). Las detecciones resueltas como mantenimiento verificado siguen resueltas, con
su nota.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0048"
down_revision: str | None = "0047"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())
OPERATION_STATUSES = ("pending_review", "approved", "revoked", "superseded")
OPERATION_KINDS = (
    "agent_install",
    "agent_upgrade",
    "sensor_install",
    "database_init",
    "server_setup",
    "software_install",
    "other",
)
ARTIFACT_KINDS = ("script", "binary", "service")
REFERENCE_SOURCES = ("manual", "server_distribution")
VERDICTS = (
    "verified_benign",
    "suspicious_unverified",
    "insufficient_evidence",
    "confirmed_malicious",
)
VERDICT_SOURCES = ("system", "analyst")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _ts(name: str, nullable: bool = True) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "maintenance_operations",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("operation_key", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "supersedes_id",
            sa.BigInteger(),
            sa.ForeignKey("maintenance_operations.id", ondelete="RESTRICT"),
        ),
        sa.Column(
            "asset_id",
            sa.BigInteger(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        _ts("window_start", False),
        _ts("window_end", False),
        _ts("expires_at", False),
        sa.Column("accounts", _JSONB, nullable=False, server_default="[]"),
        sa.Column("interpreters", _JSONB, nullable=False, server_default="[]"),
        sa.Column("parents", _JSONB, nullable=False, server_default="[]"),
        sa.Column("signer", sa.String(255)),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("approved_by", sa.String(64)),
        _ts("approved_at"),
        sa.Column("approval_note", sa.String(500)),
        sa.Column("revoked_by", sa.String(64)),
        _ts("revoked_at"),
        sa.Column("revoke_reason", sa.String(500)),
        sa.Column("matches", sa.Integer(), nullable=False, server_default="0"),
        _ts("last_match_at"),
        sa.CheckConstraint(
            _in("status", OPERATION_STATUSES), name="ck_maintenance_operations_status"
        ),
        sa.CheckConstraint(_in("kind", OPERATION_KINDS), name="ck_maintenance_operations_kind"),
        sa.CheckConstraint("window_end > window_start", name="ck_maintenance_operations_window"),
        sa.CheckConstraint("expires_at >= window_end", name="ck_maintenance_operations_expiry"),
    )
    op.create_index(
        "ix_maintenance_operations_asset_window",
        "maintenance_operations",
        ["asset_id", "window_start", "window_end"],
    )
    op.create_index(
        "ix_maintenance_operations_supersedes", "maintenance_operations", ["supersedes_id"]
    )

    op.create_table(
        "maintenance_artifacts",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "operation_id",
            sa.BigInteger(),
            sa.ForeignKey("maintenance_operations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("path", sa.String(1024)),
        sa.Column("sha256", sa.String(64)),
        sa.Column("signer", sa.String(255)),
        sa.Column("reference_source", sa.String(24), nullable=False, server_default="manual"),
        sa.Column("service_name", sa.String(255)),
        sa.Column("service_display_name", sa.String(255)),
        sa.Column("image_path", sa.String(1024)),
        sa.Column("service_account", sa.String(255)),
        sa.CheckConstraint(_in("kind", ARTIFACT_KINDS), name="ck_maintenance_artifacts_kind"),
        sa.CheckConstraint(
            _in("reference_source", REFERENCE_SOURCES), name="ck_maintenance_artifacts_source"
        ),
        sa.CheckConstraint(
            "sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'", name="ck_maintenance_artifacts_sha256"
        ),
        sa.CheckConstraint(
            "kind = 'service' OR sha256 IS NOT NULL", name="ck_maintenance_artifacts_hash"
        ),
        sa.CheckConstraint(
            "kind <> 'service' OR (service_name IS NOT NULL AND image_path IS NOT NULL)",
            name="ck_maintenance_artifacts_service",
        ),
    )
    op.create_index("ix_maintenance_artifacts_operation", "maintenance_artifacts", ["operation_id"])
    op.create_index("ix_maintenance_artifacts_sha256", "maintenance_artifacts", ["sha256"])

    op.create_table(
        "detection_attribution_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column(
            "detection_id",
            sa.BigInteger(),
            sa.ForeignKey("detections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("verdict", sa.String(32), nullable=False),
        sa.Column("previous_verdict", sa.String(32)),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column(
            "operation_id",
            sa.BigInteger(),
            sa.ForeignKey("maintenance_operations.id", ondelete="SET NULL"),
        ),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(1000)),
        sa.Column("evidence", _JSONB),
        _ts("created_at", False),
        sa.CheckConstraint(
            _in("verdict", VERDICTS), name="ck_detection_attribution_events_verdict"
        ),
        sa.CheckConstraint(
            _in("source", VERDICT_SOURCES), name="ck_detection_attribution_events_source"
        ),
        sa.CheckConstraint(
            "verdict <> 'confirmed_malicious' OR source = 'analyst'",
            name="ck_detection_attribution_events_malicious",
        ),
    )
    op.create_index(
        "ix_detection_attribution_events_detection",
        "detection_attribution_events",
        ["detection_id", "created_at"],
    )
    op.create_index(
        "ix_detection_attribution_events_operation",
        "detection_attribution_events",
        ["operation_id"],
    )

    op.add_column("detections", sa.Column("attribution_verdict", sa.String(32)))
    op.add_column("detections", sa.Column("attribution", _JSONB))
    op.add_column(
        "detections",
        sa.Column(
            "attribution_operation_id",
            sa.BigInteger(),
            sa.ForeignKey("maintenance_operations.id", ondelete="SET NULL"),
        ),
    )
    op.add_column("detections", _ts("attribution_at"))
    op.create_index(
        "ix_detections_attribution_operation",
        "detections",
        ["attribution_operation_id"],
        postgresql_where=sa.text("attribution_operation_id IS NOT NULL"),
    )
    op.create_index("ix_detections_attribution_verdict", "detections", ["attribution_verdict"])


def downgrade() -> None:
    op.drop_index("ix_detections_attribution_verdict", table_name="detections")
    op.drop_index("ix_detections_attribution_operation", table_name="detections")
    op.drop_column("detections", "attribution_at")
    op.drop_column("detections", "attribution_operation_id")
    op.drop_column("detections", "attribution")
    op.drop_column("detections", "attribution_verdict")
    op.drop_table("detection_attribution_events")
    op.drop_table("maintenance_artifacts")
    op.drop_table("maintenance_operations")
