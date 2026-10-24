"""Investigación forense remota (Fase 6E.6)

Revision ID: 0042
Revises: 0041
Create Date: 2026-10-22

Cambios (ver app/models/forensics.py y docs/forensic-investigation.md):
- investigations: casos de recogida de evidencia por activo.
- forensic_artifacts: evidencia del agente con SHA-256 recalculado por el servidor.
- investigation_notes: interpretaciones, separadas de la evidencia.
- evidence_packages: registro de cada paquete ZIP descargado.
- response_executions.investigation_id: recogida forense de una investigación.

Datos: tablas nuevas y vacías; las ejecuciones existentes quedan con investigation_id NULL.

DOWNGRADE: elimina las cuatro tablas y la columna. Se pierde la evidencia forense guardada
(exportar antes los paquetes que haya que conservar); la auditoría la sigue nombrando.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0042"
down_revision: str | None = "0041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())


def _ts(name: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _investigation_fk() -> sa.Column[object]:
    return sa.Column(
        "investigation_id",
        sa.BigInteger(),
        sa.ForeignKey("investigations.id", ondelete="RESTRICT"),
        nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("asset_id", sa.BigInteger(), sa.ForeignKey("assets.id", ondelete="SET NULL")),
        sa.Column("asset_public_id", sa.Uuid(), nullable=False),
        sa.Column("asset_label", sa.String(255), nullable=False),
        sa.Column(
            "incident_id", sa.BigInteger(), sa.ForeignKey("incidents.id", ondelete="SET NULL")
        ),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("legal_hold", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(64), nullable=False),
        _ts("created_at"),
        _ts("updated_at"),
        _ts("closed_at", nullable=True),
        sa.Column("closed_by", sa.String(64)),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("status IN ('open', 'closed')", name="ck_investigations_status"),
    )
    op.create_index("ix_investigations_asset", "investigations", ["asset_id", "created_at"])
    op.create_index("ix_investigations_incident", "investigations", ["incident_id"])
    op.create_index("ix_investigations_created", "investigations", ["created_at"])

    op.create_table(
        "forensic_artifacts",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _investigation_fk(),
        sa.Column(
            "execution_id",
            sa.BigInteger(),
            sa.ForeignKey("response_executions.id", ondelete="SET NULL"),
        ),
        sa.Column("asset_id", sa.BigInteger(), sa.ForeignKey("assets.id", ondelete="SET NULL")),
        sa.Column("agent_id", sa.Uuid()),
        sa.Column("operator", sa.String(64), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("scope", _JSONB, nullable=False),
        sa.Column("agent_sha256", sa.String(64)),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("integrity", sa.String(16), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("limitations", _JSONB, nullable=False),
        sa.Column("agent_version", sa.String(32)),
        sa.Column("platform", sa.String(16)),
        _ts("collected_at", nullable=True),
        _ts("received_at"),
        sa.CheckConstraint(
            "integrity IN ('verified', 'mismatch')", name="ck_forensic_artifacts_integrity"
        ),
    )
    op.create_index(
        "ix_forensic_artifacts_investigation",
        "forensic_artifacts",
        ["investigation_id", "received_at"],
    )
    op.create_index(
        "ix_forensic_artifacts_execution", "forensic_artifacts", ["execution_id"], unique=True
    )
    op.create_index("ix_forensic_artifacts_asset", "forensic_artifacts", ["asset_id"])

    op.create_table(
        "investigation_notes",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _investigation_fk(),
        sa.Column("kind", sa.String(16), nullable=False, server_default="note"),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("author", sa.String(64), nullable=False),
        _ts("created_at"),
        sa.CheckConstraint("kind IN ('note', 'ai_summary')", name="ck_investigation_notes_kind"),
    )
    op.create_index(
        "ix_investigation_notes_investigation",
        "investigation_notes",
        ["investigation_id", "created_at"],
    )

    op.create_table(
        "evidence_packages",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _investigation_fk(),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("artifact_count", sa.Integer(), nullable=False),
        sa.Column("includes_mismatch", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(64), nullable=False),
        _ts("created_at"),
    )
    op.create_index(
        "ix_evidence_packages_investigation",
        "evidence_packages",
        ["investigation_id", "created_at"],
    )

    op.add_column(
        "response_executions",
        sa.Column(
            "investigation_id",
            sa.BigInteger(),
            sa.ForeignKey("investigations.id", ondelete="SET NULL"),
        ),
    )
    op.create_index(
        "ix_response_executions_investigation",
        "response_executions",
        ["investigation_id"],
        postgresql_where=sa.text("investigation_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_response_executions_investigation", table_name="response_executions")
    op.drop_column("response_executions", "investigation_id")
    op.drop_table("evidence_packages")
    op.drop_table("investigation_notes")
    op.drop_table("forensic_artifacts")
    op.drop_table("investigations")
