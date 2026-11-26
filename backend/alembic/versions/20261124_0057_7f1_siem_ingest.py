"""Fase 7F.1: motor universal de ingesta SIEM (fuentes, lotes y eventos normalizados)

Revision ID: 0057
Revises: 0056
Create Date: 2026-11-24

Cambios (docs/fase-7f-migrations.md):
- `siem_sources`: catálogo de fuentes externas autorizadas por site (deshabilitadas por
  defecto), con cuota, retención, contadores y salud.
- `siem_batches`: recibo idempotente de cada lote (sensor o importación).
- `siem_events`: eventos normalizados (contrato sentra.siem.event v1) con procedencia,
  deduplicación por (fuente, dedup_key) e índices por site y fecha.

Datos: tablas nuevas y vacías; nada existente cambia.

DOWNGRADE: elimina las tres tablas (se pierden las fuentes registradas y los eventos
importados). No afecta a NDR, detecciones ni incidentes.
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0057"
down_revision: str | None = "0056"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _ts(name: str, nullable: bool = True) -> "sa.Column[Any]":
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "siem_sources",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("sensor_id", sa.BigInteger(), nullable=True),
        sa.Column("source_type", sa.String(length=24), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("transport", sa.String(length=16), nullable=False),
        sa.Column("input_name", sa.String(length=32), nullable=True),
        sa.Column("connector_version", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=True),
        sa.Column("max_events_per_minute", sa.Integer(), nullable=False),
        _ts("quota_window_start"),
        sa.Column("quota_window_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("events_received", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("events_accepted", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("events_rejected", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("events_duplicate", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("events_dropped", sa.BigInteger(), server_default="0", nullable=False),
        _ts("last_success_at"),
        _ts("last_event_at"),
        sa.Column("lag_seconds", sa.Integer(), nullable=True),
        sa.Column("last_batch_rejected", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_batch_records", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_error_code", sa.String(length=48), nullable=True),
        _ts("last_error_at"),
        sa.Column("reported_state", sa.String(length=16), nullable=True),
        _ts("reported_at"),
        sa.Column("reported", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        sa.Column("updated_by", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.id"],
            name=op.f("fk_siem_sources_site_id_sites"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["sensor_id"],
            ["sensors.id"],
            name=op.f("fk_siem_sources_sensor_id_sensors"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_siem_sources")),
        sa.UniqueConstraint("public_id", name=op.f("uq_siem_sources_public_id")),
        sa.UniqueConstraint("site_id", "name", name="uq_siem_sources_site_name"),
    )
    op.create_index(
        "uq_siem_sources_sensor_input",
        "siem_sources",
        ["sensor_id", "input_name"],
        unique=True,
        postgresql_where=sa.text("sensor_id IS NOT NULL"),
    )
    op.create_index("ix_siem_sources_sensor_id", "siem_sources", ["sensor_id"])

    op.create_table(
        "siem_batches",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("batch_id", sa.Uuid(), nullable=False),
        sa.Column("origin", sa.String(length=16), nullable=False),
        _ts("received_at", nullable=False),
        sa.Column("records", sa.Integer(), nullable=False),
        sa.Column("accepted", sa.Integer(), nullable=False),
        sa.Column("duplicates", sa.Integer(), nullable=False),
        sa.Column("rejected", sa.Integer(), nullable=False),
        sa.Column("reject_reasons", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("stats", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("processing_ms", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["siem_sources.id"],
            name=op.f("fk_siem_batches_source_id_siem_sources"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.id"],
            name=op.f("fk_siem_batches_site_id_sites"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_siem_batches")),
        sa.UniqueConstraint("source_id", "batch_id", name="uq_siem_batches_source_batch"),
    )
    op.create_index("ix_siem_batches_site_received", "siem_batches", ["site_id", "received_at"])
    op.create_index("ix_siem_batches_received_at", "siem_batches", ["received_at"])

    op.create_table(
        "siem_events",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("sensor_id", sa.BigInteger(), nullable=True),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.SmallInteger(), nullable=False),
        sa.Column("normalization_version", sa.String(length=32), nullable=False),
        sa.Column("source_type", sa.String(length=24), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("category", sa.String(length=24), nullable=False),
        _ts("observed_at", nullable=False),
        _ts("collected_at"),
        _ts("received_at", nullable=False),
        sa.Column("time_quality", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("source_severity", sa.String(length=32), nullable=True),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("src_ip", sa.String(length=45), nullable=True),
        sa.Column("dst_ip", sa.String(length=45), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=True),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("action", sa.String(length=32), nullable=True),
        sa.Column("outcome", sa.String(length=16), nullable=True),
        sa.Column("signature_id", sa.String(length=64), nullable=True),
        sa.Column("rule_id", sa.String(length=64), nullable=True),
        sa.Column("message", sa.String(length=1000), nullable=True),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("mitre_techniques", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("external_id", sa.String(length=128), nullable=True),
        sa.Column("flow_ref", sa.String(length=64), nullable=True),
        sa.Column("raw_reference", sa.String(length=255), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("raw_excerpt", sa.String(length=8192), nullable=True),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("asset_id", sa.BigInteger(), nullable=True),
        sa.Column("attribution", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["siem_sources.id"],
            name=op.f("fk_siem_events_source_id_siem_sources"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.id"],
            name=op.f("fk_siem_events_site_id_sites"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["sensor_id"],
            ["sensors.id"],
            name=op.f("fk_siem_events_sensor_id_sensors"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_siem_events_asset_id_assets"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_siem_events")),
        sa.UniqueConstraint("event_id", name=op.f("uq_siem_events_event_id")),
        sa.UniqueConstraint("source_id", "dedup_key", name="uq_siem_events_source_dedup"),
    )
    op.create_index("ix_siem_events_site_observed", "siem_events", ["site_id", "observed_at"])
    op.create_index("ix_siem_events_source_observed", "siem_events", ["source_id", "observed_at"])
    op.create_index(
        "ix_siem_events_site_src_ip", "siem_events", ["site_id", "src_ip", "observed_at"]
    )
    op.create_index(
        "ix_siem_events_site_dst_ip", "siem_events", ["site_id", "dst_ip", "observed_at"]
    )
    op.create_index(
        "ix_siem_events_site_type", "siem_events", ["site_id", "event_type", "observed_at"]
    )
    op.create_index(
        "ix_siem_events_asset_observed",
        "siem_events",
        ["asset_id", "observed_at"],
        postgresql_where=sa.text("asset_id IS NOT NULL"),
    )
    op.create_index(
        "ix_siem_events_sensor_id",
        "siem_events",
        ["sensor_id"],
        postgresql_where=sa.text("sensor_id IS NOT NULL"),
    )
    op.create_index("ix_siem_events_received_at", "siem_events", ["received_at"])


def downgrade() -> None:
    op.drop_table("siem_events")
    op.drop_table("siem_batches")
    op.drop_table("siem_sources")
