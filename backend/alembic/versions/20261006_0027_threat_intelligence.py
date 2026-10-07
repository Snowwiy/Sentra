"""Threat Intelligence & Exploitability Context (Fase 5C)

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-06

Añade:
- threat_intel_sources: fuentes de inteligencia (procedencia, confianza, estado, caducidad).
  Se crean DESACTIVADAS las fuentes oficiales CISA KEV y FIRST EPSS: Sentra no descarga nada
  hasta que un admin las active y el servidor permita la sincronización por red;
- threat_intel_syncs: historial técnico de sincronizaciones e importaciones;
- vulnerability_intel: KEV/EPSS por (fuente, tipo, CVE);
- threat_indicators: IOCs normalizados (índices de valor, tipo, fuente y GiST para CIDR);
- threat_intel_matches: coincidencias exactas con datos locales de un activo;
- threat_intel_changes: historial acotado de cambios materiales;
- threat_intel_cursors: posición del matching incremental;
- incident_threat_matches: matches vinculados a incidentes (snapshot mínimo);
- incident_vulnerabilities.intel_snapshot / resolved_intel_snapshot;
- vulnerability_findings.intel_cve (+ relleno con los findings cuyo id ya es un CVE);
- índice parcial de expresión sobre system_events (data->>'IpAddress').

No modifica ni reescribe activos, inventario, eventos, detecciones, reglas, riesgo,
incidentes, findings (salvo la columna nueva), IA, sesiones ni rate limits. Las tablas
nuevas entran en los backups de PostgreSQL de la Fase 4M (pg_dump de toda la base).

DOWNGRADE: borra las tablas y columnas nuevas y el índice de system_events. Se PIERDEN las
fuentes de inteligencia y su configuración, la inteligencia KEV/EPSS descargada, los IOCs
importados, los matches (y su estado de triage), el historial de sincronizaciones y de
cambios, los vínculos incidente-match y los snapshots de inteligencia de los incidentes.
Activos, findings, detecciones (incluidas las TI-001 ya creadas), riesgo, incidentes y
sesiones se conservan. No ejecutar el downgrade en una base real sin backup (Fase 4M): los
feeds se pueden volver a descargar, pero matches e historial no.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    tz = sa.DateTime(timezone=True)
    jsonb = postgresql.JSONB(astext_type=sa.Text())

    op.create_table(
        "threat_intel_sources",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("source_key", sa.String(64), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.String(500), nullable=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("category", sa.String(16), nullable=False),
        sa.Column("trust", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("network_required", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("sync_interval_hours", sa.Integer(), nullable=True),
        sa.Column("stale_after_hours", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(16), server_default="never", nullable=False),
        sa.Column("last_attempt_at", tz, nullable=True),
        sa.Column("last_success_at", tz, nullable=True),
        sa.Column("last_error", sa.String(64), nullable=True),
        sa.Column("last_error_message", sa.String(300), nullable=True),
        sa.Column("record_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("etag", sa.String(256), nullable=True),
        sa.Column("last_modified", sa.String(64), nullable=True),
        sa.Column("content_sha256", sa.String(64), nullable=True),
        sa.Column("next_sync_at", tz, nullable=True),
        sa.Column("sync_requested_at", tz, nullable=True),
        sa.Column("sync_requested_by", sa.String(64), nullable=True),
        sa.Column("config", jsonb, server_default="{}", nullable=False),
        sa.Column("revision", sa.Integer(), server_default="0", nullable=False),
        sa.Column("archived_at", tz, nullable=True),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", tz, nullable=False),
        sa.Column("updated_at", tz, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_intel_sources")),
        sa.UniqueConstraint("source_key", name=op.f("uq_threat_intel_sources_source_key")),
    )

    op.create_table(
        "threat_intel_syncs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("started_at", tz, nullable=False),
        sa.Column("finished_at", tz, nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("records_seen", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_new", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_updated", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_unchanged", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_removed", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_invalid", sa.Integer(), server_default="0", nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(300), nullable=True),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["threat_intel_sources.id"],
            name=op.f("fk_threat_intel_syncs_source_id_threat_intel_sources"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_intel_syncs")),
    )
    op.create_index(
        "ix_threat_intel_syncs_source", "threat_intel_syncs", ["source_id", "started_at"]
    )

    op.create_table(
        "vulnerability_intel",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("data", jsonb, nullable=False),
        sa.Column("external_id", sa.String(64), nullable=True),
        sa.Column("source_url", sa.String(500), nullable=True),
        sa.Column("published_at", tz, nullable=True),
        sa.Column("modified_at", tz, nullable=True),
        sa.Column("retrieved_at", tz, nullable=False),
        sa.Column("first_seen_at", tz, nullable=False),
        sa.Column("last_changed_at", tz, nullable=False),
        sa.Column("removed_at", tz, nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("record_version", sa.Integer(), server_default="1", nullable=False),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["threat_intel_sources.id"],
            name=op.f("fk_vulnerability_intel_source_id_threat_intel_sources"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vulnerability_intel")),
        sa.UniqueConstraint("source_id", "kind", "cve_id", name="uq_vulnerability_intel_record"),
    )
    op.create_index("ix_vulnerability_intel_cve", "vulnerability_intel", ["cve_id"])
    op.create_index(
        "ix_vulnerability_intel_epss",
        "vulnerability_intel",
        ["epss_score"],
        postgresql_where=sa.text("kind = 'epss' AND active"),
    )

    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("indicator_type", sa.String(16), nullable=False),
        sa.Column("value_normalized", sa.String(1024), nullable=False),
        sa.Column("value_original", sa.String(2048), nullable=False),
        sa.Column("network", postgresql.CIDR(), nullable=True),
        sa.Column("classification", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("confidence_score", sa.SmallInteger(), nullable=True),
        sa.Column("valid_from", tz, nullable=True),
        sa.Column("valid_until", tz, nullable=True),
        sa.Column("revoked", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("revoked_at", tz, nullable=True),
        sa.Column("first_seen_external", tz, nullable=True),
        sa.Column("last_seen_external", tz, nullable=True),
        sa.Column("tags", jsonb, server_default="[]", nullable=False),
        sa.Column("description", sa.String(1000), nullable=True),
        sa.Column("references", jsonb, server_default="[]", nullable=False),
        sa.Column("related", jsonb, server_default="[]", nullable=False),
        sa.Column("external_id", sa.String(128), nullable=True),
        sa.Column("pattern", sa.String(1024), nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("pending_match", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("match_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_matched_at", tz, nullable=True),
        sa.Column("retrieved_at", tz, nullable=False),
        sa.Column("created_at", tz, nullable=False),
        sa.Column("updated_at", tz, nullable=False),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["threat_intel_sources.id"],
            name=op.f("fk_threat_indicators_source_id_threat_intel_sources"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_indicators")),
        sa.UniqueConstraint("public_id", name=op.f("uq_threat_indicators_public_id")),
        sa.UniqueConstraint(
            "source_id", "indicator_type", "value_normalized", name="uq_threat_indicator"
        ),
    )
    op.create_index(
        "ix_threat_indicators_value",
        "threat_indicators",
        ["value_normalized"],
        postgresql_ops={"value_normalized": "text_pattern_ops"},
    )
    op.create_index("ix_threat_indicators_type", "threat_indicators", ["indicator_type", "id"])
    op.create_index("ix_threat_indicators_source", "threat_indicators", ["source_id", "id"])
    op.create_index(
        "ix_threat_indicators_network",
        "threat_indicators",
        ["network"],
        postgresql_using="gist",
        postgresql_ops={"network": "inet_ops"},
        postgresql_where=sa.text("network IS NOT NULL"),
    )
    op.create_index(
        "ix_threat_indicators_pending",
        "threat_indicators",
        ["id"],
        postgresql_where=sa.text("pending_match"),
    )
    op.create_index(
        "ix_threat_indicators_tags", "threat_indicators", ["tags"], postgresql_using="gin"
    )

    op.create_table(
        "threat_intel_matches",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("indicator_id", sa.BigInteger(), nullable=False),
        sa.Column("asset_id", sa.BigInteger(), nullable=False),
        sa.Column("observation_type", sa.String(24), nullable=False),
        sa.Column("observed_value", sa.String(1024), nullable=False),
        sa.Column("observed_field", sa.String(64), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=True),
        sa.Column("event_public_id", sa.Uuid(), nullable=True),
        sa.Column("detection_id", sa.BigInteger(), nullable=True),
        sa.Column("first_observed_at", tz, nullable=False),
        sa.Column("last_observed_at", tz, nullable=False),
        sa.Column("observation_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("classification", sa.String(16), nullable=False),
        sa.Column("indicator_confidence", sa.String(8), nullable=False),
        sa.Column("source_trust", sa.String(16), nullable=False),
        sa.Column("match_confidence", sa.String(8), nullable=False),
        sa.Column("status", sa.String(16), server_default="open", nullable=False),
        sa.Column("status_reason", sa.String(1000), nullable=True),
        sa.Column("status_changed_at", tz, nullable=False),
        sa.Column("status_changed_by", sa.String(64), nullable=False),
        sa.Column("signal_emitted_at", tz, nullable=True),
        sa.Column("evidence", jsonb, nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("matched_at", tz, nullable=False),
        sa.Column("updated_at", tz, nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["threat_indicators.id"],
            name=op.f("fk_threat_intel_matches_indicator_id_threat_indicators"),
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_threat_intel_matches_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["system_events.id"],
            name=op.f("fk_threat_intel_matches_event_id_system_events"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["detection_id"],
            ["detections.id"],
            name=op.f("fk_threat_intel_matches_detection_id_detections"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_intel_matches")),
        sa.UniqueConstraint("public_id", name=op.f("uq_threat_intel_matches_public_id")),
        sa.UniqueConstraint(
            "indicator_id",
            "asset_id",
            "observation_type",
            "observed_value",
            name="uq_threat_intel_match",
        ),
    )
    op.create_index(
        "ix_threat_intel_matches_asset", "threat_intel_matches", ["asset_id", "last_observed_at"]
    )
    op.create_index(
        "ix_threat_intel_matches_status", "threat_intel_matches", ["status", "last_observed_at"]
    )
    op.create_index(
        "ix_threat_intel_matches_last_observed",
        "threat_intel_matches",
        ["last_observed_at", "id"],
    )
    op.create_index(
        "ix_threat_intel_matches_detection",
        "threat_intel_matches",
        ["detection_id"],
        postgresql_where=sa.text("detection_id IS NOT NULL"),
    )
    op.create_index(
        "ix_threat_intel_matches_event",
        "threat_intel_matches",
        ["event_id"],
        postgresql_where=sa.text("event_id IS NOT NULL"),
    )

    op.create_table(
        "threat_intel_changes",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("sync_id", sa.BigInteger(), nullable=True),
        sa.Column("occurred_at", tz, nullable=False),
        sa.Column("record_kind", sa.String(16), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=True),
        sa.Column("indicator_id", sa.BigInteger(), nullable=True),
        sa.Column("change", sa.String(32), nullable=False),
        sa.Column("details", jsonb, nullable=True),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["threat_intel_sources.id"],
            name=op.f("fk_threat_intel_changes_source_id_threat_intel_sources"),
        ),
        sa.ForeignKeyConstraint(
            ["sync_id"],
            ["threat_intel_syncs.id"],
            name=op.f("fk_threat_intel_changes_sync_id_threat_intel_syncs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["threat_indicators.id"],
            name=op.f("fk_threat_intel_changes_indicator_id_threat_indicators"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_intel_changes")),
    )
    op.create_index(
        "ix_threat_intel_changes_occurred", "threat_intel_changes", ["occurred_at", "id"]
    )
    op.create_index(
        "ix_threat_intel_changes_source", "threat_intel_changes", ["source_id", "occurred_at"]
    )
    op.create_index(
        "ix_threat_intel_changes_sync",
        "threat_intel_changes",
        ["sync_id"],
        postgresql_where=sa.text("sync_id IS NOT NULL"),
    )
    op.create_index(
        "ix_threat_intel_changes_cve",
        "threat_intel_changes",
        ["cve_id", "occurred_at"],
        postgresql_where=sa.text("cve_id IS NOT NULL"),
    )
    op.create_index(
        "ix_threat_intel_changes_indicator",
        "threat_intel_changes",
        ["indicator_id"],
        postgresql_where=sa.text("indicator_id IS NOT NULL"),
    )

    op.create_table(
        "threat_intel_cursors",
        sa.Column("name", sa.String(32), nullable=False),
        sa.Column("position", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("position_at", tz, nullable=True),
        sa.Column("updated_at", tz, nullable=False),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_threat_intel_cursors")),
    )

    op.create_table(
        "incident_threat_matches",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("match_id", sa.BigInteger(), nullable=True),
        sa.Column("match_public_id", sa.Uuid(), nullable=False),
        sa.Column("indicator_type", sa.String(16), nullable=False),
        sa.Column("indicator_value", sa.String(1024), nullable=False),
        sa.Column("classification", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("source_name", sa.String(200), nullable=False),
        sa.Column("source_trust", sa.String(16), nullable=False),
        sa.Column("observation_type", sa.String(24), nullable=False),
        sa.Column("observed_value", sa.String(1024), nullable=False),
        sa.Column("asset_name", sa.String(255), nullable=False),
        sa.Column("intel_snapshot", jsonb, nullable=True),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("attached_at", tz, nullable=False),
        sa.Column("attached_by_user_id", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_threat_matches_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["match_id"],
            ["threat_intel_matches.id"],
            name=op.f("fk_incident_threat_matches_match_id_threat_intel_matches"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["attached_by_user_id"],
            ["users.id"],
            name=op.f("fk_incident_threat_matches_attached_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_threat_matches")),
    )
    op.create_index(
        "uq_incident_threat_matches_match",
        "incident_threat_matches",
        ["incident_id", "match_id"],
        unique=True,
        postgresql_where=sa.text("match_id IS NOT NULL"),
    )
    op.create_index(
        "ix_incident_threat_matches_match",
        "incident_threat_matches",
        ["match_id"],
        postgresql_where=sa.text("match_id IS NOT NULL"),
    )
    op.create_index(
        "ix_incident_threat_matches_attached_by",
        "incident_threat_matches",
        ["attached_by_user_id"],
        postgresql_where=sa.text("attached_by_user_id IS NOT NULL"),
    )

    op.add_column("incident_vulnerabilities", sa.Column("intel_snapshot", jsonb, nullable=True))
    op.add_column(
        "incident_vulnerabilities", sa.Column("resolved_intel_snapshot", jsonb, nullable=True)
    )

    op.add_column("vulnerability_findings", sa.Column("intel_cve", sa.String(32), nullable=True))
    # Relleno inmediato de los findings cuyo identificador ya es un CVE. Los que solo tienen
    # el CVE como alias (GHSA, avisos) se completan en su siguiente evaluación (5B la hace
    # al menos cada VULN_FULL_REFRESH_HOURS).
    op.execute(
        "UPDATE vulnerability_findings SET intel_cve = upper(vuln_external_id) "
        "WHERE vuln_external_id ~* '^CVE-[0-9]{4}-[0-9]{4,}$'"
    )
    op.create_index(
        "ix_vulnerability_findings_intel_cve",
        "vulnerability_findings",
        ["intel_cve"],
        postgresql_where=sa.text("intel_cve IS NOT NULL"),
    )

    op.create_index(
        "ix_system_events_ip_address",
        "system_events",
        [sa.text("(data ->> 'IpAddress')")],
        postgresql_where=sa.text("data ? 'IpAddress'"),
    )

    # Fuentes oficiales predefinidas, DESACTIVADAS: activarlas es una decisión del admin (y
    # descargar exige además THREAT_INTEL_SYNC_ENABLED en el servidor). Fuente local para
    # importaciones manuales de IOCs/STIX, siempre disponible y sin red.
    op.execute(
        """
        INSERT INTO threat_intel_sources
            (source_key, name, description, provider, category, trust, enabled,
             network_required, sync_interval_hours, stale_after_hours, status, config,
             created_by, created_at, updated_at)
        VALUES
            ('cisa-kev', 'CISA Known Exploited Vulnerabilities',
             'Catálogo oficial de CISA de vulnerabilidades con explotación conocida.',
             'cisa_kev', 'exploitation', 'official', false, true, 24, 120, 'never', '{}',
             'sentra', now(), now()),
            ('first-epss', 'FIRST EPSS',
             'Exploit Prediction Scoring System: probabilidad de explotación en 30 días.',
             'first_epss', 'exploitation', 'official', false, true, 24, 120, 'never', '{}',
             'sentra', now(), now()),
            ('local-iocs', 'Indicadores locales',
             'Indicadores importados a mano por un administrador (JSON o STIX 2.x).',
             'local_import', 'ioc', 'local', true, false, NULL, NULL, 'never', '{}',
             'sentra', now(), now())
        """
    )


def downgrade() -> None:
    op.drop_index("ix_system_events_ip_address", table_name="system_events")
    op.drop_index("ix_vulnerability_findings_intel_cve", table_name="vulnerability_findings")
    op.drop_column("vulnerability_findings", "intel_cve")
    op.drop_column("incident_vulnerabilities", "resolved_intel_snapshot")
    op.drop_column("incident_vulnerabilities", "intel_snapshot")
    op.drop_index("ix_incident_threat_matches_attached_by", table_name="incident_threat_matches")
    op.drop_index("ix_incident_threat_matches_match", table_name="incident_threat_matches")
    op.drop_index("uq_incident_threat_matches_match", table_name="incident_threat_matches")
    op.drop_table("incident_threat_matches")
    op.drop_table("threat_intel_cursors")
    op.drop_index("ix_threat_intel_changes_indicator", table_name="threat_intel_changes")
    op.drop_index("ix_threat_intel_changes_cve", table_name="threat_intel_changes")
    op.drop_index("ix_threat_intel_changes_occurred", table_name="threat_intel_changes")
    op.drop_index("ix_threat_intel_changes_sync", table_name="threat_intel_changes")
    op.drop_index("ix_threat_intel_changes_source", table_name="threat_intel_changes")
    op.drop_table("threat_intel_changes")
    for name in (
        "ix_threat_intel_matches_event",
        "ix_threat_intel_matches_detection",
        "ix_threat_intel_matches_last_observed",
        "ix_threat_intel_matches_status",
        "ix_threat_intel_matches_asset",
    ):
        op.drop_index(name, table_name="threat_intel_matches")
    op.drop_table("threat_intel_matches")
    for name in (
        "ix_threat_indicators_tags",
        "ix_threat_indicators_pending",
        "ix_threat_indicators_network",
        "ix_threat_indicators_source",
        "ix_threat_indicators_type",
        "ix_threat_indicators_value",
    ):
        op.drop_index(name, table_name="threat_indicators")
    op.drop_table("threat_indicators")
    op.drop_index("ix_vulnerability_intel_epss", table_name="vulnerability_intel")
    op.drop_index("ix_vulnerability_intel_cve", table_name="vulnerability_intel")
    op.drop_table("vulnerability_intel")
    op.drop_index("ix_threat_intel_syncs_source", table_name="threat_intel_syncs")
    op.drop_table("threat_intel_syncs")
    op.drop_table("threat_intel_sources")
