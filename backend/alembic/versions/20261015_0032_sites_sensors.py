"""Multi-site y sensores distribuidos (Fase 5F)

Revision ID: 0032
Revises: 0031
Create Date: 2026-10-15

Tablas nuevas (ver app/models/site.py, docs/sites.md y docs/distributed-sensors.md):
- sites, site_networks: sites monitorizados y sus redes autorizadas;
- sensors, sensor_enrollment_tokens: sensores con credencial propia (solo SHA-256) y tokens de
  enrolamiento de un solo uso;
- sensor_jobs, sensor_job_batches, sensor_observations: tareas de catálogo cerrado con lease e
  idempotencia, lotes de resultados y observaciones validadas.

Datos existentes (ninguno se reconstruye ni cambia de id):
1. Se crea el site por defecto "Local" (slug local, is_default) y la función
   sentra_default_site_id(), que devuelve su id.
2. assets.site_id y discovery_jobs.site_id se añaden nulos, se rellenan con el site local
   (backfill) y SOLO después pasan a NOT NULL con la función como valor por defecto: el código
   anterior a 5F (agentes, discovery local, CLI) sigue creando filas en el site local.
3. agent_enrollment_tokens.site_id es opcional (null = site por defecto).
4. El índice único de "una ejecución activa por red" de discovery pasa a ser por (site, red).
Detecciones, incidentes, riesgo, vulnerabilidades, informes y Response no se tocan: heredan
el site de su activo por relación (sin duplicar el dato).

DOWNGRADE: elimina las tablas, las columnas y la función, y restaura el índice único por red.
Se pierden sites, sensores, jobs de sensor y observaciones; los activos se conservan todos
(también los de otros sites, que vuelven a convivir sin dimensión de site). Los jobs de
discovery activos ejecutados por sensores se cierran como cancelados antes de restaurar el
índice (dos sites podían escanear la misma red a la vez).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OPEN_JOBS = "status IN ('pending', 'leased', 'running')"
ACTIVE_DISCOVERY = "status IN ('queued', 'running')"
DEFAULT_SITE = sa.text("sentra_default_site_id()")


def _timestamps() -> list[sa.Column]:  # type: ignore[type-arg]
    return [
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "sites",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column("description", sa.String(500), nullable=True),
        sa.Column("location_label", sa.String(200), nullable=True),
        sa.Column("timezone", sa.String(64), nullable=False, server_default="UTC"),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_by", sa.String(64), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("archive_reason", sa.String(500), nullable=True),
        *_timestamps(),
    )
    op.create_index(
        "uq_sites_default",
        "sites",
        ["is_default"],
        unique=True,
        postgresql_where=sa.text("is_default"),
    )
    # Site por defecto: todos los datos históricos son de esta instalación local.
    op.execute(
        "INSERT INTO sites (public_id, name, slug, description, timezone, status, is_default,"
        " version, created_by) VALUES (gen_random_uuid(), 'Local', 'local',"
        " 'Site por defecto: datos anteriores a la Fase 5F y discovery del propio servidor',"
        " 'UTC', 'active', true, 1, 'migration')"
    )
    # STABLE: el planner puede evaluarla una vez por sentencia (INSERT masivos). Si alguien
    # borrara el site por defecto devolvería NULL y el NOT NULL lo rechazaría (fail closed).
    op.execute(
        "CREATE FUNCTION sentra_default_site_id() RETURNS bigint LANGUAGE sql STABLE AS"
        " $$ SELECT id FROM sites WHERE is_default ORDER BY id LIMIT 1 $$"
    )

    op.create_table(
        "site_networks",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column(
            "site_id",
            sa.BigInteger(),
            sa.ForeignKey("sites.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("cidr", sa.String(64), nullable=False),
        sa.Column("name", sa.String(100), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_by", sa.String(64), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint("site_id", "cidr", name="uq_site_networks_site_cidr"),
    )

    op.create_table(
        "sensors",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column(
            "site_id",
            sa.BigInteger(),
            sa.ForeignKey("sites.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("credential_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("credential_issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pending_credential_hash", sa.String(64), nullable=True, unique=True),
        sa.Column("rotation_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("platform", sa.String(32), nullable=True),
        sa.Column("sensor_version", sa.String(32), nullable=True),
        sa.Column("capabilities", postgresql.JSONB(), nullable=True),
        sa.Column("health", postgresql.JSONB(), nullable=True),
        sa.Column("clock_skew_seconds", sa.Integer(), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(64), nullable=True),
        sa.Column("revoke_reason", sa.String(500), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        *_timestamps(),
    )
    op.create_index("ix_sensors_site", "sensors", ["site_id"])

    op.create_table(
        "sensor_enrollment_tokens",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column(
            "site_id",
            sa.BigInteger(),
            sa.ForeignKey("sites.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("sensor_name", sa.String(100), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "sensor_id",
            sa.BigInteger(),
            sa.ForeignKey("sensors.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_sensor_enrollment_tokens_site", "sensor_enrollment_tokens", ["site_id", "created_at"]
    )
    op.create_index("ix_sensor_enrollment_tokens_sensor", "sensor_enrollment_tokens", ["sensor_id"])

    # --- columnas de site en tablas existentes: nulas, backfill, NOT NULL ------------------
    op.add_column("assets", sa.Column("site_id", sa.BigInteger(), nullable=True))
    op.execute("UPDATE assets SET site_id = sentra_default_site_id()")
    op.alter_column("assets", "site_id", nullable=False, server_default=DEFAULT_SITE)
    op.create_foreign_key(
        "assets_site_id_fkey", "assets", "sites", ["site_id"], ["id"], ondelete="RESTRICT"
    )
    op.create_index("ix_assets_site_ip", "assets", ["site_id", "primary_ip"])

    op.add_column("discovery_jobs", sa.Column("site_id", sa.BigInteger(), nullable=True))
    op.execute("UPDATE discovery_jobs SET site_id = sentra_default_site_id()")
    op.alter_column("discovery_jobs", "site_id", nullable=False, server_default=DEFAULT_SITE)
    op.create_foreign_key(
        "discovery_jobs_site_id_fkey",
        "discovery_jobs",
        "sites",
        ["site_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.add_column(
        "discovery_jobs",
        sa.Column("execution_target", sa.String(16), nullable=False, server_default="local"),
    )
    op.add_column("discovery_jobs", sa.Column("sensor_id", sa.BigInteger(), nullable=True))
    op.create_foreign_key(
        "discovery_jobs_sensor_id_fkey",
        "discovery_jobs",
        "sensors",
        ["sensor_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.drop_index("uq_discovery_jobs_running_target", table_name="discovery_jobs")
    op.create_index(
        "uq_discovery_jobs_running_target",
        "discovery_jobs",
        ["site_id", "target"],
        unique=True,
        postgresql_where=sa.text(ACTIVE_DISCOVERY),
    )
    op.create_index("ix_discovery_jobs_site_started", "discovery_jobs", ["site_id", "started_at"])
    op.create_index("ix_discovery_jobs_sensor", "discovery_jobs", ["sensor_id"])

    op.add_column("agent_enrollment_tokens", sa.Column("site_id", sa.BigInteger(), nullable=True))
    op.create_foreign_key(
        "agent_enrollment_tokens_site_id_fkey",
        "agent_enrollment_tokens",
        "sites",
        ["site_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_agent_enrollment_tokens_site_id", "agent_enrollment_tokens", ["site_id"])

    # --- jobs de sensor, lotes y observaciones ----------------------------------------------
    op.create_table(
        "sensor_jobs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column(
            "site_id",
            sa.BigInteger(),
            sa.ForeignKey("sites.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "sensor_id",
            sa.BigInteger(),
            sa.ForeignKey("sensors.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("job_type", sa.String(32), nullable=False),
        sa.Column("parameters", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("leased_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.SmallInteger(), nullable=False, server_default="2"),
        sa.Column("idempotency_key", sa.String(64), nullable=True),
        sa.Column(
            "discovery_job_id",
            sa.BigInteger(),
            sa.ForeignKey("discovery_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(300), nullable=True),
        sa.Column("result_summary", postgresql.JSONB(), nullable=True),
        sa.Column("observations_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("batches_received", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index(
        "ix_sensor_jobs_open",
        "sensor_jobs",
        ["sensor_id", "status", "created_at"],
        postgresql_where=sa.text(OPEN_JOBS),
    )
    op.create_index("ix_sensor_jobs_sensor_created", "sensor_jobs", ["sensor_id", "created_at"])
    op.create_index("ix_sensor_jobs_site", "sensor_jobs", ["site_id"])
    op.create_index("ix_sensor_jobs_discovery", "sensor_jobs", ["discovery_job_id"])
    op.create_index(
        "uq_sensor_jobs_idempotency",
        "sensor_jobs",
        ["sensor_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )

    op.create_table(
        "sensor_job_batches",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "job_id",
            sa.BigInteger(),
            sa.ForeignKey("sensor_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("batch_id", sa.Uuid(), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("attempt", sa.SmallInteger(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("job_id", "batch_id", name="uq_sensor_job_batches"),
    )

    op.create_table(
        "sensor_observations",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "job_id",
            sa.BigInteger(),
            sa.ForeignKey("sensor_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "site_id",
            sa.BigInteger(),
            sa.ForeignKey("sites.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "sensor_id",
            sa.BigInteger(),
            sa.ForeignKey("sensors.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("address", sa.String(45), nullable=False),
        sa.Column("mac", sa.String(17), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("reverse_dns", sa.String(255), nullable=True),
        sa.Column("ports", postgresql.JSONB(), nullable=False),
        sa.Column("sources", postgresql.JSONB(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("job_id", "address", name="uq_sensor_observations_job_address"),
    )
    op.create_index("ix_sensor_observations_site", "sensor_observations", ["site_id", "address"])
    op.create_index(
        "ix_sensor_observations_sensor", "sensor_observations", ["sensor_id", "received_at"]
    )


def downgrade() -> None:
    op.drop_table("sensor_observations")
    op.drop_table("sensor_job_batches")
    op.drop_table("sensor_jobs")

    op.drop_index("ix_agent_enrollment_tokens_site_id", table_name="agent_enrollment_tokens")
    op.drop_constraint(
        "agent_enrollment_tokens_site_id_fkey", "agent_enrollment_tokens", type_="foreignkey"
    )
    op.drop_column("agent_enrollment_tokens", "site_id")

    # Antes de volver al índice "una ejecución activa por red" (sin site): dos sites podían
    # tener la misma red en curso. Los jobs de sensor activos no pueden seguir sin sensores.
    op.execute(
        "UPDATE discovery_jobs SET status = 'cancelled', completed_at = now(),"
        " stop_reason = 'shutdown' WHERE execution_target = 'sensor'"
        " AND status IN ('queued', 'running')"
    )
    op.drop_index("ix_discovery_jobs_sensor", table_name="discovery_jobs")
    op.drop_index("ix_discovery_jobs_site_started", table_name="discovery_jobs")
    op.drop_index("uq_discovery_jobs_running_target", table_name="discovery_jobs")
    op.create_index(
        "uq_discovery_jobs_running_target",
        "discovery_jobs",
        ["target"],
        unique=True,
        postgresql_where=sa.text(ACTIVE_DISCOVERY),
    )
    op.drop_constraint("discovery_jobs_sensor_id_fkey", "discovery_jobs", type_="foreignkey")
    op.drop_column("discovery_jobs", "sensor_id")
    op.drop_column("discovery_jobs", "execution_target")
    op.drop_constraint("discovery_jobs_site_id_fkey", "discovery_jobs", type_="foreignkey")
    op.drop_column("discovery_jobs", "site_id")

    op.drop_index("ix_assets_site_ip", table_name="assets")
    op.drop_constraint("assets_site_id_fkey", "assets", type_="foreignkey")
    op.drop_column("assets", "site_id")

    op.drop_index("ix_sensor_enrollment_tokens_sensor", table_name="sensor_enrollment_tokens")
    op.drop_index("ix_sensor_enrollment_tokens_site", table_name="sensor_enrollment_tokens")
    op.drop_table("sensor_enrollment_tokens")
    op.drop_index("ix_sensors_site", table_name="sensors")
    op.drop_table("sensors")
    op.drop_table("site_networks")
    op.execute("DROP FUNCTION sentra_default_site_id()")
    op.drop_index("uq_sites_default", table_name="sites")
    op.drop_table("sites")
