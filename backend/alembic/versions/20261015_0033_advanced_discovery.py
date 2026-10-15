"""Advanced Network Discovery (Fase 6A)

Revision ID: 0033
Revises: 0032
Create Date: 2026-10-15

Cambios (ver app/models/discovery.py y docs/advanced-network-discovery.md):
- discovery_jobs.profile (nulo): perfil quick/standard/deep; null = discovery básico. Los jobs
  existentes quedan como básicos, sin backfill.
- discovery_observations (nueva): evidencia por job y dirección, con procedencia (site,
  ejecutor local o sensor, job), métodos, reachability, puertos, RTT medido, confianza y
  cambios respecto a la observación anterior del mismo activo.
- sensor_observations.rtt_ms y .forward_dns_match (nulas): lo que añade discovery_advanced.

Sin datos destruidos ni reescritos: sites, sensores, activos, jobs e informes se conservan.

DOWNGRADE: elimina discovery_observations y las tres columnas nuevas. Se pierde el historial
de observaciones de 6A y el perfil de los jobs (que pasan a verse como básicos); activos,
cambios, alertas y jobs se conservan.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0033"
down_revision: str | None = "0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("discovery_jobs", sa.Column("profile", sa.String(length=16), nullable=True))
    op.add_column("sensor_observations", sa.Column("rtt_ms", sa.Integer(), nullable=True))
    op.add_column(
        "sensor_observations", sa.Column("forward_dns_match", sa.Boolean(), nullable=True)
    )
    op.create_table(
        "discovery_observations",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column(
            "job_id",
            sa.BigInteger(),
            sa.ForeignKey("discovery_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "site_id",
            sa.BigInteger(),
            sa.ForeignKey("sites.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("executor", sa.String(length=16), nullable=False),
        sa.Column(
            "sensor_id",
            sa.BigInteger(),
            sa.ForeignKey("sensors.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "asset_id",
            sa.BigInteger(),
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("address", sa.String(length=45), nullable=False),
        sa.Column("mac", sa.String(length=17), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("reverse_dns", sa.String(length=255), nullable=True),
        sa.Column("forward_dns_match", sa.Boolean(), nullable=True),
        sa.Column("open_ports", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("methods", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reachability", sa.String(length=16), nullable=False),
        sa.Column("rtt_ms", sa.Integer(), nullable=True),
        sa.Column("confidence", sa.String(length=8), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("changes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("profile", sa.String(length=16), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("job_id", "address", name="uq_discovery_observations_job_address"),
    )
    op.create_index(
        "ix_discovery_observations_site_address",
        "discovery_observations",
        ["site_id", "address", "observed_at"],
    )
    op.create_index(
        "ix_discovery_observations_asset", "discovery_observations", ["asset_id", "observed_at"]
    )
    op.create_index("ix_discovery_observations_sensor", "discovery_observations", ["sensor_id"])
    op.create_index("ix_discovery_observations_observed", "discovery_observations", ["observed_at"])


def downgrade() -> None:
    op.drop_table("discovery_observations")
    op.drop_column("sensor_observations", "forward_dns_match")
    op.drop_column("sensor_observations", "rtt_ms")
    op.drop_column("discovery_jobs", "profile")
