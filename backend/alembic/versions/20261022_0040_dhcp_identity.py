"""Fuentes DHCP, leases e historial de identidad (Fase 6E.2)

Revision ID: 0040
Revises: 0039
Create Date: 2026-10-22

Cambios (ver app/models/dhcp.py y docs/dhcp-identity.md):
- dhcp_sources: fuentes de leases autorizadas por site (fichero importado por un admin o
  fichero local de un sensor, referenciado por nombre; el servidor nunca guarda rutas).
- dhcp_leases: leases normalizados con su asociación a un activo y el motivo (`match`).
- asset_identity_history: cambios de nombre, etiqueta, IP, MAC, fabricante y tipo de cada
  activo con fuente y confianza.

Datos: tablas nuevas y vacías. No se toca ningún activo: los nombres DHCP aparecen con la
primera importación o lectura de un sensor. El historial empieza a registrarse desde aquí.

DOWNGRADE: elimina las tres tablas. Los nombres que un activo tomó de un lease quedan en
assets.identity_observations["dhcp_lease"] hasta su siguiente reidentificación, que ya no los
usa con el código anterior (la clave se ignora).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0040"
down_revision: str | None = "0039"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())

KINDS = ("lease_import", "sensor_file")
FORMATS = ("dnsmasq", "isc_dhcpd", "kea_csv", "windows_dhcp_csv", "generic_csv")
STATUSES = ("pending", "ok", "error", "disabled")
LEASE_STATES = ("active", "expired", "released", "unknown")
MATCHES = ("mac_ip", "mac_moved", "ip_only", "randomized_mac", "ambiguous", "no_asset", "expired")
FIELDS = ("name", "label", "ip", "mac", "vendor", "device_type")


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _ts(name: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(name: str, target: str, ondelete: str, nullable: bool = True) -> sa.Column[object]:
    return sa.Column(
        name, sa.BigInteger(), sa.ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "dhcp_sources",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("format", sa.String(24), nullable=False),
        _fk("sensor_id", "sensors.id", "SET NULL"),
        sa.Column("sensor_source_name", sa.String(64)),
        sa.Column("poll_interval_minutes", sa.Integer(), server_default="0", nullable=False),
        sa.Column("status", sa.String(16), server_default="pending", nullable=False),
        _ts("last_requested_at", nullable=True),
        _ts("last_import_at", nullable=True),
        sa.Column("last_error_code", sa.String(48)),
        sa.Column("last_stats", _JSONB),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.UniqueConstraint("site_id", "name", name="uq_dhcp_sources_site_name"),
        sa.CheckConstraint(_in("kind", KINDS), name="ck_dhcp_sources_kind"),
        sa.CheckConstraint(_in("format", FORMATS), name="ck_dhcp_sources_format"),
        sa.CheckConstraint(_in("status", STATUSES), name="ck_dhcp_sources_status"),
    )
    op.create_index("ix_dhcp_sources_sensor", "dhcp_sources", ["sensor_id"])
    op.create_index(
        "uq_dhcp_sources_sensor_source",
        "dhcp_sources",
        ["sensor_id", "sensor_source_name"],
        unique=True,
        postgresql_where=sa.text("sensor_id IS NOT NULL"),
    )

    op.create_table(
        "dhcp_leases",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        _fk("source_id", "dhcp_sources.id", "CASCADE", nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("mac", sa.String(17), nullable=False),
        sa.Column("hostname", sa.String(255)),
        sa.Column("client_id", sa.String(80)),
        _ts("starts_at", nullable=True),
        _ts("ends_at", nullable=True),
        sa.Column("state", sa.String(16), nullable=False),
        _fk("asset_id", "assets.id", "SET NULL"),
        sa.Column("match", sa.String(16), nullable=False),
        _ts("first_seen_at"),
        _ts("last_seen_at"),
        sa.UniqueConstraint("source_id", "ip", "mac", name="uq_dhcp_leases_source_ip_mac"),
        sa.CheckConstraint(_in("state", LEASE_STATES), name="ck_dhcp_leases_state"),
        sa.CheckConstraint(_in("match", MATCHES), name="ck_dhcp_leases_match"),
    )
    op.create_index("ix_dhcp_leases_site_mac", "dhcp_leases", ["site_id", "mac"])
    op.create_index("ix_dhcp_leases_site_ip", "dhcp_leases", ["site_id", "ip"])
    op.create_index("ix_dhcp_leases_asset", "dhcp_leases", ["asset_id"])

    op.create_table(
        "asset_identity_history",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        _fk("asset_id", "assets.id", "CASCADE", nullable=False),
        sa.Column("field", sa.String(16), nullable=False),
        sa.Column("old_value", sa.String(255)),
        sa.Column("new_value", sa.String(255)),
        sa.Column("source", sa.String(24), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        _ts("observed_at"),
        sa.CheckConstraint(_in("field", FIELDS), name="ck_asset_identity_history_field"),
    )
    op.create_index(
        "ix_asset_identity_history_asset", "asset_identity_history", ["asset_id", "observed_at"]
    )


def downgrade() -> None:
    op.drop_table("asset_identity_history")
    op.drop_table("dhcp_leases")
    op.drop_table("dhcp_sources")
