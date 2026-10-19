"""Wi-Fi / AP / WLAN discovery autorizado (Fase 6C.3)

Revision ID: 0035
Revises: 0034
Create Date: 2026-10-16

Cambios (ver app/models/wlan.py y docs/wlan-discovery.md):
- wlan_access_points: puntos de acceso informados por equipos gestionados (controladora o el
  propio AP vía el módulo SNMP wlan), con procedencia, vinculación con evidencia a un activo o
  equipo de red del mismo site y estado de autorización (unknown por defecto).
- wlan_bss: BSS por (site, BSSID) con SSID, banda, canal, protección y estándar cuando la
  fuente los da; fusiona la vista SNMP y la observación de los agentes.
- wlan_clients: clientes observados con su confianza de identidad (confirmed / probable /
  observation_only); una MAC aleatoria nunca identifica un dispositivo.
- wlan_configured_networks: WLANs (SSID) que declara una controladora.
- wlan_observations: historial acotado de observaciones con fuente, sensor, consulta o agente
  y hora.
- wlan_agent_reports: último estado del colector Wi-Fi de cada agente (ok, no_adapter,
  permission_limited, unsupported, error) y sus interfaces, para los indicadores de
  disponibilidad de datos.

Solo tablas nuevas: no se modifica ningún dato de fases anteriores. El módulo `wlan` del job
snmp_inventory no necesita cambios de esquema en sensor_jobs ni en network_device_polls.

DOWNGRADE: elimina las tablas de 6C.3. Se pierden el inventario Wi-Fi, las decisiones de
autorización, las vinculaciones y su historial; el inventario SNMP de 6B y el inventario de
los agentes se conservan. Las consultas ya cerradas conservan "wlan" en su lista de módulos
(un servidor anterior la muestra como un módulo más del historial).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0035"
down_revision: str | None = "0034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())
_AUTHORIZATION = "authorization_status IN ('unknown', 'authorized', 'external')"


def _ts(name: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(name: str, target: str, ondelete: str, nullable: bool = True) -> sa.Column[object]:
    return sa.Column(
        name, sa.BigInteger(), sa.ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


def _now(name: str) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)


def _authorization_columns() -> list[sa.Column[object]]:
    return [
        sa.Column(
            "authorization_status", sa.String(length=16), server_default="unknown", nullable=False
        ),
        sa.Column("authorization_reason", sa.String(length=500), nullable=True),
        sa.Column("authorization_by", sa.String(length=64), nullable=True),
        _ts("authorization_at", True),
    ]


def upgrade() -> None:
    op.create_table(
        "wlan_access_points",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        sa.Column("ap_key", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("vendor", sa.String(length=128), nullable=True),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("serial_number", sa.String(length=128), nullable=True),
        sa.Column("firmware", sa.String(length=128), nullable=True),
        sa.Column("location", sa.String(length=255), nullable=True),
        sa.Column("management_ip", sa.String(length=45), nullable=True),
        sa.Column("ethernet_mac", sa.String(length=17), nullable=True),
        sa.Column("radio_mac", sa.String(length=17), nullable=True),
        sa.Column(
            "reported_status", sa.String(length=16), server_default="unknown", nullable=False
        ),
        sa.Column("radios", _JSONB, nullable=True),
        sa.Column("source", sa.String(length=24), nullable=False),
        sa.Column(
            "confidence", sa.String(length=24), server_default="reported_by_device", nullable=False
        ),
        _fk("source_device_id", "network_devices.id", "SET NULL"),
        _fk("sensor_id", "sensors.id", "SET NULL"),
        sa.Column("last_poll_id", sa.BigInteger(), nullable=True),
        _fk("network_device_id", "network_devices.id", "SET NULL"),
        _fk("asset_id", "assets.id", "SET NULL"),
        sa.Column("link_evidence", _JSONB, nullable=True),
        sa.Column("link_suppressed", sa.Boolean(), server_default="false", nullable=False),
        *_authorization_columns(),
        sa.Column("present", sa.Boolean(), server_default="true", nullable=False),
        _ts("first_seen_at"),
        _ts("last_seen_at"),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        _now("created_at"),
        _now("updated_at"),
        sa.UniqueConstraint("site_id", "ap_key", name="uq_wlan_access_points_site_key"),
        sa.CheckConstraint(_AUTHORIZATION, name="ck_wlan_access_points_authorization"),
    )
    op.create_index(
        "ix_wlan_access_points_site_seen", "wlan_access_points", ["site_id", "last_seen_at"]
    )
    op.create_index(
        "ix_wlan_access_points_source_device", "wlan_access_points", ["source_device_id"]
    )
    op.create_index("ix_wlan_access_points_sensor", "wlan_access_points", ["sensor_id"])
    op.create_index(
        "ix_wlan_access_points_network_device", "wlan_access_points", ["network_device_id"]
    )
    op.create_index("ix_wlan_access_points_asset", "wlan_access_points", ["asset_id"])
    op.create_index(
        "ix_wlan_access_points_site_ip", "wlan_access_points", ["site_id", "management_ip"]
    )
    op.create_index(
        "ix_wlan_access_points_site_mac", "wlan_access_points", ["site_id", "ethernet_mac"]
    )

    op.create_table(
        "wlan_bss",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        sa.Column("bssid", sa.String(length=17), nullable=False),
        sa.Column("ssid", sa.String(length=64), nullable=True),
        sa.Column("band", sa.String(length=4), nullable=True),
        sa.Column("channel", sa.SmallInteger(), nullable=True),
        sa.Column("frequency_mhz", sa.Integer(), nullable=True),
        sa.Column("protection", sa.String(length=16), nullable=True),
        sa.Column("protection_reported", sa.String(length=64), nullable=True),
        sa.Column("standard", sa.String(length=16), nullable=True),
        sa.Column("signal_dbm", sa.SmallInteger(), nullable=True),
        sa.Column("signal_quality", sa.SmallInteger(), nullable=True),
        sa.Column("client_count", sa.Integer(), nullable=True),
        sa.Column("vlan_id", sa.SmallInteger(), nullable=True),
        _fk("access_point_id", "wlan_access_points.id", "SET NULL"),
        sa.Column("source", sa.String(length=24), nullable=False),
        sa.Column("sources", _JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("confidence", sa.String(length=24), nullable=False),
        _fk("source_device_id", "network_devices.id", "SET NULL"),
        _fk("sensor_id", "sensors.id", "SET NULL"),
        _fk("last_agent_asset_id", "assets.id", "SET NULL"),
        sa.Column("last_poll_id", sa.BigInteger(), nullable=True),
        _ts("last_snmp_seen_at", True),
        _ts("last_agent_seen_at", True),
        *_authorization_columns(),
        sa.Column("present", sa.Boolean(), server_default="true", nullable=False),
        _ts("first_seen_at"),
        _ts("last_seen_at"),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        _now("created_at"),
        _now("updated_at"),
        sa.UniqueConstraint("site_id", "bssid", name="uq_wlan_bss_site_bssid"),
        sa.CheckConstraint(_AUTHORIZATION, name="ck_wlan_bss_authorization"),
    )
    op.create_index("ix_wlan_bss_site_ssid", "wlan_bss", ["site_id", "ssid"])
    op.create_index("ix_wlan_bss_site_seen", "wlan_bss", ["site_id", "last_seen_at"])
    op.create_index("ix_wlan_bss_access_point", "wlan_bss", ["access_point_id"])
    op.create_index("ix_wlan_bss_source_device", "wlan_bss", ["source_device_id"])
    op.create_index("ix_wlan_bss_sensor", "wlan_bss", ["sensor_id"])
    op.create_index("ix_wlan_bss_agent_asset", "wlan_bss", ["last_agent_asset_id"])

    op.create_table(
        "wlan_clients",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        sa.Column("client_key", sa.String(length=160), nullable=False),
        sa.Column("mac", sa.String(length=17), nullable=True),
        sa.Column("mac_randomized", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("bssid", sa.String(length=17), nullable=True),
        sa.Column("ssid", sa.String(length=64), nullable=True),
        _fk("access_point_id", "wlan_access_points.id", "SET NULL"),
        sa.Column("radio_slot", sa.SmallInteger(), nullable=True),
        sa.Column("band", sa.String(length=4), nullable=True),
        sa.Column("standard", sa.String(length=16), nullable=True),
        sa.Column("state", sa.String(length=24), server_default="unknown", nullable=False),
        sa.Column("source", sa.String(length=24), nullable=False),
        sa.Column("identity_confidence", sa.String(length=24), nullable=False),
        _fk("asset_id", "assets.id", "SET NULL"),
        sa.Column("correlation_basis", sa.String(length=32), nullable=True),
        _fk("source_device_id", "network_devices.id", "SET NULL"),
        _fk("sensor_id", "sensors.id", "SET NULL"),
        sa.Column("last_poll_id", sa.BigInteger(), nullable=True),
        sa.Column("present", sa.Boolean(), server_default="true", nullable=False),
        _ts("first_seen_at"),
        _ts("last_seen_at"),
        _now("created_at"),
        _now("updated_at"),
        sa.UniqueConstraint("site_id", "client_key", name="uq_wlan_clients_site_key"),
    )
    op.create_index("ix_wlan_clients_site_seen", "wlan_clients", ["site_id", "last_seen_at"])
    op.create_index("ix_wlan_clients_access_point", "wlan_clients", ["access_point_id"])
    op.create_index("ix_wlan_clients_asset", "wlan_clients", ["asset_id"])
    op.create_index("ix_wlan_clients_source_device", "wlan_clients", ["source_device_id"])
    op.create_index("ix_wlan_clients_sensor", "wlan_clients", ["sensor_id"])
    op.create_index("ix_wlan_clients_site_bssid", "wlan_clients", ["site_id", "bssid"])

    op.create_table(
        "wlan_configured_networks",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        _fk("device_id", "network_devices.id", "CASCADE", nullable=False),
        sa.Column("source", sa.String(length=24), nullable=False),
        sa.Column("network_key", sa.String(length=32), nullable=False),
        sa.Column("ssid", sa.String(length=64), nullable=True),
        sa.Column("client_count", sa.Integer(), nullable=True),
        sa.Column("present", sa.Boolean(), server_default="true", nullable=False),
        _ts("first_seen_at"),
        _ts("last_seen_at"),
        sa.Column("last_poll_id", sa.BigInteger(), nullable=True),
        sa.UniqueConstraint(
            "device_id", "source", "network_key", name="uq_wlan_configured_networks_key"
        ),
    )
    op.create_index(
        "ix_wlan_configured_networks_site_ssid", "wlan_configured_networks", ["site_id", "ssid"]
    )

    op.create_table(
        "wlan_observations",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        _fk("access_point_id", "wlan_access_points.id", "CASCADE"),
        _fk("bss_id", "wlan_bss.id", "CASCADE"),
        _fk("client_id", "wlan_clients.id", "CASCADE"),
        sa.Column("source", sa.String(length=24), nullable=False),
        sa.Column("confidence", sa.String(length=24), nullable=False),
        _fk("poll_id", "network_device_polls.id", "SET NULL"),
        _fk("sensor_id", "sensors.id", "SET NULL"),
        _fk("source_device_id", "network_devices.id", "SET NULL"),
        _fk("agent_asset_id", "assets.id", "SET NULL"),
        _ts("observed_at"),
        _ts("received_at"),
        sa.Column("data", _JSONB, nullable=False),
        sa.CheckConstraint(
            "num_nonnulls(access_point_id, bss_id, client_id) = 1",
            name="ck_wlan_observations_one_entity",
        ),
    )
    op.create_index(
        "ix_wlan_observations_ap", "wlan_observations", ["access_point_id", "observed_at"]
    )
    op.create_index("ix_wlan_observations_bss", "wlan_observations", ["bss_id", "observed_at"])
    op.create_index(
        "ix_wlan_observations_client", "wlan_observations", ["client_id", "observed_at"]
    )
    op.create_index("ix_wlan_observations_site", "wlan_observations", ["site_id", "observed_at"])
    op.create_index("ix_wlan_observations_poll", "wlan_observations", ["poll_id"])
    op.create_index("ix_wlan_observations_sensor", "wlan_observations", ["sensor_id"])
    op.create_index("ix_wlan_observations_agent_asset", "wlan_observations", ["agent_asset_id"])
    op.create_index("ix_wlan_observations_source_device", "wlan_observations", ["source_device_id"])

    op.create_table(
        "wlan_agent_reports",
        sa.Column(
            "asset_id",
            sa.BigInteger(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        _fk("site_id", "sites.id", "RESTRICT", nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        _ts("collected_at"),
        _ts("received_at"),
        sa.Column("interfaces", _JSONB, nullable=False),
        sa.Column("networks_reported", sa.Integer(), server_default="0", nullable=False),
        sa.Column("networks_without_bssid", sa.Integer(), server_default="0", nullable=False),
    )
    op.create_index("ix_wlan_agent_reports_site", "wlan_agent_reports", ["site_id", "collected_at"])


def downgrade() -> None:
    # Orden inverso de dependencias (FK): el historial referencia a APs, BSS y clientes.
    op.drop_table("wlan_agent_reports")
    op.drop_table("wlan_observations")
    op.drop_table("wlan_configured_networks")
    op.drop_table("wlan_clients")
    op.drop_table("wlan_bss")
    op.drop_table("wlan_access_points")
