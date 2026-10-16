"""SNMP, LLDP, CDP & Switch Intelligence (Fase 6B)

Revision ID: 0034
Revises: 0033
Create Date: 2026-10-15

Cambios (ver app/models/network.py y docs/snmp-network-intelligence.md):
- snmp_credential_profiles: perfiles de acceso SNMP read-only por site. El secreto solo se
  guarda cifrado (AES-256-GCM con una clave fuera de la base de datos).
- network_devices: equipos administrables registrados por site, con la evidencia SNMP y la
  interpretación (fabricante por número de empresa IANA, clasificación con confianza).
- network_device_polls / network_poll_records: historial de consultas y área temporal de
  registros recibidos hasta el cierre del job.
- network_interfaces, network_vlans, network_vlan_memberships, network_neighbors,
  network_mac_entries: inventario observado con first/last_seen y presencia.

Solo tablas nuevas: no se modifica ni reescribe ningún dato de fases anteriores (sites,
sensores, jobs, activos, discovery, informes).

DOWNGRADE: elimina las tablas de 6B. Se pierden los perfiles SNMP (sus secretos cifrados), los
equipos registrados y todo su inventario e historial; el resto de datos se conserva. Los jobs
de sensor de tipo snmp_inventory que existan quedan en sensor_jobs como historial (un
servidor anterior no los entrega: su tipo no está en su catálogo y los falla al leerlos).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0034"
down_revision: str | None = "0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())


def _ts(name: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(name: str, target: str, ondelete: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(
        name, sa.BigInteger(), sa.ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


def _audit_columns() -> list[sa.Column[object]]:
    return [
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "snmp_credential_profiles",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("site_id", "sites.id", "RESTRICT"),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("snmp_version", sa.String(length=8), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=True),
        sa.Column("auth_protocol", sa.String(length=16), nullable=True),
        sa.Column("priv_protocol", sa.String(length=16), nullable=True),
        sa.Column("secret_blob", sa.Text(), nullable=False),
        sa.Column("secret_key_id", sa.String(length=32), nullable=False),
        sa.Column("secret_revision", sa.Integer(), server_default="1", nullable=False),
        _ts("secret_updated_at"),
        sa.Column("status", sa.String(length=16), server_default="active", nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        _ts("revoked_at", True),
        sa.Column("revoked_by", sa.String(length=64), nullable=True),
        sa.Column("revoke_reason", sa.String(length=500), nullable=True),
        *_audit_columns(),
        sa.UniqueConstraint("site_id", "name", name="uq_snmp_credential_profiles_site_name"),
    )

    op.create_table(
        "network_devices",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("site_id", "sites.id", "RESTRICT"),
        sa.Column("name", sa.String(length=100), nullable=True),
        sa.Column("management_address", sa.String(length=45), nullable=False),
        sa.Column("snmp_port", sa.Integer(), server_default="161", nullable=False),
        _fk("asset_id", "assets.id", "SET NULL", True),
        _fk("profile_id", "snmp_credential_profiles.id", "RESTRICT", True),
        _fk("sensor_id", "sensors.id", "RESTRICT", True),
        sa.Column("status", sa.String(length=16), server_default="active", nullable=False),
        sa.Column("monitoring_enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("sys_name", sa.String(length=255), nullable=True),
        sa.Column("sys_descr", sa.String(length=1024), nullable=True),
        sa.Column("sys_object_id", sa.String(length=255), nullable=True),
        sa.Column("sys_location", sa.String(length=255), nullable=True),
        sa.Column("sys_uptime_seconds", sa.BigInteger(), nullable=True),
        sa.Column("sys_services", sa.SmallInteger(), nullable=True),
        sa.Column("ip_forwarding", sa.Boolean(), nullable=True),
        sa.Column("lldp_chassis_id", sa.String(length=255), nullable=True),
        sa.Column("lldp_chassis_id_subtype", sa.String(length=32), nullable=True),
        sa.Column("lldp_sys_name", sa.String(length=255), nullable=True),
        sa.Column("lldp_capabilities", _JSONB, nullable=True),
        sa.Column("base_bridge_address", sa.String(length=17), nullable=True),
        sa.Column("bridge_ports", sa.Integer(), nullable=True),
        sa.Column("entities", _JSONB, nullable=True),
        sa.Column("enterprise_number", sa.Integer(), nullable=True),
        sa.Column("vendor", sa.String(length=128), nullable=True),
        sa.Column("vendor_source", sa.String(length=16), nullable=True),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("firmware", sa.String(length=128), nullable=True),
        sa.Column("serial_number", sa.String(length=128), nullable=True),
        sa.Column(
            "classification", sa.String(length=32), server_default="unclassified", nullable=False
        ),
        sa.Column(
            "classification_confidence", sa.String(length=8), server_default="none", nullable=False
        ),
        sa.Column("classification_evidence", _JSONB, nullable=True),
        sa.Column("layer3", sa.Boolean(), nullable=True),
        _ts("last_poll_at", True),
        _ts("last_success_at", True),
        sa.Column("last_error_code", sa.String(length=32), nullable=True),
        _ts("last_error_at", True),
        sa.Column("consecutive_failures", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_modules", _JSONB, nullable=True),
        _ts("archived_at", True),
        sa.Column("archived_by", sa.String(length=64), nullable=True),
        sa.Column("archive_reason", sa.String(length=500), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        *_audit_columns(),
        sa.UniqueConstraint(
            "site_id", "management_address", name="uq_network_devices_site_address"
        ),
    )
    op.create_index("ix_network_devices_profile", "network_devices", ["profile_id"])
    op.create_index("ix_network_devices_sensor", "network_devices", ["sensor_id"])
    op.create_index("ix_network_devices_asset", "network_devices", ["asset_id"])
    op.create_index(
        "ix_network_devices_monitoring",
        "network_devices",
        ["last_poll_at"],
        postgresql_where=sa.text("status = 'active' AND monitoring_enabled"),
    )

    op.create_table(
        "network_device_polls",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("device_id", "network_devices.id", "CASCADE"),
        _fk("site_id", "sites.id", "RESTRICT"),
        _fk("sensor_id", "sensors.id", "SET NULL", True),
        sa.Column(
            "sensor_job_id",
            sa.BigInteger(),
            sa.ForeignKey("sensor_jobs.id", ondelete="SET NULL"),
            nullable=True,
            unique=True,
        ),
        _fk("profile_id", "snmp_credential_profiles.id", "SET NULL", True),
        sa.Column("snmp_version", sa.String(length=8), nullable=True),
        sa.Column("status", sa.String(length=16), server_default="queued", nullable=False),
        sa.Column("trigger", sa.String(length=16), server_default="manual", nullable=False),
        sa.Column("requested_by", sa.String(length=64), nullable=False),
        sa.Column("modules_requested", _JSONB, nullable=False),
        sa.Column("modules", _JSONB, nullable=True),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column("error_message", sa.String(length=300), nullable=True),
        sa.Column("counts", _JSONB, nullable=True),
        sa.Column("changes", _JSONB, nullable=True),
        sa.Column("records_received", sa.Integer(), server_default="0", nullable=False),
        _ts("created_at"),
        _ts("started_at", True),
        _ts("finished_at", True),
    )
    op.create_index(
        "ix_network_device_polls_device", "network_device_polls", ["device_id", "created_at"]
    )
    op.create_index(
        "ix_network_device_polls_site", "network_device_polls", ["site_id", "created_at"]
    )
    op.create_index("ix_network_device_polls_profile", "network_device_polls", ["profile_id"])
    op.create_index("ix_network_device_polls_sensor", "network_device_polls", ["sensor_id"])
    op.create_index(
        "uq_network_device_polls_open",
        "network_device_polls",
        ["device_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )

    op.create_table(
        "network_poll_records",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        _fk("poll_id", "network_device_polls.id", "CASCADE"),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("data", _JSONB, nullable=False),
    )
    op.create_index("ix_network_poll_records_poll", "network_poll_records", ["poll_id", "id"])

    op.create_table(
        "network_interfaces",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("device_id", "network_devices.id", "CASCADE"),
        _fk("site_id", "sites.id", "RESTRICT"),
        sa.Column("stable_key", sa.String(length=255), nullable=False),
        sa.Column("if_index", sa.Integer(), nullable=False),
        sa.Column("if_name", sa.String(length=255), nullable=True),
        sa.Column("if_descr", sa.String(length=255), nullable=True),
        sa.Column("if_alias", sa.String(length=255), nullable=True),
        sa.Column("if_type", sa.Integer(), nullable=True),
        sa.Column("mtu", sa.Integer(), nullable=True),
        sa.Column("mac", sa.String(length=17), nullable=True),
        sa.Column("admin_status", sa.String(length=16), nullable=False),
        sa.Column("oper_status", sa.String(length=24), nullable=False),
        sa.Column("speed_mbps", sa.BigInteger(), nullable=True),
        sa.Column("in_octets", sa.BigInteger(), nullable=True),
        sa.Column("out_octets", sa.BigInteger(), nullable=True),
        sa.Column("counters_hc", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("in_errors", sa.BigInteger(), nullable=True),
        sa.Column("out_errors", sa.BigInteger(), nullable=True),
        sa.Column("in_discards", sa.BigInteger(), nullable=True),
        sa.Column("out_discards", sa.BigInteger(), nullable=True),
        _ts("counters_at", True),
        sa.Column("bridge_port", sa.Integer(), nullable=True),
        sa.Column("pvid", sa.SmallInteger(), nullable=True),
        sa.Column("lag_parent_if_index", sa.Integer(), nullable=True),
        sa.Column("port_kind", sa.String(length=16), nullable=False),
        sa.Column("is_trunk", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("mac_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("neighbor_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("present", sa.Boolean(), server_default="true", nullable=False),
        _ts("first_seen_at"),
        _ts("last_seen_at"),
        sa.Column("last_poll_id", sa.BigInteger(), nullable=True),
        sa.UniqueConstraint("device_id", "stable_key", name="uq_network_interfaces_device_key"),
    )
    op.create_index(
        "ix_network_interfaces_device_ifindex", "network_interfaces", ["device_id", "if_index"]
    )
    op.create_index("ix_network_interfaces_site", "network_interfaces", ["site_id"])

    op.create_table(
        "network_vlans",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        _fk("device_id", "network_devices.id", "CASCADE"),
        _fk("site_id", "sites.id", "RESTRICT"),
        sa.Column("vlan_id", sa.SmallInteger(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=True),
        sa.Column("source", sa.String(length=24), nullable=False),
        sa.Column("fdb_id", sa.Integer(), nullable=True),
        sa.Column("present", sa.Boolean(), server_default="true", nullable=False),
        _ts("first_seen_at"),
        _ts("last_seen_at"),
        sa.Column("last_poll_id", sa.BigInteger(), nullable=True),
        sa.UniqueConstraint("device_id", "vlan_id", name="uq_network_vlans_device"),
    )
    op.create_index("ix_network_vlans_site", "network_vlans", ["site_id"])

    op.create_table(
        "network_vlan_memberships",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        _fk("device_id", "network_devices.id", "CASCADE"),
        _fk("interface_id", "network_interfaces.id", "CASCADE"),
        sa.Column("vlan_id", sa.SmallInteger(), nullable=False),
        sa.Column("tagged", sa.Boolean(), nullable=False),
        sa.Column("present", sa.Boolean(), server_default="true", nullable=False),
        _ts("last_seen_at"),
        sa.Column("last_poll_id", sa.BigInteger(), nullable=True),
        sa.UniqueConstraint("interface_id", "vlan_id", name="uq_network_vlan_memberships"),
    )
    op.create_index(
        "ix_network_vlan_memberships_device_vlan",
        "network_vlan_memberships",
        ["device_id", "vlan_id"],
    )

    op.create_table(
        "network_neighbors",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("device_id", "network_devices.id", "CASCADE"),
        _fk("site_id", "sites.id", "RESTRICT"),
        _fk("sensor_id", "sensors.id", "SET NULL", True),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("local_port_key", sa.String(length=32), nullable=False),
        sa.Column("local_port_label", sa.String(length=255), nullable=True),
        sa.Column("remote_key", sa.String(length=64), nullable=False),
        sa.Column("remote_chassis_id", sa.String(length=255), nullable=True),
        sa.Column("remote_chassis_id_subtype", sa.String(length=32), nullable=True),
        sa.Column("remote_port_id", sa.String(length=255), nullable=True),
        sa.Column("remote_port_id_subtype", sa.String(length=32), nullable=True),
        sa.Column("remote_port_descr", sa.String(length=255), nullable=True),
        sa.Column("remote_sys_name", sa.String(length=255), nullable=True),
        sa.Column("remote_sys_descr", sa.String(length=1024), nullable=True),
        sa.Column("remote_platform", sa.String(length=255), nullable=True),
        sa.Column("remote_software", sa.String(length=512), nullable=True),
        sa.Column("remote_mgmt_address", sa.String(length=45), nullable=True),
        sa.Column("remote_capabilities", _JSONB, nullable=True),
        sa.Column("remote_native_vlan", sa.SmallInteger(), nullable=True),
        _fk("interface_id", "network_interfaces.id", "SET NULL", True),
        sa.Column(
            "local_port_match", sa.String(length=16), server_default="unmatched", nullable=False
        ),
        _fk("remote_device_id", "network_devices.id", "SET NULL", True),
        sa.Column("remote_match_basis", sa.String(length=16), nullable=True),
        sa.Column("reciprocal", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("present", sa.Boolean(), server_default="true", nullable=False),
        _ts("first_seen_at"),
        _ts("last_seen_at"),
        sa.Column("last_poll_id", sa.BigInteger(), nullable=True),
        sa.UniqueConstraint(
            "device_id",
            "protocol",
            "local_port_key",
            "remote_key",
            name="uq_network_neighbors_observation",
        ),
    )
    op.create_index(
        "ix_network_neighbors_site_chassis", "network_neighbors", ["site_id", "remote_chassis_id"]
    )
    op.create_index("ix_network_neighbors_remote_device", "network_neighbors", ["remote_device_id"])
    op.create_index("ix_network_neighbors_interface", "network_neighbors", ["interface_id"])
    op.create_index("ix_network_neighbors_sensor", "network_neighbors", ["sensor_id"])

    op.create_table(
        "network_mac_entries",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        _fk("device_id", "network_devices.id", "CASCADE"),
        _fk("site_id", "sites.id", "RESTRICT"),
        sa.Column("mac", sa.String(length=17), nullable=False),
        sa.Column("fdb_key", sa.Integer(), nullable=False),
        sa.Column("bridge_port", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("vlan_id", sa.SmallInteger(), nullable=True),
        sa.Column("vlan_source", sa.String(length=16), server_default="none", nullable=False),
        _fk("interface_id", "network_interfaces.id", "SET NULL", True),
        sa.Column("location", sa.String(length=24), server_default="unknown", nullable=False),
        sa.Column("location_reason", sa.String(length=64), server_default="", nullable=False),
        sa.Column("present", sa.Boolean(), server_default="true", nullable=False),
        _ts("first_seen_at"),
        _ts("last_seen_at"),
        sa.Column("last_poll_id", sa.BigInteger(), nullable=True),
        sa.UniqueConstraint("device_id", "mac", "fdb_key", name="uq_network_mac_entries"),
    )
    op.create_index("ix_network_mac_entries_site_mac", "network_mac_entries", ["site_id", "mac"])
    op.create_index("ix_network_mac_entries_interface", "network_mac_entries", ["interface_id"])


def downgrade() -> None:
    # Orden inverso de dependencias (FK): primero lo que referencia a equipos e interfaces.
    op.drop_table("network_mac_entries")
    op.drop_table("network_neighbors")
    op.drop_table("network_vlan_memberships")
    op.drop_table("network_vlans")
    op.drop_table("network_interfaces")
    op.drop_table("network_poll_records")
    op.drop_table("network_device_polls")
    op.drop_table("network_devices")
    op.drop_table("snmp_credential_profiles")
