"""Infraestructura de red administrable: SNMP, LLDP/CDP, VLANs y tablas MAC (Fase 6B).

Ver docs/snmp-network-intelligence.md. Principios de modelo:

- Todo pertenece a un Site y se deriva de él: un equipo de red, sus interfaces, vecinos y
  entradas MAC nunca se mezclan entre sites, aunque compartan rangos privados.
- Evidencia normalizada e interpretación en columnas separadas. Lo que informa el equipo se
  guarda tal cual, normalizado (ifType numérico, subtipos LLDP, puerto de bridge, fdb id); lo
  que deduce Sentra (tipo de puerto, interfaz resuelta, VLAN, clasificación, valoración de
  una MAC) va en columnas propias que se recalculan en cada consulta.
- ifIndex NO es identidad histórica: puede cambiar tras un reinicio o un cambio de hardware.
  Una interfaz se identifica dentro de su equipo por `stable_key` (ifName, si no ifDescr, y
  solo como último recurso el ifIndex), y el ifIndex es un atributo más que se actualiza.
- Sin borrados por ausencia: lo que deja de verse en una consulta COMPLETA queda con
  present=false y conserva first/last_seen (historial para 6D/6E). Una consulta parcial nunca
  marca nada como ausente.
- Los secretos SNMP solo existen cifrados (AES-256-GCM, app/core/secret_box.py) en
  snmp_credential_profiles.secret_blob. Ninguna otra tabla, log, auditoría ni informe los
  contiene.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

PROFILE_STATUSES = ("active", "revoked")
DEVICE_STATUSES = ("active", "archived")
POLL_STATUSES = ("queued", "running", "succeeded", "partial", "failed", "cancelled", "expired")
OPEN_POLL_STATUSES = ("queued", "running")
OPEN_POLL_PREDICATE = "status IN ('queued', 'running')"


class SnmpCredentialProfile(Base):
    """Perfil de acceso SNMP read-only con alcance de UN site.

    El secreto (passphrases v3 o comunidad v2c) se guarda cifrado y autenticado; el AAD liga el
    texto cifrado a este perfil, así copiar el blob a otro perfil o a otro site no lo descifra.
    """

    __tablename__ = "snmp_credential_profiles"
    __table_args__ = (
        UniqueConstraint("site_id", "name", name="uq_snmp_credential_profiles_site_name"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(String(500))
    snmp_version: Mapped[str] = mapped_column(String(8))
    # v3: usuario USM y protocolos (no son secretos, pero solo los ve snmp_credentials:manage).
    username: Mapped[str | None] = mapped_column(String(64))
    auth_protocol: Mapped[str | None] = mapped_column(String(16))
    priv_protocol: Mapped[str | None] = mapped_column(String(16))
    # "v1.<kid>.<base64(nonce || ciphertext || tag)>". Text sin límite fijo porque el formato
    # puede crecer de versión; el contenido real está acotado por la validación de la API.
    secret_blob: Mapped[str] = mapped_column(Text)
    secret_key_id: Mapped[str] = mapped_column(String(32))
    secret_revision: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    secret_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    created_by: Mapped[str | None] = mapped_column(String(64))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(64))
    revoke_reason: Mapped[str | None] = mapped_column(String(500))
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class NetworkDevice(Base):
    """Equipo de red administrable registrado por un admin dentro de un site.

    (site, management_address) es único: la misma IP privada en dos sites son dos equipos.
    """

    __tablename__ = "network_devices"
    __table_args__ = (
        UniqueConstraint("site_id", "management_address", name="uq_network_devices_site_address"),
        Index("ix_network_devices_profile", "profile_id"),
        Index("ix_network_devices_sensor", "sensor_id"),
        Index("ix_network_devices_asset", "asset_id"),
        # Programador de consultas periódicas: solo equipos activos con monitorización.
        Index(
            "ix_network_devices_monitoring",
            "last_poll_at",
            postgresql_where=text("status = 'active' AND monitoring_enabled"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    name: Mapped[str | None] = mapped_column(String(100))
    management_address: Mapped[str] = mapped_column(String(45))
    snmp_port: Mapped[int] = mapped_column(Integer, default=161, server_default="161")
    # Activo del MISMO site (lo garantiza el servicio). SET NULL: purgar un activo descubierto
    # no borra el inventario del equipo.
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    profile_id: Mapped[int | None] = mapped_column(
        ForeignKey("snmp_credential_profiles.id", ondelete="RESTRICT")
    )
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="RESTRICT"))
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # --- evidencia SNMPv2-MIB / ENTITY-MIB / BRIDGE-MIB (tal y como la informa el equipo) ---
    sys_name: Mapped[str | None] = mapped_column(String(255))
    sys_descr: Mapped[str | None] = mapped_column(String(1024))
    sys_object_id: Mapped[str | None] = mapped_column(String(255))
    sys_location: Mapped[str | None] = mapped_column(String(255))
    sys_uptime_seconds: Mapped[int | None] = mapped_column(BigInteger)
    sys_services: Mapped[int | None] = mapped_column(SmallInteger)
    ip_forwarding: Mapped[bool | None] = mapped_column(Boolean)
    lldp_chassis_id: Mapped[str | None] = mapped_column(String(255))
    lldp_chassis_id_subtype: Mapped[str | None] = mapped_column(String(32))
    lldp_sys_name: Mapped[str | None] = mapped_column(String(255))
    lldp_capabilities: Mapped[list[str] | None] = mapped_column(JSONB)
    base_bridge_address: Mapped[str | None] = mapped_column(String(17))
    bridge_ports: Mapped[int | None] = mapped_column(Integer)
    # Componentes chassis/stack de ENTITY-MIB (acotado por el servicio: como mucho 16).
    entities: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB)
    # --- interpretación de Sentra ---
    enterprise_number: Mapped[int | None] = mapped_column(Integer)
    vendor: Mapped[str | None] = mapped_column(String(128))
    vendor_source: Mapped[str | None] = mapped_column(String(16))
    model: Mapped[str | None] = mapped_column(String(128))
    firmware: Mapped[str | None] = mapped_column(String(128))
    serial_number: Mapped[str | None] = mapped_column(String(128))
    classification: Mapped[str] = mapped_column(
        String(32), default="unclassified", server_default="unclassified"
    )
    classification_confidence: Mapped[str] = mapped_column(
        String(8), default="none", server_default="none"
    )
    # [{"source": ..., "detail": ...}], como mucho 8 entradas (lo acota classify.py).
    classification_evidence: Mapped[list[dict[str, str]] | None] = mapped_column(JSONB)
    layer3: Mapped[bool | None] = mapped_column(Boolean)
    # --- estado de monitorización ---
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(32))
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_modules: Mapped[dict[str, str] | None] = mapped_column(JSONB)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    archived_by: Mapped[str | None] = mapped_column(String(64))
    archive_reason: Mapped[str | None] = mapped_column(String(500))
    created_by: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class NetworkDevicePoll(Base):
    """Una consulta SNMP de un equipo (historial). Ligada 1:1 a su job de sensor."""

    __tablename__ = "network_device_polls"
    __table_args__ = (
        Index("ix_network_device_polls_device", "device_id", "created_at"),
        Index("ix_network_device_polls_site", "site_id", "created_at"),
        Index("ix_network_device_polls_profile", "profile_id"),
        Index("ix_network_device_polls_sensor", "sensor_id"),
        # Una sola consulta abierta por equipo: un doble clic o el programador periódico no
        # pueden encolar dos consultas simultáneas del mismo equipo.
        Index(
            "uq_network_device_polls_open",
            "device_id",
            unique=True,
            postgresql_where=text(OPEN_POLL_PREDICATE),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    device_id: Mapped[int] = mapped_column(ForeignKey("network_devices.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    sensor_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("sensor_jobs.id", ondelete="SET NULL"), unique=True
    )
    profile_id: Mapped[int | None] = mapped_column(
        ForeignKey("snmp_credential_profiles.id", ondelete="SET NULL")
    )
    snmp_version: Mapped[str | None] = mapped_column(String(8))
    status: Mapped[str] = mapped_column(String(16), default="queued", server_default="queued")
    trigger: Mapped[str] = mapped_column(String(16), default="manual", server_default="manual")
    requested_by: Mapped[str] = mapped_column(String(64))
    modules_requested: Mapped[list[str]] = mapped_column(JSONB)
    # {"interfaces": "complete", "lldp": "unsupported", ...}: claves del catálogo cerrado.
    modules: Mapped[dict[str, str] | None] = mapped_column(JSONB)
    error_code: Mapped[str | None] = mapped_column(String(32))
    error_message: Mapped[str | None] = mapped_column(String(300))
    # Recuentos y cambios: diccionarios de enteros con claves fijas (schemas.network).
    counts: Mapped[dict[str, int] | None] = mapped_column(JSONB)
    changes: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    records_received: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class NetworkPollRecord(Base):
    """Registro normalizado recibido de un sensor y pendiente de aplicar (área temporal).

    Los lotes llegan en cualquier orden y la interpretación necesita cruzar tablas (puerto de
    bridge → ifIndex, puerto LLDP → interfaz, bitmaps de VLAN → puertos), así que se guardan
    hasta el cierre del job y se aplican juntos. Cada registro está validado y acotado por el
    esquema; el total por consulta lo limita SNMP_MAX_VARBINDS_PER_JOB. Se borran al aplicar
    o al cerrar la consulta sin aplicar.
    """

    __tablename__ = "network_poll_records"
    __table_args__ = (Index("ix_network_poll_records_poll", "poll_id", "id"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    poll_id: Mapped[int] = mapped_column(ForeignKey("network_device_polls.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(24))
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)


class NetworkInterface(Base):
    __tablename__ = "network_interfaces"
    __table_args__ = (
        UniqueConstraint("device_id", "stable_key", name="uq_network_interfaces_device_key"),
        # No es único a propósito: tras un reinicio dos claves estables pueden haber tenido
        # el mismo ifIndex en momentos distintos.
        Index("ix_network_interfaces_device_ifindex", "device_id", "if_index"),
        Index("ix_network_interfaces_site", "site_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    device_id: Mapped[int] = mapped_column(ForeignKey("network_devices.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    stable_key: Mapped[str] = mapped_column(String(255))
    # --- evidencia IF-MIB ---
    if_index: Mapped[int] = mapped_column(Integer)
    if_name: Mapped[str | None] = mapped_column(String(255))
    if_descr: Mapped[str | None] = mapped_column(String(255))
    if_alias: Mapped[str | None] = mapped_column(String(255))
    if_type: Mapped[int | None] = mapped_column(Integer)
    mtu: Mapped[int | None] = mapped_column(Integer)
    mac: Mapped[str | None] = mapped_column(String(17))
    admin_status: Mapped[str] = mapped_column(String(16), default="unknown")
    oper_status: Mapped[str] = mapped_column(String(24), default="unknown")
    speed_mbps: Mapped[int | None] = mapped_column(BigInteger)
    in_octets: Mapped[int | None] = mapped_column(BigInteger)
    out_octets: Mapped[int | None] = mapped_column(BigInteger)
    counters_hc: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    in_errors: Mapped[int | None] = mapped_column(BigInteger)
    out_errors: Mapped[int | None] = mapped_column(BigInteger)
    in_discards: Mapped[int | None] = mapped_column(BigInteger)
    out_discards: Mapped[int | None] = mapped_column(BigInteger)
    counters_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    bridge_port: Mapped[int | None] = mapped_column(Integer)
    pvid: Mapped[int | None] = mapped_column(SmallInteger)
    lag_parent_if_index: Mapped[int | None] = mapped_column(Integer)
    # --- interpretación ---
    port_kind: Mapped[str] = mapped_column(String(16), default="other")
    is_trunk: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    mac_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    neighbor_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_poll_id: Mapped[int | None] = mapped_column(BigInteger)


class NetworkVlan(Base):
    __tablename__ = "network_vlans"
    __table_args__ = (
        UniqueConstraint("device_id", "vlan_id", name="uq_network_vlans_device"),
        Index("ix_network_vlans_site", "site_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("network_devices.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    vlan_id: Mapped[int] = mapped_column(SmallInteger)
    name: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(24))
    fdb_id: Mapped[int | None] = mapped_column(Integer)
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_poll_id: Mapped[int | None] = mapped_column(BigInteger)


class NetworkVlanMembership(Base):
    """Pertenencia de una interfaz a una VLAN (tagged/untagged) según Q-BRIDGE-MIB."""

    __tablename__ = "network_vlan_memberships"
    __table_args__ = (
        UniqueConstraint("interface_id", "vlan_id", name="uq_network_vlan_memberships"),
        Index("ix_network_vlan_memberships_device_vlan", "device_id", "vlan_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("network_devices.id", ondelete="CASCADE"))
    interface_id: Mapped[int] = mapped_column(
        ForeignKey("network_interfaces.id", ondelete="CASCADE")
    )
    vlan_id: Mapped[int] = mapped_column(SmallInteger)
    tagged: Mapped[bool] = mapped_column(Boolean)
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_poll_id: Mapped[int | None] = mapped_column(BigInteger)


class NetworkNeighbor(Base):
    """Vecino informado por un equipo vía LLDP o CDP (observación, no enlace confirmado).

    La clave natural es lo que el equipo informa: protocolo, puerto local y la identidad
    remota (chasis y puerto). La misma observación repetida actualiza last_seen; un cambio de
    vecino en el mismo puerto es otra fila (la anterior queda ausente con su historial).
    """

    __tablename__ = "network_neighbors"
    __table_args__ = (
        UniqueConstraint(
            "device_id",
            "protocol",
            "local_port_key",
            "remote_key",
            name="uq_network_neighbors_observation",
        ),
        Index("ix_network_neighbors_site_chassis", "site_id", "remote_chassis_id"),
        Index("ix_network_neighbors_remote_device", "remote_device_id"),
        Index("ix_network_neighbors_interface", "interface_id"),
        Index("ix_network_neighbors_sensor", "sensor_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    device_id: Mapped[int] = mapped_column(ForeignKey("network_devices.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    protocol: Mapped[str] = mapped_column(String(8))
    # --- evidencia (normalizada) ---
    # LLDP: lldpLocPortNum; CDP: cdpCacheIfIndex. Texto para que ambas claves convivan.
    local_port_key: Mapped[str] = mapped_column(String(32))
    local_port_label: Mapped[str | None] = mapped_column(String(255))
    remote_key: Mapped[str] = mapped_column(String(64))
    remote_chassis_id: Mapped[str | None] = mapped_column(String(255))
    remote_chassis_id_subtype: Mapped[str | None] = mapped_column(String(32))
    remote_port_id: Mapped[str | None] = mapped_column(String(255))
    remote_port_id_subtype: Mapped[str | None] = mapped_column(String(32))
    remote_port_descr: Mapped[str | None] = mapped_column(String(255))
    remote_sys_name: Mapped[str | None] = mapped_column(String(255))
    remote_sys_descr: Mapped[str | None] = mapped_column(String(1024))
    remote_platform: Mapped[str | None] = mapped_column(String(255))
    remote_software: Mapped[str | None] = mapped_column(String(512))
    remote_mgmt_address: Mapped[str | None] = mapped_column(String(45))
    remote_capabilities: Mapped[list[str] | None] = mapped_column(JSONB)
    remote_native_vlan: Mapped[int | None] = mapped_column(SmallInteger)
    # --- interpretación ---
    interface_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_interfaces.id", ondelete="SET NULL")
    )
    local_port_match: Mapped[str] = mapped_column(
        String(16), default="unmatched", server_default="unmatched"
    )
    remote_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_devices.id", ondelete="SET NULL")
    )
    remote_match_basis: Mapped[str | None] = mapped_column(String(16))
    reciprocal: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_poll_id: Mapped[int | None] = mapped_column(BigInteger)


class NetworkMacEntry(Base):
    """Entrada de la tabla de reenvío (BRIDGE-MIB / Q-BRIDGE-MIB) de un equipo.

    Es evidencia de que el equipo reenvía tráfico de esa MAC por un puerto, no de que el
    endpoint esté cableado ahí: un uplink o un trunk ve muchas MACs. `location` resume esa
    valoración y nunca se usa para fusionar activos (y menos entre sites).
    """

    __tablename__ = "network_mac_entries"
    __table_args__ = (
        # fdb_key = fdb id del Q-BRIDGE o 0 en BRIDGE-MIB (sin VLAN): evita NULL en el único.
        UniqueConstraint("device_id", "mac", "fdb_key", name="uq_network_mac_entries"),
        Index("ix_network_mac_entries_site_mac", "site_id", "mac"),
        Index("ix_network_mac_entries_interface", "interface_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    device_id: Mapped[int] = mapped_column(ForeignKey("network_devices.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    mac: Mapped[str] = mapped_column(String(17))
    # --- evidencia ---
    fdb_key: Mapped[int] = mapped_column(Integer)
    bridge_port: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))
    # --- interpretación ---
    vlan_id: Mapped[int | None] = mapped_column(SmallInteger)
    vlan_source: Mapped[str] = mapped_column(String(16), default="none", server_default="none")
    interface_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_interfaces.id", ondelete="SET NULL")
    )
    location: Mapped[str] = mapped_column(String(24), default="unknown", server_default="unknown")
    location_reason: Mapped[str] = mapped_column(String(64), default="", server_default="")
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_poll_id: Mapped[int | None] = mapped_column(BigInteger)
