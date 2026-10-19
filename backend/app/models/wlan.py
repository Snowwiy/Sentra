"""Inventario Wi-Fi / AP / WLAN autorizado (Fase 6C.3, docs/wlan-discovery.md).

Extiende la infraestructura de la Fase 6B (sites, sensores, equipos SNMP) sin duplicarla:
la evidencia SNMP llega por el mismo job snmp_inventory (módulo `wlan`) y la de los agentes
por su POST /inventory (campo opcional `wireless`). Principios:

- Todo pertenece a UN site. Identidad natural por site: AP por `ap_key`, BSS por BSSID,
  cliente por `client_key`. La misma MAC en dos sites son dos filas: nunca se fusionan.
- Procedencia siempre visible: fuente (`snmp_ieee802dot11`, `snmp_airespace`, `snmp_unifi`,
  `agent`), confianza y hora. Lo que informa un equipo gestionado es `reported_by_device`;
  lo que ve un agente cerca es `observed` (un agente que ve una red no prueba que el AP sea
  de la organización).
- Sin borrados por ausencia y sin inferencias por fallo: solo una consulta SNMP COMPLETA con
  la fuente completa marca present=false; un agente nunca marca ausencias (su exploración de
  radio es intrínsecamente parcial). La frescura de lo observado se deriva al leer.
- Autorización de un AP o BSS: `unknown` por defecto. Nunca se marca "rogue" por no estar
  registrado; un operador con network:manage decide authorized / external / unknown.
- Una MAC con el bit localmente administrado (aleatoria) nunca se trata como identidad de un
  dispositivo físico ni se enlaza con un activo por coincidencia de MAC.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

AUTHORIZATION_STATUSES = ("unknown", "authorized", "external")


class WlanAccessPoint(Base):
    """Punto de acceso informado por un equipo gestionado (controladora o el propio AP).

    `ap_key`: "mac:<MAC base de radio>" para los APs de una controladora (identidad estable que
    la controladora usa como índice) y "device:<uuid del equipo 6B>" para un AP autónomo que
    se consulta directamente (la identidad es el equipo registrado).
    """

    __tablename__ = "wlan_access_points"
    __table_args__ = (
        UniqueConstraint("site_id", "ap_key", name="uq_wlan_access_points_site_key"),
        Index("ix_wlan_access_points_site_seen", "site_id", "last_seen_at"),
        Index("ix_wlan_access_points_source_device", "source_device_id"),
        Index("ix_wlan_access_points_sensor", "sensor_id"),
        Index("ix_wlan_access_points_network_device", "network_device_id"),
        Index("ix_wlan_access_points_asset", "asset_id"),
        Index("ix_wlan_access_points_site_ip", "site_id", "management_ip"),
        Index("ix_wlan_access_points_site_mac", "site_id", "ethernet_mac"),
        CheckConstraint(
            "authorization_status IN ('unknown', 'authorized', 'external')",
            name="ck_wlan_access_points_authorization",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    ap_key: Mapped[str] = mapped_column(String(64))
    # --- evidencia (tal y como la informa la fuente; None = la fuente no lo da) ---
    name: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(128))
    model: Mapped[str | None] = mapped_column(String(128))
    serial_number: Mapped[str | None] = mapped_column(String(128))
    firmware: Mapped[str | None] = mapped_column(String(128))
    location: Mapped[str | None] = mapped_column(String(255))
    management_ip: Mapped[str | None] = mapped_column(String(45))
    ethernet_mac: Mapped[str | None] = mapped_column(String(17))
    radio_mac: Mapped[str | None] = mapped_column(String(17))
    # up / down / transitional / unknown, según la fuente (controladora: asociado o no).
    reported_status: Mapped[str] = mapped_column(
        String(16), default="unknown", server_default="unknown"
    )
    # [{"slot", "band", "channel", "status", "clients", "standard"}], como mucho 8.
    radios: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB)
    source: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[str] = mapped_column(
        String(24), default="reported_by_device", server_default="reported_by_device"
    )
    # Equipo 6B consultado que informó del AP (la controladora o el propio AP) y su sensor.
    source_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_devices.id", ondelete="SET NULL")
    )
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    last_poll_id: Mapped[int | None] = mapped_column(BigInteger)
    # --- vinculación con evidencia (mismo site) ---
    network_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_devices.id", ondelete="SET NULL")
    )
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    # {"asset": {...}, "network_device": {...}}: base (management_ip, mac, source_device),
    # valor coincidente, método (automatic/manual), quién y cuándo.
    link_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Tras desvincular a mano, la vinculación automática no vuelve a enlazar sola.
    link_suppressed: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # --- decisión del operador ---
    authorization_status: Mapped[str] = mapped_column(
        String(16), default="unknown", server_default="unknown"
    )
    authorization_reason: Mapped[str | None] = mapped_column(String(500))
    authorization_by: Mapped[str | None] = mapped_column(String(64))
    authorization_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class WlanBss(Base):
    """Un BSS (BSSID) del site: lo emite una radio de un AP con un SSID.

    Se fusionan por (site, BSSID) la vista de la infraestructura (SNMP) y la de los agentes:
    los campos que da cada fuente se guardan en su columna y la procedencia queda en
    `sources` y en el historial. `vlan_id` solo se rellenaría con evidencia verificable; hoy
    ninguna fuente implementada la da, así que siempre es None (documentado).
    """

    __tablename__ = "wlan_bss"
    __table_args__ = (
        UniqueConstraint("site_id", "bssid", name="uq_wlan_bss_site_bssid"),
        Index("ix_wlan_bss_site_ssid", "site_id", "ssid"),
        Index("ix_wlan_bss_site_seen", "site_id", "last_seen_at"),
        Index("ix_wlan_bss_access_point", "access_point_id"),
        Index("ix_wlan_bss_source_device", "source_device_id"),
        Index("ix_wlan_bss_sensor", "sensor_id"),
        Index("ix_wlan_bss_agent_asset", "last_agent_asset_id"),
        CheckConstraint(
            "authorization_status IN ('unknown', 'authorized', 'external')",
            name="ck_wlan_bss_authorization",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    bssid: Mapped[str] = mapped_column(String(17))
    ssid: Mapped[str | None] = mapped_column(String(64))
    # "2.4" / "5" / "6" o None si la fuente no permite determinarla sin adivinar.
    band: Mapped[str | None] = mapped_column(String(4))
    channel: Mapped[int | None] = mapped_column(SmallInteger)
    frequency_mhz: Mapped[int | None] = mapped_column(Integer)
    # Protección informada, normalizada (open, wep, wpa, wpa2, wpa3, wpa2_wpa3, owe, rsn,
    # legacy, unknown) y el texto original del agente, acotado.
    protection: Mapped[str | None] = mapped_column(String(16))
    protection_reported: Mapped[str | None] = mapped_column(String(64))
    standard: Mapped[str | None] = mapped_column(String(16))
    signal_dbm: Mapped[int | None] = mapped_column(SmallInteger)
    signal_quality: Mapped[int | None] = mapped_column(SmallInteger)
    client_count: Mapped[int | None] = mapped_column(Integer)
    vlan_id: Mapped[int | None] = mapped_column(SmallInteger)
    access_point_id: Mapped[int | None] = mapped_column(
        ForeignKey("wlan_access_points.id", ondelete="SET NULL")
    )
    # Fuente más reciente y conjunto de fuentes que lo han informado (acotado).
    source: Mapped[str] = mapped_column(String(24))
    sources: Mapped[list[str]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    confidence: Mapped[str] = mapped_column(String(24))
    source_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_devices.id", ondelete="SET NULL")
    )
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    last_agent_asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL")
    )
    last_poll_id: Mapped[int | None] = mapped_column(BigInteger)
    last_snmp_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_agent_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    authorization_status: Mapped[str] = mapped_column(
        String(16), default="unknown", server_default="unknown"
    )
    authorization_reason: Mapped[str | None] = mapped_column(String(500))
    authorization_by: Mapped[str | None] = mapped_column(String(64))
    authorization_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class WlanClient(Base):
    """Cliente inalámbrico observado.

    `client_key` = "mac:<MAC>" si hay MAC; si no, "asset:<uuid>:<interfaz>" (un agente que
    informa de su propia interfaz sin MAC). `identity_confidence`:
    - confirmed: el propio agente del activo informa de su interfaz conectada;
    - probable: MAC globalmente administrada que coincide con UN activo del mismo site;
    - observation_only: MAC aleatoria (bit localmente administrado) o sin coincidencia.
    """

    __tablename__ = "wlan_clients"
    __table_args__ = (
        UniqueConstraint("site_id", "client_key", name="uq_wlan_clients_site_key"),
        Index("ix_wlan_clients_site_seen", "site_id", "last_seen_at"),
        Index("ix_wlan_clients_access_point", "access_point_id"),
        Index("ix_wlan_clients_asset", "asset_id"),
        Index("ix_wlan_clients_source_device", "source_device_id"),
        Index("ix_wlan_clients_sensor", "sensor_id"),
        Index("ix_wlan_clients_site_bssid", "site_id", "bssid"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    client_key: Mapped[str] = mapped_column(String(160))
    mac: Mapped[str | None] = mapped_column(String(17))
    mac_randomized: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    bssid: Mapped[str | None] = mapped_column(String(17))
    ssid: Mapped[str | None] = mapped_column(String(64))
    access_point_id: Mapped[int | None] = mapped_column(
        ForeignKey("wlan_access_points.id", ondelete="SET NULL")
    )
    radio_slot: Mapped[int | None] = mapped_column(SmallInteger)
    band: Mapped[str | None] = mapped_column(String(4))
    standard: Mapped[str | None] = mapped_column(String(16))
    # associated, authenticated, connected, idle, power_save, disassociated, pending,
    # probing, excluded, unknown (según la fuente).
    state: Mapped[str] = mapped_column(String(24), default="unknown", server_default="unknown")
    source: Mapped[str] = mapped_column(String(24))
    identity_confidence: Mapped[str] = mapped_column(String(24))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    correlation_basis: Mapped[str | None] = mapped_column(String(32))
    source_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_devices.id", ondelete="SET NULL")
    )
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    last_poll_id: Mapped[int | None] = mapped_column(BigInteger)
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class WlanConfiguredNetwork(Base):
    """WLAN (SSID) configurada en una controladora, tal como la informa (sin BSSID)."""

    __tablename__ = "wlan_configured_networks"
    __table_args__ = (
        UniqueConstraint(
            "device_id", "source", "network_key", name="uq_wlan_configured_networks_key"
        ),
        Index("ix_wlan_configured_networks_site_ssid", "site_id", "ssid"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    device_id: Mapped[int] = mapped_column(ForeignKey("network_devices.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(24))
    network_key: Mapped[str] = mapped_column(String(32))
    ssid: Mapped[str | None] = mapped_column(String(64))
    client_count: Mapped[int | None] = mapped_column(Integer)
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_poll_id: Mapped[int | None] = mapped_column(BigInteger)


class WlanObservation(Base):
    """Historial: una observación de un AP, BSS o cliente con su procedencia y hora.

    Exactamente una de access_point_id / bss_id / client_id. Para acotar el volumen, una
    misma entidad y fuente solo genera fila nueva si algo material cambió o si la última es
    más antigua que el intervalo mínimo (app/network/wlan.py). `data` es una foto acotada.
    """

    __tablename__ = "wlan_observations"
    __table_args__ = (
        Index("ix_wlan_observations_ap", "access_point_id", "observed_at"),
        Index("ix_wlan_observations_bss", "bss_id", "observed_at"),
        Index("ix_wlan_observations_client", "client_id", "observed_at"),
        Index("ix_wlan_observations_site", "site_id", "observed_at"),
        Index("ix_wlan_observations_poll", "poll_id"),
        Index("ix_wlan_observations_sensor", "sensor_id"),
        Index("ix_wlan_observations_agent_asset", "agent_asset_id"),
        Index("ix_wlan_observations_source_device", "source_device_id"),
        CheckConstraint(
            "num_nonnulls(access_point_id, bss_id, client_id) = 1",
            name="ck_wlan_observations_one_entity",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    access_point_id: Mapped[int | None] = mapped_column(
        ForeignKey("wlan_access_points.id", ondelete="CASCADE")
    )
    bss_id: Mapped[int | None] = mapped_column(ForeignKey("wlan_bss.id", ondelete="CASCADE"))
    client_id: Mapped[int | None] = mapped_column(ForeignKey("wlan_clients.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[str] = mapped_column(String(24))
    poll_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_device_polls.id", ondelete="SET NULL")
    )
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    source_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_devices.id", ondelete="SET NULL")
    )
    agent_asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)


class WlanAgentReport(Base):
    """Último informe `wireless` de cada agente (estado de la fuente y sus interfaces).

    Sirve para los indicadores de disponibilidad de datos: un agente sin adaptador, sin
    permisos (p. ej. macOS sin permiso de ubicación oculta los BSSID) o con error no es lo
    mismo que "no hay redes". Una fila por activo; solo se sustituye por un informe más nuevo.
    """

    __tablename__ = "wlan_agent_reports"
    __table_args__ = (Index("ix_wlan_agent_reports_site", "site_id", "collected_at"),)

    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    status: Mapped[str] = mapped_column(String(24))
    source: Mapped[str] = mapped_column(String(32))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # [{"name", "mac", "mac_randomized", "connected_ssid", "connected_bssid"}], como mucho 8.
    interfaces: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    networks_reported: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    networks_without_bssid: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
