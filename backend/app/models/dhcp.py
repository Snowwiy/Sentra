"""Fuentes DHCP autorizadas, leases e historial de identidad (Fase 6E.2, docs/dhcp-identity.md).

- dhcp_sources: de dónde se leen leases en un site. Solo lectura y solo de fuentes que un
  admin declaró: un fichero que sube él mismo (`lease_import`) o un fichero local de un sensor
  (`sensor_file`), referenciado por el NOMBRE que el sensor define en su propia configuración.
  El servidor nunca guarda ni envía rutas: un servidor comprometido no puede pedir a un sensor
  que lea otro fichero.
- dhcp_leases: lo que dijo la fuente, normalizado. La asociación a un activo es una
  conclusión aparte (`asset_id` + `match`) con reglas estrictas: nunca fusiona activos y
  nunca asocia por solo IP o por una MAC aleatoria.
- asset_identity_history: cada cambio de nombre automático, etiqueta, IP, MAC, fabricante o
  tipo de un activo con su fuente y confianza. Alimenta la vista de historial de identidad.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

DHCP_SOURCE_KINDS = ("lease_import", "sensor_file")
DHCP_FORMATS = ("dnsmasq", "isc_dhcpd", "kea_csv", "windows_dhcp_csv", "generic_csv")
DHCP_SOURCE_STATUSES = ("pending", "ok", "error", "disabled")
LEASE_STATES = ("active", "expired", "released", "unknown")
# Por qué un lease está (o no) asociado a un activo. Ver app/dhcp/matching.py.
LEASE_MATCHES = (
    "mac_ip",
    "mac_moved",
    "ip_only",
    "randomized_mac",
    "ambiguous",
    "no_asset",
    "expired",
)
# La asociación Wi-Fi (AP, SSID) no se repite aquí: ya la registra network_changes (6E.1)
# con su evidencia, y duplicarla daría dos historias que podrían contradecirse.
IDENTITY_FIELDS = ("name", "label", "ip", "mac", "vendor", "device_type")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class DhcpSource(Base):
    __tablename__ = "dhcp_sources"
    __table_args__ = (
        UniqueConstraint("site_id", "name", name="uq_dhcp_sources_site_name"),
        Index("ix_dhcp_sources_sensor", "sensor_id"),
        # Un job dhcp_leases solo lleva el nombre que el sensor conoce (su esquema no admite más
        # campos), así que (sensor, nombre) debe identificar una única fuente.
        Index(
            "uq_dhcp_sources_sensor_source",
            "sensor_id",
            "sensor_source_name",
            unique=True,
            postgresql_where=text("sensor_id IS NOT NULL"),
        ),
        CheckConstraint(_in("kind", DHCP_SOURCE_KINDS), name="ck_dhcp_sources_kind"),
        CheckConstraint(_in("format", DHCP_FORMATS), name="ck_dhcp_sources_format"),
        CheckConstraint(_in("status", DHCP_SOURCE_STATUSES), name="ck_dhcp_sources_status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(16))
    format: Mapped[str] = mapped_column(String(24))
    # sensor_file: sensor que tiene el fichero y nombre de la entrada [[dhcp_lease_files]] en
    # su sensor.toml. Nunca una ruta.
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    sensor_source_name: Mapped[str | None] = mapped_column(String(64))
    # Cada cuántos minutos se pide al sensor (0 = solo a demanda).
    poll_interval_minutes: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    # Última petición de lectura a un sensor (manual o por poll_interval_minutes).
    last_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_import_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(48))
    # {"lines", "parsed", "skipped", "matched", "truncated"} de la última importación.
    last_stats: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class DhcpLease(Base):
    __tablename__ = "dhcp_leases"
    __table_args__ = (
        # Un lease por (fuente, IP, MAC): la misma IP con otra MAC es otro lease (reutilización).
        UniqueConstraint("source_id", "ip", "mac", name="uq_dhcp_leases_source_ip_mac"),
        Index("ix_dhcp_leases_site_mac", "site_id", "mac"),
        Index("ix_dhcp_leases_site_ip", "site_id", "ip"),
        Index("ix_dhcp_leases_asset", "asset_id"),
        CheckConstraint(_in("state", LEASE_STATES), name="ck_dhcp_leases_state"),
        CheckConstraint(_in("match", LEASE_MATCHES), name="ck_dhcp_leases_match"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    source_id: Mapped[int] = mapped_column(ForeignKey("dhcp_sources.id", ondelete="CASCADE"))
    ip: Mapped[str] = mapped_column(String(45))
    mac: Mapped[str] = mapped_column(String(17))
    hostname: Mapped[str | None] = mapped_column(String(255))
    # Client identifier opaco: se guarda como hash (sha256:...) para correlacionar sin guardar
    # el valor; si era la propia MAC (tipo 01) no aporta nada y queda null.
    client_id: Mapped[str | None] = mapped_column(String(80))
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(String(16))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    match: Mapped[str] = mapped_column(String(16))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AssetIdentityHistory(Base):
    __tablename__ = "asset_identity_history"
    __table_args__ = (
        Index("ix_asset_identity_history_asset", "asset_id", "observed_at"),
        CheckConstraint(_in("field", IDENTITY_FIELDS), name="ck_asset_identity_history_field"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    field: Mapped[str] = mapped_column(String(16))
    old_value: Mapped[str | None] = mapped_column(String(255))
    new_value: Mapped[str | None] = mapped_column(String(255))
    # Quién produjo el valor nuevo: la fuente del nombre (agent_hostname, dhcp_lease, mdns...),
    # agent, discovery o manual.
    source: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[str] = mapped_column(String(8))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
