"""Asset Context (Fase 4L): contexto operacional y de negocio de un activo.

Asset sigue siendo la identidad (qué equipo es, cómo lo vemos). Asset Context es lo que el
SOC sabe de él y que la red o el agente no pueden observar: función, entorno, responsable,
sensibilidad de los datos, zona lógica, exposición a Internet y etiquetas. No es una CMDB:
son pocos campos acotados, configurados por un administrador.

Diseño:
- tabla 1:1 `asset_context` (PK = asset_id). Una fila ausente equivale a "todo unknown":
  los activos existentes no necesitan backfill y discovery/heartbeat nunca escriben aquí;
- la criticidad NO se duplica: sigue en assets.criticality (Fase 4I). Aquí solo se guarda
  su justificación y quién/cuándo la cambió;
- `provenance` guarda, por campo, de dónde salió el valor (hoy solo "manual"); el modelo
  admite fuentes futuras (snmp, lldp, manufacturer, threat_intel) sin migración;
- `version` es el token de concurrencia optimista (mismo patrón que incidentes 4K);
- etiquetas normalizadas en `asset_tags` e historial de cambios por campo en
  `asset_context_changes` (sin snapshots por heartbeat).
"""

import enum
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    return Enum(enum_cls, name=name, values_callable=lambda members: [m.value for m in members])


class AssetRole(enum.StrEnum):
    """Función operacional del activo. "unknown" mientras nadie la confirme."""

    WORKSTATION = "workstation"
    SERVER = "server"
    DOMAIN_CONTROLLER = "domain_controller"
    DATABASE = "database"
    WEB_SERVER = "web_server"
    APPLICATION_SERVER = "application_server"
    SECURITY_SERVER = "security_server"
    NETWORK_DEVICE = "network_device"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    WIRELESS_AP = "wireless_ap"
    PRINTER = "printer"
    IOT = "iot"
    MOBILE = "mobile"
    VIRTUAL_MACHINE = "virtual_machine"
    CONTAINER_HOST = "container_host"
    UNKNOWN = "unknown"
    OTHER = "other"


class AssetEnvironment(enum.StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
    LAB = "lab"
    PERSONAL = "personal"
    UNKNOWN = "unknown"


class DataSensitivity(enum.StrEnum):
    UNKNOWN = "unknown"
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class NetworkZone(enum.StrEnum):
    """Zona lógica CONFIGURADA. No es una VLAN ni se deduce de la subred."""

    UNKNOWN = "unknown"
    USER = "user"
    SERVER = "server"
    MANAGEMENT = "management"
    DMZ = "dmz"
    GUEST = "guest"
    IOT = "iot"
    SECURITY = "security"
    LAB = "lab"


class ContextSource(enum.StrEnum):
    """Origen de un dato de contexto.

    Hoy solo la API escribe (manual) y la identificación 4E aporta sugerencias calculadas
    (inferred). agent y discovery describen datos observados que ya viven en Asset. Los
    valores *_future quedan reservados para integraciones que NO existen todavía; ninguna
    ruta los acepta como entrada.
    """

    MANUAL = "manual"
    AGENT = "agent"
    DISCOVERY = "discovery"
    INFERRED = "inferred"
    SNMP = "snmp"
    LLDP = "lldp"
    MANUFACTURER = "manufacturer"
    THREAT_INTEL = "threat_intel"


class AssetBusinessContext(Base):
    __tablename__ = "asset_context"
    __table_args__ = (
        # Filtros del listado de activos. Solo donde una condición es selectiva: la
        # exposición confirmada (pocos activos) y el texto de departamento. Los enums de baja
        # cardinalidad (rol, entorno, zona) no se indexan: con 10k activos un índice no
        # mejora un filtro que devuelve una fracción grande de la tabla (ver
        # docs/asset-context.md, Rendimiento).
        Index(
            "ix_asset_context_internet_exposed",
            "internet_exposed",
            postgresql_where=text("internet_exposed IS NOT NULL"),
        ),
        Index("ix_asset_context_department", text("lower(department)")),
        Index(
            "ix_asset_context_updated_by",
            "updated_by_user_id",
            postgresql_where=text("updated_by_user_id IS NOT NULL"),
        ),
    )

    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[AssetRole] = mapped_column(
        _enum(AssetRole, "asset_role"),
        default=AssetRole.UNKNOWN,
        server_default=AssetRole.UNKNOWN.value,
    )
    environment: Mapped[AssetEnvironment] = mapped_column(
        _enum(AssetEnvironment, "asset_environment"),
        default=AssetEnvironment.UNKNOWN,
        server_default=AssetEnvironment.UNKNOWN.value,
    )
    data_sensitivity: Mapped[DataSensitivity] = mapped_column(
        _enum(DataSensitivity, "asset_data_sensitivity"),
        default=DataSensitivity.UNKNOWN,
        server_default=DataSensitivity.UNKNOWN.value,
    )
    network_zone: Mapped[NetworkZone] = mapped_column(
        _enum(NetworkZone, "asset_network_zone"),
        default=NetworkZone.UNKNOWN,
        server_default=NetworkZone.UNKNOWN.value,
    )
    # Tri-estado: NULL = desconocido. True solo cuando un admin lo confirma; un puerto
    # abierto visto desde el servidor de Sentra NO demuestra exposición a Internet.
    internet_exposed: Mapped[bool | None] = mapped_column(Boolean)
    # Texto simple (no es un User de Sentra ni un directorio): persona o equipo responsable.
    owner: Mapped[str | None] = mapped_column(String(128))
    department: Mapped[str | None] = mapped_column(String(64))
    # Justificación de la criticidad (el valor está en assets.criticality) y su autoría.
    criticality_rationale: Mapped[str | None] = mapped_column(String(200))
    criticality_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    criticality_updated_by: Mapped[str | None] = mapped_column(String(64))
    # {campo: {"source": "manual", "updated_at": iso, "updated_by": usuario}}. Solo campos
    # con valor conocido; un campo ausente se presenta como desconocido.
    provenance: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str | None] = mapped_column(String(64))
    updated_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class AssetTag(Base):
    """Etiqueta administrativa normalizada (minúsculas, [a-z0-9._-], límite por activo)."""

    __tablename__ = "asset_tags"
    __table_args__ = (
        # Filtro "activos con la etiqueta X" sin recorrer todas las etiquetas.
        Index("ix_asset_tags_tag", "tag"),
    )

    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    tag: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AssetContextChange(Base):
    """Historial de un campo de contexto: valor anterior, nuevo, actor y origen.

    Una fila por campo cambiado en cada operación (nunca por heartbeat). Los valores van
    acotados y como texto: es historial para personas, no un snapshot del activo.
    """

    __tablename__ = "asset_context_changes"
    __table_args__ = (
        Index("ix_asset_context_changes_asset", "asset_id", "changed_at"),
        Index(
            "ix_asset_context_changes_actor",
            "actor_user_id",
            postgresql_where=text("actor_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    field: Mapped[str] = mapped_column(String(32))
    old_value: Mapped[str | None] = mapped_column(String(300))
    new_value: Mapped[str | None] = mapped_column(String(300))
    source: Mapped[str] = mapped_column(String(16))
    actor: Mapped[str] = mapped_column(String(64))
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
