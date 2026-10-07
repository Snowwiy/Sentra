import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
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


class EventLevel(enum.StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class SystemEvent(Base):
    """An event reported by an agent from the host's own logs (Windows Event Log, systemd journal).

    Kept separate from telemetry (periodic measurements) and alerts (Sentra's own rule
    findings): events are facts the host recorded, which future rules can turn into alerts.
    """

    __tablename__ = "system_events"
    __table_args__ = (
        # Agents may resend events after a lost response; the host's own record id makes the
        # insert idempotent instead of duplicating rows.
        UniqueConstraint("asset_id", "channel", "record_id", name="uq_system_events_record"),
        Index("ix_system_events_asset_occurred", "asset_id", "occurred_at"),
        Index("ix_system_events_occurred", "occurred_at"),
        # Fase 5C: matching retroactivo de IOCs de IP contra la IP de origen de los logons
        # (4624/4625) sin recorrer toda la tabla. Parcial: solo eventos que la traen.
        Index(
            "ix_system_events_ip_address",
            text("(data ->> 'IpAddress')"),
            postgresql_where=text("data ? 'IpAddress'"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))

    source: Mapped[str] = mapped_column(String(32))
    channel: Mapped[str] = mapped_column(String(255))
    record_id: Mapped[int] = mapped_column(BigInteger)
    # Id del evento en Windows. Null en Linux (Fase 5C.1): el journal no tiene ids de evento
    # y un número inventado se confundiría con un id real de Windows.
    event_code: Mapped[int | None] = mapped_column(Integer)
    # Tipo normalizado de los eventos Linux (auth_failure, sudo_command, service_failed...),
    # asignado por el agente con una lista cerrada. Null en los eventos de Windows.
    event_type: Mapped[str | None] = mapped_column(String(48))
    provider: Mapped[str] = mapped_column(String(255))
    level: Mapped[EventLevel] = mapped_column(
        Enum(
            EventLevel,
            name="event_level",
            values_callable=lambda members: [m.value for m in members],
        )
    )
    message: Mapped[str] = mapped_column(Text)
    # Host name recorded in the event itself (Windows <Computer>). Usually the asset's own
    # name; differs for forwarded events. Null for events sent by older agents.
    computer: Mapped[str | None] = mapped_column(String(255))
    # Campos estructurados del evento (EventData/UserData) que el agente envía desde una
    # lista cerrada por id (Fase 4H): cuenta, SID, tipo de logon, servicio... Datos NO
    # confiables: el motor de detección los normaliza y acota antes de usarlos.
    data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
