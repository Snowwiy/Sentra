"""Integración SIEM: fuentes externas y eventos normalizados (Fase 7F, docs/fase-7f.md).

Principios:

- Sentra conserva sus propios motores. Syslog, Suricata, Zeek o Wazuh son FUENTES opcionales
  de telemetría: sin ninguna configurada, nada de esto se usa y la plataforma funciona igual.
- Una fuente pertenece a UN site. El site de cada evento sale de la fuente registrada (y de la
  credencial del sensor que la recibe), nunca del contenido del evento.
- Todo lo que llega es dato no confiable: se valida, se acota y se normaliza a un contrato
  propio (`SiemEvent`) con su versión de esquema y de normalizador. Lo que no se puede
  normalizar se rechaza y se cuenta; nunca se rellena un campo con un valor inventado.
- Procedencia: cada evento guarda la fuente, la referencia al registro original
  (`raw_reference`) y el SHA-256 del registro tal como se recibió (`evidence_hash`).
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
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SiemSource(Base):
    """Fuente externa autorizada por un admin (siem:manage).

    `transport` dice cómo llegan sus registros: `sensor` (un sensor del site los recibe o los
    lee y los reenvía por HTTPS saliente) o `upload` (un admin importa un fichero exportado
    desde el dashboard). Con `transport = sensor`, `input_name` es el ALIAS que el operador
    del sensor declaró en su sensor.toml: el servidor nunca envía rutas, puertos ni órdenes.

    El estado (`disabled`, `configured`, `healthy`, `degraded`, `offline`, `error`) se calcula
    al leer (app/siem/status.py) a partir de lo reportado y de los contadores: guardar una
    configuración nunca la deja en `healthy`.
    """

    __tablename__ = "siem_sources"
    __table_args__ = (
        UniqueConstraint("site_id", "name", name="uq_siem_sources_site_name"),
        # Un alias del sensor alimenta como mucho una fuente (si no, el mismo registro
        # entraría por dos fuentes y se contaría dos veces).
        Index(
            "uq_siem_sources_sensor_input",
            "sensor_id",
            "input_name",
            unique=True,
            postgresql_where=text("sensor_id IS NOT NULL"),
        ),
        Index("ix_siem_sources_sensor_id", "sensor_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    source_type: Mapped[str] = mapped_column(String(24))
    name: Mapped[str] = mapped_column(String(100))
    transport: Mapped[str] = mapped_column(String(16))
    input_name: Mapped[str | None] = mapped_column(String(32))
    connector_version: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # Sube con cada cambio de configuración: el sensor reconfigura de forma idempotente.
    revision: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    # Configuración aprobada y validada por el conector (política de severidad, tipos de
    # evento admitidos...). Nunca secretos: las fuentes no guardan credenciales.
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # Días de retención de sus eventos. Null = SIEM_EVENT_RETENTION_DAYS.
    retention_days: Mapped[int | None] = mapped_column(Integer)
    # Cuota propia (eventos por minuto). El exceso responde 429 y el sensor reintenta desde
    # su spool (backpressure), sin perder lo ya aceptado.
    max_events_per_minute: Mapped[int] = mapped_column(Integer)
    quota_window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    quota_window_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    # Contadores acumulados (bigint: una fuente ruidosa puede superar 2^31 en meses).
    events_received: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    events_accepted: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    events_rejected: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    events_duplicate: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    # Pérdidas declaradas por el receptor (tamaño, origen no permitido, spool lleno...).
    events_dropped: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")

    # Salud. `last_success_at`: último lote aceptado; `last_event_at`: marca temporal más
    # reciente de un evento aceptado (lo que la fuente "dice"); `lag_seconds`: retraso entre
    # esa marca y la recepción en el último lote.
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lag_seconds: Mapped[int | None] = mapped_column(Integer)
    last_batch_rejected: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_batch_records: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_error_code: Mapped[str | None] = mapped_column(String(48))
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Lo que el receptor reporta en el heartbeat del sensor (estado enumerado y contadores).
    reported_state: Mapped[str | None] = mapped_column(String(16))
    reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reported: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    created_by: Mapped[str | None] = mapped_column(String(64))
    updated_by: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class SiemBatch(Base):
    """Recibo de un lote (sensor o importación): idempotencia y trazabilidad de rechazos.

    El par (fuente, batch_id) es único: un reenvío del mismo lote responde `duplicate` sin
    tocar nada. Solo se guardan recuentos y motivos de rechazo, nunca los registros.
    """

    __tablename__ = "siem_batches"
    __table_args__ = (
        UniqueConstraint("source_id", "batch_id", name="uq_siem_batches_source_batch"),
        Index("ix_siem_batches_site_received", "site_id", "received_at"),
        Index("ix_siem_batches_received_at", "received_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("siem_sources.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    batch_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    origin: Mapped[str] = mapped_column(String(16))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    records: Mapped[int] = mapped_column(Integer, default=0)
    accepted: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    # {"invalid_json": 3, "too_old": 1}: motivos enumerados, nunca contenido del registro.
    reject_reasons: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    stats: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Retraso de normalización y almacenamiento del lote en el servidor (medido).
    processing_ms: Mapped[int | None] = mapped_column(Integer)


class SiemEvent(Base):
    """Evento normalizado (contrato `sentra.siem.event`, versión SCHEMA_VERSION).

    Los campos ausentes en el origen quedan a NULL: nunca se rellenan para "cumplir" el
    esquema. `observed_at` es la marca del propio evento (UTC); si no la trae, o la trae en
    el futuro más allá del desfase tolerado, se usa la de recepción y `time_quality` lo dice.
    """

    __tablename__ = "siem_events"
    __table_args__ = (
        # Deduplicación garantizada por la base de datos (reintentos, relecturas de un
        # fichero, el mismo registro importado dos veces).
        UniqueConstraint("source_id", "dedup_key", name="uq_siem_events_source_dedup"),
        Index("ix_siem_events_site_observed", "site_id", "observed_at"),
        Index("ix_siem_events_source_observed", "source_id", "observed_at"),
        Index("ix_siem_events_site_src_ip", "site_id", "src_ip", "observed_at"),
        Index("ix_siem_events_site_dst_ip", "site_id", "dst_ip", "observed_at"),
        Index("ix_siem_events_site_type", "site_id", "event_type", "observed_at"),
        Index(
            "ix_siem_events_asset_observed",
            "asset_id",
            "observed_at",
            postgresql_where=text("asset_id IS NOT NULL"),
        ),
        Index(
            "ix_siem_events_sensor_id",
            "sensor_id",
            postgresql_where=text("sensor_id IS NOT NULL"),
        ),
        Index("ix_siem_events_received_at", "received_at"),
        # Fase 7F.6: hunting por usuario dentro de un site y una ventana.
        Index(
            "ix_siem_events_site_username",
            "site_id",
            "username",
            "observed_at",
            postgresql_where=text("username IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    source_id: Mapped[int] = mapped_column(ForeignKey("siem_sources.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    dedup_key: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[int] = mapped_column(SmallInteger)
    normalization_version: Mapped[str] = mapped_column(String(32))
    source_type: Mapped[str] = mapped_column(String(24))
    event_type: Mapped[str] = mapped_column(String(48))
    category: Mapped[str] = mapped_column(String(24))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Cuándo lo recibió el sensor (o se importó) y cuándo lo guardó el servidor.
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # source | receiver (el evento no traía hora) | clamped (venía del futuro).
    time_quality: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    # Valor original de la fuente (p. ej. "level 10", "severity 2"), para ver la política.
    source_severity: Mapped[str | None] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(16))
    hostname: Mapped[str | None] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(45))
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))
    username: Mapped[str | None] = mapped_column(String(128))
    process_name: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str | None] = mapped_column(String(32))
    outcome: Mapped[str | None] = mapped_column(String(16))
    signature_id: Mapped[str | None] = mapped_column(String(64))
    rule_id: Mapped[str | None] = mapped_column(String(64))
    message: Mapped[str | None] = mapped_column(String(1000))
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Identificadores del origen: id de la alerta (Wazuh), flow_id (Suricata) o uid de la
    # conexión (Zeek). Sirven para agrupar registros de una misma comunicación.
    external_id: Mapped[str | None] = mapped_column(String(128))
    flow_ref: Mapped[str | None] = mapped_column(String(64))
    raw_reference: Mapped[str] = mapped_column(String(255))
    evidence_hash: Mapped[str] = mapped_column(String(64))
    # Extracto del registro saneado (acotado por SIEM_RAW_STORE_BYTES; vacío si es 0). Solo
    # con siem:evidence.
    raw_excerpt: Mapped[str | None] = mapped_column(String(8192))
    # Campos propios del conector, acotados (facility, app_name, alert.category...).
    data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Atribución conservadora a un activo del MISMO site (app/siem/identity.py). Sin
    # evidencia suficiente queda a NULL: un evento no atribuible se conserva igual.
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    attribution: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class SiemEventLink(Base):
    """Relación explicada entre un evento SIEM y otra evidencia (Fase 7F.3).

    `kind` dice con qué se relaciona: `ndr_flow` (un flujo del sensor NDR de Sentra),
    `ndr_anomaly`, `siem_event` (otro evento SIEM, p. ej. la misma conexión vista por
    Suricata y Zeek) o `detection`. `method` dice cómo se estableció (5-tupla y tiempo,
    community_id, uid de flujo...) y `confidence` cuánto vale. Un enlace nunca afirma
    causalidad: solo que los dos registros describen, con esa confianza, la misma actividad.

    `target_id` no es clave foránea: los flujos NDR y los eventos se purgan por retención
    con ritmos distintos y un enlace huérfano solo deja de resolverse (se purga con el evento).
    """

    __tablename__ = "siem_event_links"
    __table_args__ = (
        UniqueConstraint("event_id", "kind", "target_id", name="uq_siem_event_links_target"),
        Index("ix_siem_event_links_target", "kind", "target_id"),
        Index("ix_siem_event_links_site_created", "site_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    event_id: Mapped[int] = mapped_column(
        ForeignKey("siem_events.id", ondelete="CASCADE"), index=True
    )
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    target_id: Mapped[int] = mapped_column(BigInteger)
    # Referencia legible del destino (uid del flujo, public_id de la anomalía o del evento).
    target_ref: Mapped[str] = mapped_column(String(64))
    method: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(16))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SiemSavedSearch(Base):
    """Búsqueda guardada de hunting (Fase 7F.6). Privada de quien la crea.

    `query` es el filtro tipado ya validado (app/schemas/siem_hunting.py), nunca SQL ni texto
    libre interpretado. Se vuelve a validar al ejecutarla: si el esquema cambia, una búsqueda
    antigua inválida falla con 422 en vez de ejecutarse a medias.
    """

    __tablename__ = "siem_saved_searches"
    __table_args__ = (
        UniqueConstraint("owner_user_id", "name", name="uq_siem_saved_searches_owner_name"),
        Index("ix_siem_saved_searches_owner", "owner_user_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(100))
    query: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IncidentSiemEvent(Base):
    """Evento SIEM añadido a un incidente como evidencia (Fase 7F.6).

    Guarda una COPIA acotada del evento normalizado y su hash: la retención de eventos SIEM
    es corta (30 días por defecto) y la evidencia de un caso debe sobrevivirla. Si el evento
    se purga, `event_id` queda a NULL y el caso conserva la copia y el hash del registro
    original. Solo se añaden filas; quitar un evento de un caso no está previsto.
    """

    __tablename__ = "incident_siem_events"
    __table_args__ = (
        UniqueConstraint("incident_id", "event_public_id", name="uq_incident_siem_events_event"),
        Index(
            "ix_incident_siem_events_event",
            "event_id",
            postgresql_where=text("event_id IS NOT NULL"),
        ),
        Index(
            "ix_incident_siem_events_attached_by",
            "attached_by_user_id",
            postgresql_where=text("attached_by_user_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    event_id: Mapped[int | None] = mapped_column(ForeignKey("siem_events.id", ondelete="SET NULL"))
    event_public_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    source_name: Mapped[str] = mapped_column(String(100))
    source_type: Mapped[str] = mapped_column(String(24))
    event_type: Mapped[str] = mapped_column(String(48))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    evidence_hash: Mapped[str] = mapped_column(String(64))
    # Campos normalizados y extracto en el momento de añadirlo (texto no confiable).
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    # SHA-256 del snapshot canónico: permite comprobar que la copia no cambió.
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    note: Mapped[str | None] = mapped_column(String(500))
    attached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    attached_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    attached_by: Mapped[str] = mapped_column(String(64))
