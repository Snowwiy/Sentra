"""Sites y sensores distribuidos (Fase 5F, docs/sites.md y docs/distributed-sensors.md).

Un Site es una ubicación lógica/física monitorizada (oficina, sede, laboratorio). NO es un
tenant: todos los sites pertenecen a la misma instalación de Sentra y el RBAC sigue siendo
global. Sirve para que las direcciones privadas dejen de ser globalmente únicas: dos sites
pueden usar 192.168.1.0/24 a la vez y 192.168.1.20 de cada uno son activos distintos.

Tablas:
- sites / site_networks: el site y sus redes autorizadas (las únicas que un sensor del site
  puede escanear). Se permite el solapamiento ENTRE sites, nunca dentro de uno.
- sensors / sensor_enrollment_tokens: sensores (procesos de observación de red dentro de un
  site) con identidad propia; solo se guarda el SHA-256 de su credencial y del token de un
  solo uso con el que se enrolaron.
- sensor_jobs: tareas de un catálogo cerrado dirigidas a UN sensor concreto, con lease,
  intentos e idempotencia. Nunca existe un campo de comando: no hay ejecución arbitraria.
- sensor_job_batches / sensor_observations: lotes de resultados recibidos (idempotentes por
  batch_id) y las observaciones validadas que contienen. Son evidencia con procedencia
  (site, sensor, job, hora) que el servidor convierte en activos con su propia lógica: el
  sensor nunca decide "este es el activo X".
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

SITE_STATUSES = ("active", "disabled", "archived")
# Expresión SQL del site por defecto. Es el valor por defecto de assets.site_id y
# discovery_jobs.site_id (función creada en la migración 0032): así todo el código anterior a
# 5F (agentes, discovery local, CLI, tests) que crea filas sin site sigue funcionando y sus
# datos caen en el site local, que es exactamente la semántica histórica.
DEFAULT_SITE_SQL = "sentra_default_site_id()"

# Estados guardados de un sensor. El estado que ve la UI (online/offline/stale/pending) se
# deriva al leer de last_seen_at, igual que el de los agentes: nunca queda desfasado.
SENSOR_STATUSES = ("active", "disabled", "revoked")

SENSOR_JOB_STATUSES = (
    "pending",
    "leased",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "expired",
)
OPEN_SENSOR_JOB_STATUSES = ("pending", "leased", "running")
OPEN_SENSOR_JOB_PREDICATE = "status IN ('pending', 'leased', 'running')"


class Site(Base):
    __tablename__ = "sites"
    __table_args__ = (
        # Un único site por defecto (el "Local" histórico), garantizado por la base de datos.
        Index("uq_sites_default", "is_default", unique=True, postgresql_where=text("is_default")),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100))
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str | None] = mapped_column(String(500))
    # Etiqueta libre ("Madrid - planta 2"). No se pide una dirección física precisa.
    location_label: Mapped[str | None] = mapped_column(String(200))
    # Zona IANA para mostrar horas locales del site; internamente todo sigue en UTC.
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", server_default="UTC")
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # Concurrencia optimista de la edición (409 site_conflict).
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_by: Mapped[str | None] = mapped_column(String(64))
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    archive_reason: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    @property
    def is_active(self) -> bool:
        return self.status == "active"


class SiteNetwork(Base):
    __tablename__ = "site_networks"
    __table_args__ = (
        # Misma red repetida en un site = ambigüedad; entre sites distintos sí se permite.
        UniqueConstraint("site_id", "cidr", name="uq_site_networks_site_cidr"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # RESTRICT: un site nunca se borra con datos; sus redes se quitan antes de forma explícita.
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    cidr: Mapped[str] = mapped_column(String(64))
    name: Mapped[str | None] = mapped_column(String(100))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_by: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Sensor(Base):
    __tablename__ = "sensors"
    __table_args__ = (Index("ix_sensors_site", "site_id"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # El site del sensor se fija al enrolar (lo decide el token, nunca el sensor) y es la
    # única fuente del site de todo lo que el sensor envía: un sensor no puede hablar por otro.
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    # SHA-256 de la credencial (256 bits aleatorios: no hace falta un hash lento). Se conserva
    # tras revocar para poder responder 403 sensor_revoked en vez de 401: el sensor deja de
    # reintentar en lugar de quedarse en bucle.
    credential_hash: Mapped[str] = mapped_column(String(64), unique=True)
    credential_issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Rotación en dos fases: la nueva credencial convive con la anterior hasta su primer uso,
    # así un corte justo después de rotar no deja al sensor sin identidad.
    pending_credential_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    rotation_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hostname: Mapped[str | None] = mapped_column(String(255))
    platform: Mapped[str | None] = mapped_column(String(32))
    sensor_version: Mapped[str | None] = mapped_column(String(32))
    # Capacidades declaradas, filtradas por la allowlist del servidor (app/sensors/catalog.py).
    capabilities: Mapped[list[str] | None] = mapped_column(JSONB)
    # Metadata operativa del último heartbeat (cola, spool, uptime, último job correcto).
    # Solo claves conocidas y numéricas/fechas: nunca variables de entorno ni secretos.
    health: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Diferencia reloj del sensor - reloj del servidor en el último heartbeat (diagnóstico).
    clock_skew_seconds: Mapped[int | None] = mapped_column(Integer)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(64))
    revoke_reason: Mapped[str | None] = mapped_column(String(500))
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class SensorEnrollmentToken(Base):
    """Token de un solo uso para enrolar UN sensor en un site concreto.

    Solo se guarda su SHA-256; el valor se muestra una vez al crearlo. Se consume en la misma
    transacción que crea el sensor, con la fila bloqueada: dos sensores con el mismo token no
    pueden entrar los dos.
    """

    __tablename__ = "sensor_enrollment_tokens"
    __table_args__ = (
        Index("ix_sensor_enrollment_tokens_site", "site_id", "created_at"),
        Index("ix_sensor_enrollment_tokens_sensor", "sensor_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    # Nombre que tendrá el sensor: lo decide el admin, no el host que se enrola.
    sensor_name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))

    def state(self, now: datetime) -> str:
        if self.revoked_at is not None:
            return "revoked"
        if self.used_at is not None:
            return "consumed"
        if now >= self.expires_at:
            return "expired"
        return "active"


class SensorJob(Base):
    __tablename__ = "sensor_jobs"
    __table_args__ = (
        # Poll del sensor y barrido de leases: solo filas vivas (índice parcial pequeño).
        Index(
            "ix_sensor_jobs_open",
            "sensor_id",
            "status",
            "created_at",
            postgresql_where=text(OPEN_SENSOR_JOB_PREDICATE),
        ),
        # Historial por sensor (UI) y FK.
        Index("ix_sensor_jobs_sensor_created", "sensor_id", "created_at"),
        Index("ix_sensor_jobs_site", "site_id"),
        Index("ix_sensor_jobs_discovery", "discovery_job_id"),
        # Un doble clic (misma clave) no crea dos jobs para el mismo sensor.
        Index(
            "uq_sensor_jobs_idempotency",
            "sensor_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    # Siempre dirigido a un sensor concreto: nada de reparto aleatorio entre sensores.
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensors.id", ondelete="RESTRICT"))
    job_type: Mapped[str] = mapped_column(String(32))
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Plazo para EMPEZAR: un job que nadie recoge a tiempo caduca (expired), nunca espera
    # indefinidamente a un sensor que quizá no vuelva.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    leased_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    max_attempts: Mapped[int] = mapped_column(SmallInteger, default=2, server_default="2")
    idempotency_key: Mapped[str | None] = mapped_column(String(64))
    discovery_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("discovery_jobs.id", ondelete="SET NULL")
    )
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(String(300))
    # Resumen del cierre (outcome y contadores) para responder igual a un complete repetido.
    result_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    observations_received: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    batches_received: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_SENSOR_JOB_STATUSES


class SensorJobBatch(Base):
    """Lote de resultados recibido. (job, batch_id) único: reenviar el mismo lote es inocuo."""

    __tablename__ = "sensor_job_batches"
    __table_args__ = (UniqueConstraint("job_id", "batch_id", name="uq_sensor_job_batches"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("sensor_jobs.id", ondelete="CASCADE"))
    batch_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    # Huella del contenido: el mismo batch_id con otro contenido es un conflicto (409), no un
    # reintento, y nunca se mezcla en silencio.
    payload_sha256: Mapped[str] = mapped_column(String(64))
    observation_count: Mapped[int] = mapped_column(Integer)
    attempt: Mapped[int] = mapped_column(SmallInteger)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SensorObservation(Base):
    """Un host visto por un sensor en un job (evidencia; el servidor decide la identidad).

    (job, address) único: el mismo host en dos lotes o en un reintento se fusiona en la misma
    fila (puertos y fuentes por unión) en lugar de duplicarse.
    """

    __tablename__ = "sensor_observations"
    __table_args__ = (
        UniqueConstraint("job_id", "address", name="uq_sensor_observations_job_address"),
        Index("ix_sensor_observations_site", "site_id", "address"),
        Index("ix_sensor_observations_sensor", "sensor_id", "received_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("sensor_jobs.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensors.id", ondelete="RESTRICT"))
    address: Mapped[str] = mapped_column(String(45))
    mac: Mapped[str | None] = mapped_column(String(17))
    hostname: Mapped[str | None] = mapped_column(String(255))
    reverse_dns: Mapped[str | None] = mapped_column(String(255))
    # {"22": "open", "80": "closed"}: estado de cada puerto sondeado.
    ports: Mapped[dict[str, str]] = mapped_column(JSONB)
    sources: Mapped[list[str]] = mapped_column(JSONB)
    # Hora del sensor (validada contra el desfase permitido) y hora del servidor al recibir:
    # la del servidor es la autoridad; la del sensor se conserva como evidencia (6D/6E).
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
