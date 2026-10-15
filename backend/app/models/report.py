"""Informes persistentes (Fase 5E): trabajo, snapshot reproducible y artefacto final.

Un informe es evidencia del SOC: debe poder responder qué datos se usaron, cuándo, con qué
filtros, quién lo pidió y con qué plantilla. Por eso la fila guarda, además del estado del
trabajo, el snapshot estructurado (acotado por REPORT_MAX_ROWS) del que salen TODOS los
formatos, su SHA-256 y la hora de corte de los datos (`cutoff_at`). El artefacto (PDF, HTML,
CSV o ZIP) vive en disco, fuera del repositorio; aquí solo su metadata y su checksum.

Ver docs/reporting.md, docs/report-storage.md y docs/report-security.md.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

PENDING = "pending"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
CANCELLED = "cancelled"
EXPIRED = "expired"
REPORT_STATUSES = (PENDING, RUNNING, SUCCEEDED, FAILED, CANCELLED, EXPIRED)
ACTIVE_REPORT_STATUSES = frozenset({PENDING, RUNNING})
ACTIVE_PREDICATE = "status IN ('pending', 'running')"


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        # Historial (más recientes primero) y filtros habituales.
        Index("ix_reports_created", "created_at"),
        Index("ix_reports_type_created", "report_type", "created_at"),
        Index("ix_reports_status_created", "status", "created_at"),
        Index("ix_reports_user_created", "created_by_user_id", "created_at"),
        # Cola del worker y recuperación de trabajos huérfanos: solo filas vivas.
        Index(
            "ix_reports_active",
            "status",
            "lease_until",
            postgresql_where=text(ACTIVE_PREDICATE),
        ),
        # Doble clic o reintento del navegador: la misma clave de idempotencia de un usuario
        # devuelve siempre el mismo informe (también si ya terminó).
        Index(
            "uq_reports_idempotency",
            "created_by_user_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
        # Anti-duplicado: la misma petición (mismo usuario, tipo, formato, filtros y rango) no
        # puede tener dos trabajos vivos a la vez; la segunda recibe el primero.
        Index(
            "uq_reports_active_request",
            "request_hash",
            unique=True,
            postgresql_where=text(ACTIVE_PREDICATE),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # Tipo del catálogo cerrado (app/reports/catalog.py) y versión de su plantilla.
    report_type: Mapped[str] = mapped_column(String(32))
    template_version: Mapped[int] = mapped_column(Integer)
    # Título generado por el servidor (nunca texto libre del usuario).
    title: Mapped[str] = mapped_column(String(200))
    format: Mapped[str] = mapped_column(String(16))
    classification: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    # Quién lo pidió: copia del nombre (se lee aunque el usuario se borre) y FK.
    created_by: Mapped[str] = mapped_column(String(64))
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Hora de corte común de TODAS las secciones: inicio de la transacción REPEATABLE READ
    # en la que se leyeron los datos ("Datos a fecha de").
    cutoff_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Rango normalizado en UTC (null en tipos que no usan rango, p. ej. incidente).
    time_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    time_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timezone: Mapped[str] = mapped_column(String(32))
    # Filtros ya validados y normalizados por el servidor, y alcance resuelto (nombres de
    # los objetivos en el momento de pedirlo).
    filters: Mapped[dict[str, Any]] = mapped_column(JSONB)
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB)
    # Frases deterministas del resumen (app/reports/summary.py).
    summary: Mapped[list[str] | None] = mapped_column(JSONB)
    # Snapshot estructurado del que salen todos los formatos. Acotado (REPORT_MAX_ROWS por
    # tabla y tope total en el servicio); se vacía al expirar el informe.
    snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    snapshot_sha256: Mapped[str | None] = mapped_column(String(64))
    snapshot_bytes: Mapped[int | None] = mapped_column(Integer)
    idempotency_key: Mapped[str | None] = mapped_column(String(64))
    request_hash: Mapped[str] = mapped_column(String(64))
    # Lease del worker: un trabajo running con el lease vencido es de un proceso caído.
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(SmallInteger, default=0)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(String(500))
    # Expiración por retención o borrado por un admin: el artefacto se elimina, la fila
    # (metadata, checksum, resumen) se conserva como rastro.
    expired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expired_by: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, default=1)


class ReportArtifact(Base):
    """Fichero final de un informe. Nombre y ruta los genera el servidor; nunca el cliente."""

    __tablename__ = "report_artifacts"
    __table_args__ = (
        # Un artefacto por informe (también sirve de índice de la FK).
        Index("uq_report_artifacts_report", "report_id", unique=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id", ondelete="CASCADE"))
    format: Mapped[str] = mapped_column(String(16))
    # Nombre de descarga (Content-Disposition) construido solo con tipo, fecha e id.
    filename: Mapped[str] = mapped_column(String(160))
    content_type: Mapped[str] = mapped_column(String(64))
    # Ruta RELATIVA dentro de REPORT_OUTPUT_DIR ("2026/10/<uuid>.pdf"), validada al leer.
    storage_key: Mapped[str] = mapped_column(String(200))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
