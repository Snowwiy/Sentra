"""Operaciones de mantenimiento autorizadas y atribución de detecciones (Fase 7B.1).

Ver docs/detection-attribution.md. Una OPERACIÓN describe, antes o después de hacerla, una
tarea de mantenimiento concreta sobre UN activo (instalar el agente, inicializar la base de
datos...) con referencias comprobables: SHA-256 y ruta canónica de cada script o binario,
servicios que crea (nombre + ImagePath exacto + cuenta), cuentas ejecutoras, intérprete o
proceso padre esperado y una ventana temporal cerrada. Un admin la crea y la aprueba de
forma explícita; caduca y se revoca (nunca se borra), y cada versión nueva sustituye a la
anterior sin modificarla.

La ATRIBUCIÓN compara la evidencia guardada de una detección (detection_evidence) con las
operaciones aprobadas del activo y deja un veredicto:

- verified_benign: TODA la evidencia casa con UNA operación (hash, ruta, cuenta, ventana...);
- suspicious_unverified: hay evidencia comprobable y algo no casa (o no hay operación);
- insufficient_evidence: falta un dato necesario para comprobar (sin hash, sin cuenta...);
- confirmed_malicious: solo lo decide una persona (analista), nunca el motor.

El historial (detection_attribution_events) es de solo inserción: cada evaluación que cambia
el veredicto y cada decisión del analista es una fila nueva, y la API no expone ni UPDATE
ni DELETE sobre ella.
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
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


OPERATION_STATUSES = ("pending_review", "approved", "revoked", "superseded")
OPERATION_KINDS = (
    "agent_install",
    "agent_upgrade",
    "sensor_install",
    "database_init",
    "server_setup",
    "software_install",
    "other",
)
ARTIFACT_KINDS = ("script", "binary", "service")
# De dónde sale la referencia de un hash: la escribe un admin tras comprobar el fichero, o
# es el fichero que distribuye este mismo servidor (catálogo de referencia). Nunca se copia
# de lo que observó una detección.
REFERENCE_SOURCES = ("manual", "server_distribution")

VERDICTS = (
    "verified_benign",
    "suspicious_unverified",
    "insufficient_evidence",
    "confirmed_malicious",
)
VERDICT_SOURCES = ("system", "analyst")


class MaintenanceOperation(Base):
    __tablename__ = "maintenance_operations"
    __table_args__ = (
        Index("ix_maintenance_operations_asset_window", "asset_id", "window_start", "window_end"),
        Index("ix_maintenance_operations_supersedes", "supersedes_id"),
        CheckConstraint(_in("status", OPERATION_STATUSES), name="ck_maintenance_operations_status"),
        CheckConstraint(_in("kind", OPERATION_KINDS), name="ck_maintenance_operations_kind"),
        CheckConstraint("window_end > window_start", name="ck_maintenance_operations_window"),
        CheckConstraint("expires_at >= window_end", name="ck_maintenance_operations_expiry"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # Identificador estable de la operación a través de sus versiones: lo que enlaza los
    # eventos relacionados (detecciones, historial) aunque un admin corrija la ficha.
    operation_key: Mapped[uuid.UUID] = mapped_column(Uuid, default=uuid.uuid4)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    supersedes_id: Mapped[int | None] = mapped_column(
        ForeignKey("maintenance_operations.id", ondelete="RESTRICT")
    )
    # Siempre UN activo: una operación nunca vale para "todos los equipos".
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(200))
    reason: Mapped[str] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(16), default="pending_review")
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Cuentas que pueden ejecutar los scripts (SID S-1-5-... o DOMINIO\usuario, en
    # minúsculas), intérprete esperado (ruta canónica de powershell.exe/pwsh.exe) y proceso
    # padre esperado (ruta canónica). Listas vacías = "no se exige" (y el veredicto lo dice).
    accounts: Mapped[list[str]] = mapped_column(JSONB, default=list)
    interpreters: Mapped[list[str]] = mapped_column(JSONB, default=list)
    parents: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Firmante exigido al intérprete o al binario si la telemetría lo trae.
    signer: Mapped[str | None] = mapped_column(String(255))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    approved_by: Mapped[str | None] = mapped_column(String(64))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approval_note: Mapped[str | None] = mapped_column(String(500))
    revoked_by: Mapped[str | None] = mapped_column(String(64))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(500))
    # Cuántas detecciones verificó (contador informativo, lo actualiza la atribución).
    matches: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_match_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MaintenanceArtifact(Base):
    """Un script, binario o servicio que la operación autoriza (inmutable con su versión)."""

    __tablename__ = "maintenance_artifacts"
    __table_args__ = (
        Index("ix_maintenance_artifacts_operation", "operation_id"),
        Index("ix_maintenance_artifacts_sha256", "sha256"),
        CheckConstraint(_in("kind", ARTIFACT_KINDS), name="ck_maintenance_artifacts_kind"),
        CheckConstraint(
            _in("reference_source", REFERENCE_SOURCES), name="ck_maintenance_artifacts_source"
        ),
        CheckConstraint(
            "sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'", name="ck_maintenance_artifacts_sha256"
        ),
        # Un script o binario sin hash no se puede verificar: la ficha lo exige.
        CheckConstraint(
            "kind = 'service' OR sha256 IS NOT NULL", name="ck_maintenance_artifacts_hash"
        ),
        CheckConstraint(
            "kind <> 'service' OR (service_name IS NOT NULL AND image_path IS NOT NULL)",
            name="ck_maintenance_artifacts_service",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    operation_id: Mapped[int] = mapped_column(
        ForeignKey("maintenance_operations.id", ondelete="CASCADE")
    )
    kind: Mapped[str] = mapped_column(String(16))
    # Ruta canónica (minúsculas, separadores normalizados) del script o binario.
    path: Mapped[str | None] = mapped_column(String(1024))
    sha256: Mapped[str | None] = mapped_column(String(64))
    signer: Mapped[str | None] = mapped_column(String(255))
    reference_source: Mapped[str] = mapped_column(String(24), default="manual")
    # Servicio: nombre (clave del SCM o nombre visible del 7045, en minúsculas), ImagePath
    # completo normalizado y cuenta con la que corre.
    service_name: Mapped[str | None] = mapped_column(String(255))
    service_display_name: Mapped[str | None] = mapped_column(String(255))
    image_path: Mapped[str | None] = mapped_column(String(1024))
    service_account: Mapped[str | None] = mapped_column(String(255))


class DetectionAttributionEvent(Base):
    """Historial inmutable de veredictos de una detección (sistema y analista)."""

    __tablename__ = "detection_attribution_events"
    __table_args__ = (
        Index("ix_detection_attribution_events_detection", "detection_id", "created_at"),
        Index("ix_detection_attribution_events_operation", "operation_id"),
        CheckConstraint(_in("verdict", VERDICTS), name="ck_detection_attribution_events_verdict"),
        CheckConstraint(
            _in("source", VERDICT_SOURCES), name="ck_detection_attribution_events_source"
        ),
        # El motor nunca confirma un compromiso: solo una persona.
        CheckConstraint(
            "verdict <> 'confirmed_malicious' OR source = 'analyst'",
            name="ck_detection_attribution_events_malicious",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    detection_id: Mapped[int] = mapped_column(ForeignKey("detections.id", ondelete="CASCADE"))
    verdict: Mapped[str] = mapped_column(String(32))
    previous_verdict: Mapped[str | None] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(16))
    operation_id: Mapped[int | None] = mapped_column(
        ForeignKey("maintenance_operations.id", ondelete="SET NULL")
    )
    actor: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str | None] = mapped_column(String(1000))
    # Comprobaciones hechas (qué se esperaba, qué se observó, resultado) y lo que faltó.
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
