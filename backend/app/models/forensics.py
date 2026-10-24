"""Investigación forense remota (Fase 6E.6, docs/forensic-investigation.md).

- investigations: un caso de recogida de evidencia sobre un activo (opcionalmente ligado a
  un incidente). Agrupa artefactos, notas y paquetes. Nunca se borra desde la API.
- forensic_artifacts: cada evidencia devuelta por el agente para una ejecución de Response.
  El contenido se guarda como el JSON canónico exacto (texto, no JSONB): JSONB reordena y
  normaliza números, y entonces el SHA-256 ya no se podría volver a comprobar.
- investigation_notes: interpretaciones humanas o de IA, siempre separadas de la evidencia.
- evidence_packages: cada ZIP generado, con su SHA-256 y quién lo descargó.

Las FK al activo y al incidente pasan a NULL si se borran: la evidencia conserva una copia del
identificador y del nombre del activo para seguir siendo legible.
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
    String,
    Text,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

INVESTIGATION_STATUSES = ("open", "closed")
INTEGRITY_STATES = ("verified", "mismatch")
NOTE_KINDS = ("note", "ai_summary")


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        Index("ix_investigations_asset", "asset_id", "created_at"),
        Index("ix_investigations_incident", "incident_id"),
        Index("ix_investigations_created", "created_at"),
        CheckConstraint("status IN ('open', 'closed')", name="ck_investigations_status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    asset_public_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    asset_label: Mapped[str] = mapped_column(String(255))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(16), default="open")
    # Retención legal: mientras esté activa, ninguna limpieza futura puede tocar el caso.
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_by: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, default=1)


class ForensicArtifact(Base):
    __tablename__ = "forensic_artifacts"
    __table_args__ = (
        Index("ix_forensic_artifacts_investigation", "investigation_id", "received_at"),
        Index("ix_forensic_artifacts_execution", "execution_id", unique=True),
        Index("ix_forensic_artifacts_asset", "asset_id"),
        CheckConstraint(
            "integrity IN ('verified', 'mismatch')", name="ck_forensic_artifacts_integrity"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT")
    )
    execution_id: Mapped[int | None] = mapped_column(
        ForeignKey("response_executions.id", ondelete="SET NULL")
    )
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    agent_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    # Quién pidió la recogida (operador de la ejecución de Response).
    operator: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    # Alcance pedido (parámetros validados de la acción, p. ej. la ruta del fichero).
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    agent_sha256: Mapped[str | None] = mapped_column(String(64))
    sha256: Mapped[str] = mapped_column(String(64))
    integrity: Mapped[str] = mapped_column(String(16))
    size_bytes: Mapped[int] = mapped_column(Integer)
    content: Mapped[str] = mapped_column(Text)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    limitations: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    platform: Mapped[str | None] = mapped_column(String(16))
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"
    __table_args__ = (
        Index("ix_investigation_notes_investigation", "investigation_id", "created_at"),
        CheckConstraint("kind IN ('note', 'ai_summary')", name="ck_investigation_notes_kind"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT")
    )
    kind: Mapped[str] = mapped_column(String(16), default="note")
    body: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EvidencePackage(Base):
    __tablename__ = "evidence_packages"
    __table_args__ = (
        Index("ix_evidence_packages_investigation", "investigation_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT")
    )
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    artifact_count: Mapped[int] = mapped_column(Integer)
    # El paquete incluía artefactos con integridad no verificada (descarga con aviso aceptado).
    includes_mismatch: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
