"""Aislamiento seguro de equipos (Fase 6E.7, docs/safe-isolation.md).

Una sesión por petición de aislamiento. El estado del servidor nunca se da por bueno sin el
equipo: `isolated` solo llega con la confirmación verificada del helper local, y el heartbeat
del agente informa del estado real. Si discrepan, la sesión pasa a `unknown` y se alerta.

Estados: requested → approved → applying → isolated → reverting → restored, más failed,
expired (el helper revirtió solo al caducar) y unknown (servidor y equipo no coinciden).
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
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

ISOLATION_STATES = (
    "requested",
    "approved",
    "applying",
    "isolated",
    "reverting",
    "restored",
    "failed",
    "expired",
    "unknown",
)
# Una sesión "viva" impide abrir otra en el mismo activo. `unknown` cuenta como viva: hasta
# que se aclare, el equipo podría seguir aislado.
ACTIVE_ISOLATION_STATES = frozenset(
    {"requested", "approved", "applying", "isolated", "reverting", "unknown"}
)
ACTIVE_ISOLATION_PREDICATE = (
    "status IN ('requested', 'approved', 'applying', 'isolated', 'reverting', 'unknown')"
)


class IsolationSession(Base):
    __tablename__ = "isolation_sessions"
    __table_args__ = (
        Index("ix_isolation_sessions_asset", "asset_id", "requested_at"),
        Index(
            "uq_isolation_sessions_active_asset",
            "asset_id",
            unique=True,
            postgresql_where=text(ACTIVE_ISOLATION_PREDICATE),
        ),
        Index("ix_isolation_sessions_isolate_execution", "isolate_execution_id"),
        Index("ix_isolation_sessions_release_execution", "release_execution_id"),
        Index(
            "ix_isolation_sessions_expires",
            "expires_at",
            postgresql_where=text(ACTIVE_ISOLATION_PREDICATE),
        ),
        CheckConstraint(
            "status IN (" + ", ".join(f"'{s}'" for s in ISOLATION_STATES) + ")",
            name="ck_isolation_sessions_status",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    asset_public_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    asset_label: Mapped[str] = mapped_column(String(255))
    agent_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    status: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(String(500))
    duration_minutes: Mapped[int] = mapped_column(Integer)
    requested_by: Mapped[str] = mapped_column(String(64))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Aprobación = confirmación escrita del admin (nombre del equipo) en la misma petición.
    approved_by: Mapped[str | None] = mapped_column(String(64))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_by: Mapped[str | None] = mapped_column(String(64))
    release_reason: Mapped[str | None] = mapped_column(String(500))
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Lo que el helper aplicó y verificó (informado por el equipo, solo informativo).
    method: Mapped[str | None] = mapped_column(String(32))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed: Mapped[list[str]] = mapped_column(JSONB, default=list)
    rules: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    error_code: Mapped[str | None] = mapped_column(String(64))
    isolate_execution_id: Mapped[int | None] = mapped_column(
        ForeignKey("response_executions.id", ondelete="SET NULL")
    )
    release_execution_id: Mapped[int | None] = mapped_column(
        ForeignKey("response_executions.id", ondelete="SET NULL")
    )
    # Último estado que informó el equipo (heartbeat o resultado de un comando).
    reported_state: Mapped[str | None] = mapped_column(String(16))
    reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, default=1)
