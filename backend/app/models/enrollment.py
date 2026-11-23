import enum
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class EnrollmentTokenState(enum.StrEnum):
    """Derived, never stored: computed from the timestamps and counters."""

    ACTIVE = "active"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AgentEnrollmentToken(Base):
    """A bootstrap credential that lets one new agent enroll (one-time by default).

    Only the SHA-256 of the token is stored: the token itself is shown once, when created,
    and cannot be recovered from the database. After enrollment the agent uses its own
    per-agent token; this one is never accepted by any other endpoint.
    """

    __tablename__ = "agent_enrollment_tokens"
    __table_args__ = (Index("ix_agent_enrollment_tokens_created", "created_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Set when use_count reaches max_uses.
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    max_uses: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    use_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Optional restrictions checked at enrollment (case-insensitive).
    expected_platform: Mapped[str | None] = mapped_column(String(32))
    expected_hostname: Mapped[str | None] = mapped_column(String(255))
    # Free text for the operator ("Laptop de Ana"); never a secret.
    note: Mapped[str | None] = mapped_column(String(200))
    # How it was created ("cli", "api") and the asset that used it last (audit).
    created_via: Mapped[str] = mapped_column(String(16), default="api")
    last_asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )
    # Fase 5F: site en el que quedará el agente que enrole con este token (null: el site por
    # defecto). Lo decide el admin al crear el token, nunca el agente.
    site_id: Mapped[int | None] = mapped_column(
        ForeignKey("sites.id", ondelete="RESTRICT"), index=True
    )

    def state(self, now: datetime) -> EnrollmentTokenState:
        if self.revoked_at is not None:
            return EnrollmentTokenState.REVOKED
        if self.use_count >= self.max_uses:
            return EnrollmentTokenState.CONSUMED
        if now >= self.expires_at:
            return EnrollmentTokenState.EXPIRED
        return EnrollmentTokenState.ACTIVE


class AgentRecoveryToken(Base):
    """Autorización de recuperación de UNA identidad de agente existente (Fase 7D.1, H01).

    Un token de enrolamiento ordinario solo da de alta identidades NUEVAS: nunca sustituye la
    credencial de un agent_id ya registrado. Cuando una instalación legítima pierde su
    credencial (estado borrado, reinstalación, revocación y rehabilitación), un admin emite
    esta autorización: ligada a un activo, a su agent_id y a su site, de vida corta, de un
    solo uso, con motivo obligatorio y auditada. Solo se guarda el SHA-256.
    """

    __tablename__ = "agent_recovery_tokens"
    __table_args__ = (Index("ix_agent_recovery_tokens_created", "created_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    # Copia del agent_id y del site al emitirla: si un admin mueve el activo de site o una
    # reconciliación cambia su agente, la autorización deja de valer (no se reinterpreta).
    agent_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    site_id: Mapped[int | None] = mapped_column(
        ForeignKey("sites.id", ondelete="SET NULL"), index=True
    )
    expected_hostname: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(64))
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def state(self, now: datetime) -> EnrollmentTokenState:
        if self.revoked_at is not None:
            return EnrollmentTokenState.REVOKED
        if self.used_at is not None:
            return EnrollmentTokenState.CONSUMED
        if now >= self.expires_at:
            return EnrollmentTokenState.EXPIRED
        return EnrollmentTokenState.ACTIVE
