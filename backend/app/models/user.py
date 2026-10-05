import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class User(Base):
    """Usuario local del dashboard.

    Sin datos personales (ni nombre real ni email): Sentra solo necesita saber quién hizo
    qué y con qué rol. Los usuarios no se borran, se desactivan: el registro de auditoría
    sigue apuntando a quien hizo cada acción.
    """

    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('admin', 'analyst', 'viewer')", name="role"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # Siempre en forma canónica (core/passwords.normalize_username): el índice único es el
    # que garantiza que no existan "Admin" y "admin" a la vez, también ante dos altas en
    # paralelo.
    username: Mapped[str] = mapped_column(String(32), unique=True)
    # Hash Argon2id en formato PHC (incluye algoritmo, parámetros y sal). Nunca la contraseña.
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Defensa en profundidad: una sesión creada antes de este instante no vale aunque su
    # revocación explícita hubiera fallado (ver services/auth_service.py).
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    sessions: Mapped[list["UserSession"]] = relationship(back_populates="user")


class UserSession(Base):
    """Sesión web del dashboard (cookie HttpOnly). Solo se guarda el hash del ID."""

    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # Identificador público para listar/revocar sesiones sin exponer el ID real.
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Caducidad absoluta: ni con actividad continua una sesión dura más que esto.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Para la caducidad por inactividad; se actualiza como mucho una vez por minuto.
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # logout, password_changed, password_reset, user_disabled, admin, rotated...
    revoked_reason: Mapped[str | None] = mapped_column(String(32))
    # Contexto para que el admin reconozca la sesión al revisarla; no se usa para autorizar.
    client_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))

    user: Mapped[User] = relationship(back_populates="sessions")
