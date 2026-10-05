from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditEvent(Base):
    """Acción administrativa o de seguridad: quién, qué, sobre qué, cuándo y con qué resultado.

    Solo se añaden filas; ninguna ruta de la API las modifica ni las borra. `details` nunca
    lleva contraseñas, IDs de sesión, tokens de agente o de enrollment ni ADMIN_API_KEY
    (services/audit_service.py filtra las claves sensibles por si acaso).
    """

    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_created", "created_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Usuario del dashboard que actuó; null para la CLI, la API de administración o un
    # login fallido de un usuario inexistente.
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    # Copia del nombre en el momento de la acción ("cli", "admin-api" o el usuario
    # intentado en un login fallido), para que el registro se lea sin joins.
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(128))
    # success, failure (la operación falló) o denied (sin permiso).
    result: Mapped[str] = mapped_column(String(16))
    client_ip: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
