"""Registro de auditoría de acciones administrativas y de seguridad.

Cada entrada se guarda en `audit_events` y se escribe también en el log ("sentra.audit"),
para que una auditoría sobreviva aunque se purgue la tabla y se pueda enviar a un SIEM
más adelante sin tocar el código.

Nunca se registra un secreto: las rutas solo pasan identificadores públicos y, por si un
cambio futuro se equivoca, `_clean` elimina cualquier clave de `details` con nombre de
credencial antes de guardarla.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import AuditEvent
from app.models.user import User
from app.schemas.audit import AuditEventList, AuditEventRead

logger = logging.getLogger("sentra.audit")

SUCCESS = "success"
FAILURE = "failure"
DENIED = "denied"

# Fragmentos de nombre de clave que nunca llegan a la auditoría.
_SECRET_KEYS = ("password", "token", "secret", "key", "cookie", "session", "csrf", "hash")


def _clean(details: dict[str, Any] | None) -> dict[str, Any] | None:
    if not details:
        return None
    return {
        key: value
        for key, value in details.items()
        if not any(fragment in key.lower() for fragment in _SECRET_KEYS)
    }


@dataclass(frozen=True)
class Actor:
    """Quién actúa: un usuario del dashboard, la CLI o la API de administración legacy."""

    name: str
    user_id: int | None = None
    client_ip: str | None = None

    @classmethod
    def for_user(cls, user: User, client_ip: str | None) -> "Actor":
        return cls(user.username, user.id, client_ip)


CLI = Actor("cli")


def record(
    session: Session,
    actor: Actor,
    action: str,
    result: str = SUCCESS,
    target_type: str | None = None,
    target_id: object = None,
    details: dict[str, Any] | None = None,
    commit: bool = True,
) -> None:
    """Añade una entrada. Con commit=False queda en la transacción de quien llama."""
    clean = _clean(details)
    target = str(target_id)[:128] if target_id is not None else None
    session.add(
        AuditEvent(
            created_at=datetime.now(UTC),
            actor_user_id=actor.user_id,
            actor=actor.name[:64],
            action=action,
            target_type=target_type,
            target_id=target,
            result=result,
            client_ip=actor.client_ip,
            details=clean,
        )
    )
    if commit:
        session.commit()
    logger.info(
        "audit",
        extra={
            "action": action,
            "actor": actor.name,
            "result": result,
            "target_type": target_type,
            "target_id": target,
            "client": actor.client_ip,
        },
    )


def list_events(session: Session, limit: int, offset: int, action: str | None) -> AuditEventList:
    query = select(AuditEvent)
    if action:
        query = query.where(AuditEvent.action == action)
    rows = session.scalars(
        query.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return AuditEventList(items=[AuditEventRead.model_validate(row) for row in rows])
