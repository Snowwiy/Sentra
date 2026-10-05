"""Administración de usuarios del dashboard (solo permiso users:manage, es decir, admin).

Los usuarios no se borran: se desactivan, para que la auditoría siga apuntando a quien hizo
cada acción. Ninguna respuesta incluye hashes de contraseña ni IDs de sesión.
"""

from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.exceptions import SentraError
from app.core.permissions import Permission
from app.schemas.auth import (
    PasswordResetRequest,
    SessionList,
    UserCreate,
    UserList,
    UserRead,
    UserUpdate,
)
from app.services import audit_service
from app.services.auth_service import AuthContext, SessionPolicy, UserService

router = APIRouter(prefix="/users", tags=["users"], responses=error_responses(401, 403))
Admin = Annotated[AuthContext, Depends(require_permission(Permission.USERS_MANAGE))]


def get_user_service(session: DbSession, settings: AppSettings) -> UserService:
    return UserService(session, SessionPolicy.from_settings(settings))


Users = Annotated[UserService, Depends(get_user_service)]


def _audited[T](
    session: DbSession, ctx: AuthContext, action: str, target: object, run: Callable[[], T]
) -> T:
    """Ejecuta la operación y la audita con su resultado (también si falla: 404/409/422)."""
    try:
        result = run()
    except SentraError as exc:
        session.rollback()
        audit_service.record(
            session,
            actor(ctx),
            action,
            audit_service.FAILURE,
            "user",
            target,
            details={"error": exc.code},
        )
        raise
    return result


@router.get("", response_model=UserList)
def list_users(_: Admin, users: Users) -> UserList:
    return users.list()


@router.post(
    "",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(409, 422),
)
def create_user(payload: UserCreate, ctx: Admin, users: Users, session: DbSession) -> UserRead:
    user = _audited(session, ctx, "user_created", None, lambda: users.create(payload))
    audit_service.record(
        session,
        actor(ctx),
        "user_created",
        target_type="user",
        target_id=user.public_id,
        details={"username": user.username, "role": user.role},
    )
    return users.read(user)


@router.patch("/{user_id}", response_model=UserRead, responses=error_responses(404, 409, 422))
def update_user(
    user_id: UUID, payload: UserUpdate, ctx: Admin, users: Users, session: DbSession
) -> UserRead:
    user = _audited(session, ctx, "user_updated", user_id, lambda: users.get(user_id))
    changes = _audited(
        session, ctx, "user_updated", user_id, lambda: users.update(user, payload, ctx.user)
    )
    if "role" in changes:
        audit_service.record(
            session,
            actor(ctx),
            "role_changed",
            target_type="user",
            target_id=user_id,
            details={"username": user.username, **changes},
        )
    if "is_active" in changes:
        audit_service.record(
            session,
            actor(ctx),
            "user_enabled" if user.is_active else "user_disabled",
            target_type="user",
            target_id=user_id,
            details={"username": user.username},
        )
    return users.read(user)


@router.post("/{user_id}/password", response_model=UserRead, responses=error_responses(404, 422))
def reset_password(
    user_id: UUID, payload: PasswordResetRequest, ctx: Admin, users: Users, session: DbSession
) -> UserRead:
    """Contraseña nueva fijada por un admin: cierra todas las sesiones de ese usuario."""
    user = _audited(session, ctx, "password_reset", user_id, lambda: users.get(user_id))
    revoked = _audited(
        session,
        ctx,
        "password_reset",
        user_id,
        lambda: users.reset_password(user, payload.new_password),
    )
    audit_service.record(
        session,
        actor(ctx),
        "password_reset",
        target_type="user",
        target_id=user_id,
        details={"username": user.username, "revoked": revoked},
    )
    return users.read(user)


@router.get("/{user_id}/sessions", response_model=SessionList, responses=error_responses(404))
def list_sessions(user_id: UUID, ctx: Admin, users: Users) -> SessionList:
    return users.sessions(users.get(user_id), ctx.session)


@router.post("/{user_id}/sessions/revoke", response_model=UserRead, responses=error_responses(404))
def revoke_sessions(user_id: UUID, ctx: Admin, users: Users, session: DbSession) -> UserRead:
    """Cierra todas las sesiones del usuario (también la propia si es uno mismo)."""
    user = _audited(session, ctx, "sessions_revoked", user_id, lambda: users.get(user_id))
    revoked = users.revoke_sessions(user)
    audit_service.record(
        session,
        actor(ctx),
        "sessions_revoked",
        target_type="user",
        target_id=user_id,
        details={"username": user.username, "count": revoked},
    )
    return users.read(user)
