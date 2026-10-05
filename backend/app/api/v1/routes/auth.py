"""Login, logout, sesión actual y cambio de contraseña propia (Fase 4G).

Rutas públicas solo /auth/login (sin sesión, por definición). El resto exige sesión válida.
Ninguna respuesta incluye el ID de sesión: viaja solo en la cookie HttpOnly.
"""

import logging

from fastapi import APIRouter, Request, Response, status

from app.api.auth import (
    Auth,
    CurrentAuth,
    actor,
    check_origin,
    clear_session_cookie,
    client_ip,
    get_login_guard,
    session_cookie_name,
    set_session_cookie,
)
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.exceptions import CsrfError, InvalidCredentialsError, RateLimitedError
from app.core.permissions import Role, permissions_for
from app.core.security import csrf_token_for
from app.models.user import User, UserSession
from app.schemas.auth import AuthState, CurrentUser, LoginRequest, PasswordChangeRequest
from app.services import audit_service
from app.services.audit_service import Actor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Mismo mensaje para usuario inexistente, contraseña incorrecta o usuario desactivado.
INVALID_LOGIN = "Invalid username or password"


def auth_state(user: User, session: UserSession, token: str) -> AuthState:
    return AuthState(
        user=CurrentUser(
            user_id=user.public_id,
            username=user.username,
            role=Role(user.role),
            last_login_at=user.last_login_at,
        ),
        permissions=sorted(permissions_for(user.role)),
        csrf_token=csrf_token_for(token),
        session_expires_at=session.expires_at,
    )


@router.post("/login", response_model=AuthState, responses=error_responses(401, 403, 422, 429))
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    settings: AppSettings,
    auth: Auth,
    session: DbSession,
) -> AuthState:
    # Sin sesión todavía no hay token CSRF: el Origin y el Content-Type JSON impiden que
    # otra web haga iniciar sesión al navegador del operador con una cuenta del atacante.
    check_origin(request, settings)
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise CsrfError("Login requires a JSON body")
    ip = client_ip(request)
    guard = get_login_guard(request)
    try:
        guard.check(payload.username, ip)
    except RateLimitedError:
        # Solo al log (sin contraseña): un ataque no debe poder llenar la tabla de auditoría.
        logger.warning("login rate limited", extra={"client": ip})
        raise
    user, ok = auth.authenticate(payload.username, payload.password)
    if user is None or not ok:
        guard.failed(payload.username, ip)
        # El nombre intentado solo se registra si existe: un usuario que no existe a menudo
        # es una contraseña escrita en el campo equivocado y no debe acabar en ningún log.
        audit_service.record(
            session,
            Actor(user.username if user else "unknown", user.id if user else None, ip),
            "login_failed",
            audit_service.FAILURE,
            target_type="user" if user else None,
            target_id=user.public_id if user else None,
            details={"reason": "inactive"} if user is not None and not user.is_active else None,
        )
        raise InvalidCredentialsError(INVALID_LOGIN)
    previous = request.cookies.get(session_cookie_name(settings))
    token, row = auth.start_session(user, ip, request.headers.get("user-agent"), previous)
    guard.succeeded(payload.username, ip)
    audit_service.record(
        session,
        Actor.for_user(user, ip),
        "login_success",
        target_type="user",
        target_id=user.public_id,
    )
    set_session_cookie(response, settings, token)
    return auth_state(user, row, token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, responses=error_responses(401, 403))
def logout(ctx: CurrentAuth, auth: Auth, settings: AppSettings, session: DbSession) -> Response:
    auth.end_session(ctx.session, "logout")
    audit_service.record(
        session, actor(ctx), "logout", target_type="user", target_id=ctx.user.public_id
    )
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookie(response, settings)
    return response


@router.get("/me", response_model=AuthState, responses=error_responses(401))
def me(ctx: CurrentAuth) -> AuthState:
    """Usuario, rol, permisos y token CSRF de la sesión actual (401 si no hay sesión).

    El frontend lo llama al cargar para restaurar la sesión: el token CSRF no se guarda en
    ningún almacenamiento del navegador, se vuelve a pedir aquí.
    """
    return auth_state(ctx.user, ctx.session, ctx.token)


@router.post("/password", response_model=AuthState, responses=error_responses(401, 403, 422))
def change_password(
    payload: PasswordChangeRequest,
    ctx: CurrentAuth,
    auth: Auth,
    response: Response,
    settings: AppSettings,
    session: DbSession,
) -> AuthState:
    """Cambia la contraseña propia; cierra las demás sesiones y rota la actual."""
    try:
        token, row = auth.change_own_password(ctx, payload.current_password, payload.new_password)
    except Exception:
        session.rollback()
        audit_service.record(
            session,
            actor(ctx),
            "password_changed",
            audit_service.FAILURE,
            target_type="user",
            target_id=ctx.user.public_id,
        )
        raise
    audit_service.record(
        session,
        actor(ctx),
        "password_changed",
        target_type="user",
        target_id=ctx.user.public_id,
    )
    set_session_cookie(response, settings, token)
    return auth_state(ctx.user, row, token)
