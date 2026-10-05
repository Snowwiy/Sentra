"""Autenticación y autorización de las peticiones del dashboard (Fase 4G).

Sustituye a la guarda temporal de consola local (api/console.py, DASHBOARD_ADMIN_ENABLED y
X-Sentra-Console). Cada ruta del dashboard declara el permiso que necesita con
`require_permission(Permission.X)`; ninguna compara roles.

Credenciales separadas, cada una con su propósito, que nunca se aceptan en lugar de otra:
- cookie de sesión (este módulo): personas en el dashboard;
- token de agente (Authorization: Bearer): heartbeat, telemetría, inventario, eventos;
- token o clave de enrollment (X-Enrollment-Token / X-Enrollment-Key): solo /agents/register;
- ADMIN_API_KEY (X-Admin-Key): API de administración legacy, nunca desde el navegador.
Los endpoints de agentes no leen la cookie, y estos no leen el Bearer.

CSRF: el navegador adjunta la cookie a cualquier petición hacia la API, también a las que
dispara otra web. Defensas, en capas (no se confía solo en CORS, que no impide enviar):
1. SameSite=Strict en la cookie: el navegador no la envía en peticiones iniciadas por otro
   sitio;
2. token CSRF (X-CSRF-Token) obligatorio en POST/PUT/PATCH/DELETE: derivado de la sesión,
   solo lo conoce el frontend legítimo (lo recibe de /auth/me, que otro origen no puede
   leer) y una cabecera personalizada obliga además a un preflight CORS;
3. Origin, si el navegador lo envía, debe ser el propio origen de la API o uno de
   CORS_ORIGINS. El login, que aún no tiene sesión ni token, se protege con 3 y con el
   Content-Type JSON (un formulario HTML no puede enviarlo sin preflight).
"""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request, Response

from app.api.deps import AppSettings, DbSession
from app.core.config import Settings
from app.core.exceptions import CsrfError, NotAuthenticatedError, PermissionDeniedError
from app.core.permissions import Permission
from app.core.security import csrf_token_matches
from app.services import audit_service
from app.services.audit_service import Actor
from app.services.auth_service import AuthContext, AuthService, LoginGuard, SessionPolicy

CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def session_cookie_name(settings: Settings) -> str:
    # Con Secure se usa el prefijo __Host-: el navegador solo la acepta si llega por HTTPS,
    # sin Domain y con Path=/, así un subdominio o una respuesta HTTP no pueden plantarla.
    return "__Host-sentra_session" if settings.cookie_secure else "sentra_session"


def set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    response.set_cookie(
        session_cookie_name(settings),
        token,
        max_age=settings.session_ttl_hours * 3600,
        # HttpOnly: JavaScript (y por tanto un XSS) no puede leer la sesión.
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.session_cookie_samesite,
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        session_cookie_name(settings),
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.session_cookie_samesite,
    )


def client_ip(request: Request) -> str | None:
    # Detrás de un reverse proxy es la dirección del proxy salvo que uvicorn confíe en sus
    # cabeceras (--proxy-headers / FORWARDED_ALLOW_IPS); ver docs/authentication.md.
    return request.client.host if request.client else None


def check_origin(request: Request, settings: Settings) -> None:
    """Rechaza peticiones mutables cuyo Origin no es el dashboard.

    Sin Origin (curl, scripts, navegadores antiguos en peticiones del mismo origen) no se
    rechaza aquí: el token CSRF sigue siendo obligatorio para cualquier petición con sesión.
    "null" (iframes sandbox, file://) nunca es válido.
    """
    origin = request.headers.get("origin")
    if origin is None:
        return
    own = f"{request.url.scheme}://{request.headers.get('host', '')}"
    if origin != "null" and (origin == own or origin in settings.cors_origin_list):
        return
    raise CsrfError(
        "Request origin is not allowed; add the dashboard origin to CORS_ORIGINS on the server"
    )


def get_auth_service(session: DbSession, settings: AppSettings) -> AuthService:
    return AuthService(session, SessionPolicy.from_settings(settings))


Auth = Annotated[AuthService, Depends(get_auth_service)]


def get_login_guard(request: Request) -> LoginGuard:
    # Uno por aplicación (create_app), en memoria: ver core/rate_limit.py.
    guard: LoginGuard = request.app.state.login_guard
    return guard


def get_auth_context(request: Request, settings: AppSettings, auth: Auth) -> AuthContext:
    """Sesión válida de la petición; 401 si no la hay y 403 si falta CSRF en una mutación."""
    token = request.cookies.get(session_cookie_name(settings))
    ctx = auth.resolve(token, client_ip(request))
    if ctx is None:
        raise NotAuthenticatedError("Authentication required")
    if request.method not in SAFE_METHODS:
        check_origin(request, settings)
        if not csrf_token_matches(ctx.token, request.headers.get(CSRF_HEADER)):
            raise CsrfError("Missing or invalid CSRF token")
    return ctx


CurrentAuth = Annotated[AuthContext, Depends(get_auth_context)]


def require_permission(permission: Permission) -> Callable[..., AuthContext]:
    """Dependencia que exige sesión válida (401), CSRF en mutaciones y el permiso (403)."""

    def dependency(request: Request, ctx: CurrentAuth, session: DbSession) -> AuthContext:
        if not ctx.has(permission):
            if request.method not in SAFE_METHODS:
                # Un intento de escritura sin permiso es relevante (cuenta comprometida, UI
                # manipulada); las lecturas denegadas no se auditan para no llenar la tabla.
                audit_service.record(
                    session,
                    Actor.for_user(ctx.user, ctx.client_ip),
                    "permission_denied",
                    audit_service.DENIED,
                    target_type="endpoint",
                    target_id=f"{request.method} {request.url.path}",
                    details={"permission": permission.value},
                )
            raise PermissionDeniedError(f"Your role does not allow this action ({permission})")
        return ctx

    dependency.__name__ = f"require_{permission.name.lower()}"
    return dependency


# Atajo para las rutas de solo lectura del dashboard.
READ = Depends(require_permission(Permission.MONITORING_READ))


def actor(ctx: AuthContext) -> Actor:
    return Actor.for_user(ctx.user, ctx.client_ip)
