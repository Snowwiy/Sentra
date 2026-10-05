from datetime import datetime
from uuid import UUID

from pydantic import ConfigDict, Field

from app.core.passwords import PASSWORD_MAX_LENGTH
from app.core.permissions import Permission, Role
from app.schemas.common import RequestModel, ResponseModel


class _SecretInput(RequestModel):
    # Las contraseñas no se recortan: un espacio forma parte de la contraseña escrita y
    # recortarlo en silencio haría que la misma contraseña valga en un sitio y no en otro.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class LoginRequest(_SecretInput):
    # Límites holgados: la validación de formato se hace al normalizar, y cualquier fallo
    # responde el mismo error genérico que una contraseña incorrecta.
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class PasswordChangeRequest(_SecretInput):
    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    new_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class PasswordResetRequest(_SecretInput):
    new_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class UserCreate(_SecretInput):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    role: Role


class UserUpdate(RequestModel):
    role: Role | None = None
    is_active: bool | None = None


class UserRead(ResponseModel):
    """Un usuario tal como lo ve la API: nunca incluye el hash de la contraseña."""

    user_id: UUID
    username: str
    role: Role
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None
    active_sessions: int = 0


class UserList(ResponseModel):
    items: list[UserRead]


class CurrentUser(ResponseModel):
    user_id: UUID
    username: str
    role: Role
    last_login_at: datetime | None


class AuthState(ResponseModel):
    """Respuesta de login y de GET /auth/me.

    `csrf_token` no es la sesión: el frontend lo guarda solo en memoria y lo envía en
    X-CSRF-Token en cada petición mutable. La sesión viaja únicamente en la cookie HttpOnly,
    que JavaScript no puede leer.
    """

    user: CurrentUser
    permissions: list[Permission]
    csrf_token: str
    session_expires_at: datetime


class SessionRead(ResponseModel):
    """Sesión listada para un admin: identificador público, nunca el ID de la cookie."""

    session_id: UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    client_ip: str | None
    user_agent: str | None
    current: bool = False


class SessionList(ResponseModel):
    items: list[SessionRead]
