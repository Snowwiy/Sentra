"""Autenticación del dashboard: login, sesiones de servidor y gestión de usuarios.

Decisiones (ver docs/authentication.md):
- Sesiones de servidor con cookie HttpOnly en vez de JWT en localStorage: JavaScript (y por
  tanto un XSS) no puede leer la credencial, y una sesión se revoca al instante borrando
  su fila; un JWT seguiría siendo válido hasta caducar.
- Rotación: cada login crea un ID de sesión nuevo y revoca el que traía el navegador, así
  un ID fijado de antemano por un atacante (session fixation) nunca queda autenticado.
- Invalidación: desactivar un usuario o cambiar/resetear su contraseña revoca todas sus
  sesiones. Además, cada petición vuelve a comprobar `is_active` y `password_changed_at`,
  de modo que una sesión antigua no sirve aunque la revocación explícita se hubiera perdido.
- Los permisos se calculan en cada petición a partir del rol actual en la base de datos:
  un cambio de rol se aplica en la siguiente petición sin esperar a que caduque la sesión.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import passwords
from app.core.config import Settings
from app.core.exceptions import (
    ConflictError,
    LastAdminError,
    NotFoundError,
    PolicyError,
    RateLimitedError,
)
from app.core.permissions import Permission, Role, permissions_for
from app.core.rate_limit import RateLimiter
from app.core.security import (
    MAX_CREDENTIAL_LENGTH,
    SESSION_TOKEN_PREFIX,
    generate_session_token,
    hash_token,
)
from app.models.user import User, UserSession
from app.schemas.auth import SessionList, SessionRead, UserCreate, UserList, UserRead, UserUpdate

logger = logging.getLogger(__name__)

# last_seen_at se escribe como mucho una vez por este intervalo: el dashboard consulta la
# API cada pocos segundos y una escritura por petición sería carga inútil para PostgreSQL.
LAST_SEEN_RESOLUTION = timedelta(seconds=60)
USER_AGENT_MAX = 255


@dataclass(frozen=True)
class SessionPolicy:
    ttl: timedelta
    idle: timedelta

    @classmethod
    def from_settings(cls, settings: Settings) -> "SessionPolicy":
        return cls(
            timedelta(hours=settings.session_ttl_hours),
            timedelta(minutes=settings.session_idle_minutes),
        )


@dataclass(frozen=True)
class AuthContext:
    """Usuario autenticado de la petición actual."""

    user: User
    session: UserSession
    token: str
    permissions: frozenset[Permission]
    client_ip: str | None

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions


def _now() -> datetime:
    return datetime.now(UTC)


def _policy_error(exc: passwords.PolicyError) -> PolicyError:
    return PolicyError(str(exc))


# --- Rate limiting del login ----------------------------------------------------------------


class LoginGuard:
    """Tres límites independientes contra fuerza bruta:

    - fallos por usuario+dirección: frena a quien prueba contraseñas desde un equipo sin
      permitirle bloquear al usuario legítimo que entra desde otro;
    - intentos por dirección (correctos o no): frena a quien prueba muchos usuarios;
    - fallos por usuario desde cualquier dirección: frena un ataque distribuido contra una
      cuenta concreta (umbral alto para que no sea fácil bloquear al admin a propósito).
    Se comprueban ANTES de verificar la contraseña: bloqueado, ni siquiera se calcula el hash.
    """

    def __init__(self, settings: Settings) -> None:
        window = settings.login_rate_window_minutes * 60
        self.user_ip = RateLimiter(settings.login_max_failures_per_user_ip, window)
        self.ip = RateLimiter(settings.login_max_attempts_per_ip, window)
        self.user = RateLimiter(settings.login_max_failures_per_user, window)

    @staticmethod
    def _user_key(username: str) -> str:
        return passwords.normalize_username(username)[:128]

    def check(self, username: str, client_ip: str | None) -> None:
        user = self._user_key(username)
        ip = client_ip or "unknown"
        wait = max(
            self.user_ip.blocked_for(f"{user}|{ip}"),
            self.ip.blocked_for(ip),
            self.user.blocked_for(user),
        )
        if wait > 0:
            raise RateLimitedError("Too many login attempts, try again later", wait)
        self.ip.hit(ip)

    def failed(self, username: str, client_ip: str | None) -> None:
        user = self._user_key(username)
        self.user_ip.hit(f"{user}|{client_ip or 'unknown'}")
        self.user.hit(user)

    def succeeded(self, username: str, client_ip: str | None) -> None:
        # Un login correcto limpia los fallos de ese usuario desde ese equipo (el operador que
        # se equivocó dos veces no arrastra el contador), pero no los de otras direcciones.
        self.user_ip.reset(f"{self._user_key(username)}|{client_ip or 'unknown'}")


# --- Sesiones -------------------------------------------------------------------------------


class AuthService:
    def __init__(self, session: Session, policy: SessionPolicy) -> None:
        self._db = session
        self._policy = policy

    def authenticate(self, username: str, password: str) -> tuple[User | None, bool]:
        """(usuario encontrado, credenciales válidas y usuario activo).

        El usuario se devuelve aunque la contraseña falle, solo para la auditoría; la
        respuesta HTTP es la misma en todos los fallos. Todas las ramas cuestan lo mismo
        (una verificación Argon2) para que el tiempo de respuesta no distinga "no existe"
        de "contraseña incorrecta".
        """
        try:
            canonical = passwords.validate_username(username)
        except passwords.PolicyError:
            passwords.burn_verification_time(password)
            return None, False
        user = self._db.scalars(select(User).where(User.username == canonical)).one_or_none()
        if user is None:
            passwords.burn_verification_time(password)
            return None, False
        if not passwords.verify_password(password, user.password_hash) or not user.is_active:
            return user, False
        if passwords.needs_rehash(user.password_hash):
            user.password_hash = passwords.hash_password(password)
        return user, True

    def start_session(
        self,
        user: User,
        client_ip: str | None,
        user_agent: str | None,
        previous_token: str | None = None,
    ) -> tuple[str, UserSession]:
        """Crea una sesión nueva (rotación) y devuelve el ID en claro, que solo va a la cookie."""
        now = _now()
        if previous_token:
            old = self._find(previous_token)
            if old is not None and old.revoked_at is None:
                old.revoked_at = now
                old.revoked_reason = "rotated"
        token = generate_session_token()
        row = UserSession(
            user_id=user.id,
            token_hash=hash_token(token),
            created_at=now,
            expires_at=now + self._policy.ttl,
            last_seen_at=now,
            client_ip=client_ip,
            user_agent=(user_agent or "")[:USER_AGENT_MAX] or None,
        )
        self._db.add(row)
        user.last_login_at = now
        self._db.commit()
        return token, row

    def _find(self, token: str) -> UserSession | None:
        if len(token) > MAX_CREDENTIAL_LENGTH or not token.startswith(SESSION_TOKEN_PREFIX):
            return None
        return self._db.scalars(
            select(UserSession).where(UserSession.token_hash == hash_token(token))
        ).one_or_none()

    def resolve(self, token: str | None, client_ip: str | None) -> AuthContext | None:
        """Contexto de la sesión si sigue siendo válida; None si no (la ruta responde 401)."""
        if not token:
            return None
        row = self._find(token)
        if row is None:
            return None
        now = _now()
        user = row.user
        if (
            row.revoked_at is not None
            or now >= row.expires_at
            or now - row.last_seen_at >= self._policy.idle
            or not user.is_active
            # Sesión anterior al último cambio de contraseña: nunca válida.
            or row.created_at < user.password_changed_at
        ):
            return None
        if now - row.last_seen_at >= LAST_SEEN_RESOLUTION:
            row.last_seen_at = now
            self._db.commit()
        return AuthContext(user, row, token, permissions_for(user.role), client_ip)

    def end_session(self, row: UserSession, reason: str = "logout") -> None:
        if row.revoked_at is None:
            row.revoked_at = _now()
            row.revoked_reason = reason
        self._db.commit()

    def revoke_user_sessions(
        self, user: User, reason: str, keep: UserSession | None = None, commit: bool = True
    ) -> int:
        query = (
            update(UserSession)
            .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
            .values(revoked_at=_now(), revoked_reason=reason)
        )
        if keep is not None:
            query = query.where(UserSession.id != keep.id)
        count = self._db.execute(query).rowcount  # type: ignore[attr-defined]
        if commit:
            self._db.commit()
        return int(count or 0)

    def change_own_password(
        self, ctx: AuthContext, current: str, new: str
    ) -> tuple[str, UserSession]:
        """Cambia la contraseña propia: revoca TODAS las sesiones y abre una nueva para este
        navegador, así otra sesión robada deja de valer pero el operador sigue dentro."""
        user = ctx.user
        if not passwords.verify_password(current, user.password_hash):
            raise PolicyError("Current password is not correct")
        try:
            passwords.validate_password(new, user.username)
        except passwords.PolicyError as exc:
            raise _policy_error(exc) from exc
        _set_password(user, new)
        self.revoke_user_sessions(user, "password_changed", commit=False)
        self._db.flush()
        return self.start_session(user, ctx.client_ip, ctx.session.user_agent)


def _set_password(user: User, password: str) -> None:
    now = _now()
    user.password_hash = passwords.hash_password(password)
    # Resolución de microsegundos: la sesión nueva que se crea justo después tiene
    # created_at >= password_changed_at y sigue siendo válida.
    user.password_changed_at = now
    user.updated_at = now


# --- Administración de usuarios -------------------------------------------------------------


def _user_read(user: User, active_sessions: int = 0) -> UserRead:
    return UserRead(
        user_id=user.public_id,
        username=user.username,
        role=Role(user.role),
        is_active=user.is_active,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login_at=user.last_login_at,
        active_sessions=active_sessions,
    )


class UserService:
    def __init__(self, session: Session, policy: SessionPolicy) -> None:
        self._db = session
        self._auth = AuthService(session, policy)
        self._policy = policy

    def get(self, public_id: UUID) -> User:
        user = self._db.scalars(select(User).where(User.public_id == public_id)).one_or_none()
        if user is None:
            raise NotFoundError("User not found")
        return user

    def get_by_username(self, username: str) -> User | None:
        canonical = passwords.normalize_username(username)
        return self._db.scalars(select(User).where(User.username == canonical)).one_or_none()

    def _active_session_counts(self) -> dict[int, int]:
        now = _now()
        rows = self._db.execute(
            select(UserSession.user_id, func.count())
            .where(
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > now,
                UserSession.last_seen_at > now - self._policy.idle,
            )
            .group_by(UserSession.user_id)
        ).all()
        return {user_id: count for user_id, count in rows}

    def list(self) -> UserList:
        counts = self._active_session_counts()
        users = self._db.scalars(select(User).order_by(User.username)).all()
        return UserList(items=[_user_read(u, counts.get(u.id, 0)) for u in users])

    def read(self, user: User) -> UserRead:
        return _user_read(user, self._active_session_counts().get(user.id, 0))

    def create(self, request: UserCreate) -> User:
        try:
            username = passwords.validate_username(request.username)
            passwords.validate_password(request.password, username)
        except passwords.PolicyError as exc:
            raise _policy_error(exc) from exc
        if self.get_by_username(username) is not None:
            raise ConflictError("Username already exists")
        now = _now()
        user = User(
            username=username,
            password_hash=passwords.hash_password(request.password),
            role=request.role.value,
            is_active=True,
            created_at=now,
            updated_at=now,
            password_changed_at=now,
        )
        self._db.add(user)
        try:
            self._db.commit()
        except IntegrityError as exc:
            # Dos altas simultáneas del mismo nombre: la segunda choca con el índice único.
            self._db.rollback()
            raise ConflictError("Username already exists") from exc
        return user

    def _ensure_other_active_admin(self, user: User) -> None:
        """Lanza LastAdminError si `user` es el único admin activo.

        SELECT ... FOR UPDATE sobre los admins activos: dos admins que se degradan el uno al
        otro a la vez se serializan aquí, y el segundo ve que ya no queda ningún otro.
        """
        admins = self._db.scalars(
            select(User.id)
            .where(User.role == Role.ADMIN.value, User.is_active.is_(True))
            .with_for_update()
        ).all()
        if not [admin_id for admin_id in admins if admin_id != user.id]:
            raise LastAdminError("Sentra must keep at least one active admin")

    def update(self, user: User, request: UserUpdate, actor: User) -> dict[str, object]:
        """Cambia rol y/o estado. Devuelve los cambios aplicados (para la auditoría)."""
        changes: dict[str, object] = {}
        new_role = request.role.value if request.role is not None else user.role
        new_active = request.is_active if request.is_active is not None else user.is_active
        loses_admin = user.role == Role.ADMIN.value and user.is_active
        loses_admin = loses_admin and (new_role != Role.ADMIN.value or not new_active)
        if loses_admin:
            if user.id == actor.id:
                # Un admin no se quita a sí mismo el acceso desde el dashboard (un clic
                # accidental lo dejaría fuera); otro admin o la CLI pueden hacerlo.
                raise ConflictError("You cannot remove your own admin access")
            self._ensure_other_active_admin(user)
        if new_role != user.role:
            changes["role"] = {"from": user.role, "to": new_role}
            user.role = new_role
        if new_active != user.is_active:
            changes["is_active"] = new_active
            user.is_active = new_active
            if not new_active:
                # Desactivar corta el acceso ya, no cuando caduque su sesión.
                self._auth.revoke_user_sessions(user, "user_disabled", commit=False)
        if changes:
            user.updated_at = _now()
        self._db.commit()
        return changes

    def reset_password(self, user: User, new_password: str) -> int:
        """Contraseña nueva fijada por un admin (o la CLI); revoca todas sus sesiones."""
        try:
            passwords.validate_password(new_password, user.username)
        except passwords.PolicyError as exc:
            raise _policy_error(exc) from exc
        _set_password(user, new_password)
        revoked = self._auth.revoke_user_sessions(user, "password_reset", commit=False)
        self._db.commit()
        return revoked

    def sessions(self, user: User, current: UserSession | None = None) -> SessionList:
        now = _now()
        rows = self._db.scalars(
            select(UserSession)
            .where(
                UserSession.user_id == user.id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > now,
                UserSession.last_seen_at > now - self._policy.idle,
                UserSession.created_at >= user.password_changed_at,
            )
            .order_by(UserSession.last_seen_at.desc())
        ).all()
        return SessionList(
            items=[
                SessionRead(
                    session_id=row.public_id,
                    created_at=row.created_at,
                    last_seen_at=row.last_seen_at,
                    expires_at=row.expires_at,
                    client_ip=row.client_ip,
                    user_agent=row.user_agent,
                    current=current is not None and row.id == current.id,
                )
                for row in rows
            ]
        )

    def revoke_sessions(self, user: User) -> int:
        return self._auth.revoke_user_sessions(user, "admin")
