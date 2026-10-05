"""Fase 4G: login, sesiones, CSRF, RBAC, auditoría y separación de credenciales.

Incluye pruebas negativas pensadas para fallar si alguien introduce los errores más
peligrosos: un endpoint público por accidente, una comparación de roles incorrecta, CSRF
omitido, un usuario inactivo o una sesión antigua aceptados, o un viewer capaz de mutar.
"""

import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app import cli
from app.api.auth import CSRF_HEADER
from app.core import passwords
from app.core.config import Settings, get_settings
from app.core.permissions import ROLE_PERMISSIONS, Permission, Role, permissions_for
from app.core.rate_limit import RateLimiter
from app.models.alert import Alert, AlertRule, AlertSeverity, AlertStatus
from app.models.audit import AuditEvent
from app.models.user import User, UserSession
from tests.conftest import (
    TEST_ADMIN_KEY,
    TEST_ENROLLMENT_KEY,
    TEST_PASSWORD,
    agent_payload,
    authenticate,
    create_user,
)

API = "/api/v1"
LOGIN = f"{API}/auth/login"
ME = f"{API}/auth/me"
LOGOUT = f"{API}/auth/logout"
USERS = f"{API}/users"
COOKIE = "sentra_session"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def anonymous(client: TestClient) -> Iterator[TestClient]:
    """Navegador sin sesión contra la misma aplicación."""
    with TestClient(client.app) as browser:
        yield browser


def _login(browser: TestClient, username: str, password: str = TEST_PASSWORD) -> Any:
    response = browser.post(LOGIN, json={"username": username, "password": password})
    if response.status_code == 200:
        browser.headers[CSRF_HEADER] = response.json()["csrf_token"]
    return response


def _session_rows(db: Session, user: User) -> list[UserSession]:
    db.expire_all()
    return list(db.scalars(select(UserSession).where(UserSession.user_id == user.id)))


def _audit(db: Session, action: str) -> list[AuditEvent]:
    db.expire_all()
    return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


def _alert(db: Session, registered_agent: dict[str, Any]) -> Alert:
    from app.models.asset import Asset

    asset = db.scalars(
        select(Asset).where(Asset.public_id == registered_agent["response"]["asset_id"])
    ).one()
    now = datetime.now(UTC)
    alert = Alert(
        asset_id=asset.id,
        rule=AlertRule.HIGH_CPU,
        severity=AlertSeverity.WARNING,
        status=AlertStatus.OPEN,
        message="CPU alta",
        opened_at=now,
        last_triggered_at=now,
        occurrences=1,
    )
    db.add(alert)
    db.commit()
    return alert


# --- Contraseñas y usuarios ----------------------------------------------------------------


def test_password_is_hashed_with_argon2id_never_stored_in_clear(db: Session) -> None:
    hashed = passwords.hash_password(TEST_PASSWORD)
    assert hashed.startswith("$argon2id$")
    assert TEST_PASSWORD not in hashed
    assert passwords.verify_password(TEST_PASSWORD, hashed)
    assert not passwords.verify_password(TEST_PASSWORD + "x", hashed)
    assert not passwords.verify_password(TEST_PASSWORD, "not-a-hash")
    create_user(db, "ana", "viewer")
    stored = db.execute(text("SELECT password_hash FROM users WHERE username='ana'")).scalar()
    assert stored is not None and stored.startswith("$argon2id$") and TEST_PASSWORD not in stored


@pytest.mark.parametrize(
    ("password", "valid"),
    [
        ("correct horse battery staple", True),
        ("una frase larga sin símbolos", True),
        ("short-pass1", False),  # < 12
        ("password1234", False),  # común
        ("aaaaaaaaaaaaaaaa", False),  # repetitiva
        (" leading space pass", False),
        ("x" * 257, False),
        ("my-anabel-password", False),  # contiene el usuario
    ],
)
def test_password_policy(password: str, valid: bool) -> None:
    if valid:
        passwords.validate_password(password, "anabel")
    else:
        with pytest.raises(passwords.PolicyError):
            passwords.validate_password(password, "anabel")


def test_username_normalization() -> None:
    assert passwords.validate_username("  Ana.Lopez ") == "ana.lopez"
    # Ancho completo (NFKC) se normaliza a ASCII: mismo usuario que "admin".
    assert passwords.validate_username("\uff21\uff44\uff4d\uff49\uff4e") == "admin"
    for bad in ("ab", "x" * 33, "ana lopez", "-ana", "\u0430dmin", "ana@corp"):
        with pytest.raises(passwords.PolicyError):
            passwords.validate_username(bad)


# --- Bootstrap del primer admin (CLI) ------------------------------------------------------


def _answers(*values: str) -> Any:
    queue = list(values)
    return lambda _prompt: queue.pop(0)


def test_cli_create_admin(db: Session, capsys: pytest.CaptureFixture[str]) -> None:
    code = cli._create_admin(db, None, _answers("Jefe"), _answers(TEST_PASSWORD, TEST_PASSWORD))
    assert code == 0
    user = db.scalars(select(User).where(User.username == "jefe")).one()
    assert user.role == "admin" and user.is_active
    assert user.password_hash.startswith("$argon2id$")
    assert TEST_PASSWORD not in capsys.readouterr().out
    assert [e.actor for e in _audit(db, "user_created")] == ["cli"]
    # Duplicado (también con otra capitalización): se niega sin pedir contraseña.
    assert cli._create_admin(db, "JEFE", _answers(), _answers()) == 1
    # Confirmación distinta y contraseña débil: no se crea nada.
    assert cli._create_admin(db, "otro", _answers(), _answers(TEST_PASSWORD, "x" * 20)) == 2
    assert cli._create_admin(db, "otro", _answers(), _answers("password1234")) == 2
    assert db.scalars(select(User).where(User.username == "otro")).one_or_none() is None


def test_cli_reset_password_recovers_access(db: Session, anonymous: TestClient) -> None:
    user = create_user(db, "perdido", "admin", active=False)
    new = "otra frase de recuperacion"
    assert cli._reset_password(db, "perdido", True, _answers(new, new)) == 0
    db.refresh(user)
    assert user.is_active
    assert _login(anonymous, "perdido", new).status_code == 200
    assert cli._reset_password(db, "nadie", False, _answers()) == 1


# --- Login ---------------------------------------------------------------------------------


def test_login_sets_a_secure_cookie_and_restores_via_me(db: Session, anonymous: TestClient) -> None:
    create_user(db, "ana", "analyst")
    response = _login(anonymous, "ANA")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user"]["username"] == "ana" and body["user"]["role"] == "analyst"
    assert set(body["permissions"]) == {"monitoring:read", "alerts:manage", "discovery:run"}
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE}=sentra_s_")
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie
    # Desarrollo por HTTP: sin Secure (configurable); el ID de sesión nunca va en el cuerpo.
    assert "Secure" not in cookie
    token = anonymous.cookies[COOKIE]
    assert token not in response.text
    assert anonymous.get(ME).json()["csrf_token"] == body["csrf_token"]
    [row] = _session_rows(db, db.scalars(select(User).where(User.username == "ana")).one())
    assert row.token_hash != token and len(row.token_hash) == 64
    assert row.client_ip == "testclient"


def test_cookie_is_secure_in_production(client: TestClient, engine: Engine) -> None:
    client.app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(  # type: ignore[attr-defined]
        update={"environment": "production"}
    )
    with sessionmaker(bind=engine)() as session:
        create_user(session, "prod", "viewer")
    with TestClient(client.app, base_url="https://sentra.lan") as browser:
        response = _login(browser, "prod")
    cookie = response.headers["set-cookie"]
    assert cookie.startswith("__Host-sentra_session=") and "Secure" in cookie


def test_login_errors_are_generic(db: Session, anonymous: TestClient) -> None:
    create_user(db, "ana", "viewer")
    create_user(db, "baja", "viewer", active=False)
    answers = [
        _login(anonymous, "ana", "contraseña equivocada"),
        _login(anonymous, "nadie", TEST_PASSWORD),
        _login(anonymous, "baja", TEST_PASSWORD),  # contraseña correcta pero inactivo
        _login(anonymous, "x y z", TEST_PASSWORD),  # formato inválido
    ]
    for response in answers:
        assert response.status_code == 401
        assert response.json() == {
            "error": {"code": "invalid_credentials", "message": "Invalid username or password"}
        }
        assert COOKIE not in response.headers.get("set-cookie", "")
    failed = _audit(db, "login_failed")
    assert len(failed) == 4
    # Un usuario inexistente se registra como "unknown": puede ser una contraseña tecleada
    # en el campo equivocado.
    assert sorted(e.actor for e in failed) == ["ana", "baja", "unknown", "unknown"]


def test_login_rotates_the_session(db: Session, anonymous: TestClient) -> None:
    user = create_user(db, "ana", "viewer")
    _login(anonymous, "ana")
    first = anonymous.cookies[COOKIE]
    _login(anonymous, "ana")
    second = anonymous.cookies[COOKIE]
    assert first != second
    rows = {r.revoked_reason for r in _session_rows(db, user)}
    assert rows == {"rotated", None}
    with TestClient(anonymous.app) as stolen:
        stolen.cookies.set(COOKIE, first)
        assert stolen.get(ME).status_code == 401


def test_login_and_logout_are_audited(db: Session, anonymous: TestClient) -> None:
    create_user(db, "ana", "viewer")
    _login(anonymous, "ana")
    assert anonymous.post(LOGOUT).status_code == 204
    assert [e.result for e in _audit(db, "login_success")] == ["success"]
    assert [e.actor for e in _audit(db, "logout")] == ["ana"]


# --- Sesiones ------------------------------------------------------------------------------


def test_logout_revokes_the_session(db: Session, anonymous: TestClient) -> None:
    create_user(db, "ana", "viewer")
    _login(anonymous, "ana")
    token = anonymous.cookies[COOKIE]
    response = anonymous.post(LOGOUT)
    assert response.status_code == 204
    assert 'sentra_session=""' in response.headers["set-cookie"]
    with TestClient(anonymous.app) as replay:
        replay.cookies.set(COOKIE, token)
        assert replay.get(ME).status_code == 401


@pytest.mark.parametrize("column", ["expires_at", "last_seen_at"])
def test_expired_sessions_are_refused(db: Session, anonymous: TestClient, column: str) -> None:
    user = create_user(db, "ana", "viewer")
    _login(anonymous, "ana")
    past = datetime.now(UTC) - timedelta(days=2)
    db.execute(update(UserSession).where(UserSession.user_id == user.id).values({column: past}))
    db.commit()
    response = anonymous.get(f"{API}/assets")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "not_authenticated"


def test_inactive_user_is_refused_even_without_revocation(
    db: Session, anonymous: TestClient
) -> None:
    user = create_user(db, "ana", "viewer")
    _login(anonymous, "ana")
    # Desactivado directamente en la base, sin pasar por la revocación de sesiones: la
    # comprobación por petición tiene que cortar el acceso igual.
    db.execute(update(User).where(User.id == user.id).values(is_active=False))
    db.commit()
    assert anonymous.get(f"{API}/assets").status_code == 401


def test_stale_session_after_password_change_is_refused(db: Session, anonymous: TestClient) -> None:
    user = create_user(db, "ana", "viewer")
    _login(anonymous, "ana")
    # Contraseña cambiada sin revocar la sesión (p. ej. una revocación perdida).
    db.execute(update(User).where(User.id == user.id).values(password_changed_at=datetime.now(UTC)))
    db.commit()
    assert anonymous.get(ME).status_code == 401


def test_admin_reset_password_invalidates_sessions(
    client: TestClient, db: Session, anonymous: TestClient
) -> None:
    user = create_user(db, "ana", "viewer")
    _login(anonymous, "ana")
    new = "nueva frase muy larga"
    response = client.post(f"{USERS}/{user.public_id}/password", json={"new_password": new})
    assert response.status_code == 200, response.text
    assert anonymous.get(ME).status_code == 401
    assert {r.revoked_reason for r in _session_rows(db, user)} == {"password_reset"}
    assert _login(anonymous, "ana", TEST_PASSWORD).status_code == 401
    assert _login(anonymous, "ana", new).status_code == 200
    [event] = _audit(db, "password_reset")
    assert new not in repr(event.details) and event.details == {"username": "ana", "revoked": 1}


def test_own_password_change_keeps_this_browser_and_closes_the_rest(
    db: Session, anonymous: TestClient
) -> None:
    create_user(db, "ana", "viewer")
    _login(anonymous, "ana")
    with TestClient(anonymous.app) as other_pc:
        _login(other_pc, "ana")
        new = "frase nueva y segura 42"
        wrong = anonymous.post(
            f"{API}/auth/password",
            json={"current_password": "no es esta", "new_password": new},
        )
        assert wrong.status_code == 422
        response = anonymous.post(
            f"{API}/auth/password",
            json={"current_password": TEST_PASSWORD, "new_password": new},
        )
        assert response.status_code == 200, response.text
        anonymous.headers[CSRF_HEADER] = response.json()["csrf_token"]
        assert anonymous.get(ME).status_code == 200
        assert other_pc.get(ME).status_code == 401


def test_admin_can_list_and_revoke_sessions(
    client: TestClient, db: Session, anonymous: TestClient
) -> None:
    user = create_user(db, "ana", "viewer")
    _login(anonymous, "ana")
    listed = client.get(f"{USERS}/{user.public_id}/sessions").json()["items"]
    assert len(listed) == 1 and listed[0]["client_ip"] == "testclient"
    assert anonymous.cookies[COOKIE] not in repr(listed)
    assert set(listed[0]) == {
        "session_id", "created_at", "last_seen_at", "expires_at", "client_ip", "user_agent",
        "current",
    }  # fmt: skip
    assert client.post(f"{USERS}/{user.public_id}/sessions/revoke").status_code == 200
    assert anonymous.get(ME).status_code == 401


# --- Administración de usuarios ------------------------------------------------------------


def test_admin_creates_users_without_exposing_hashes(client: TestClient, db: Session) -> None:
    response = client.post(
        USERS, json={"username": " Ana.Lopez ", "password": TEST_PASSWORD, "role": "viewer"}
    )
    assert response.status_code == 201, response.text
    assert response.json()["username"] == "ana.lopez"
    duplicate = client.post(
        USERS, json={"username": "ANA.LOPEZ", "password": TEST_PASSWORD, "role": "admin"}
    )
    assert duplicate.status_code == 409
    weak = client.post(USERS, json={"username": "pepe", "password": "short", "role": "viewer"})
    assert weak.status_code == 422 and weak.json()["error"]["code"] == "policy_violation"
    bad_role = client.post(
        USERS, json={"username": "pepe", "password": TEST_PASSWORD, "role": "root"}
    )
    assert bad_role.status_code == 422
    listing = client.get(USERS).text
    assert "password" not in listing and "$argon2" not in listing
    [created] = [e for e in _audit(db, "user_created") if e.result == "success"]
    assert created.details == {"username": "ana.lopez", "role": "viewer"}


def test_role_change_applies_on_the_next_request(
    client: TestClient,
    db: Session,
    anonymous: TestClient,
    registered_agent: dict[str, Any],
) -> None:
    user = create_user(db, "ana", "viewer")
    alert = _alert(db, registered_agent)
    _login(anonymous, "ana")
    ack = f"{API}/alerts/{alert.public_id}/acknowledge"
    assert anonymous.post(ack).status_code == 403
    response = client.patch(f"{USERS}/{user.public_id}", json={"role": "analyst"})
    assert response.status_code == 200 and response.json()["role"] == "analyst"
    assert anonymous.post(ack).status_code == 200
    [event] = _audit(db, "role_changed")
    assert event.details == {"username": "ana", "role": {"from": "viewer", "to": "analyst"}}


def test_disabling_a_user_closes_their_sessions(
    client: TestClient, db: Session, anonymous: TestClient
) -> None:
    user = create_user(db, "ana", "viewer")
    _login(anonymous, "ana")
    response = client.patch(f"{USERS}/{user.public_id}", json={"is_active": False})
    assert response.status_code == 200
    assert anonymous.get(ME).status_code == 401
    assert {r.revoked_reason for r in _session_rows(db, user)} == {"user_disabled"}
    assert _login(anonymous, "ana").status_code == 401
    assert len(_audit(db, "user_disabled")) == 1


def test_last_admin_is_protected(client: TestClient, db: Session) -> None:
    me = db.scalars(select(User).where(User.username == "admin")).one()
    # Un admin no puede quitarse a sí mismo el acceso desde el dashboard.
    for change in ({"is_active": False}, {"role": "viewer"}):
        response = client.patch(f"{USERS}/{me.public_id}", json=change)
        assert response.status_code == 409
    # Otro admin sí puede degradarlo... mientras no sea el último admin activo.
    other = create_user(db, "segundo", "admin")
    with TestClient(client.app) as second:
        _login(second, "segundo")
        assert second.patch(f"{USERS}/{me.public_id}", json={"role": "analyst"}).status_code == 200
        response = client.patch(f"{USERS}/{other.public_id}", json={"is_active": False})
        assert response.status_code == 403  # "admin" ya es analyst
    db.expire_all()
    service_user = db.scalars(select(User).where(User.username == "segundo")).one()
    assert service_user.role == "admin" and service_user.is_active


def test_last_admin_guard_in_the_service(db: Session) -> None:
    from app.core.exceptions import LastAdminError
    from app.schemas.auth import UserUpdate
    from app.services.auth_service import SessionPolicy, UserService

    service = UserService(db, SessionPolicy.from_settings(get_settings()))
    admin = db.scalars(select(User).where(User.username == "admin")).one()
    actor = create_user(db, "cli-actor", "viewer")
    with pytest.raises(LastAdminError):
        service.update(admin, UserUpdate(is_active=False), actor)
    db.rollback()
    db.refresh(admin)
    assert admin.is_active and admin.role == "admin"


# --- RBAC ----------------------------------------------------------------------------------


def test_role_permissions_are_least_privilege() -> None:
    writes = set(Permission) - {Permission.MONITORING_READ}
    assert ROLE_PERMISSIONS[Role.VIEWER] == {Permission.MONITORING_READ}
    assert not writes & ROLE_PERMISSIONS[Role.VIEWER]
    assert ROLE_PERMISSIONS[Role.ANALYST] == {
        Permission.MONITORING_READ, Permission.ALERTS_MANAGE, Permission.DISCOVERY_RUN,
    }  # fmt: skip
    assert ROLE_PERMISSIONS[Role.ADMIN] == set(Permission)
    # Un rol desconocido (BD manipulada) o con otra capitalización no hereda nada.
    for role in ("ADMIN", "Admin", "root", "", "admin "):
        assert permissions_for(role) == frozenset()


def _matrix_requests(
    alert_id: str, asset_id: str, user_id: str, job_id: str
) -> list[tuple[str, str, dict[str, Any] | None, Permission]]:
    return [
        ("GET", f"{API}/assets", None, Permission.MONITORING_READ),
        ("GET", f"{API}/assets/{asset_id}", None, Permission.MONITORING_READ),
        ("GET", f"{API}/alerts", None, Permission.MONITORING_READ),
        ("GET", f"{API}/events", None, Permission.MONITORING_READ),
        ("GET", f"{API}/agents", None, Permission.MONITORING_READ),
        ("GET", f"{API}/discovery/jobs", None, Permission.MONITORING_READ),
        ("POST", f"{API}/alerts/{alert_id}/acknowledge", None, Permission.ALERTS_MANAGE),
        ("POST", f"{API}/alerts/{alert_id}/resolve", None, Permission.ALERTS_MANAGE),
        ("POST", f"{API}/console/discovery/jobs/{job_id}/cancel", None, Permission.DISCOVERY_RUN),
        ("GET", f"{API}/console", None, Permission.ENROLLMENT_MANAGE),
        ("POST", f"{API}/console/enrollment-tokens", {}, Permission.ENROLLMENT_MANAGE),
        ("POST", f"{API}/console/agents/{asset_id}/revoke", None, Permission.AGENTS_MANAGE),
        ("GET", USERS, None, Permission.USERS_MANAGE),
        (
            "POST",
            USERS,
            {"username": f"u{uuid4().hex[:6]}", "password": TEST_PASSWORD, "role": "viewer"},
            Permission.USERS_MANAGE,
        ),
        ("PATCH", f"{USERS}/{user_id}", {"role": "viewer"}, Permission.USERS_MANAGE),
        ("GET", f"{API}/audit", None, Permission.AUDIT_READ),
    ]


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_permission_matrix(
    client: TestClient,
    engine: Engine,
    db: Session,
    registered_agent: dict[str, Any],
    role: str,
) -> None:
    alert = _alert(db, registered_agent)
    target = create_user(db, f"target-{role}", "viewer")
    asset_id = registered_agent["response"]["asset_id"]
    granted = permissions_for(role)
    with TestClient(client.app) as browser:
        authenticate(browser, engine, role)
        for method, path, body, permission in _matrix_requests(
            str(alert.public_id), asset_id, str(target.public_id), str(uuid4())
        ):
            response = browser.request(method, path, json=body)
            if permission in granted:
                # Permitido: cualquier cosa menos 401/403 (p. ej. 404 de un job inexistente).
                assert response.status_code not in (401, 403), (role, method, path, response.text)
            else:
                assert response.status_code == 403, (role, method, path)
                assert response.json()["error"]["code"] == "permission_denied"
    # El agente siguió activo (el viewer/analyst no pudo revocarlo; el admin sí lo hizo).
    revoked = db.execute(
        text("SELECT agent_token_revoked_at FROM assets WHERE public_id = :id"), {"id": asset_id}
    ).scalar()
    assert (revoked is not None) == (role == "admin")


# Rutas que no usan la sesión del dashboard, cada una con su credencial y motivo.
NON_SESSION_ROUTES = {
    ("GET", "/api/v1/health"),  # monitorización/balanceadores; sin datos sensibles
    ("POST", "/api/v1/auth/login"),  # por definición, sin sesión
    ("POST", "/api/v1/agents/register"),  # token/clave de enrollment
    ("POST", "/api/v1/agents/heartbeat"),  # token de agente
    ("POST", "/api/v1/telemetry"),
    ("POST", "/api/v1/inventory"),
    ("POST", "/api/v1/processes"),
    ("POST", "/api/v1/events"),
    ("GET", "/api/v1/agent-enrollment-tokens"),  # X-Admin-Key (legacy)
    ("POST", "/api/v1/agent-enrollment-tokens"),
    ("POST", "/api/v1/agent-enrollment-tokens/{token_id}/revoke"),
}


def _api_routes(client: TestClient) -> list[tuple[str, str]]:
    # Del documento OpenAPI (contrato público de FastAPI) en vez de recorrer app.routes.
    paths = client.get("/openapi.json").json()["paths"]
    return sorted(
        (method.upper(), f"{API}{path}" if not path.startswith(API) else path)
        for path, operations in paths.items()
        for method in operations
    )


def _concrete(path: str) -> str:
    for name in ("asset_id", "alert_id", "job_id", "token_id", "user_id"):
        path = path.replace("{" + name + "}", str(uuid4()))
    assert "{" not in path, path
    return path


def test_no_dashboard_endpoint_is_public(client: TestClient, anonymous: TestClient) -> None:
    routes = _api_routes(client)
    assert set(routes) >= NON_SESSION_ROUTES
    checked = 0
    for method, path in routes:
        if (method, path) in NON_SESSION_ROUTES:
            continue
        response = anonymous.request(method, _concrete(path), json={})
        # Una ruta nueva sin require_permission respondería 200/404/422 aquí.
        assert response.status_code == 401, (method, path, response.status_code)
        assert response.json()["error"]["code"] == "not_authenticated"
        checked += 1
    assert checked >= 30


# Mutaciones que cualquier usuario autenticado puede hacer sobre sí mismo.
SELF_SERVICE = {("POST", "/api/v1/auth/logout"), ("POST", "/api/v1/auth/password")}


def test_viewer_cannot_mutate_anything(client: TestClient, engine: Engine, db: Session) -> None:
    # Recorre TODAS las rutas mutables del dashboard: una ruta nueva que olvide su permiso,
    # o que compare roles mal, deja que un viewer escriba y este test falla.
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        checked = 0
        for method, path in _api_routes(client):
            if method == "GET" or (method, path) in NON_SESSION_ROUTES | SELF_SERVICE:
                continue
            response = viewer.request(method, _concrete(path), json={})
            assert response.status_code == 403, (method, path, response.status_code)
            assert response.json()["error"]["code"] == "permission_denied"
            checked += 1
    assert checked >= 10
    denied = _audit(db, "permission_denied")
    assert len(denied) == checked and {e.result for e in denied} == {"denied"}


# --- CSRF y Origin -------------------------------------------------------------------------


def test_mutations_require_csrf(client: TestClient, db: Session) -> None:
    user = create_user(db, "ana", "viewer")
    path = f"{USERS}/{user.public_id}"
    for headers in ({CSRF_HEADER: ""}, {CSRF_HEADER: "0" * 64}, {CSRF_HEADER: "x" * 300}):
        response = client.patch(path, json={"role": "admin"}, headers=headers)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "csrf_failed"
    without = dict(client.headers)
    without.pop(CSRF_HEADER.lower(), None)
    with TestClient(client.app) as browser:
        browser.cookies = client.cookies
        assert browser.patch(path, json={"role": "admin"}).status_code == 403
        assert browser.post(LOGOUT).status_code == 403
        # Las lecturas no necesitan token (no cambian nada).
        assert browser.get(f"{API}/assets").status_code == 200
    db.refresh(user)
    assert user.role == "viewer"


def test_csrf_token_of_another_session_is_refused(
    client: TestClient, engine: Engine, db: Session
) -> None:
    user = create_user(db, "ana", "viewer")
    with TestClient(client.app) as other:
        authenticate(other, engine, "admin")
        foreign = other.headers[CSRF_HEADER]
    response = client.patch(
        f"{USERS}/{user.public_id}", json={"role": "admin"}, headers={CSRF_HEADER: foreign}
    )
    assert response.status_code == 403


@pytest.mark.parametrize("origin", ["http://evil.example", "null", "http://localhost:3000"])
def test_foreign_origins_are_refused(
    client: TestClient, anonymous: TestClient, db: Session, origin: str
) -> None:
    create_user(db, "ana", "viewer")
    response = client.post(f"{API}/console/enrollment-tokens", json={}, headers={"Origin": origin})
    assert response.status_code == 403 and response.json()["error"]["code"] == "csrf_failed"
    # Login CSRF: otra web no puede iniciar sesión en el navegador del operador.
    login = anonymous.post(
        LOGIN, json={"username": "ana", "password": TEST_PASSWORD}, headers={"Origin": origin}
    )
    assert login.status_code == 403


def test_same_origin_and_configured_origins_are_accepted(
    client: TestClient, anonymous: TestClient, db: Session
) -> None:
    create_user(db, "ana", "viewer")
    own = anonymous.post(
        LOGIN,
        json={"username": "ana", "password": TEST_PASSWORD},
        headers={"Origin": "http://testserver"},
    )
    assert own.status_code == 200
    client.app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(  # type: ignore[attr-defined]
        update={"cors_origins": "http://192.168.50.201:5173"}
    )
    response = client.post(
        f"{API}/console/enrollment-tokens",
        json={},
        headers={"Origin": "http://192.168.50.201:5173"},
    )
    assert response.status_code == 201


def test_login_requires_a_json_body(db: Session, anonymous: TestClient) -> None:
    create_user(db, "ana", "viewer")
    # Un formulario HTML de otra web enviaría text/plain o form-urlencoded.
    response = anonymous.post(
        LOGIN,
        content='{"username": "ana", "password": "correct horse battery staple"}',
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code in (403, 422)
    assert COOKIE not in anonymous.cookies


def test_cors_never_allows_any_origin_with_credentials() -> None:
    with pytest.raises(ValueError, match="CORS_ORIGINS"):
        Settings(database_url="postgresql://x", cors_origins="*")
    with pytest.raises(ValueError, match="CORS_ORIGINS"):
        Settings(database_url="postgresql://x", cors_origins="http://a.lan,*")


def test_cors_preflight_for_the_configured_dashboard(engine: Engine) -> None:
    from app.main import create_app

    settings = get_settings()
    original = settings.cors_origins
    settings.cors_origins = "http://192.168.50.201:5173"
    try:
        app = create_app()
    finally:
        settings.cors_origins = original
    with TestClient(app) as browser:
        allowed = browser.options(
            LOGIN,
            headers={
                "Origin": "http://192.168.50.201:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,x-csrf-token",
            },
        )
        assert allowed.headers["access-control-allow-origin"] == "http://192.168.50.201:5173"
        assert allowed.headers["access-control-allow-credentials"] == "true"
        foreign = browser.options(
            LOGIN,
            headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "POST"},
        )
        assert "access-control-allow-origin" not in foreign.headers


def test_trusted_hosts_when_configured(engine: Engine) -> None:
    from app.main import create_app

    settings = get_settings()
    settings.allowed_hosts = "sentra.lan,192.168.50.201"
    try:
        app = create_app()
    finally:
        settings.allowed_hosts = ""
    with TestClient(app, base_url="http://evil.example") as bad:
        assert bad.get(f"{API}/health").status_code == 400
    with TestClient(app, base_url="http://192.168.50.201:8000") as good:
        assert good.get(f"{API}/health").status_code in (200, 503)


# --- Rate limiting -------------------------------------------------------------------------


def test_login_is_rate_limited(db: Session, anonymous: TestClient) -> None:
    create_user(db, "ana", "viewer")
    limit = get_settings().login_max_failures_per_user_ip
    for _ in range(limit):
        assert _login(anonymous, "ana", "intento equivocado").status_code == 401
    blocked = _login(anonymous, "ana", TEST_PASSWORD)  # ni siquiera la correcta
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "rate_limited"
    assert int(blocked.headers["Retry-After"]) >= 1
    # Desde otro equipo el usuario legítimo sigue pudiendo entrar.
    with TestClient(anonymous.app, client=("192.168.50.30", 1)) as other_pc:
        assert _login(other_pc, "ana").status_code == 200


def test_login_attempts_per_address_are_limited(db: Session, client: TestClient) -> None:
    limit = get_settings().login_max_attempts_per_ip
    with TestClient(client.app, client=("10.9.9.9", 1)) as attacker:
        codes = [
            _login(attacker, f"user{i}", "intento equivocado").status_code for i in range(limit + 1)
        ]
    assert codes[:limit] == [401] * limit and codes[-1] == 429


def test_rate_limiter_window() -> None:
    now = [0.0]
    limiter = RateLimiter(2, 60, clock=lambda: now[0])
    limiter.hit("k")
    limiter.hit("k")
    assert limiter.blocked_for("k") == 60
    now[0] = 61
    assert limiter.blocked_for("k") == 0
    limiter.hit("k")
    limiter.reset("k")
    assert limiter.blocked_for("k") == 0


def test_agent_registration_is_rate_limited_but_heartbeats_are_not(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    limit = get_settings().agent_register_max_per_minute
    with TestClient(client.app, client=("10.7.7.7", 1)) as prober:
        codes = [
            prober.post(
                f"{API}/agents/register",
                json=agent_payload(),
                headers={"X-Enrollment-Token": "sentra_et_wrong"},
            ).status_code
            for _ in range(limit + 1)
        ]
    assert codes[:limit] == [401] * limit
    assert codes[-1] == 429
    agent_id = registered_agent["payload"]["agent_id"]
    for _ in range(limit + 5):
        response = client.post(f"{API}/agents/heartbeat", json={"agent_id": agent_id})
        assert response.status_code == 200


# --- Separación de credenciales ------------------------------------------------------------


def test_agents_work_without_a_web_session(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    token = client.tokens[registered_agent["payload"]["agent_id"]]  # type: ignore[attr-defined]
    with TestClient(client.app) as agent:
        response = agent.post(
            f"{API}/agents/heartbeat",
            json={"agent_id": registered_agent["payload"]["agent_id"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        # El token de agente no es una sesión del dashboard...
        agent.cookies.set(COOKIE, token)
        assert agent.get(f"{API}/assets").status_code == 401
        assert (
            agent.get(f"{API}/assets", headers={"Authorization": f"Bearer {token}"}).status_code
            == 401
        )


def test_web_session_is_not_an_agent_credential(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    session_token = client.cookies[COOKIE]
    response = client.post(
        f"{API}/agents/heartbeat",
        json={"agent_id": registered_agent["payload"]["agent_id"]},
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert response.status_code == 401


def test_enrollment_credentials_are_not_sessions(client: TestClient) -> None:
    created = client.post(f"{API}/console/enrollment-tokens", json={}).json()["token"]
    with TestClient(client.app) as browser:
        for value in (created, TEST_ENROLLMENT_KEY, TEST_ADMIN_KEY):
            browser.cookies.set(COOKIE, value)
            assert browser.get(ME).status_code == 401
    # Y el token de enrollment sigue siendo de un solo uso y válido para registrar.
    response = client.post(
        f"{API}/agents/register", json=agent_payload(), headers={"X-Enrollment-Token": created}
    )
    assert response.status_code == 201


def test_admin_api_key_is_separate_from_sessions(client: TestClient) -> None:
    with TestClient(client.app) as script:
        # La clave legacy no abre el dashboard...
        assert (
            script.get(f"{API}/assets", headers={"X-Admin-Key": TEST_ADMIN_KEY}).status_code == 401
        )
        # ...y la sesión del dashboard no abre la API legacy.
        script.cookies = client.cookies
        assert script.get(f"{API}/agent-enrollment-tokens").status_code == 401
        listed = script.get(
            f"{API}/agent-enrollment-tokens", headers={"X-Admin-Key": TEST_ADMIN_KEY}
        )
        assert listed.status_code == 200


def test_admin_api_key_never_reaches_the_browser(client: TestClient) -> None:
    for path in (ME, f"{API}/console", USERS, f"{API}/audit", f"{API}/agents"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert TEST_ADMIN_KEY not in response.text and TEST_ENROLLMENT_KEY not in response.text


def test_no_secrets_in_logs_or_audit(
    client: TestClient,
    db: Session,
    anonymous: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    create_user(db, "ana", "viewer")
    secret_typo = "esto-es-una-contraseña-en-el-usuario"
    _login(anonymous, secret_typo, TEST_PASSWORD)
    _login(anonymous, "ana", "contraseña equivocada muy larga")
    _login(anonymous, "ana")
    session_token = anonymous.cookies[COOKIE]
    csrf = anonymous.headers[CSRF_HEADER]
    created = client.post(f"{API}/console/enrollment-tokens", json={}).json()["token"]
    registered = client.post(
        f"{API}/agents/register", json=agent_payload(), headers={"X-Enrollment-Token": created}
    ).json()
    anonymous.post(LOGOUT)
    logs = caplog.text
    db.expire_all()
    audit = repr([(e.actor, e.target_id, e.details) for e in db.scalars(select(AuditEvent)).all()])
    for secret in (
        TEST_PASSWORD,
        "contraseña equivocada muy larga",
        secret_typo,
        session_token,
        csrf,
        created,
        registered["agent_token"],
        TEST_ADMIN_KEY,
        client.cookies[COOKIE],
    ):
        assert secret not in logs, secret[:6]
        assert secret not in audit, secret[:6]


def test_audit_log_is_admin_only(client: TestClient, engine: Engine) -> None:
    events = client.get(f"{API}/audit").json()["items"]
    assert isinstance(events, list)
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        assert analyst.get(f"{API}/audit").status_code == 403
