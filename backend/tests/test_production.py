"""Fase 4M: endurecimiento de producción y despliegue en servidor central.

Cubre la validación de producción (sin filtrar secretos), el proxy de confianza (anti
spoofing), la exigencia de HTTPS, Host/Origin detrás del proxy, la cookie de producción, la
redacción de logs, el rate limiting compartido en PostgreSQL, los locks de jobs, readiness,
métricas protegidas, el resumen del dashboard y la paginación en SQL, y las copias de
seguridad (sin contraseña en la línea de comandos, destino y restauración seguros).
"""

import io
import json
import logging
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from alembic import command
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session, sessionmaker
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.core.config import Settings, get_settings, parse_networks
from app.core.logging import JsonFormatter, RequestContextFilter
from app.core.production import InsecureConfigurationError, config_findings, startup_failures
from app.core.proxy import TrustedProxyMiddleware, parse_ip, resolve_client
from app.core.rate_limit import DatabaseRateLimiter, RateLimiter
from app.core.redaction import REDACTED, redact_text, redact_value
from app.core.request_context import request_id_var
from app.db.locks import JOB_LOCK_KEYS, singleton_lock
from app.db.session import get_db
from app.main import create_app
from app.models.asset import Asset, AssetStatus, MonitoringMethod
from app.models.rate_limit import RateLimitHit
from app.services import backup_service
from app.services.asset_service import effective_status
from app.services.background import PeriodicJob
from app.services.backup_service import BackupError
from tests.conftest import TEST_PASSWORD, _alembic_config, authenticate, create_user

API = "/api/v1"
# Contraseña de ejemplo para una URL de producción válida (no es ningún secreto real).
STRONG_DB_PASSWORD = "Xk3v9Qm2Lp8Rt5Wz7Hn4"
PROD_DB = f"postgresql+psycopg://sentra:{STRONG_DB_PASSWORD}@127.0.0.1:5433/sentra"


def prod_settings(**overrides: Any) -> Settings:
    """Configuración de producción correcta; cada test cambia lo que quiere romper."""
    values: dict[str, Any] = {
        "_env_file": None,
        "environment": "production",
        "database_url": PROD_DB,
        "allowed_hosts": "sentra.lan",
        "cors_origins": "",
        "agent_server_url": "https://sentra.lan",
        # Memoria para no depender de la base principal en estos tests (es un WARN).
        "rate_limit_backend": "memory",
        "db_statement_timeout_seconds": 30,
        "agent_enrollment_key": None,
        "admin_api_key": None,
        "background_jobs_enabled": False,
    }
    values.update(overrides)
    return Settings(**values)


# --- Validación de producción ---------------------------------------------------------------


def test_secure_production_configuration_starts() -> None:
    settings = prod_settings()
    assert startup_failures(settings) == []
    codes = {f.code: f.level for f in config_findings(settings)}
    # La IA apagada es solo un aviso: Sentra funciona sin ella.
    assert codes["ai"] == "WARN"
    assert codes["ai_external"] == "PASS"
    create_app(settings)


def test_insecure_production_refuses_to_start_without_printing_secrets() -> None:
    weak_password = "weak-SECRET-pw"  # < 16 caracteres
    metrics_token = "metrics-changeme-0123456789abcdef-SECRET"
    settings = prod_settings(
        database_url=f"postgresql+psycopg://sentra:{weak_password}@127.0.0.1:5433/sentra",
        log_level="DEBUG",
        session_cookie_secure=False,
        cors_origins="http://sentra.lan",
        agent_server_url="http://sentra.lan:8000",
        allowed_hosts="",
        metrics_enabled=True,
        metrics_token=metrics_token,
    )
    with pytest.raises(InsecureConfigurationError) as raised:
        create_app(settings)
    failed = {f.code for f in raised.value.findings}
    assert {
        "log_level",
        "allowed_hosts",
        "cors_origins",
        "session_cookie",
        "database_password",
        "agent_server_url",
        "metrics_token",
    } <= failed
    message = str(raised.value)
    assert weak_password not in message
    assert metrics_token not in message
    assert STRONG_DB_PASSWORD not in message


def test_production_rejects_wildcard_hosts_and_the_postgres_superuser() -> None:
    settings = prod_settings(
        allowed_hosts="*",
        database_url=f"postgresql+psycopg://postgres:{STRONG_DB_PASSWORD}@127.0.0.1:5433/sentra",
    )
    failed = {f.code for f in startup_failures(settings)}
    assert {"allowed_hosts", "database_user"} <= failed


def test_development_is_never_blocked() -> None:
    settings = Settings(_env_file=None, database_url="postgresql+psycopg://sentra:x@h/sentra")
    assert startup_failures(settings) == []


def test_settings_errors_never_echo_the_rejected_value() -> None:
    short_token = "tiny-SECRET-token"
    with pytest.raises(ValidationError) as raised:
        Settings(_env_file=None, database_url="postgresql://x", metrics_token=short_token)
    assert short_token not in str(raised.value)


def test_trusted_proxies_never_accept_everything() -> None:
    for bad in ("0.0.0.0/0", "::/0", "proxy.lan", "10.0.0.0/33"):
        with pytest.raises(ValueError):
            parse_networks(bad, "TRUSTED_PROXIES")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, database_url="postgresql://x", trusted_proxies="0.0.0.0/0")


# --- Proxy de confianza ---------------------------------------------------------------------

LOCAL = parse_networks("127.0.0.1,::1", "TRUSTED_PROXIES")


def _ip(value: str) -> Any:
    address = parse_ip(value)
    assert address is not None
    return address


@pytest.mark.parametrize(
    ("peer", "forwarded", "networks", "expected"),
    [
        # Cliente directo (no es un proxy de confianza): su X-Forwarded-For no cuenta.
        ("203.0.113.5", "1.2.3.4", LOCAL, "203.0.113.5"),
        # Proxy local: el cliente es lo que añadió el proxy.
        ("127.0.0.1", "198.51.100.7", LOCAL, "198.51.100.7"),
        # El cliente intenta colar una IP a la izquierda: se ignora.
        ("127.0.0.1", "1.2.3.4, 198.51.100.7", LOCAL, "198.51.100.7"),
        # Cadena de proxies de confianza (balanceador interno + proxy local).
        (
            "127.0.0.1",
            "198.51.100.7, 10.0.0.5",
            parse_networks("127.0.0.1,10.0.0.0/8", "TRUSTED_PROXIES"),
            "198.51.100.7",
        ),
        # Basura en la cabecera: nunca se toma como IP.
        ("127.0.0.1", "evil, <script>", LOCAL, "127.0.0.1"),
        ("127.0.0.1", None, LOCAL, "127.0.0.1"),
        # IPv4 mapeada en IPv6 = la misma máquina.
        ("::ffff:127.0.0.1", "198.51.100.7", LOCAL, "198.51.100.7"),
    ],
)
def test_client_address_behind_the_proxy(
    peer: str, forwarded: str | None, networks: Any, expected: str
) -> None:
    assert str(resolve_client(_ip(peer), forwarded, networks)) == expected


def _echo_app() -> Any:
    async def echo(request: Request) -> JSONResponse:
        client = request.client.host if request.client else None
        return JSONResponse({"client": client, "scheme": request.url.scheme})

    return TrustedProxyMiddleware(Starlette(routes=[Route("/", echo)]), LOCAL)


def test_forwarded_headers_are_ignored_from_untrusted_clients() -> None:
    spoof = {"X-Forwarded-For": "1.2.3.4", "X-Forwarded-Proto": "https"}
    with TestClient(_echo_app(), client=("203.0.113.5", 4000)) as direct:
        assert direct.get("/", headers=spoof).json() == {"client": "203.0.113.5", "scheme": "http"}
    with TestClient(_echo_app(), client=("127.0.0.1", 4000)) as proxy:
        assert proxy.get("/", headers=spoof).json() == {"client": "1.2.3.4", "scheme": "https"}
        # Un esquema inventado no se acepta.
        weird = proxy.get("/", headers={"X-Forwarded-Proto": "gopher"}).json()
        assert weird["scheme"] == "http"


def test_production_requires_https_except_for_local_probes() -> None:
    app = create_app(prod_settings())
    with TestClient(app, base_url="http://sentra.lan", client=("203.0.113.5", 1)) as direct:
        refused = direct.get(f"{API}/auth/me")
        assert refused.status_code == 403
        assert refused.json()["error"]["code"] == "https_required"
        # Un cliente directo no puede hacerse pasar por HTTPS con la cabecera.
        spoofed = direct.get(f"{API}/auth/me", headers={"X-Forwarded-Proto": "https"})
        assert spoofed.status_code == 403
        assert direct.get(f"{API}/health").status_code == 200
    with TestClient(app, base_url="http://sentra.lan", client=("127.0.0.1", 1)) as proxy:
        through = proxy.get(f"{API}/auth/me", headers={"X-Forwarded-Proto": "https"})
        assert through.status_code == 401  # pasó el control de HTTPS; falta la sesión
    with TestClient(app, base_url="https://evil.example") as wrong_host:
        assert wrong_host.get(f"{API}/health").status_code == 400


@pytest.fixture
def prod_app(engine: Engine, client: TestClient) -> Iterator[Any]:
    """App de producción detrás de un proxy local, con la base de tests.

    Depende de `client` para heredar su limpieza de tablas al terminar.
    """
    settings = prod_settings()
    app = create_app(settings)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_db() -> Iterator[Session]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = lambda: settings
    yield app


def _proxied(app: Any) -> TestClient:
    # Lo que hace Caddy: conecta desde 127.0.0.1, conserva Host y añade X-Forwarded-*.
    browser = TestClient(app, base_url="http://sentra.lan", client=("127.0.0.1", 1))
    browser.headers.update({"X-Forwarded-For": "198.51.100.20", "X-Forwarded-Proto": "https"})
    return browser


def test_production_login_cookie_and_origin_behind_the_proxy(prod_app: Any, engine: Engine) -> None:
    with Session(engine) as db:
        create_user(db, "ana", "viewer")
    browser = _proxied(prod_app)
    body = {"username": "ana", "password": TEST_PASSWORD}

    foreign = browser.post(
        f"{API}/auth/login", json=body, headers={"Origin": "https://evil.example"}
    )
    assert foreign.status_code == 403

    response = browser.post(
        f"{API}/auth/login", json=body, headers={"Origin": "https://sentra.lan"}
    )
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert cookie.startswith("__Host-sentra_session=")
    for attribute in ("Secure", "HttpOnly", "SameSite=strict", "Path=/"):
        assert attribute in cookie
    assert "Domain" not in cookie
    # El token de sesión nunca va en el cuerpo (no acaba en localStorage).
    assert "sentra_s_" not in response.text
    with Session(engine) as db:
        ip = db.execute(
            text("SELECT client_ip FROM user_sessions ORDER BY created_at DESC LIMIT 1")
        ).scalar()
    assert str(ip) == "198.51.100.20"


def test_login_rate_limit_counts_the_real_client_not_the_proxy(
    prod_app: Any, engine: Engine
) -> None:
    with Session(engine) as db:
        create_user(db, "ana", "viewer")
    browser = _proxied(prod_app)
    limit = get_settings().login_max_failures_per_user_ip
    for _ in range(limit):
        bad = {"username": "ana", "password": "intento equivocado"}
        assert browser.post(f"{API}/auth/login", json=bad).status_code == 401
    assert (
        browser.post(
            f"{API}/auth/login", json={"username": "ana", "password": TEST_PASSWORD}
        ).status_code
        == 429
    )
    # Otro cliente real tras el mismo proxy no hereda el bloqueo.
    browser.headers["X-Forwarded-For"] = "198.51.100.21"
    assert (
        browser.post(
            f"{API}/auth/login", json={"username": "ana", "password": TEST_PASSWORD}
        ).status_code
        == 200
    )


# --- Redacción de logs ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("connect postgresql+psycopg://sentra:Pa55w0rdXYZ@db.lan:5433/sentra", "Pa55w0rdXYZ"),
        ("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi.payload.sig"),
        ("cookie=__Host-sentra_session=sentra_s_abcdef0123456789", "sentra_s_abcdef0123456789"),
        ("token sentra_et_0123456789abcdef issued", "sentra_et_0123456789abcdef"),
        ("password=hunter2hunter2 user=ana", "hunter2hunter2"),
        ("X-CSRF-Token: 0123456789abcdef0123", "0123456789abcdef0123"),
        ('{"api_key": "sk-local-123456789"}', "sk-local-123456789"),
    ],
)
def test_redact_text(raw: str, secret: str) -> None:
    redacted = redact_text(raw)
    assert secret not in redacted
    assert REDACTED in redacted


def test_redact_value_keeps_structure_and_numbers() -> None:
    value = {
        "username": "ana",
        "password": "hunter2",
        "headers": {"Cookie": "a=b", "User-Agent": "Firefox"},
        "agent_token": "x" * 40,
        "max_tokens": 128,
        "items": [{"secret": "s"}, "postgresql://u:p4ss@h/d"],
    }
    redacted = redact_value(value)
    assert redacted["username"] == "ana"
    assert redacted["password"] == REDACTED
    assert redacted["headers"] == {"Cookie": REDACTED, "User-Agent": "Firefox"}
    assert redacted["agent_token"] == REDACTED
    assert redacted["max_tokens"] == 128  # un número no es un secreto
    assert redacted["items"][0] == {"secret": REDACTED}
    assert "p4ss" not in redacted["items"][1]


def test_json_logs_redact_messages_extras_and_tracebacks() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestContextFilter())
    logger = logging.getLogger("sentra.test.redaction")
    logger.addHandler(handler)
    logger.propagate = False
    token = request_id_var.set("req-123")
    try:
        try:
            raise RuntimeError("could not connect to postgresql://sentra:TopSecret99@db/sentra")
        except RuntimeError:
            logger.exception(
                "login failed for password=Hunter2Hunter2",
                extra={"authorization": "Bearer abc", "ai_api_key": "k-1", "attempts": 3},
            )
    finally:
        request_id_var.reset(token)
        logger.removeHandler(handler)
    output = stream.getvalue()
    for secret in ("TopSecret99", "Hunter2Hunter2", "Bearer abc", "k-1"):
        assert secret not in output
    record = json.loads(output)
    assert record["request_id"] == "req-123"
    assert record["attempts"] == 3
    assert record["level"] == "ERROR"
    assert "timestamp" in record and "event" in record


def test_internal_errors_never_expose_a_traceback(client: TestClient) -> None:
    # Una ruta que no existe y una petición inválida: envoltorio estable, sin trazas.
    response = client.get(f"{API}/assets/not-a-uuid")
    assert "Traceback" not in response.text
    assert "error" in response.json()


# --- Rate limiting compartido ---------------------------------------------------------------


def test_database_rate_limit_is_shared_between_workers(engine: Engine, client: TestClient) -> None:
    worker_a = DatabaseRateLimiter("test_shared", 3, 60, lambda: engine)
    worker_b = DatabaseRateLimiter("test_shared", 3, 60, lambda: engine)
    assert worker_a.acquire("ana@10.0.0.1") == 0
    assert worker_b.acquire("ana@10.0.0.1") == 0
    assert worker_a.acquire("ana@10.0.0.1") == 0
    # El cuarto intento se bloquea en cualquiera de los dos procesos.
    assert worker_b.acquire("ana@10.0.0.1") > 0
    assert worker_a.blocked_for("ana@10.0.0.1") > 0
    assert worker_a.acquire("otra-clave") == 0
    # Persistente: un "reinicio" (instancia nueva) sigue bloqueado.
    restarted = DatabaseRateLimiter("test_shared", 3, 60, lambda: engine)
    assert restarted.blocked_for("ana@10.0.0.1") > 0
    restarted.reset("ana@10.0.0.1")
    assert worker_a.blocked_for("ana@10.0.0.1") == 0
    # La clave no queda en claro en la tabla.
    with Session(engine) as db:
        stored = db.scalars(select(RateLimitHit.key_hash)).all()
    assert stored and all("ana" not in key and len(key) == 64 for key in stored)


def test_database_rate_limit_is_atomic_under_concurrency(
    engine: Engine, client: TestClient
) -> None:
    limiters = [DatabaseRateLimiter("test_race", 5, 60, lambda: engine) for _ in range(4)]
    results: list[float] = []
    lock = threading.Lock()

    def attempt(index: int) -> None:
        wait = limiters[index % len(limiters)].acquire("same-key")
        with lock:
            results.append(wait)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(1 for wait in results if wait == 0) == 5


def test_memory_rate_limit_acquire() -> None:
    now = [0.0]
    limiter = RateLimiter(2, 60, clock=lambda: now[0])
    assert limiter.acquire("k") == 0
    assert limiter.acquire("k") == 0
    assert limiter.acquire("k") == pytest.approx(60)
    now[0] = 30
    assert limiter.acquire("k") == pytest.approx(30)
    now[0] = 61
    assert limiter.acquire("k") == 0


# --- Jobs con varios workers ----------------------------------------------------------------


def test_singleton_job_lock(engine: Engine) -> None:
    key = JOB_LOCK_KEYS["risk-engine"]
    with (
        singleton_lock(lambda: engine, key) as first,
        singleton_lock(lambda: engine, key) as second,
    ):
        assert first is True
        assert second is False
    with singleton_lock(lambda: engine, key) as again:
        assert again is True


def test_periodic_job_skips_while_another_worker_runs_it(engine: Engine) -> None:
    runs: list[int] = []
    job = PeriodicJob("risk-engine", 60, lambda: runs.append(1), lock_engine=lambda: engine)
    with singleton_lock(lambda: engine, JOB_LOCK_KEYS["risk-engine"]):
        assert job.run_once() == "skipped"
    assert runs == []
    assert job.run_once() == "success"
    assert runs == [1]


# --- Salud y métricas -----------------------------------------------------------------------


def test_readiness_turns_off_while_draining(client: TestClient) -> None:
    assert client.get(f"{API}/health/ready").status_code == 200
    client.app.state.draining = True  # type: ignore[attr-defined]
    try:
        response = client.get(f"{API}/health/ready")
        assert response.status_code == 503
        assert response.json()["status"] == "not_ready"
        # Liveness no depende del apagado: el proceso sigue vivo.
        assert client.get(f"{API}/health").status_code == 200
    finally:
        client.app.state.draining = False  # type: ignore[attr-defined]


def _metrics_settings(**overrides: Any) -> Settings:
    return get_settings().model_copy(update={"metrics_enabled": True, **overrides})


def test_metrics_are_disabled_by_default(client: TestClient) -> None:
    with TestClient(client.app, client=("127.0.0.1", 1)) as local:
        assert local.get(f"{API}/metrics").status_code == 404


def test_metrics_only_from_allowed_networks_and_with_token(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    token = "m" * 16 + "-metrics-token-0123456789"
    app = client.app
    app.dependency_overrides[get_settings] = lambda: _metrics_settings(  # type: ignore[attr-defined]
        metrics_token=SecretStr(token)
    )
    try:
        with TestClient(app, client=("127.0.0.1", 1)) as local:
            assert local.get(f"{API}/metrics").status_code == 401
            wrong = local.get(f"{API}/metrics", headers={"Authorization": "Bearer nope"})
            assert wrong.status_code == 401
            ok = local.get(f"{API}/metrics", headers={"Authorization": f"Bearer {token}"})
            # Vía el proxy, la IP real (de Internet) no está en la red autorizada.
            proxied = local.get(
                f"{API}/metrics",
                headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "203.0.113.9"},
            )
        with TestClient(app, client=("203.0.113.9", 1)) as remote:
            outside = remote.get(f"{API}/metrics", headers={"Authorization": f"Bearer {token}"})
    finally:
        app.dependency_overrides.pop(get_settings)  # type: ignore[attr-defined]
    assert ok.status_code == 200
    assert ok.headers["content-type"].startswith("text/plain")
    assert "sentra_assets{" in ok.text
    assert "sentra_http_requests_total" in ok.text
    # Sin datos sensibles en las etiquetas: ni hostnames ni IPs ni identificadores.
    payload = registered_agent["payload"]
    for leak in (payload["hostname"], payload["primary_ip"], payload["agent_id"]):
        assert leak not in ok.text
    assert proxied.status_code == 404
    assert outside.status_code == 404


# --- Dashboard y paginación en SQL ----------------------------------------------------------


def _asset(db: Session, ip: str, **fields: Any) -> Asset:
    asset = Asset(primary_ip=ip, first_seen_at=datetime.now(UTC), **fields)
    db.add(asset)
    db.commit()
    return asset


@pytest.fixture
def fleet(engine: Engine, client: TestClient) -> list[Asset]:
    """Un activo de cada caso de estado efectivo, con IPs que ordenan distinto como texto."""
    now = datetime.now(UTC)
    agent = MonitoringMethod.AGENT
    with Session(engine, expire_on_commit=False) as db:
        return [
            _asset(db, "10.0.0.9", monitoring_method=agent, agent_id=uuid4(), hostname="web-9",
                   status=AssetStatus.ONLINE, last_seen_at=now),
            _asset(db, "10.0.0.10", monitoring_method=agent, agent_id=uuid4(), hostname="db-10",
                   status=AssetStatus.ONLINE, last_seen_at=now - timedelta(hours=2)),
            _asset(db, "10.0.0.100", monitoring_method=agent, agent_id=uuid4(),
                   hostname="new-100", status=AssetStatus.ONLINE),
            _asset(db, "10.0.1.5", monitoring_method=MonitoringMethod.DISCOVERED,
                   network_status=AssetStatus.ONLINE, last_network_seen_at=now,
                   device_type="printer"),
            _asset(db, "192.168.1.7", monitoring_method=MonitoringMethod.DISCOVERED,
                   network_status=AssetStatus.OFFLINE, last_network_seen_at=now),
            _asset(db, "192.168.1.8", monitoring_method=MonitoringMethod.AGENTLESS),
        ]  # fmt: skip


def test_sql_status_matches_the_python_rule(client: TestClient, fleet: list[Asset]) -> None:
    timeout = timedelta(seconds=get_settings().heartbeat_timeout_seconds)
    now = datetime.now(UTC)
    expected = {a.primary_ip: effective_status(a, now, timeout).value for a in fleet}
    listed = client.get(f"{API}/assets", params={"limit": 500}).json()
    assert {a["primary_ip"]: a["status"] for a in listed["items"]} == expected
    counts = {s: list(expected.values()).count(s) for s in ("online", "offline", "unknown")}
    assert listed["status_counts"] == counts
    for state, count in counts.items():
        filtered = client.get(f"{API}/assets", params={"status": state}).json()
        assert filtered["total"] == count
        assert {a["status"] for a in filtered["items"]} <= {state}

    summary = client.get(f"{API}/dashboard/summary").json()
    assert summary["assets"]["total"] == len(fleet)
    assert {k: summary["assets"][k] for k in counts} == counts
    assert summary["assets"]["by_method"] == {"agent": 3, "discovered": 2, "agentless": 1}
    assert summary["assets"]["by_device_type"]["printer"] == 1
    assert summary["incidents"] is not None  # el admin puede leer incidentes


def test_assets_are_paginated_sorted_and_filtered_in_sql(
    client: TestClient, fleet: list[Asset]
) -> None:
    by_ip = client.get(f"{API}/assets", params={"sort": "ip"}).json()
    ips = [a["primary_ip"] for a in by_ip["items"]]
    # Orden numérico de IP, no alfabético (10.0.0.9 < 10.0.0.10 < 10.0.0.100).
    assert ips == ["10.0.0.9", "10.0.0.10", "10.0.0.100", "10.0.1.5", "192.168.1.7", "192.168.1.8"]
    desc = client.get(f"{API}/assets", params={"sort": "ip", "order": "desc"}).json()
    assert [a["primary_ip"] for a in desc["items"]] == list(reversed(ips))

    first = client.get(f"{API}/assets", params={"sort": "ip", "limit": 4}).json()
    second = client.get(f"{API}/assets", params={"sort": "ip", "limit": 4, "offset": 4}).json()
    assert first["total"] == second["total"] == 6
    assert (first["limit"], first["offset"], second["offset"]) == (4, 0, 4)
    paged = [a["primary_ip"] for a in first["items"] + second["items"]]
    assert paged == ips

    subnet = client.get(f"{API}/assets", params={"subnet": "10.0.0.0/24"}).json()
    assert subnet["total"] == 3
    search = client.get(f"{API}/assets", params={"q": "DB-1"}).json()
    assert [a["primary_ip"] for a in search["items"]] == ["10.0.0.10"]
    assert client.get(f"{API}/assets", params={"limit": 501}).status_code == 422
    assert client.get(f"{API}/assets", params={"sort": "nope"}).status_code == 422


def test_summary_needs_a_session_and_is_readable_by_viewers(
    client: TestClient, engine: Engine, fleet: list[Asset]
) -> None:
    with TestClient(client.app) as anonymous:
        assert anonymous.get(f"{API}/dashboard/summary").status_code == 401
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        summary = viewer.get(f"{API}/dashboard/summary")
    assert summary.status_code == 200
    assert summary.json()["assets"]["total"] == len(fleet)


# --- Copias de seguridad --------------------------------------------------------------------


def test_backup_password_never_in_the_command_line(tmp_path: Path) -> None:
    url = "postgresql+psycopg://sentra:Sup3rS3cret!@db.lan:5433/sentra?sslmode=require"
    command_line = backup_service.dump_command("pg_dump", tmp_path / "x.dump")
    assert not any("Sup3rS3cret" in part or "db.lan" in part for part in command_line)
    assert "--no-password" in command_line
    env = backup_service.connection_env(url, base={"PGPASSWORD": "other", "PGSERVICE": "x"})
    assert env["PGPASSWORD"] == "Sup3rS3cret!"
    assert (env["PGHOST"], env["PGPORT"], env["PGUSER"], env["PGDATABASE"]) == (
        "db.lan",
        "5433",
        "sentra",
        "sentra",
    )
    assert env["PGSSLMODE"] == "require"
    assert "PGSERVICE" not in env


def test_backup_destination_must_be_safe(tmp_path: Path) -> None:
    with pytest.raises(BackupError, match="absolute"):
        backup_service.check_destination(Path("backups"))
    with pytest.raises(BackupError, match="outside"):
        backup_service.check_destination(backup_service.REPO_DIR / "backups")
    webroot = tmp_path / "www"
    with pytest.raises(BackupError, match="outside"):
        backup_service.check_destination(webroot / "dumps", str(webroot))
    assert backup_service.check_destination(tmp_path / "ok") == (tmp_path / "ok").resolve()


def _tool_filename(name: str) -> str:
    """Nombre del ejecutable tal como lo busca find_tool en PG_BIN_DIR (.exe en Windows)."""
    return name + (".exe" if sys.platform == "win32" else "")


def _fake_tools(tmp_path: Path) -> str:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("pg_dump", "pg_restore"):
        (bin_dir / _tool_filename(name)).write_text("")
    return str(bin_dir)


def test_find_tool_requires_the_platform_executable_in_pg_bin_dir(tmp_path: Path) -> None:
    bin_dir = _fake_tools(tmp_path)
    found = backup_service.find_tool("pg_dump", bin_dir)
    assert Path(found).name == _tool_filename("pg_dump") and Path(found).is_file()
    # Sin el ejecutable exacto no se acepta nada parecido (ni se cae al PATH).
    with pytest.raises(BackupError, match="not found in PG_BIN_DIR"):
        backup_service.find_tool("pg_dumpall", bin_dir)


LISTING = "\n".join(f"1; 2615 1 TABLE public {t} sentra" for t in backup_service.KEY_TABLES)


def test_create_backup_verifies_checksums_and_prunes(tmp_path: Path) -> None:
    bin_dir = _fake_tools(tmp_path)
    calls: list[tuple[list[str], dict[str, str] | None]] = []

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs.get("env")))
        if "--list" in args:
            return subprocess.CompletedProcess(args, 0, LISTING, "")
        target = next(a.split("=", 1)[1] for a in args if a.startswith("--file="))
        Path(target).write_bytes(b"PGDMP fake dump")
        return subprocess.CompletedProcess(args, 0, "", "")

    dest = tmp_path / "backups"
    dest.mkdir()
    old = datetime(2026, 1, 1, tzinfo=UTC)
    stale = []
    for day in range(5):
        path = dest / f"sentra-sentra-2026010{day + 1}T000000Z.dump"
        path.write_bytes(b"old")
        stamp = (old + timedelta(days=day)).timestamp()
        os.utime(path, (stamp, stamp))
        stale.append(path)

    url = "postgresql+psycopg://sentra:Pw0rd-NotInArgs@127.0.0.1:5433/sentra"
    now = datetime(2026, 10, 6, 3, 0, tzinfo=UTC)
    result = backup_service.create_backup(url, dest, 14, bin_dir, run=run, now=now)

    assert result.path.name == "sentra-sentra-20261006T030000Z.dump"
    assert result.path.is_file() and not list(dest.glob("*.partial"))
    sidecar = backup_service.checksum_path(result.path).read_text()
    assert sidecar.split()[0] == result.sha256
    # Retención: se borran las viejas pero quedan al menos MIN_KEEP copias.
    remaining = sorted(dest.glob("sentra-*.dump"))
    assert len(remaining) == backup_service.MIN_KEEP
    assert len(result.deleted) == 3
    for args, _env in calls:
        assert not any("Pw0rd-NotInArgs" in part for part in args)
    # Una copia alterada ya no pasa la verificación.
    result.path.write_bytes(b"PGDMP tampered")
    with pytest.raises(BackupError, match="checksum"):
        backup_service.verify_backup(result.path, "pg_restore", run)


def test_failed_dump_leaves_no_partial_file(tmp_path: Path) -> None:
    bin_dir = _fake_tools(tmp_path)

    calls: list[list[str]] = []

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        target = next(a.split("=", 1)[1] for a in args if a.startswith("--file="))
        Path(target).write_bytes(b"half")
        return subprocess.CompletedProcess(args, 1, "", "pg_dump: error: connection refused")

    dest = tmp_path / "backups"
    url = "postgresql+psycopg://sentra:Pw0rd-NotInError@127.0.0.1/sentra"
    with pytest.raises(BackupError, match="exit 1") as failure:
        backup_service.create_backup(url, dest, 14, bin_dir, run=run)
    # Llegó a ejecutar pg_dump (no se quedó en find_tool) y no dejó el parcial.
    assert len(calls) == 1
    assert Path(calls[0][0]).name == _tool_filename("pg_dump")
    assert list(dest.iterdir()) == []
    assert "Pw0rd-NotInError" not in str(failure.value)
    assert not any("Pw0rd-NotInError" in part for part in calls[0])


def test_restore_needs_explicit_confirmation_and_an_empty_target(engine: Engine) -> None:
    url = engine.url.render_as_string(hide_password=False)
    target = engine.url.database or ""
    with pytest.raises(BackupError, match="--confirm"):
        backup_service.check_restore_target(url, target, None)
    with pytest.raises(BackupError, match="--confirm"):
        backup_service.check_restore_target(url, target, "otra")
    # La base de tests tiene tablas (y conexiones): nunca se restaura encima.
    with pytest.raises(BackupError, match=r"not empty|other connection"):
        backup_service.check_restore_target(url, target, target)
    with pytest.raises(BackupError, match="create it first"):
        backup_service.check_restore_target(url, "sentra_does_not_exist", "sentra_does_not_exist")
    restore = backup_service.restore_command("pg_restore", Path("/b/x.dump"), "sentra_restored")
    assert "--single-transaction" in restore and "--exit-on-error" in restore
    assert "--clean" not in restore


# --- Migración 0024 -------------------------------------------------------------------------


def test_rate_limit_migration_downgrades_and_upgrades(engine: Engine) -> None:
    config = _alembic_config(engine.url.render_as_string(hide_password=False))
    command.downgrade(config, "0023")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT to_regclass('public.rate_limit_hits')")).scalar() is None
    command.upgrade(config, "0024")
    command.downgrade(config, "0023")
    command.upgrade(config, "head")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT to_regclass('public.rate_limit_hits')")).scalar()


# --- IA local -------------------------------------------------------------------------------


def test_the_browser_never_reaches_the_ai_runtime_directly() -> None:
    # Ninguna ruta reenvía rutas arbitrarias (un proxy abierto al runtime de IA) y ningún
    # esquema de respuesta publica la URL del runtime ni la clave.
    app = create_app()
    assert not [r for r in app.routes if ":path}" in getattr(r, "path", "")]
    schemas = app.openapi()["components"]["schemas"]
    exposed = {
        f"{name}.{field}"
        for name, schema in schemas.items()
        for field in schema.get("properties", {})
        if field in {"base_url", "ai_base_url", "api_key", "ai_api_key", "runtime_url"}
    }
    assert exposed == set()
