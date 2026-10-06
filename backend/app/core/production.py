"""Validación de configuración de producción (Fase 4M).

Dos usos con las mismas reglas:
- al arrancar con ENVIRONMENT=production, create_app() se niega a iniciar si hay algún FAIL
  (fail fast: mejor un servicio que no arranca con un mensaje claro que uno expuesto);
- `python -m app.cli production-check` muestra todo (PASS/WARN/FAIL) y añade las
  comprobaciones que necesitan red o disco (base de datos, migraciones, frontend...).

Los mensajes nunca incluyen el valor de un secreto: solo qué variable falla y por qué.
"""

import ipaddress
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.core.config import Settings, parse_name_list

Level = Literal["PASS", "WARN", "FAIL"]

# Valores de ejemplo o triviales que nunca deben llegar a producción. Comparación sin
# mayúsculas; además se rechaza cualquier valor que contenga "change-me" o "changeme".
_PLACEHOLDERS = frozenset(
    {
        "sentra",
        "postgres",
        "password",
        "admin",
        "secret",
        "changeme",
        "change-me",
        "example",
        "test",
        "sentra_dev_pw",
        "change-me-enrollment-key",
    }
)
MIN_DB_PASSWORD = 16


@dataclass(frozen=True)
class Finding:
    level: Level
    code: str
    message: str


class InsecureConfigurationError(RuntimeError):
    """Configuración de producción rechazada al arrancar. El texto no contiene secretos."""

    def __init__(self, findings: list[Finding]) -> None:
        lines = "\n".join(f"  FAIL {f.code}: {f.message}" for f in findings)
        super().__init__(
            "Refusing to start: insecure production configuration\n"
            f"{lines}\nRun `python -m app.cli production-check` for the full report."
        )
        self.findings = findings


def _placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered in _PLACEHOLDERS or "change-me" in lowered or "changeme" in lowered


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _check_secret(name: str, value: str | None, legacy_note: str | None) -> list[Finding]:
    if value is None:
        return [Finding("PASS", name.lower(), f"{name} not set")]
    if _placeholder(value) or len(set(value)) < 8:
        return [Finding("FAIL", name.lower(), f"{name} is an example or trivial value")]
    if legacy_note:
        return [Finding("WARN", name.lower(), legacy_note)]
    return [Finding("PASS", name.lower(), f"{name} set")]


def _database_findings(settings: Settings) -> list[Finding]:
    try:
        url = make_url(settings.database_url)
    except ArgumentError:
        return [Finding("FAIL", "database_url", "DATABASE_URL is not a valid SQLAlchemy URL")]
    findings: list[Finding] = []
    if not url.drivername.startswith("postgresql"):
        findings.append(Finding("FAIL", "database_url", "DATABASE_URL must be PostgreSQL"))
    if (url.username or "") == "postgres":
        findings.append(
            Finding(
                "FAIL",
                "database_user",
                "DATABASE_URL uses the postgres superuser; use a dedicated role (sentra)",
            )
        )
    password = url.password if isinstance(url.password, str) else None
    if password is None:
        # Sin contraseña en la URL puede ser .pgpass o peer: válido, pero se avisa.
        findings.append(
            Finding("WARN", "database_password", "DATABASE_URL has no password (pgpass/peer?)")
        )
    elif _placeholder(password) or len(password) < MIN_DB_PASSWORD:
        findings.append(
            Finding(
                "FAIL",
                "database_password",
                f"database password is an example value or shorter than {MIN_DB_PASSWORD}",
            )
        )
    else:
        findings.append(Finding("PASS", "database_password", "database password set"))
    host = url.host or ""
    sslmode = str(url.query.get("sslmode", ""))
    if host and not _is_loopback_host(host) and not host.startswith("/"):
        if sslmode in ("require", "verify-ca", "verify-full"):
            findings.append(Finding("PASS", "database_tls", f"remote database with {sslmode}"))
        else:
            findings.append(
                Finding(
                    "WARN",
                    "database_tls",
                    "database on another host without sslmode=require/verify-full",
                )
            )
    return findings


def config_findings(settings: Settings) -> list[Finding]:
    """Reglas que solo leen la configuración (sin red ni disco). Pensadas para producción."""
    f: list[Finding] = []

    if settings.is_production:
        f.append(Finding("PASS", "environment", "ENVIRONMENT=production"))
    else:
        f.append(
            Finding("FAIL", "environment", f"ENVIRONMENT is {settings.environment}, not production")
        )

    if settings.log_level.upper() == "DEBUG":
        f.append(Finding("FAIL", "log_level", "LOG_LEVEL=DEBUG is not allowed in production"))
    else:
        f.append(Finding("PASS", "log_level", f"LOG_LEVEL={settings.log_level.upper()}"))

    hosts = settings.allowed_host_list
    if not hosts:
        f.append(Finding("FAIL", "allowed_hosts", "ALLOWED_HOSTS is empty; list the public names"))
    elif any("*" in host for host in hosts):
        f.append(Finding("FAIL", "allowed_hosts", "ALLOWED_HOSTS must not contain wildcards"))
    else:
        f.append(Finding("PASS", "allowed_hosts", f"ALLOWED_HOSTS has {len(hosts)} name(s)"))

    insecure_origins = [o for o in settings.cors_origin_list if urlsplit(o).scheme != "https"]
    if insecure_origins:
        f.append(Finding("FAIL", "cors_origins", "CORS_ORIGINS must only list https:// origins"))
    elif settings.cors_origin_list:
        f.append(Finding("PASS", "cors_origins", "CORS_ORIGINS is an explicit https allowlist"))
    else:
        f.append(Finding("PASS", "cors_origins", "same-origin dashboard (no CORS)"))

    if settings.session_cookie_secure is False:
        f.append(
            Finding(
                "FAIL", "session_cookie", "SESSION_COOKIE_SECURE=false sends the cookie over HTTP"
            )
        )
    elif settings.session_cookie_samesite != "strict":
        f.append(
            Finding("WARN", "session_cookie", "SESSION_COOKIE_SAMESITE is lax (strict recommended)")
        )
    else:
        f.append(
            Finding("PASS", "session_cookie", "session cookie Secure, HttpOnly, SameSite=Strict")
        )

    if settings.trusted_proxies.strip():
        f.append(Finding("PASS", "trusted_proxies", "forwarded headers only from TRUSTED_PROXIES"))
    else:
        f.append(
            Finding(
                "WARN",
                "trusted_proxies",
                "TRUSTED_PROXIES is empty: behind a proxy every client shares its address",
            )
        )

    if settings.effective_rate_limit_backend == "database":
        f.append(Finding("PASS", "rate_limit", "rate limits shared in PostgreSQL"))
    else:
        f.append(Finding("WARN", "rate_limit", "RATE_LIMIT_BACKEND=memory: limits are per process"))

    f += _database_findings(settings)

    if settings.db_statement_timeout_seconds:
        f.append(Finding("PASS", "db_statement_timeout", "DB_STATEMENT_TIMEOUT_SECONDS set"))
    else:
        f.append(
            Finding("WARN", "db_statement_timeout", "DB_STATEMENT_TIMEOUT_SECONDS unset (no limit)")
        )

    enrollment = settings.agent_enrollment_key
    f += _check_secret(
        "AGENT_ENROLLMENT_KEY",
        enrollment.get_secret_value() if enrollment else None,
        "AGENT_ENROLLMENT_KEY (legacy shared key) is set; prefer one-time enrollment tokens",
    )
    admin = settings.admin_api_key
    f += _check_secret(
        "ADMIN_API_KEY",
        admin.get_secret_value() if admin else None,
        "ADMIN_API_KEY (legacy automation API) is enabled; unset it if no script uses it",
    )

    server_url = settings.agent_server_url
    if server_url is None:
        f.append(
            Finding("WARN", "agent_server_url", "AGENT_SERVER_URL unset; set https://<sentra-host>")
        )
    elif not server_url.startswith("https://"):
        f.append(Finding("FAIL", "agent_server_url", "AGENT_SERVER_URL must use https://"))
    else:
        f.append(Finding("PASS", "agent_server_url", "agents enroll over https"))

    if settings.metrics_enabled:
        token = settings.metrics_token
        if token is None:
            f.append(Finding("WARN", "metrics", "metrics enabled without METRICS_TOKEN"))
        else:
            f += _check_secret("METRICS_TOKEN", token.get_secret_value(), None)
    else:
        f.append(Finding("PASS", "metrics", "metrics endpoint disabled"))

    if not settings.ai_enabled:
        f.append(Finding("WARN", "ai", "AI disabled (optional; Sentra works without it)"))
    else:
        f.append(Finding("PASS", "ai", "AI enabled"))
    if settings.ai_allow_external:
        f.append(
            Finding("WARN", "ai_external", "AI_ALLOW_EXTERNAL=true: data may leave the server")
        )
    else:
        f.append(Finding("PASS", "ai_external", "AI external providers blocked"))
    if settings.ai_api_key is not None and _placeholder(settings.ai_api_key.get_secret_value()):
        f.append(Finding("FAIL", "ai_api_key", "AI_API_KEY is an example value"))

    if (
        parse_name_list(settings.discovery_allowed_networks)
        and settings.discovery_allow_public_networks
    ):
        f.append(
            Finding(
                "WARN", "discovery", "DISCOVERY_ALLOW_PUBLIC_NETWORKS=true allows Internet scans"
            )
        )
    return f


def startup_failures(settings: Settings) -> list[Finding]:
    """FAIL que impiden arrancar en producción (fuera de producción, ninguno)."""
    if not settings.is_production:
        return []
    return [finding for finding in config_findings(settings) if finding.level == "FAIL"]


def enforce_production(settings: Settings) -> None:
    failures = startup_failures(settings)
    if failures:
        raise InsecureConfigurationError(failures)
