"""Comprobaciones previas al arranque o a una actualización (Fase 4M).

`python -m app.cli production-check` = reglas de configuración (core/production.py) + estas,
que necesitan red o disco. Ninguna modifica nada: no migra, no crea directorios ni toca la
base. Pensadas para el flujo backup -> preflight -> migración -> health -> arranque.
"""

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import Settings, parse_model_directories
from app.core.production import Finding, config_findings
from app.db.migrations import BACKEND_DIR
from app.db.session import engine_from_settings

REPO_DIR = BACKEND_DIR.parent


@dataclass(frozen=True)
class MigrationState:
    current: tuple[str, ...]
    heads: tuple[str, ...]
    unknown: tuple[str, ...]

    @property
    def up_to_date(self) -> bool:
        return set(self.current) == set(self.heads)


def script_directory() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(str(BACKEND_DIR / "alembic.ini")))


def migration_state(engine: Engine) -> MigrationState:
    """Revisión actual de la base frente a la(s) del código. Lanza SQLAlchemyError."""
    script = script_directory()
    heads = tuple(sorted(script.get_heads()))
    with engine.connect() as conn:
        exists = conn.execute(text("SELECT to_regclass('public.alembic_version')")).scalar()
        rows = (
            conn.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
            if exists
            else []
        )
    unknown: list[str] = []
    for revision in rows:
        try:
            if script.get_revision(revision) is None:
                unknown.append(revision)
        except CommandError:
            # La base está en una revisión que este código no conoce (más nueva o de otra
            # rama): migrar o arrancar con este código podría romperla.
            unknown.append(revision)
    return MigrationState(tuple(sorted(rows)), heads, tuple(unknown))


def _migration_findings(state: MigrationState) -> list[Finding]:
    current = ",".join(state.current) or "none"
    target = ",".join(state.heads)
    if len(state.heads) != 1:
        return [Finding("FAIL", "migrations", f"code has multiple Alembic heads: {target}")]
    if state.unknown:
        return [
            Finding(
                "FAIL",
                "migrations",
                f"database revision {current} is unknown to this code (newer?); do not start",
            )
        ]
    if state.up_to_date:
        return [Finding("PASS", "migrations", f"migration current ({current})")]
    return [
        Finding(
            "WARN",
            "migrations",
            f"migration pending: current {current}, target {target}; run alembic upgrade head",
        )
    ]


def _writable_dir(path: Path) -> bool:
    return path.is_dir() and os.access(path, os.W_OK | os.X_OK)


def _inside(path: Path, root: Path) -> bool:
    resolved = path.resolve()
    return resolved == root or root in resolved.parents


def _dist_dir(settings: Settings) -> Path:
    if settings.frontend_dist_dir:
        return Path(settings.frontend_dist_dir)
    return REPO_DIR / "frontend" / "dist"


def filesystem_findings(settings: Settings) -> list[Finding]:
    f: list[Finding] = []
    dist = _dist_dir(settings)
    if (dist / "index.html").is_file():
        f.append(Finding("PASS", "frontend", "frontend build present (dist/index.html)"))
        if any(dist.rglob("*.map")):
            f.append(
                Finding("WARN", "frontend_sourcemaps", "source maps (*.map) in the published build")
            )
        else:
            f.append(Finding("PASS", "frontend_sourcemaps", "no source maps published"))
    else:
        f.append(Finding("FAIL", "frontend", "frontend build missing; run npm run build"))

    if settings.log_file:
        parent = Path(settings.log_file).parent
        if _writable_dir(parent):
            f.append(Finding("PASS", "log_file", "log directory writable"))
        else:
            f.append(Finding("FAIL", "log_file", "LOG_FILE directory missing or not writable"))

    if settings.backup_dir:
        backup = Path(settings.backup_dir)
        if not backup.is_absolute():
            f.append(Finding("FAIL", "backup_dir", "BACKUP_DIR must be absolute"))
        elif _inside(backup, REPO_DIR.resolve()) or _inside(backup, dist.resolve()):
            f.append(Finding("FAIL", "backup_dir", "BACKUP_DIR is inside the source tree/webroot"))
        elif _writable_dir(backup):
            f.append(Finding("PASS", "backup_dir", "backup directory writable"))
        else:
            f.append(Finding("WARN", "backup_dir", "BACKUP_DIR missing or not writable yet"))
    else:
        f.append(Finding("WARN", "backup_dir", "BACKUP_DIR unset; configure scheduled backups"))

    for root in parse_model_directories(settings.ai_model_directories):
        if not Path(root).is_dir():
            f.append(
                Finding("WARN", "ai_model_directories", "an AI_MODEL_DIRECTORIES root is missing")
            )
        elif _inside(Path(root), dist.resolve()):
            f.append(Finding("FAIL", "ai_model_directories", "model files inside the webroot"))

    for env_file in (BACKEND_DIR / ".env", REPO_DIR / ".env"):
        if env_file.is_file() and os.name == "posix":
            mode = stat.S_IMODE(env_file.stat().st_mode)
            if mode & 0o077:
                f.append(
                    Finding(
                        "WARN",
                        "env_permissions",
                        f"{env_file.name} is readable by others; chmod 600",
                    )
                )
            else:
                f.append(Finding("PASS", "env_permissions", ".env readable only by its owner"))

    hosts = settings.allowed_host_list
    if settings.agent_server_url and hosts:
        host = urlsplit(settings.agent_server_url).hostname or ""
        if host and host not in hosts:
            f.append(
                Finding("WARN", "agent_server_url", "AGENT_SERVER_URL host is not in ALLOWED_HOSTS")
            )
    return f


def database_findings(settings: Settings) -> list[Finding]:
    engine = engine_from_settings(settings)
    try:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                superuser = conn.execute(
                    text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
                ).scalar()
        except SQLAlchemyError as exc:
            return [
                Finding("FAIL", "database", f"database unreachable ({type(exc).__name__})"),
            ]
        f = [Finding("PASS", "database", "database reachable")]
        if superuser:
            f.append(Finding("FAIL", "database_role", "the application role is a superuser"))
        else:
            f.append(Finding("PASS", "database_role", "application role is not a superuser"))
        try:
            f += _migration_findings(migration_state(engine))
        except SQLAlchemyError as exc:
            f.append(Finding("FAIL", "migrations", f"cannot read revision ({type(exc).__name__})"))
        return f
    finally:
        engine.dispose()


def production_report(settings: Settings) -> list[Finding]:
    return config_findings(settings) + database_findings(settings) + filesystem_findings(settings)
