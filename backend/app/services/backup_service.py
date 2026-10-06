"""Copias de seguridad y restauración de PostgreSQL (Fase 4M, docs/backup-restore.md).

Envuelve pg_dump/pg_restore (las herramientas oficiales, mismas en Linux y Windows) con las
reglas que un script suelto suele olvidar:
- la contraseña nunca va en la línea de comandos (visible en ps / el Administrador de
  tareas) ni en los logs: viaja en PGPASSWORD dentro del entorno del proceso hijo;
- formato custom (-Fc): comprimido, restaurable tabla a tabla y verificable con
  `pg_restore --list` sin restaurar;
- un pg_dump con código 0 no basta: el fichero se comprueba (existe, no está vacío,
  pg_restore lo lista y contiene las tablas clave) y se guarda su SHA-256 junto a él;
- se escribe primero como .partial y se renombra al final: un fichero sentra-*.dump siempre
  es una copia completa y verificada;
- la retención solo borra ficheros sentra-*.dump (y su .sha256) de BACKUP_DIR y nunca deja
  menos de MIN_KEEP copias, aunque sean antiguas;
- restaurar exige nombrar la base destino dos veces, que esté vacía y que la API no tenga
  conexiones abiertas en ella: nunca se sobrescribe la base de producción por accidente.
"""

import hashlib
import os
import re
import shutil
import subprocess  # pg_dump/pg_restore con argumentos fijos, nunca con shell
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_DIR = BACKEND_DIR.parent
PREFIX = "sentra-"
SUFFIX = ".dump"
MIN_KEEP = 3
# Tablas que una copia útil de Sentra tiene que contener (si falta una, no es de Sentra o
# está incompleta). Cubren activos, eventos, detecciones, riesgo, incidentes, auditoría, IA,
# contexto, usuarios y la versión del esquema.
KEY_TABLES = (
    "alembic_version",
    "assets",
    "system_events",
    "detections",
    "asset_risk",
    "incidents",
    "audit_events",
    "ai_insights",
    "asset_context",
    "users",
)
CHUNK = 1024 * 1024

Runner = Callable[..., subprocess.CompletedProcess[str]]


class BackupError(Exception):
    """Fallo de copia o restauración con un mensaje apto para el operador (sin secretos)."""


@dataclass(frozen=True)
class BackupResult:
    path: Path
    size: int
    sha256: str
    deleted: list[Path]


def _sqlalchemy_url(database_url: str) -> URL:
    return make_url(database_url)


def connection_env(database_url: str, base: dict[str, str] | None = None) -> dict[str, str]:
    """Entorno libpq para pg_dump/pg_restore. La contraseña solo aquí (PGPASSWORD)."""
    url = _sqlalchemy_url(database_url)
    env = dict(os.environ if base is None else base)
    # Nunca heredar otra contraseña o servicio del entorno del operador.
    for name in ("PGPASSWORD", "PGSERVICE", "PGDATABASE"):
        env.pop(name, None)
    if url.host:
        env["PGHOST"] = url.host
    if url.port:
        env["PGPORT"] = str(url.port)
    if url.username:
        env["PGUSER"] = url.username
    if url.password:
        env["PGPASSWORD"] = str(url.password)
    if url.database:
        env["PGDATABASE"] = url.database
    sslmode = url.query.get("sslmode")
    if isinstance(sslmode, str):
        env["PGSSLMODE"] = sslmode
    env["PGAPPNAME"] = "sentra-backup"
    return env


def database_name(database_url: str) -> str:
    name = _sqlalchemy_url(database_url).database
    if not name:
        raise BackupError("DATABASE_URL has no database name")
    return name


def find_tool(name: str, bin_dir: str | None) -> str:
    """Ruta de pg_dump/pg_restore: PG_BIN_DIR si se configuró, si no el PATH."""
    if bin_dir:
        exe = name + (".exe" if sys.platform == "win32" else "")
        candidate = Path(bin_dir) / exe
        if candidate.is_file():
            return str(candidate)
        raise BackupError(f"{exe} not found in PG_BIN_DIR")
    found = shutil.which(name)
    if not found:
        raise BackupError(
            f"{name} not found; install the PostgreSQL client tools or set PG_BIN_DIR"
        )
    return found


def dump_command(pg_dump: str, target: Path) -> list[str]:
    """Argumentos de pg_dump. Sin contraseña, sin host ni base (van en el entorno)."""
    return [
        pg_dump,
        "--format=custom",
        "--compress=6",
        # La copia se restaura con el rol de la aplicación, no con el propietario original.
        "--no-owner",
        "--no-privileges",
        "--no-password",
        f"--file={target}",
    ]


def check_destination(directory: Path, webroot: str | None = None) -> Path:
    """BACKUP_DIR seguro: absoluto, fuera del repositorio y del webroot del frontend."""
    if not directory.is_absolute():
        raise BackupError("BACKUP_DIR must be an absolute path")
    resolved = directory.resolve()
    forbidden = [REPO_DIR.resolve()]
    if webroot:
        forbidden.append(Path(webroot).resolve())
    for root in forbidden:
        if resolved == root or root in resolved.parents:
            # Dentro del repo acabaría en frontend/dist (servido por el proxy), en un
            # `git add` o en la copia del código: las copias contienen datos sensibles.
            raise BackupError("BACKUP_DIR must be outside the Sentra source tree and webroot")
    return resolved


def _restrict(path: Path, mode: int) -> None:
    # En Windows chmod solo controla "solo lectura"; los permisos reales son las ACL de la
    # carpeta (docs/backup-restore.md). En Linux/macOS: solo el usuario del servicio.
    if os.name == "posix":
        path.chmod(mode)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def checksum_path(path: Path) -> Path:
    return path.with_name(path.name + ".sha256")


def verify_backup(path: Path, pg_restore: str, run: Runner = subprocess.run) -> str:
    """Comprueba una copia sin restaurarla. Devuelve su SHA-256 o lanza BackupError."""
    if not path.is_file():
        raise BackupError(f"backup file not found: {path.name}")
    if path.stat().st_size == 0:
        raise BackupError(f"backup file is empty: {path.name}")
    digest = sha256_of(path)
    sidecar = checksum_path(path)
    if sidecar.is_file():
        expected = sidecar.read_text(encoding="utf-8").split()[0].strip().lower()
        if expected != digest:
            raise BackupError(f"checksum mismatch for {path.name}: the file changed or is corrupt")
    listing = run([pg_restore, "--list", str(path)], capture_output=True, text=True, check=False)
    if listing.returncode != 0:
        raise BackupError(f"pg_restore cannot read {path.name} (exit {listing.returncode})")
    missing = [
        t for t in KEY_TABLES if not re.search(rf"\bTABLE public {t}(\s|$)", listing.stdout, re.M)
    ]
    if missing:
        raise BackupError(f"{path.name} lacks Sentra tables: {', '.join(missing)}")
    return digest


def prune(directory: Path, retention_days: int, keep: Sequence[Path], now: datetime) -> list[Path]:
    """Borra copias sentra-*.dump más antiguas que la retención, dejando al menos MIN_KEEP."""
    backups = sorted(
        (p for p in directory.glob(f"{PREFIX}*{SUFFIX}") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    cutoff = (now - timedelta(days=retention_days)).timestamp()
    deleted: list[Path] = []
    for index, path in enumerate(backups):
        if index < MIN_KEEP or path in keep or path.stat().st_mtime >= cutoff:
            continue
        path.unlink()
        checksum_path(path).unlink(missing_ok=True)
        deleted.append(path)
    return deleted


def create_backup(
    database_url: str,
    directory: Path,
    retention_days: int,
    bin_dir: str | None,
    run: Runner = subprocess.run,
    now: datetime | None = None,
    webroot: str | None = None,
) -> BackupResult:
    now = now or datetime.now(UTC)
    directory = check_destination(directory, webroot)
    directory.mkdir(parents=True, exist_ok=True)
    _restrict(directory, 0o700)
    pg_dump = find_tool("pg_dump", bin_dir)
    pg_restore = find_tool("pg_restore", bin_dir)
    name = f"{PREFIX}{database_name(database_url)}-{now.strftime('%Y%m%dT%H%M%SZ')}{SUFFIX}"
    final = directory / name
    partial = directory / (name + ".partial")
    if final.exists():
        raise BackupError(f"{name} already exists")
    result = run(
        dump_command(pg_dump, partial),
        env=connection_env(database_url),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        partial.unlink(missing_ok=True)
        # stderr de pg_dump no contiene la contraseña (va por entorno); se acota por si acaso.
        detail = (result.stderr or "").strip().splitlines()[-1:] or ["no output"]
        raise BackupError(f"pg_dump failed (exit {result.returncode}): {detail[0][:300]}")
    _restrict(partial, 0o600)
    try:
        digest = verify_backup(partial, pg_restore, run)
    except BackupError:
        partial.unlink(missing_ok=True)
        raise
    partial.rename(final)
    sidecar = checksum_path(final)
    sidecar.write_text(f"{digest}  {final.name}\n", encoding="utf-8")
    _restrict(sidecar, 0o600)
    deleted = prune(directory, retention_days, [final], now)
    return BackupResult(final, final.stat().st_size, digest, deleted)


# --- Restauración ---------------------------------------------------------------------------


def _target_url(database_url: str, target_db: str) -> URL:
    return _sqlalchemy_url(database_url).set(database=target_db)


def check_restore_target(database_url: str, target_db: str, confirm: str | None) -> None:
    """Reglas que impiden una restauración accidental. Lanza BackupError si no se cumplen.

    - `--confirm` debe repetir el nombre de la base destino (decisión explícita);
    - la base debe existir (la crea un administrador de PostgreSQL: el rol de Sentra no
      tiene CREATEDB por mínimo privilegio) y estar vacía (sin tablas en public);
    - nadie de Sentra puede estar conectado a ella (API parada).
    """
    if confirm != target_db:
        raise BackupError(
            "restore needs --confirm with the exact target database name (explicit decision)"
        )
    engine = create_engine(_target_url(database_url, target_db), pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            tables = conn.execute(
                text("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
            ).scalar()
            others = conn.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
                    " AND pid <> pg_backend_pid()"
                )
            ).scalar()
    except Exception as exc:
        raise BackupError(
            f"cannot connect to target database {target_db!r}; create it first"
            f" (CREATE DATABASE {target_db} OWNER <sentra role>) ({type(exc).__name__})"
        ) from None
    finally:
        engine.dispose()
    if others:
        raise BackupError(
            f"{target_db} has {others} other connection(s); stop the Sentra API first"
        )
    if tables:
        raise BackupError(
            f"{target_db} is not empty ({tables} tables); restore only into a new empty database"
        )


def restore_command(pg_restore: str, path: Path, target_db: str) -> list[str]:
    return [
        pg_restore,
        f"--dbname={target_db}",
        "--no-owner",
        "--no-privileges",
        "--no-password",
        # Todo o nada: un error deja la base destino como estaba (vacía).
        "--single-transaction",
        "--exit-on-error",
        str(path),
    ]


def restore_backup(
    database_url: str,
    path: Path,
    target_db: str,
    confirm: str | None,
    bin_dir: str | None,
    run: Runner = subprocess.run,
) -> dict[str, int | str]:
    """Verifica la copia, restaura en la base vacía `target_db` y devuelve recuentos."""
    pg_restore = find_tool("pg_restore", bin_dir)
    verify_backup(path, pg_restore, run)
    check_restore_target(database_url, target_db, confirm)
    env = connection_env(database_url)
    env["PGDATABASE"] = target_db
    result = run(
        restore_command(pg_restore, path, target_db),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()[-1:] or ["no output"]
        raise BackupError(f"pg_restore failed (exit {result.returncode}): {detail[0][:300]}")
    return integrity_report(_target_url(database_url, target_db))


def integrity_report(url: URL | str) -> dict[str, int | str]:
    """Revisión del esquema y recuento de las tablas clave de una base Sentra."""
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            report: dict[str, int | str] = {
                "alembic_version": str(
                    conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
                )
            }
            for table in KEY_TABLES:
                if table == "alembic_version":
                    continue
                # Nombres de una lista fija del código, nunca de la entrada del usuario.
                report[table] = int(
                    conn.execute(text(f"SELECT count(*) FROM {table}")).scalar() or 0  # noqa: S608
                )
    finally:
        engine.dispose()
    return report
