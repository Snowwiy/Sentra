"""Operator commands: `python -m app.cli <command>` from the backend folder.

Running this requires shell access to the server and its database credentials. Desde la
Fase 4G el dashboard tiene login y roles, y la CLI sigue siendo la vía de bootstrap y de
emergencia: crear el primer admin (`create-admin`), recuperar el acceso si se pierde la
contraseña del último admin (`reset-password`) y operar sin dashboard.
"""

import argparse
import getpass
import secrets
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import passwords
from app.core.config import get_settings
from app.core.exceptions import CatalogError, ConflictError, NotFoundError, PolicyError
from app.core.permissions import Role
from app.db.locks import VULN_CATALOG_LOCK_KEY, singleton_lock
from app.db.session import get_engine, get_sessionmaker
from app.detection.config import DetectionConfig
from app.detection.engine import DetectionEngine, EngineRun
from app.discovery.targets import TargetError
from app.models.asset import Asset
from app.models.discovery import DiscoveryTrigger
from app.models.user import User
from app.risk.config import RiskConfig
from app.risk.engine import RiskEngine, RiskRun
from app.risk.queue import request_recalculation
from app.schemas.auth import UserCreate
from app.schemas.enrollment import EnrollmentTokenCreate
from app.services import audit_service
from app.services.agent_service import reinstate_agent, revoke_agent
from app.services.alert_service import AlertService, AlertThresholds
from app.services.asset_service import open_ports_by_asset
from app.services.auth_service import SessionPolicy, UserService
from app.services.backup_service import (
    BackupError,
    create_backup,
    find_tool,
    integrity_report,
    restore_backup,
    verify_backup,
)
from app.services.discovery_service import DiscoveryConfig, DiscoveryService
from app.services.enrollment_token_service import EnrollmentTokenService
from app.services.identification import oui_database, refresh_identity
from app.services.preflight import migration_state, production_report
from app.services.retention_service import RetentionPolicy, RetentionService
from app.services.vulnerability_catalog_service import VulnerabilityCatalogService
from app.vulnerabilities.engine import VulnerabilityConfig, VulnerabilityEngine, VulnerabilityRun
from app.vulnerabilities.queue import mark_dirty


def _list_agents(session: Session) -> None:
    # Only assets with an agent: discovered hosts have no credential to manage.
    assets = session.scalars(
        select(Asset).where(Asset.agent_id.is_not(None)).order_by(Asset.hostname, Asset.id)
    ).all()
    print(f"{'asset_id':36}  {'hostname':24}  {'token':8}  revoked_at")
    for asset in assets:
        token = "issued" if asset.agent_token_hash else "none"
        revoked = asset.agent_token_revoked_at.isoformat() if asset.agent_token_revoked_at else "-"
        print(f"{asset.public_id!s:36}  {asset.display_name[:24]:24}  {token:8}  {revoked}")


def _purge_old_data(session: Session) -> int:
    # Same policy as the in-process retention job; useful for a first purge of a large backlog
    # or to run retention from a scheduled task instead of the API process.
    policy = RetentionPolicy.from_settings(get_settings())
    if not policy.enabled:
        print(
            "no retention configured: set TELEMETRY_RETENTION_DAYS, EVENT_RETENTION_DAYS,"
            " CHANGE_RETENTION_DAYS, ALERT_RETENTION_DAYS, DETECTION_RETENTION_DAYS or"
            " RISK_HISTORY_RETENTION_DAYS",
            file=sys.stderr,
        )
        return 1
    result = RetentionService(session, policy).purge()
    print(
        f"deleted {result.telemetry_samples} telemetry samples, {result.system_events} events,"
        f" {result.asset_changes} inventory changes, {result.alerts} resolved alerts and"
        f" {result.detections} resolved detections and {result.risk_snapshots} risk snapshots"
    )
    return 0


def _detections(session: Session, reevaluate_hours: int | None) -> int:
    """Fase 4H: evalúa ahora las señales pendientes (y opcionalmente las recientes otra vez).

    Útil tras activar una regla con DETECTION_DISABLED_RULES o con la API parada. Repetirlo
    es seguro: la evidencia es idempotente por señal, no duplica detecciones.
    """
    settings = get_settings()
    engine = DetectionEngine(
        session, DetectionConfig.from_settings(settings), AlertThresholds.from_settings(settings)
    )
    if reevaluate_hours is not None:
        since = datetime.now(UTC) - timedelta(hours=reevaluate_hours)
        print(f"{engine.reevaluate(since)} signals queued again")
    total = EngineRun()
    while True:
        run = engine.process_pending()
        total.signals += run.signals
        total.created += run.created
        total.updated += run.updated
        total.rule_errors += run.rule_errors
        if run.signals == 0:
            break
    print(
        f"{total.signals} signals evaluated: {total.created} detections created,"
        f" {total.updated} updated, {total.rule_errors} rule errors"
    )
    return 1 if total.rule_errors else 0


def _risk(session: Session, everything: bool) -> int:
    """Fase 4I: procesa ahora la cola de riesgo (y con --all recalcula todos los activos).

    Útil con la API parada o tras cambiar RISK_* (umbrales, decay). Recalcular es
    idempotente: solo añade snapshots si el riesgo cambia de forma material.
    """
    settings = get_settings()
    engine = RiskEngine(
        session, RiskConfig.from_settings(settings), AlertThresholds.from_settings(settings)
    )
    engine.seed_missing(limit=1_000_000)
    if everything:
        request_recalculation(session, session.scalars(select(Asset.id)).all())
        session.commit()
    total = RiskRun()
    while True:
        run = engine.process_dirty()
        total.add(run)
        if run.assets + run.errors == 0 or run.errors == run.assets + run.errors:
            break
    print(
        f"{total.assets} assets evaluated: {total.snapshots} history points,"
        f" {total.transitions} level changes, {total.alerts} alerts, {total.errors} errors"
    )
    return 1 if total.errors else 0


def _vuln_catalog_import(session: Session, file: str, skip_invalid: bool) -> int:
    """Fase 5B: importa un catálogo local grande por lotes (la API acepta tamaños menores).

    Solo lee el fichero indicado (nunca descarga nada). El lock del catálogo se mantiene en
    una conexión propia durante toda la importación: ni otra CLI ni la API importan a la vez.
    """
    settings = get_settings()
    service = VulnerabilityCatalogService(session, settings)
    with singleton_lock(get_engine, VULN_CATALOG_LOCK_KEY) as acquired:
        if not acquired:
            print("another catalog import is in progress", file=sys.stderr)
            return 1
        try:
            result, created = service.import_file(
                Path(file),
                audit_service.CLI,
                skip_invalid=skip_invalid,
                batch_size=settings.vuln_import_batch_size,
                progress=lambda done, total: print(f"  {done}/{total} records", flush=True),
            )
        except CatalogError as exc:
            print(f"refused ({exc.code}): {exc.message}", file=sys.stderr)
            return 2
        audit_service.record(
            session,
            audit_service.CLI,
            "vulnerability_catalog_imported" if created else "vulnerability_catalog_updated",
            target_type="vulnerability_catalog",
            target_id=result.source,
            details={
                "sha256": result.sha256,
                "revision": result.revision,
                "new": result.new,
                "updated": result.updated,
                "unchanged": result.unchanged,
                "invalid": result.invalid,
                "assets_queued": result.assets_queued,
                "via": "cli",
            },
        )
    print(
        f"catalog {result.source} revision {result.revision}: {result.new} new,"
        f" {result.updated} updated, {result.unchanged} unchanged, {result.invalid} invalid;"
        f" {result.assets_queued} assets queued for evaluation"
    )
    return 0


def _vuln_evaluate(session: Session, everything: bool) -> int:
    """Fase 5B: procesa ya la cola de evaluación de vulnerabilidades (con --all, todo).

    Útil tras importar un catálogo con la API parada. Repetirlo es seguro: un activo cuyo
    inventario y catálogo no cambiaron deja sus findings como estaban.
    """
    settings = get_settings()
    engine = VulnerabilityEngine(
        session,
        VulnerabilityConfig.from_settings(settings),
        AlertThresholds.from_settings(settings),
    )
    engine.seed_missing(limit=1_000_000)
    if everything:
        assets = session.scalars(select(Asset.id).where(Asset.agent_id.is_not(None))).all()
        mark_dirty(session, assets, "manual")
        session.commit()
    total = VulnerabilityRun()
    while True:
        run = engine.process_dirty()
        total.add(run)
        if run.assets == 0 or run.errors == run.assets:
            break
    print(
        f"{total.assets} assets evaluated: {total.created} findings created, {total.updated}"
        f" updated, {total.resolved} resolved, {total.reopened} reopened, {total.alerts} alerts,"
        f" {total.errors} errors"
    )
    return 1 if total.errors else 0


def _alert_action(session: Session, command: str, alert_id: UUID) -> int:
    # También disponible en el dashboard (POST /alerts/{id}/acknowledge|resolve, permiso
    # alerts:manage); la CLI queda para operar sin navegador.
    service = AlertService(session, AlertThresholds.from_settings(get_settings()))
    try:
        if command == "ack-alert":
            alert = service.acknowledge(alert_id)
        else:
            alert = service.resolve(alert_id)
    except NotFoundError:
        print(f"alert {alert_id} not found", file=sys.stderr)
        return 1
    except ConflictError as exc:
        print(f"alert {alert_id}: {exc.message}", file=sys.stderr)
        return 1
    print(f"alert {alert.public_id} ({alert.rule.value}) is {alert.status.value}")
    return 0


def _enrollment_tokens(session: Session, args: argparse.Namespace) -> int:
    settings = get_settings()
    service = EnrollmentTokenService(
        session, timedelta(minutes=settings.enrollment_token_ttl_minutes)
    )
    if args.command == "create-enrollment-token":
        created = service.create(
            EnrollmentTokenCreate(
                ttl_minutes=args.ttl_minutes,
                max_uses=args.max_uses,
                expected_platform=args.platform,
                expected_hostname=args.hostname,
                note=args.note,
            ),
            created_via="cli",
        )
        # The only time the token is shown: it is not stored and cannot be listed later.
        print(f"token:      {created.token}")
        print(f"token id:   {created.token_id}")
        print(f"expires at: {created.expires_at.isoformat()}  (uses: {created.max_uses})")
        print("Give it to the new host (SENTRA_AGENT_ENROLLMENT_TOKEN or a token file).")
        return 0
    if args.command == "list-enrollment-tokens":
        print(f"{'token_id':36}  {'state':9}  {'uses':5}  {'expires_at':25}  note")
        for item in service.list(args.limit).items:
            uses = f"{item.use_count}/{item.max_uses}"
            print(
                f"{item.token_id!s:36}  {item.state.value:9}  {uses:5}"
                f"  {item.expires_at.isoformat()[:25]:25}  {item.note or ''}"
            )
        return 0
    try:
        revoked = service.revoke(args.token_id)
    except NotFoundError:
        print(f"enrollment token {args.token_id} not found", file=sys.stderr)
        return 1
    except ConflictError as exc:
        print(f"enrollment token {args.token_id}: {exc.message}", file=sys.stderr)
        return 1
    print(f"enrollment token {revoked.token_id} is {revoked.state.value}")
    return 0


# --- Usuarios del dashboard (Fase 4G) -----------------------------------------------------


def _ask_password(username: str, prompt: Callable[[str], str] = getpass.getpass) -> str | None:
    """Pide la contraseña dos veces sin mostrarla. None si no coinciden o no cumple la política.

    Nunca se acepta por argumento ni variable de entorno: quedaría en el historial de la
    shell, en la lista de procesos o en un .env.
    """
    first = prompt(f"New password for {username} (min {passwords.PASSWORD_MIN_LENGTH} chars): ")
    try:
        passwords.validate_password(first, username)
    except passwords.PolicyError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return None
    if prompt("Repeat the password: ") != first:
        print("refused: passwords do not match", file=sys.stderr)
        return None
    return first


def _users_service(session: Session) -> UserService:
    return UserService(session, SessionPolicy.from_settings(get_settings()))


def _create_admin(
    session: Session,
    username: str | None,
    ask: Callable[[str], str] = input,
    prompt: Callable[[str], str] = getpass.getpass,
) -> int:
    """Crea un admin. Sirve para el primero y para recuperar el acceso si todos los admins
    quedaron desactivados: quien tiene shell en el servidor ya controla Sentra."""
    users = _users_service(session)
    raw = username if username is not None else ask("Admin username: ")
    try:
        canonical = passwords.validate_username(raw)
    except passwords.PolicyError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    if users.get_by_username(canonical) is not None:
        print(f"refused: user {canonical!r} already exists (use reset-password)", file=sys.stderr)
        return 1
    password = _ask_password(canonical, prompt)
    if password is None:
        return 2
    try:
        user = users.create(UserCreate(username=canonical, password=password, role=Role.ADMIN))
    except (ConflictError, PolicyError) as exc:
        print(f"refused: {exc.message}", file=sys.stderr)
        return 1
    audit_service.record(
        session,
        audit_service.CLI,
        "user_created",
        target_type="user",
        target_id=user.public_id,
        details={"username": user.username, "role": user.role},
    )
    print(f"admin {user.username} created; sign in at the dashboard (/login)")
    return 0


def _reset_password(
    session: Session, username: str, activate: bool, prompt: Callable[[str], str] = getpass.getpass
) -> int:
    """Recuperación: contraseña nueva (y opcionalmente reactivar); cierra sus sesiones."""
    users = _users_service(session)
    user = users.get_by_username(username)
    if user is None:
        print(f"user {username!r} not found", file=sys.stderr)
        return 1
    password = _ask_password(user.username, prompt)
    if password is None:
        return 2
    revoked = users.reset_password(user, password)
    if activate and not user.is_active:
        user.is_active = True
        session.commit()
    audit_service.record(
        session,
        audit_service.CLI,
        "password_reset",
        target_type="user",
        target_id=user.public_id,
        details={"username": user.username, "revoked": revoked, "activated": activate},
    )
    state = "active" if user.is_active else "INACTIVE (use --activate)"
    print(f"password of {user.username} reset; {revoked} sessions closed; user is {state}")
    return 0


def _list_users(session: Session) -> None:
    print(f"{'username':32}  {'role':8}  {'active':6}  last_login_at")
    for user in session.scalars(select(User).order_by(User.username)).all():
        last = user.last_login_at.isoformat() if user.last_login_at else "-"
        print(f"{user.username:32}  {user.role:8}  {user.is_active!s:6}  {last}")


def _discovery_scope() -> int:
    """Show what discovery may touch, without probing anything."""
    settings = get_settings()
    scope = settings.discovery_scope()
    if not scope.enabled:
        print("discovery disabled: DISCOVERY_ALLOWED_NETWORKS is empty")
        return 0
    for network in scope.allowed:
        hosts = sum(1 for _ in scope.hosts(network))
        print(f"allowed  {network!s:20}  {hosts} addresses to probe")
    for network in scope.excluded:
        print(f"excluded {network}")
    ports = DiscoveryConfig.from_settings(settings).scan.ports
    print(f"ports    {', '.join(map(str, ports))}")
    return 0


def _discover(target: str | None) -> int:
    # Herramienta administrativa/debug: el uso normal es la página Red del dashboard
    # (Fase 4D). Misma capa de servicio y mismas comprobaciones de allowlist que la web y
    # el scheduler; ejecuta en primer plano y no pasa por la cola del runner de la API.
    settings = get_settings()
    service = DiscoveryService(
        get_sessionmaker(),
        DiscoveryConfig.from_settings(settings),
        AlertThresholds.from_settings(settings),
    )
    try:
        summaries = service.run(target, DiscoveryTrigger.MANUAL, via="cli")
    except TargetError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    if not summaries:
        print("nothing scanned (a run for that network is already in progress)", file=sys.stderr)
        return 1
    for summary in summaries:
        baseline = " (baseline)" if summary.baseline else ""
        print(
            f"{summary.target}: {summary.status.value}{baseline}, {summary.hosts_scanned} scanned,"
            f" {summary.hosts_alive} up, {summary.hosts_new} new, {summary.open_ports} open ports,"
            f" {len(summary.errors)} errors"
        )
    return 0


def _reclassify_assets(session: Session) -> int:
    """Recalcula la identificación de todos los activos con los datos ya guardados.

    Sin sondear la red: sirve tras actualizar el fichero OUI o tras migrar a la 0015, para
    no esperar al siguiente scan/heartbeat. No registra cambios en el historial: el
    dispositivo no cambió, cambiaron las reglas o los datos de referencia.
    """
    assets = session.scalars(select(Asset)).all()
    ports = open_ports_by_asset(session, (a.id for a in assets))
    database = oui_database()
    changed = 0
    for asset in assets:
        before = (asset.device_type, asset.device_name, asset.device_vendor)
        refresh_identity(asset, ports.get(asset.id, []), database)
        changed += before != (asset.device_type, asset.device_name, asset.device_vendor)
    session.commit()
    print(f"{len(assets)} assets reclassified ({changed} changed); OUI entries: {len(database)}")
    return 0


# --- Fase 4M: operación en producción ------------------------------------------------------


def _production_check() -> int:
    """PASS/WARN/FAIL de configuración, base, migraciones y disco. No modifica nada."""
    findings = production_report(get_settings())
    for finding in findings:
        print(f"{finding.level:4}  {finding.message}")
    fails = sum(1 for f in findings if f.level == "FAIL")
    warns = sum(1 for f in findings if f.level == "WARN")
    print(f"\n{len(findings)} checks: {fails} FAIL, {warns} WARN")
    return 1 if fails else 0


def _migration_status() -> int:
    """Revisión actual y destino antes de `alembic upgrade head` (no migra).

    Códigos: 0 al día, 1 hay migraciones pendientes, 2 error (base no disponible, varias
    heads o una revisión que este código no conoce).
    """
    from sqlalchemy.exc import SQLAlchemyError

    from app.db.session import engine_from_settings

    engine = engine_from_settings(get_settings())
    try:
        state = migration_state(engine)
    except SQLAlchemyError as exc:
        print(f"database unavailable ({type(exc).__name__})", file=sys.stderr)
        return 2
    finally:
        engine.dispose()
    print(f"current revision: {', '.join(state.current) or 'none'}")
    print(f"target revision:  {', '.join(state.heads)}")
    if len(state.heads) != 1:
        print("FAIL multiple Alembic heads in the code; do not migrate", file=sys.stderr)
        return 2
    if state.unknown:
        print("FAIL the database is at a revision this code does not know", file=sys.stderr)
        return 2
    if state.up_to_date:
        print("up to date")
        return 0
    print("pending: back up first, then run `alembic upgrade head`")
    return 1


def _generate_secret(nbytes: int) -> int:
    # Para ADMIN_API_KEY, METRICS_TOKEN, AGENT_ENROLLMENT_KEY o la contraseña de PostgreSQL.
    # Se imprime una vez para copiarla al .env; Sentra nunca la genera sola al arrancar
    # (un secreto distinto en cada reinicio rompería agentes y scripts).
    print(secrets.token_urlsafe(nbytes))
    return 0


def _backup(directory: str | None) -> int:
    from pathlib import Path

    settings = get_settings()
    target = directory or settings.backup_dir
    if not target:
        print("set BACKUP_DIR or pass --dir", file=sys.stderr)
        return 2
    try:
        result = create_backup(
            settings.database_url,
            Path(target),
            settings.backup_retention_days,
            settings.pg_bin_dir,
            webroot=settings.frontend_dist_dir,
        )
    except BackupError as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1
    print(f"backup ok: {result.path} ({result.size} bytes) sha256 {result.sha256}")
    for path in result.deleted:
        print(f"retention: deleted {path.name}")
    return 0


def _verify_backup(file: str) -> int:
    from pathlib import Path

    settings = get_settings()
    try:
        digest = verify_backup(Path(file), find_tool("pg_restore", settings.pg_bin_dir))
    except BackupError as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"backup verified: sha256 {digest}")
    return 0


def _restore(file: str, target_db: str, confirm: str | None) -> int:
    from pathlib import Path

    settings = get_settings()
    try:
        report = restore_backup(
            settings.database_url, Path(file), target_db, confirm, settings.pg_bin_dir
        )
    except BackupError as exc:
        print(f"restore refused or failed: {exc}", file=sys.stderr)
        return 1
    print(f"restored into {target_db}:")
    for key, value in report.items():
        print(f"  {key}: {value}")
    print("next: alembic upgrade head (if the code is newer), start the API, check /health/ready")
    return 0


def _integrity(database: str | None) -> int:
    settings = get_settings()
    from sqlalchemy.engine import make_url

    url = make_url(settings.database_url)
    if database:
        url = url.set(database=database)
    try:
        report = integrity_report(url)
    except Exception as exc:
        print(f"integrity check failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    for key, value in report.items():
        print(f"{key}: {value}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Sentra operator tools")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list-agents", help="list agents and their credential state")
    admin = commands.add_parser(
        "create-admin", help="create a dashboard admin (asks for the password, never echoed)"
    )
    admin.add_argument("--username", help="asked interactively when omitted")
    reset = commands.add_parser(
        "reset-password",
        help="set a new password for a dashboard user and close their sessions (recovery)",
    )
    reset.add_argument("username")
    reset.add_argument("--activate", action="store_true", help="also re-enable the user")
    commands.add_parser("list-users", help="list dashboard users and roles")
    commands.add_parser(
        "purge-old-data",
        help="delete telemetry/events older than the configured retention (see README)",
    )
    for name, text in (
        ("revoke-agent", "invalidate an agent's token and block its re-enrollment"),
        ("reinstate-agent", "allow a revoked agent to enroll again"),
    ):
        command = commands.add_parser(name, help=text)
        command.add_argument("asset_id", type=UUID, help="public asset id (as shown in the UI)")
    for name, text in (
        ("ack-alert", "acknowledge an active alert (it stays active until resolved)"),
        ("resolve-alert", "resolve an alert by hand"),
    ):
        command = commands.add_parser(name, help=text)
        command.add_argument("alert_id", type=UUID, help="public alert id")
    create = commands.add_parser(
        "create-enrollment-token",
        help="create a one-time token for enrolling a new agent (shown once)",
    )
    create.add_argument("--ttl-minutes", type=int, help="lifetime (default from settings, 15)")
    create.add_argument("--max-uses", type=int, default=1, help="agents it may enroll (1)")
    create.add_argument("--platform", choices=["windows", "linux"], help="only this OS")
    create.add_argument("--hostname", help="only a host with this hostname")
    create.add_argument("--note", help="free text shown when listing (no secrets)")
    listing = commands.add_parser(
        "list-enrollment-tokens", help="list enrollment tokens and their state (never the token)"
    )
    listing.add_argument("--limit", type=int, default=50)
    revoke = commands.add_parser(
        "revoke-enrollment-token", help="revoke an enrollment token that was not used up"
    )
    revoke.add_argument("token_id", type=UUID, help="token id (from create/list)")
    commands.add_parser(
        "reclassify-assets",
        help="recompute device identification from stored data (no network probes)",
    )
    commands.add_parser(
        "discovery-scope", help="show the networks and ports discovery may probe (no probing)"
    )
    detect = commands.add_parser(
        "run-detections", help="evaluate pending detection signals now (Fase 4H)"
    )
    detect.add_argument(
        "--reevaluate-hours",
        type=int,
        help="queue again the signals of the last N hours before evaluating (safe to repeat)",
    )
    risk = commands.add_parser(
        "run-risk", help="process the risk recalculation queue now (Fase 4I)"
    )
    risk.add_argument(
        "--all", action="store_true", help="recalculate every asset, not only the queued ones"
    )
    catalog = commands.add_parser(
        "vuln-catalog-import",
        help="import a local vulnerability catalog file (sentra-vuln-catalog/1, Fase 5B)",
    )
    catalog.add_argument("file", help="local JSON file (never a URL)")
    catalog.add_argument(
        "--skip-invalid", action="store_true", help="import the valid records, skip the rest"
    )
    evaluate = commands.add_parser(
        "vuln-evaluate", help="process the vulnerability evaluation queue now (Fase 5B)"
    )
    evaluate.add_argument(
        "--all", action="store_true", help="evaluate every agent asset, not only the queued ones"
    )
    discover = commands.add_parser(
        "discover", help="run network discovery now over the allowed networks (or one target)"
    )
    discover.add_argument(
        "--target", help="CIDR or address inside DISCOVERY_ALLOWED_NETWORKS (default: all)"
    )
    commands.add_parser(
        "production-check",
        help="PASS/WARN/FAIL report of configuration, database, migrations and files (Fase 4M)",
    )
    commands.add_parser(
        "migration-status", help="show current and target Alembic revision (does not migrate)"
    )
    secret = commands.add_parser("generate-secret", help="print a new random secret for .env")
    secret.add_argument("--bytes", type=int, default=32, choices=range(24, 129), metavar="24-128")
    backup = commands.add_parser(
        "backup", help="pg_dump (custom format) + checksum + verification + retention"
    )
    backup.add_argument("--dir", help="destination (default BACKUP_DIR)")
    verify = commands.add_parser("verify-backup", help="checksum and pg_restore --list a backup")
    verify.add_argument("file")
    restore = commands.add_parser(
        "restore", help="restore a verified backup into a NEW EMPTY database (never in place)"
    )
    restore.add_argument("file")
    restore.add_argument("--target-db", required=True, help="existing empty database")
    restore.add_argument("--confirm", help="repeat the target database name to confirm")
    integrity = commands.add_parser(
        "integrity-check", help="schema revision and row counts of the key tables"
    )
    integrity.add_argument("--database", help="database name (default: the configured one)")
    args = parser.parse_args(argv)

    if args.command == "production-check":
        return _production_check()
    if args.command == "migration-status":
        return _migration_status()
    if args.command == "generate-secret":
        return _generate_secret(args.bytes)
    if args.command == "backup":
        return _backup(args.dir)
    if args.command == "verify-backup":
        return _verify_backup(args.file)
    if args.command == "restore":
        return _restore(args.file, args.target_db, args.confirm)
    if args.command == "integrity-check":
        return _integrity(args.database)
    if args.command == "discovery-scope":
        return _discovery_scope()
    if args.command == "discover":
        return _discover(args.target)

    with get_sessionmaker()() as session:
        if args.command == "list-agents":
            _list_agents(session)
            return 0
        if args.command == "create-admin":
            return _create_admin(session, args.username)
        if args.command == "reset-password":
            return _reset_password(session, args.username, args.activate)
        if args.command == "list-users":
            _list_users(session)
            return 0
        if args.command == "purge-old-data":
            return _purge_old_data(session)
        if args.command == "reclassify-assets":
            return _reclassify_assets(session)
        if args.command == "run-detections":
            return _detections(session, args.reevaluate_hours)
        if args.command == "run-risk":
            return _risk(session, args.all)
        if args.command == "vuln-catalog-import":
            return _vuln_catalog_import(session, args.file, args.skip_invalid)
        if args.command == "vuln-evaluate":
            return _vuln_evaluate(session, args.all)
        if args.command in (
            "create-enrollment-token",
            "list-enrollment-tokens",
            "revoke-enrollment-token",
        ):
            try:
                return _enrollment_tokens(session, args)
            except ValidationError as exc:
                print(f"invalid value: {exc.errors()[0]['msg']}", file=sys.stderr)
                return 2
        if args.command in ("ack-alert", "resolve-alert"):
            return _alert_action(session, args.command, args.alert_id)
        action = revoke_agent if args.command == "revoke-agent" else reinstate_agent
        try:
            asset = action(session, args.asset_id)
        except NotFoundError:
            print(f"asset {args.asset_id} not found", file=sys.stderr)
            return 1
        state = "revoked" if asset.agent_token_revoked_at else "reinstated"
        print(f"agent of asset {asset.public_id} ({asset.display_name}) {state}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
