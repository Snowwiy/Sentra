"""Operator commands: `python -m app.cli <command>` from the backend folder.

Running this requires shell access to the server and its database credentials. Desde la
Fase 4G el dashboard tiene login y roles, y la CLI sigue siendo la vía de bootstrap y de
emergencia: crear el primer admin (`create-admin`), recuperar el acceso si se pierde la
contraseña del último admin (`reset-password`) y operar sin dashboard.
"""

import argparse
import getpass
import sys
from collections.abc import Callable
from datetime import timedelta
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import passwords
from app.core.config import get_settings
from app.core.exceptions import ConflictError, NotFoundError, PolicyError
from app.core.permissions import Role
from app.db.session import get_sessionmaker
from app.discovery.targets import TargetError
from app.models.asset import Asset
from app.models.discovery import DiscoveryTrigger
from app.models.user import User
from app.schemas.auth import UserCreate
from app.schemas.enrollment import EnrollmentTokenCreate
from app.services import audit_service
from app.services.agent_service import reinstate_agent, revoke_agent
from app.services.alert_service import AlertService, AlertThresholds
from app.services.asset_service import open_ports_by_asset
from app.services.auth_service import SessionPolicy, UserService
from app.services.discovery_service import DiscoveryConfig, DiscoveryService
from app.services.enrollment_token_service import EnrollmentTokenService
from app.services.identification import oui_database, refresh_identity
from app.services.retention_service import RetentionPolicy, RetentionService


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
            " CHANGE_RETENTION_DAYS or ALERT_RETENTION_DAYS",
            file=sys.stderr,
        )
        return 1
    result = RetentionService(session, policy).purge()
    print(
        f"deleted {result.telemetry_samples} telemetry samples, {result.system_events} events,"
        f" {result.asset_changes} inventory changes and {result.alerts} resolved alerts"
    )
    return 0


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
    discover = commands.add_parser(
        "discover", help="run network discovery now over the allowed networks (or one target)"
    )
    discover.add_argument(
        "--target", help="CIDR or address inside DISCOVERY_ALLOWED_NETWORKS (default: all)"
    )
    args = parser.parse_args(argv)

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
