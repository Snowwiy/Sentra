"""Operator commands: `python -m app.cli <command>` from the backend folder.

Agent revocation lives here rather than behind an HTTP endpoint on purpose: the dashboard
API has no user authentication yet, and an unauthenticated "revoke" endpoint would let anyone
who can reach the API cut every agent off. Running this requires shell access to the server
and its database credentials, which is the right bar until dashboard auth exists.
"""

import argparse
import sys
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import ConflictError, NotFoundError
from app.db.session import get_sessionmaker
from app.discovery.targets import TargetError
from app.models.asset import Asset
from app.models.discovery import DiscoveryTrigger
from app.services.agent_service import reinstate_agent, revoke_agent
from app.services.alert_service import AlertService, AlertThresholds
from app.services.discovery_service import DiscoveryConfig, DiscoveryService
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
    # Acknowledge/resolve live here, not in the HTTP API, for the same reason as revocation:
    # without dashboard authentication anyone reaching the API could silence alerts.
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
    # Manual run, here rather than over HTTP: probing the network is an active operation and
    # the dashboard has no authentication yet. Same allowlist checks as the periodic job.
    settings = get_settings()
    service = DiscoveryService(
        get_sessionmaker(),
        DiscoveryConfig.from_settings(settings),
        AlertThresholds.from_settings(settings),
    )
    try:
        summaries = service.run(target, DiscoveryTrigger.MANUAL)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Sentra operator tools")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list-agents", help="list agents and their credential state")
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
        if args.command == "purge-old-data":
            return _purge_old_data(session)
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
