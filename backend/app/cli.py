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

from app.core.exceptions import NotFoundError
from app.db.session import get_sessionmaker
from app.models.asset import Asset
from app.services.agent_service import reinstate_agent, revoke_agent


def _list_agents(session: Session) -> None:
    assets = session.scalars(select(Asset).order_by(Asset.hostname, Asset.id)).all()
    print(f"{'asset_id':36}  {'hostname':24}  {'token':8}  revoked_at")
    for asset in assets:
        token = "issued" if asset.agent_token_hash else "none"
        revoked = asset.agent_token_revoked_at.isoformat() if asset.agent_token_revoked_at else "-"
        print(f"{asset.public_id!s:36}  {asset.hostname[:24]:24}  {token:8}  {revoked}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Sentra operator tools")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list-agents", help="list agents and their credential state")
    for name, text in (
        ("revoke-agent", "invalidate an agent's token and block its re-enrollment"),
        ("reinstate-agent", "allow a revoked agent to enroll again"),
    ):
        command = commands.add_parser(name, help=text)
        command.add_argument("asset_id", type=UUID, help="public asset id (as shown in the UI)")
    args = parser.parse_args(argv)

    with get_sessionmaker()() as session:
        if args.command == "list-agents":
            _list_agents(session)
            return 0
        action = revoke_agent if args.command == "revoke-agent" else reinstate_agent
        try:
            asset = action(session, args.asset_id)
        except NotFoundError:
            print(f"asset {args.asset_id} not found", file=sys.stderr)
            return 1
        state = "revoked" if asset.agent_token_revoked_at else "reinstated"
        print(f"agent of asset {asset.public_id} ({asset.hostname}) {state}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
