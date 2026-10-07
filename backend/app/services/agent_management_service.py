"""Agents as managed from the dashboard: listing, credential state, revoke and reinstate.

Reuses the existing building blocks (agent_service.revoke_agent / reinstate_agent, the
liveness rule of asset_service.effective_status); only adds the read model and the checks
the dashboard needs. Revocation never deletes anything: the asset, its telemetry, events,
inventory, alerts and discovery/exposure history stay for audit.
"""

import contextlib
import ipaddress
import logging
import socket
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError
from app.models.asset import Asset, AssetStatus
from app.repositories.asset_repository import AssetRepository
from app.schemas.agent_management import (
    AgentList,
    AgentPlatform,
    AgentRead,
    AgentSummary,
    CredentialStatus,
)
from app.services.agent_service import reinstate_agent, revoke_agent
from app.services.asset_service import effective_status

logger = logging.getLogger(__name__)


def credential_status(asset: Asset) -> CredentialStatus:
    if asset.agent_token_revoked_at is not None:
        return CredentialStatus.REVOKED
    if asset.agent_token_hash is None:
        return CredentialStatus.RE_ENROLLMENT_REQUIRED
    return CredentialStatus.ACTIVE


def agent_platform(os_name: str | None) -> AgentPlatform:
    name = (os_name or "").lower()
    if "windows" in name:
        return "windows"
    if "linux" in name:
        return "linux"
    return "other"


class AgentManagementService:
    def __init__(self, session: Session, heartbeat_timeout: timedelta) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._timeout = heartbeat_timeout

    def list_agents(self) -> AgentList:
        now = datetime.now(UTC)
        rows = self._session.scalars(
            select(Asset).where(Asset.agent_id.is_not(None)).order_by(Asset.first_seen_at.desc())
        ).all()
        items = [self._read(asset, now) for asset in rows]
        current = sum(1 for agent in items if agent.asset_state == "active")
        summary = AgentSummary(total=current, online=0, offline=0, pending=0, revoked=0)
        for agent in items:
            if agent.asset_state == "archived":
                summary.archived += 1
            elif agent.credential_status == CredentialStatus.REVOKED:
                summary.revoked += 1
            elif agent.status == AssetStatus.ONLINE:
                summary.online += 1
            elif agent.status == AssetStatus.OFFLINE:
                summary.offline += 1
            else:
                summary.pending += 1
        return AgentList(summary=summary, items=items)

    def get_agent(self, asset_public_id: UUID) -> AgentRead:
        return self._read(self._managed(asset_public_id), datetime.now(UTC))

    def revoke(self, asset_public_id: UUID, via: str) -> AgentRead:
        asset = self._managed(asset_public_id)
        already = asset.agent_token_revoked_at is not None
        revoke_agent(self._session, asset_public_id)
        if not already:
            logger.info("agent revoked", extra={"asset_id": str(asset_public_id), "via": via})
        return self.get_agent(asset_public_id)

    def reinstate(self, asset_public_id: UUID, via: str) -> AgentRead:
        """Lift a revocation. The agent still needs a NEW enrollment credential to get in.

        No token is issued or restored: the old one was destroyed at revocation. The host
        re-enrolls with a fresh one-time token (installer run again), keeping its agent_id,
        so it stays the same asset with its history.
        """
        asset = self._managed(asset_public_id)
        if asset.agent_token_revoked_at is None:
            raise ConflictError("Agent is not revoked")
        reinstate_agent(self._session, asset_public_id)
        logger.info("agent reinstated", extra={"asset_id": str(asset_public_id), "via": via})
        return self.get_agent(asset_public_id)

    def _managed(self, asset_public_id: UUID) -> Asset:
        asset = self._assets.get_by_public_id(asset_public_id)
        # Assets only seen on the network have no agent and nothing to revoke.
        if asset is None or asset.agent_id is None:
            raise NotFoundError("Agent not found")
        return asset

    def _read(self, asset: Asset, now: datetime) -> AgentRead:
        assert asset.agent_id is not None  # noqa: S101  (only managed assets get here)
        return AgentRead(
            asset_id=asset.public_id,
            agent_id=asset.agent_id,
            display_name=asset.display_name,
            hostname=asset.hostname,
            primary_ip=asset.primary_ip,
            os_name=asset.os_name,
            os_version=asset.os_version,
            architecture=asset.architecture,
            platform=agent_platform(asset.os_name),
            agent_version=asset.agent_version,
            installation_method=asset.agent_installation_method,
            monitoring_method=asset.monitoring_method,
            status=effective_status(asset, now, self._timeout),
            credential_status=credential_status(asset),
            enrolled_at=asset.first_seen_at,
            credential_issued_at=asset.agent_token_issued_at,
            revoked_at=asset.agent_token_revoked_at,
            last_seen_at=asset.last_seen_at,
            asset_state="archived" if asset.archived_at is not None else "active",
            archived_at=asset.archived_at,
            lifecycle_version=asset.lifecycle_version,
        )


def local_ipv4_addresses() -> list[str]:
    """This machine's IPv4 addresses other hosts could use (no loopback, no link-local)."""
    found: list[str] = []
    try:
        # Connecting a UDP socket sends nothing; it only selects the address of the default
        # route, which is the one a LAN host most likely reaches.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            found.append(probe.getsockname()[0])
    except OSError:
        pass
    with contextlib.suppress(OSError):
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        found += [str(info[4][0]) for info in infos]
    usable: list[str] = []
    for text in found:
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            continue
        if address.is_loopback or address.is_link_local or address.is_unspecified:
            continue
        if text not in usable:
            usable.append(text)
    return usable


def suggested_server_urls(
    configured: str | None,
    port: int | None,
    addresses: Callable[[], list[str]] | None = None,
) -> list[str]:
    """URLs agents could use to reach this server, best first. Never localhost: an agent on
    another machine cannot reach the server's loopback."""
    if configured:
        return [configured]
    suffix = f":{port}" if port and port != 80 else ""
    return [f"http://{address}{suffix}" for address in (addresses or local_ipv4_addresses)()]
