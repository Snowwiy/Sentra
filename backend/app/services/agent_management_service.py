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
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError
from app.core.ingest_quota import ThrottleState
from app.core.platforms import is_macos
from app.core.security import generate_recovery_token, hash_token
from app.models.asset import Asset, AssetStatus
from app.models.enrollment import AgentRecoveryToken
from app.repositories.asset_repository import AssetRepository
from app.schemas.agent_management import (
    AgentList,
    AgentPlatform,
    AgentRead,
    AgentRecoveryCreate,
    AgentRecoveryCreated,
    AgentRecoveryList,
    AgentRecoveryRead,
    AgentSummary,
    CredentialStatus,
)
from app.services.agent_service import ROTATION_OPERATOR, reinstate_agent, revoke_agent
from app.services.asset_service import effective_status
from app.services.site_service import SiteRef, site_refs

logger = logging.getLogger(__name__)

# Fase 7D.2: un agente cuenta como "limitado ahora" en el resumen si recibió un 429 de cuota en
# este plazo. Más corto que la purga de cubos (un día), que acota los rechazos acumulados.
THROTTLED_RECENTLY = timedelta(minutes=15)
ThrottleLookup = Callable[[Sequence[UUID]], dict[UUID, ThrottleState]]


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
    if is_macos(os_name):
        return "macos"
    return "other"


class AgentManagementService:
    def __init__(
        self,
        session: Session,
        heartbeat_timeout: timedelta,
        throttle: ThrottleLookup | None = None,
    ) -> None:
        self._session = session
        # Fase 7D.2 (H06): estado de las cuotas de ingesta (app.state.ingest_quota). Ausente en
        # la CLI, que no tiene almacén de cuotas: los campos quedan vacíos.
        self._throttle = throttle
        self._assets = AssetRepository(session)
        self._timeout = heartbeat_timeout
        self._sites: dict[int, SiteRef] | None = None

    def list_agents(self, site_id: int | None = None) -> AgentList:
        now = datetime.now(UTC)
        query = select(Asset).where(Asset.agent_id.is_not(None))
        if site_id is not None:
            query = query.where(Asset.site_id == site_id)
        rows = self._session.scalars(query.order_by(Asset.first_seen_at.desc())).all()
        items = self._with_throttle([self._read(asset, now) for asset in rows])
        current = sum(1 for agent in items if agent.asset_state == "active")
        summary = AgentSummary(total=current, online=0, offline=0, pending=0, revoked=0)
        for agent in items:
            if agent.asset_state == "active" and agent.transport == "http_remote":
                summary.insecure_transport += 1
            if agent.asset_state == "active" and agent.credential_source == "legacy_key":
                summary.legacy_key += 1
            throttled_at = agent.ingest_throttled_at
            if (
                agent.asset_state == "active"
                and throttled_at
                and now - throttled_at < (THROTTLED_RECENTLY)
            ):
                summary.throttled += 1
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
        agent = self._read(self._managed(asset_public_id), datetime.now(UTC))
        return self._with_throttle([agent])[0]

    def _with_throttle(self, items: list[AgentRead]) -> list[AgentRead]:
        if self._throttle is None or not items:
            return items
        states = self._throttle([item.agent_id for item in items])
        for item in items:
            state = states.get(item.agent_id)
            if state is not None:
                item.ingest_throttled_at = state.last_rejected_at
                item.ingest_rejections = state.rejected_total
        return items

    def revoke(self, asset_public_id: UUID, via: str) -> AgentRead:
        asset = self._managed(asset_public_id)
        already = asset.agent_token_revoked_at is not None
        revoke_agent(self._session, asset_public_id)
        if not already:
            logger.info("agent revoked", extra={"asset_id": str(asset_public_id), "via": via})
        return self.get_agent(asset_public_id)

    def reinstate(self, asset_public_id: UUID, via: str) -> AgentRead:
        """Lift a revocation. The agent still needs a NEW enrollment credential to get in.

        No token is issued or restored: the old one was destroyed at revocation. Fase 7D.1:
        the host comes back with a recovery authorization for THIS asset
        (create_recovery), keeping its agent_id, so it stays the same asset with its history.
        """
        asset = self._managed(asset_public_id)
        if asset.agent_token_revoked_at is None:
            raise ConflictError("Agent is not revoked")
        reinstate_agent(self._session, asset_public_id)
        logger.info("agent reinstated", extra={"asset_id": str(asset_public_id), "via": via})
        return self.get_agent(asset_public_id)

    # --- Fase 7D.1 (H01): recuperación autorizada y rotación pedida ------------------------

    def create_recovery(
        self,
        asset_public_id: UUID,
        payload: AgentRecoveryCreate,
        actor_name: str,
        actor_user_id: int | None,
        default_ttl: timedelta,
    ) -> AgentRecoveryCreated:
        """Emite una autorización de recuperación para ESTE activo (un solo uso, vida corta).

        Una nueva sustituye a las activas del mismo activo (se revocan): nunca hay dos
        autorizaciones vivas para una identidad. El token no se registra en logs ni en la
        auditoría; solo su id.
        """
        asset = self._session.scalar(
            select(Asset).where(Asset.public_id == asset_public_id).with_for_update()
        )
        if asset is None or asset.agent_id is None:
            raise NotFoundError("Agent not found")
        if asset.agent_token_revoked_at is not None:
            raise ConflictError("Agent is revoked; reinstate it before authorizing recovery")
        if asset.archived_at is not None:
            raise ConflictError("The asset is archived; restore it before authorizing recovery")
        now = datetime.now(UTC)
        for row in self._session.scalars(
            select(AgentRecoveryToken)
            .where(
                AgentRecoveryToken.asset_id == asset.id,
                AgentRecoveryToken.used_at.is_(None),
                AgentRecoveryToken.revoked_at.is_(None),
                AgentRecoveryToken.expires_at > now,
            )
            .with_for_update()
        ):
            row.revoked_at = now
        token = generate_recovery_token()
        ttl = timedelta(minutes=payload.ttl_minutes) if payload.ttl_minutes else default_ttl
        row = AgentRecoveryToken(
            token_hash=hash_token(token),
            asset_id=asset.id,
            agent_id=asset.agent_id,
            site_id=asset.site_id,
            expected_hostname=payload.expected_hostname,
            reason=payload.reason,
            created_by=actor_name[:64],
            created_by_user_id=actor_user_id,
            created_at=now,
            expires_at=now + ttl,
        )
        self._session.add(row)
        self._session.flush()
        logger.info(
            "agent recovery authorized",
            extra={"asset_id": str(asset.public_id), "recovery_id": str(row.public_id)},
        )
        return AgentRecoveryCreated(
            **self._recovery_read(row, asset, now).model_dump(), token=token
        )

    def list_recoveries(self, asset_public_id: UUID) -> AgentRecoveryList:
        asset = self._managed(asset_public_id)
        now = datetime.now(UTC)
        rows = self._session.scalars(
            select(AgentRecoveryToken)
            .where(AgentRecoveryToken.asset_id == asset.id)
            .order_by(AgentRecoveryToken.created_at.desc(), AgentRecoveryToken.id.desc())
            .limit(50)
        ).all()
        return AgentRecoveryList(items=[self._recovery_read(r, asset, now) for r in rows])

    def revoke_recovery(self, recovery_public_id: UUID) -> AgentRecoveryRead:
        row = self._session.scalar(
            select(AgentRecoveryToken)
            .where(AgentRecoveryToken.public_id == recovery_public_id)
            .with_for_update()
        )
        if row is None:
            raise NotFoundError("Recovery authorization not found")
        now = datetime.now(UTC)
        if row.used_at is not None:
            raise ConflictError("Recovery authorization already used")
        if row.revoked_at is None:
            row.revoked_at = now
        asset = self._session.get(Asset, row.asset_id)
        assert asset is not None  # noqa: S101  (FK con borrado en cascada)
        return self._recovery_read(row, asset, now)

    def request_rotation(self, asset_public_id: UUID) -> AgentRead:
        asset = self._managed(asset_public_id)
        if asset.agent_token_revoked_at is not None:
            raise ConflictError("Agent is revoked")
        asset.agent_rotation_requested_at = datetime.now(UTC)
        asset.agent_rotation_reason = ROTATION_OPERATOR
        self._session.flush()
        return self._read(asset, datetime.now(UTC))

    def _recovery_read(
        self, row: AgentRecoveryToken, asset: Asset, now: datetime
    ) -> AgentRecoveryRead:
        site = self._site(row.site_id) if row.site_id is not None else None
        return AgentRecoveryRead(
            recovery_id=row.public_id,
            asset_id=asset.public_id,
            agent_id=row.agent_id,
            state=row.state(now).value,
            reason=row.reason,
            created_by=row.created_by,
            created_at=row.created_at,
            expires_at=row.expires_at,
            used_at=row.used_at,
            revoked_at=row.revoked_at,
            expected_hostname=row.expected_hostname,
            site_name=site.name if site else None,
        )

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
            site_id=self._site(asset.site_id).public_id,
            site_name=self._site(asset.site_id).name,
            credential_source=asset.agent_credential_source,
            rotation_pending=asset.agent_token_pending_hash is not None,
            rotation_requested_at=asset.agent_rotation_requested_at,
            rotation_reason=asset.agent_rotation_reason,
            transport=asset.agent_transport,
            transport_at=asset.agent_transport_at,
            insecure_transport_at=asset.agent_insecure_transport_at,
        )

    def _site(self, site_id: int) -> SiteRef:
        if self._sites is None or site_id not in self._sites:
            self._sites = site_refs(self._session)
        return self._sites[site_id]


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
    https_port: int | None,
    addresses: Callable[[], list[str]] | None = None,
) -> list[str]:
    """URLs agents could use to reach this server, best first. Never localhost: an agent on
    another machine cannot reach the server's loopback.

    Fase 7D.1 (H04): siempre https:// (el agente 0.7.0 no acepta http:// fuera de loopback).
    `https_port` es el puerto HTTPS por el que llegó la consola (el del proxy); sin él se
    supone el 443 del proxy de referencia, nunca el puerto interno de uvicorn.
    """
    if configured:
        return [configured]
    suffix = f":{https_port}" if https_port and https_port != 443 else ""
    return [f"https://{address}{suffix}" for address in (addresses or local_ipv4_addresses)()]
