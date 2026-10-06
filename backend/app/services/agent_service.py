import logging
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, object_session

from app.core.exceptions import (
    AgentRevokedError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
)
from app.core.security import (
    enrollment_key_matches,
    generate_agent_token,
    hash_token,
    token_matches,
)
from app.models.asset import Asset, AssetStatus
from app.repositories.asset_repository import AssetRepository
from app.schemas.agent import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    HostInfo,
)
from app.services.alert_service import resolve_offline_alert
from app.services.enrollment_token_service import EnrollmentTokenService
from app.services.identification import refresh_identity
from app.services.reconciliation import adopt_discovered
from app.vulnerabilities.queue import mark_dirty

logger = logging.getLogger(__name__)


def record_contact(session: Session, asset: Asset, now: datetime) -> None:
    """Record proof of life from any authenticated agent call and resolve its offline alert.

    `now` must be server time so agents cannot fake liveness. One UPDATE with GREATEST
    because concurrent calls of one agent (heartbeat, telemetry, events, inventory) take
    `now` before they commit, not necessarily in the same order: last_seen_at must never move
    backwards. The UPDATE also takes the asset's row lock, which the offline sweeper honors
    (AlertService.sweep_offline), so no offline alert is opened for an asset that is
    reporting at that very moment. Every agent call resolves the offline alert, not only
    heartbeats: the asset is shown online as soon as any of them arrives.
    """
    session.execute(
        update(Asset)
        .where(Asset.id == asset.id)
        .values(last_seen_at=func.greatest(Asset.last_seen_at, now), status=AssetStatus.ONLINE)
    )
    resolve_offline_alert(session, asset.id, now)


def apply_host_info(asset: Asset, host: HostInfo) -> None:
    # Fase 5B: un cambio de SO (actualización de build, kernel nuevo) cambia qué
    # vulnerabilidades de SO aplican; se encola su evaluación, nunca en cada heartbeat.
    os_changed = (asset.os_name, asset.os_version) != (host.os_name, host.os_version)
    # Plain attribute assignment: SQLAlchemy only issues an UPDATE (and bumps updated_at)
    # for values that actually changed.
    asset.hostname = host.hostname
    asset.os_name = host.os_name
    asset.os_version = host.os_version
    asset.architecture = host.architecture
    asset.primary_ip = str(host.primary_ip)
    asset.agent_version = host.agent_version
    # Se asigna aunque venga vacío: refleja cómo corre el agente que informa ahora (p. ej.
    # un servicio desinstalado y el agente lanzado a mano deja de mostrar "Servicio Windows").
    asset.agent_installation_method = host.installation_method
    # El agente es la fuente autoritativa del nombre y del tipo: se recalcula con lo que
    # acaba de reportar (sin escrituras si nada cambió).
    refresh_identity(asset)
    session = object_session(asset)
    if os_changed and session is not None and asset.id is not None:
        mark_dirty(session, [asset.id], "os_change")


def authenticate_agent(assets: AssetRepository, agent_id: UUID, token: str | None) -> Asset:
    """Return the asset of an agent whose bearer token is valid, or raise 401.

    Unknown agent, missing token and wrong token all produce the same error so a caller
    cannot probe which agent_ids exist. Agents react to 401 by enrolling again.
    """
    asset = assets.get_by_agent_id(agent_id)
    if (
        asset is None
        or token is None
        # Revocation also clears the hash; checking the flag too keeps a revoked agent out even
        # if a hash were ever restored by hand or by a buggy migration.
        or asset.agent_token_revoked_at is not None
        or not token_matches(token, asset.agent_token_hash)
    ):
        raise UnauthorizedError("Invalid or missing agent credentials")
    return asset


def revoke_agent(session: Session, asset_public_id: UUID) -> Asset:
    """Invalidate an agent's token now and block its re-enrollment until reinstated.

    Revocation is per agent: other agents and the shared enrollment key keep working. The
    agent's next call gets 401, it tries to enroll again and receives 403 agent_revoked, after
    which it backs off to its maximum retry interval. Its history is kept.
    """
    asset = AssetRepository(session).get_by_public_id(asset_public_id)
    if asset is None:
        raise NotFoundError("Asset not found")
    asset.agent_token_hash = None
    asset.agent_token_issued_at = None
    if asset.agent_token_revoked_at is None:
        asset.agent_token_revoked_at = datetime.now(UTC)
    session.commit()
    return asset


def reinstate_agent(session: Session, asset_public_id: UUID) -> Asset:
    """Allow a revoked agent to enroll again (it still needs the enrollment key).

    No token is issued here: the agent obtains a fresh one through normal enrollment, so a
    token never has to be handed over out of band.
    """
    asset = AssetRepository(session).get_by_public_id(asset_public_id)
    if asset is None:
        raise NotFoundError("Asset not found")
    asset.agent_token_revoked_at = None
    session.commit()
    return asset


class AgentService:
    def __init__(self, session: Session, enrollment_key: str | None) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._enrollment_key = enrollment_key
        self._tokens = EnrollmentTokenService(session)

    def register(
        self,
        data: AgentRegisterRequest,
        provided_key: str | None,
        enrollment_token: str | None = None,
    ) -> tuple[AgentRegisterResponse, bool]:
        """Enroll an agent and issue a fresh token. Returns (response, created).

        Two credentials can authorize it:
        - a one-time enrollment token (recommended): validated and locked here, consumed in
          the same transaction as the enrollment, so it can never be used twice;
        - the shared enrollment key (legacy, kept for existing installations).
        Enrolling an agent_id that already exists is allowed and rotates its token: this is
        how an agent that lost its token (reinstall, deleted state) recovers. The previous
        token stops working immediately.
        """
        bootstrap = None
        if enrollment_token is not None:
            bootstrap = self._tokens.lock_for_enrollment(enrollment_token, data)
        else:
            if self._enrollment_key is None:
                raise ForbiddenError("Agent enrollment is disabled on this server")
            if not enrollment_key_matches(provided_key, self._enrollment_key):
                raise UnauthorizedError("Invalid enrollment key")

        asset = self._assets.get_by_agent_id(data.agent_id)
        # Checked only after the credential, so revocation status is never revealed to
        # callers without one. A revoked agent does not consume the enrollment token.
        if asset is not None and asset.agent_token_revoked_at is not None:
            raise AgentRevokedError("This agent has been revoked by an operator")

        token = generate_agent_token()
        created = asset is None
        if asset is None:
            asset = self._assets.add(
                Asset(
                    agent_id=data.agent_id,
                    hostname=data.hostname,
                    os_name=data.os_name,
                    os_version=data.os_version,
                    architecture=data.architecture,
                    primary_ip=str(data.primary_ip),
                    agent_version=data.agent_version,
                    agent_installation_method=data.installation_method,
                    # Registration alone does not prove the agent keeps running; it becomes
                    # online with its first heartbeat or telemetry sample.
                    status=AssetStatus.UNKNOWN,
                    first_seen_at=datetime.now(UTC),
                )
            )
            refresh_identity(asset)
        else:
            apply_host_info(asset, data)
        asset.agent_token_hash = hash_token(token)
        asset.agent_token_issued_at = datetime.now(UTC)

        try:
            self._session.flush()
            # Installed on a host discovery already knew: converge into this asset. Only by
            # address here (the agent reports MACs with its inventory, which retries it).
            adopt_discovered(self._session, asset, {str(data.primary_ip)}, set())
            if bootstrap is not None:
                self._tokens.consume(bootstrap, asset)
            else:
                logger.info(
                    "agent enrolled with the shared enrollment key (legacy)",
                    extra={"agent_id": str(data.agent_id)},
                )
            self._session.commit()
        except IntegrityError as exc:
            # A concurrent first registration with the same agent_id won the race; the agent
            # retries and then takes the re-enrollment path.
            self._session.rollback()
            raise ConflictError("Agent registration in progress, retry") from exc

        response = AgentRegisterResponse(
            asset_id=asset.public_id,
            agent_id=data.agent_id,
            status=asset.status,
            first_seen_at=asset.first_seen_at,
            agent_token=token,
        )
        return response, created

    def heartbeat(self, data: HeartbeatRequest, token: str | None) -> HeartbeatResponse:
        asset = authenticate_agent(self._assets, data.agent_id, token)
        now = datetime.now(UTC)
        record_contact(self._session, asset, now)
        if data.host is not None:
            apply_host_info(asset, data.host)
        self._session.commit()
        return HeartbeatResponse(
            asset_id=asset.public_id,
            status=AssetStatus.ONLINE,
            # The stored value: a delayed heartbeat never reports an older time than the
            # newest contact already recorded.
            last_seen_at=asset.last_seen_at or now,
        )
