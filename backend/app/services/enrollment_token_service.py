"""One-time enrollment tokens: create, list, revoke, and consume at agent enrollment.

Threats considered and how they are handled:
- Database leak: only SHA-256 hashes are stored (tokens are 256-bit random, so the hash is
  not brute-forceable); a leaked table cannot enroll anything.
- Token leak after use: single use by default and short lived (ENROLLMENT_TOKEN_TTL_MINUTES,
  15 min); the agent gets its own token and the bootstrap one is dead.
- Replay / race: consumption happens in the same transaction as the enrollment, under a row
  lock (SELECT ... FOR UPDATE), so two agents racing with one token cannot both get in.
- Probing: every rejection (unknown, expired, revoked, used, wrong platform/host) answers
  the same 401; the specific reason is logged server side, with the token id, never the
  token.
- Scope: a bootstrap token is only accepted by POST /agents/register. Heartbeat, telemetry,
  inventory, processes and events authenticate with the per-agent token only.
"""

import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, UnauthorizedError
from app.core.security import (
    ENROLLMENT_TOKEN_PREFIX,
    MAX_CREDENTIAL_LENGTH,
    generate_enrollment_token,
    hash_token,
)
from app.models.asset import Asset
from app.models.enrollment import AgentEnrollmentToken, EnrollmentTokenState
from app.schemas.agent import HostInfo
from app.schemas.enrollment import (
    EnrollmentTokenCreate,
    EnrollmentTokenCreated,
    EnrollmentTokenList,
    EnrollmentTokenRead,
)

logger = logging.getLogger(__name__)

INVALID_TOKEN = "Invalid enrollment token"  # noqa: S105  (an error message)


class EnrollmentTokenService:
    def __init__(self, session: Session, default_ttl: timedelta = timedelta(minutes=15)) -> None:
        self._session = session
        self._default_ttl = default_ttl

    def create(self, request: EnrollmentTokenCreate, created_via: str) -> EnrollmentTokenCreated:
        now = datetime.now(UTC)
        ttl = timedelta(minutes=request.ttl_minutes) if request.ttl_minutes else self._default_ttl
        token = generate_enrollment_token()
        row = AgentEnrollmentToken(
            token_hash=hash_token(token),
            created_at=now,
            expires_at=now + ttl,
            max_uses=request.max_uses,
            use_count=0,
            expected_platform=request.expected_platform,
            expected_hostname=request.expected_hostname,
            note=request.note,
            created_via=created_via,
        )
        self._session.add(row)
        self._session.commit()
        logger.info(
            "enrollment token created",
            extra={
                "token_id": str(row.public_id),
                "expires_at": row.expires_at.isoformat(),
                "max_uses": row.max_uses,
                "via": created_via,
            },
        )
        return EnrollmentTokenCreated(**self._read(row, now).model_dump(), token=token)

    def list(self, limit: int = 100) -> EnrollmentTokenList:
        now = datetime.now(UTC)
        rows = self._session.scalars(
            select(AgentEnrollmentToken)
            .order_by(AgentEnrollmentToken.created_at.desc(), AgentEnrollmentToken.id.desc())
            .limit(limit)
        ).all()
        return EnrollmentTokenList(items=[self._read(row, now) for row in rows])

    def revoke(self, token_public_id: UUID) -> EnrollmentTokenRead:
        row = self._session.scalar(
            select(AgentEnrollmentToken)
            .where(AgentEnrollmentToken.public_id == token_public_id)
            .with_for_update()
        )
        if row is None:
            raise NotFoundError("Enrollment token not found")
        now = datetime.now(UTC)
        state = row.state(now)
        if state == EnrollmentTokenState.CONSUMED:
            raise ConflictError("Enrollment token already used up; revoke the agent instead")
        if row.revoked_at is None:
            row.revoked_at = now
            logger.info("enrollment token revoked", extra={"token_id": str(row.public_id)})
        self._session.commit()
        return self._read(row, now)

    def lock_for_enrollment(self, token: str, host: HostInfo) -> AgentEnrollmentToken:
        """Validate a presented token and lock its row until the enrollment commits.

        Raises UnauthorizedError (same message for every reason). Does not consume it:
        call `consume` once the asset is in place, in the same transaction.
        """
        if not token.startswith(ENROLLMENT_TOKEN_PREFIX) or len(token) > MAX_CREDENTIAL_LENGTH:
            logger.warning("enrollment token rejected", extra={"reason": "malformed"})
            raise UnauthorizedError(INVALID_TOKEN)
        row = self._session.scalar(
            select(AgentEnrollmentToken)
            .where(AgentEnrollmentToken.token_hash == hash_token(token))
            .with_for_update()
        )
        if row is None:
            logger.warning("enrollment token rejected", extra={"reason": "unknown"})
            raise UnauthorizedError(INVALID_TOKEN)
        state = row.state(datetime.now(UTC))
        reason = None
        if state != EnrollmentTokenState.ACTIVE:
            reason = state.value
        elif row.expected_platform and row.expected_platform not in host.os_name.lower():
            reason = "platform mismatch"
        elif row.expected_hostname and row.expected_hostname.lower() != host.hostname.lower():
            reason = "hostname mismatch"
        if reason is not None:
            logger.warning(
                "enrollment token rejected",
                extra={"reason": reason, "token_id": str(row.public_id)},
            )
            raise UnauthorizedError(INVALID_TOKEN)
        return row

    def consume(self, row: AgentEnrollmentToken, asset: Asset) -> None:
        """Count one use (no commit: part of the enrollment transaction)."""
        now = datetime.now(UTC)
        row.use_count += 1
        row.last_used_at = now
        row.last_asset_id = asset.id
        if row.use_count >= row.max_uses:
            row.consumed_at = now
        logger.info(
            "enrollment token used",
            extra={
                "token_id": str(row.public_id),
                "asset_id": str(asset.public_id),
                "uses": f"{row.use_count}/{row.max_uses}",
            },
        )

    def _read(self, row: AgentEnrollmentToken, now: datetime) -> EnrollmentTokenRead:
        asset_id = None
        if row.last_asset_id is not None:
            asset_id = self._session.scalar(
                select(Asset.public_id).where(Asset.id == row.last_asset_id)
            )
        return EnrollmentTokenRead(
            token_id=row.public_id,
            state=row.state(now),
            created_at=row.created_at,
            expires_at=row.expires_at,
            consumed_at=row.consumed_at,
            revoked_at=row.revoked_at,
            last_used_at=row.last_used_at,
            max_uses=row.max_uses,
            use_count=row.use_count,
            expected_platform=row.expected_platform,
            expected_hostname=row.expected_hostname,
            note=row.note,
            created_via=row.created_via,
            last_asset_id=asset_id,
        )
