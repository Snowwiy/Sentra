"""Persistent agent identity.

The agent_id must survive restarts and reboots: losing it makes the server see a brand new
asset and leaves the old one as a stale offline duplicate.

File format (version 2):
    {"version": 2, "agent_id": "...", "asset_id": "...",
     "token": {"scheme": "dpapi-user", "value": "<base64 DPAPI blob>"},
     "token_issued_at": "2026-10-04T01:00:00+00:00"}

Version 1 files (token in plain text) are read and immediately rewritten encrypted.
"""

import json
import logging
import os
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sentra_agent.credentials import CredentialError, protect_token, unprotect_token

logger = logging.getLogger("sentra_agent")

IDENTITY_FILE = "identity.json"
FORMAT_VERSION = 2


@dataclass
class Identity:
    agent_id: uuid.UUID
    asset_id: uuid.UUID | None = None
    # Bearer token issued at enrollment. It is a credential: anyone holding it can report as
    # this agent. It only exists decrypted in memory; on disk it is DPAPI-protected.
    token: str | None = None
    # When the current token was issued. Kept for a future rotation policy (rotate tokens
    # older than N days) without another file format change.
    token_issued_at: datetime | None = None

    def __repr__(self) -> str:
        # Never let the token reach logs or tracebacks through a repr().
        return (
            f"Identity(agent_id={self.agent_id}, asset_id={self.asset_id}, "
            f"token={'<set>' if self.token else None})"
        )


def write_atomic(path: Path, content: str, private: bool = True) -> None:
    # Write-then-rename so a crash or power loss never leaves a truncated file, which for the
    # identity would otherwise force a new identity on next start.
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if private and sys.platform != "win32":
            # Windows: %LOCALAPPDATA% is already private to the user through its ACL, and the
            # token itself is DPAPI-encrypted.
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class IdentityStore:
    def __init__(self, state_dir: Path) -> None:
        self.path = state_dir / IDENTITY_FILE

    def load_or_create(self) -> Identity:
        if self.path.exists():
            try:
                return self._load()
            # AttributeError: valid JSON of the wrong shape (a list, a number as agent_id).
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                # Unreadable identity (should not happen thanks to atomic writes, but disks and
                # people fail). Keep the evidence and start fresh: an agent that refuses to start
                # is worse than one stale duplicate asset on the server.
                backup = self.path.with_name(
                    f"{self.path.name}.corrupt-{datetime.now(UTC):%Y%m%dT%H%M%SZ}"
                )
                os.replace(self.path, backup)
                logger.error(
                    "identity file unreadable, created a new identity",
                    extra={"error": str(exc), "backup": str(backup)},
                )
        identity = Identity(agent_id=uuid.uuid4())
        self.save(identity)
        return identity

    def _load(self) -> Identity:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        asset_id = data.get("asset_id")
        identity = Identity(
            agent_id=uuid.UUID(data["agent_id"]),
            asset_id=uuid.UUID(asset_id) if asset_id else None,
        )
        issued = data.get("token_issued_at")
        identity.token_issued_at = datetime.fromisoformat(issued) if issued else None

        stored = data.get("token")
        if isinstance(stored, str):
            # Version 1 kept the token in plain text: upgrade the file right away.
            identity.token = stored
            self.save(identity)
            logger.info("token migrated to protected storage")
        elif stored is not None:
            try:
                identity.token = unprotect_token(stored)
            except CredentialError as exc:
                # Typically the file was copied from another user or machine. The agent keeps
                # its agent_id and enrolls again, which rotates the token server side.
                logger.warning(
                    "stored token unusable, will enroll again", extra={"error": str(exc)}
                )
                identity.token = None
                identity.token_issued_at = None
                self.save(identity)
        return identity

    def save(self, identity: Identity) -> None:
        payload = {
            "version": FORMAT_VERSION,
            "agent_id": str(identity.agent_id),
            "asset_id": str(identity.asset_id) if identity.asset_id else None,
            "token": protect_token(identity.token) if identity.token else None,
            "token_issued_at": identity.token_issued_at.isoformat()
            if identity.token_issued_at
            else None,
        }
        write_atomic(self.path, json.dumps(payload, indent=2))
