"""Agent credentials: enrollment key check and per-agent tokens.

Model:
- An operator-configured enrollment key (AGENT_ENROLLMENT_KEY) authorizes registering agents.
  Only hosts that were given the key can join.
- Registration returns a random per-agent token exactly once. The server stores only its
  SHA-256 hash, so a database leak does not expose usable credentials.
- Every later agent call sends the token as a Bearer credential.

SHA-256 (not bcrypt/argon2) is correct here: tokens are 256-bit random values, so there is
nothing to brute force, and a slow hash would add latency to every heartbeat.
"""

import hashlib
import hmac
import secrets

TOKEN_BYTES = 32


def generate_agent_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def token_matches(token: str, stored_hash: str | None) -> bool:
    if stored_hash is None:
        return False
    # Constant-time comparison so response timing does not leak how much of a hash matched.
    return hmac.compare_digest(hash_token(token), stored_hash)


def enrollment_key_matches(provided: str | None, expected: str) -> bool:
    if not provided:
        return False
    return hmac.compare_digest(provided.encode(), expected.encode())
