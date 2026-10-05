"""Agent credentials: enrollment key check and per-agent tokens.

Model:
- An operator-configured enrollment key (AGENT_ENROLLMENT_KEY) authorizes registering agents.
  Only hosts that were given the key can join.
- Registration returns a random per-agent token exactly once. The server stores only its
  SHA-256 hash, so a database leak does not expose usable credentials.
- Every later agent call sends the token as a Bearer credential.
- Recommended for new agents: a one-time enrollment token (created by an operator, short
  lived, single use, stored as a hash) instead of the shared key, which stays as legacy.

SHA-256 (not bcrypt/argon2) is correct here: tokens are 256-bit random values, so there is
nothing to brute force, and a slow hash would add latency to every heartbeat.
"""

import hashlib
import hmac
import secrets

TOKEN_BYTES = 32
# One-time enrollment tokens carry a recognisable prefix so a leaked one is easy to spot in
# a ticket, a chat or a secret scanner, and is never mistaken for an agent token.
ENROLLMENT_TOKEN_PREFIX = "sentra_et_"  # noqa: S105  (a prefix, not a secret)
# Longest value accepted in X-Enrollment-Token / X-Admin-Key (real ones are ~53/≥24 chars).
MAX_CREDENTIAL_LENGTH = 256


def generate_agent_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def generate_enrollment_token() -> str:
    return ENROLLMENT_TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)


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


# --- Sesiones del dashboard ---------------------------------------------------------------
#
# El ID de sesión es un valor aleatorio de 256 bits que solo viaja en una cookie HttpOnly;
# la base de datos guarda su SHA-256 (igual que los tokens de agente), así una copia de
# `user_sessions` no permite secuestrar sesiones. Son credenciales distintas: un token de
# agente nunca se acepta como sesión ni al revés (tablas y cabeceras separadas).

SESSION_TOKEN_PREFIX = "sentra_s_"  # noqa: S105  (un prefijo, no un secreto)
_CSRF_CONTEXT = b"sentra-csrf-v1"


def generate_session_token() -> str:
    return SESSION_TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)


def csrf_token_for(session_token: str) -> str:
    """Token CSRF derivado de la sesión (HMAC-SHA256 con el ID de sesión como clave).

    No se guarda en ningún sitio: el servidor lo recalcula a partir de la cookie. Un sitio
    ajeno no puede calcularlo porque no puede leer la cookie (HttpOnly) ni la respuesta de
    /auth/me (CORS), y cambia con cada sesión, así que rotar la sesión en el login también
    invalida cualquier token CSRF anterior.
    """
    return hmac.new(session_token.encode(), _CSRF_CONTEXT, hashlib.sha256).hexdigest()


def csrf_token_matches(session_token: str, provided: str | None) -> bool:
    if not provided or len(provided) > MAX_CREDENTIAL_LENGTH:
        return False
    return hmac.compare_digest(csrf_token_for(session_token).encode(), provided.encode())
