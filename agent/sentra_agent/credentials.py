"""Protection of the agent token at rest.

On Windows the token is encrypted with DPAPI (CryptProtectData) in the *current user* scope:
only the same Windows account on the same machine can decrypt it, so copying identity.json
to another host or reading it from another local account yields nothing usable. User scope is
deliberate: machine scope (CRYPTPROTECT_LOCAL_MACHINE) would let any local user decrypt it.
A future Windows service will run as its own account and simply re-enroll once (same agent_id)
because the old blob will not decrypt under the new account.

DPAPI is called through ctypes (crypt32.dll ships with Windows) to avoid a pywin32 dependency.

Elsewhere the token is stored as-is and the file is protected by 0600 permissions; Linux has no
equivalent per-user secret store that works headless without extra daemons.
"""

import base64
import sys
from typing import Any

SCHEME_DPAPI = "dpapi-user"
SCHEME_PLAIN = "plain"
# Extra secret mixed into the DPAPI key derivation. It is not a password (it lives in this
# source file); it only scopes the blob to Sentra so another program running as the same user
# cannot decrypt it by accident with a bare CryptUnprotectData call.
_ENTROPY = b"sentra-agent/agent-token/v1"


class CredentialError(Exception):
    """The stored token cannot be decrypted (other user/machine, corrupted blob)."""


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _CRYPTPROTECT_UI_FORBIDDEN = 0x1  # never show a prompt: the agent runs unattended

    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Explicit signatures: ctypes' default int conversion would truncate 64-bit pointers.
    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    def _blob(data: bytes) -> tuple[_DataBlob, Any]:
        # The buffer is returned too so it stays alive for the duration of the call.
        buffer = ctypes.create_string_buffer(data, len(data))
        return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer

    def _dpapi(data: bytes, protect: bool) -> bytes:
        source, _source_buffer = _blob(data)
        entropy, _entropy_buffer = _blob(_ENTROPY)
        result = _DataBlob()
        call = _crypt32.CryptProtectData if protect else _crypt32.CryptUnprotectData
        description = "Sentra agent token" if protect else None
        if not call(
            ctypes.byref(source),
            description,
            ctypes.byref(entropy),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(result),
        ):
            raise CredentialError(f"DPAPI failed (Windows error {ctypes.get_last_error()})")
        try:
            return ctypes.string_at(result.pbData, result.cbData)
        finally:
            # DPAPI allocates the output with LocalAlloc; the caller must free it.
            _kernel32.LocalFree(ctypes.cast(result.pbData, ctypes.c_void_p))


def protect_token(token: str) -> dict[str, str]:
    """Return the JSON-serializable stored form of a token."""
    if sys.platform == "win32":
        blob = _dpapi(token.encode(), protect=True)
        return {"scheme": SCHEME_DPAPI, "value": base64.b64encode(blob).decode()}
    return {"scheme": SCHEME_PLAIN, "value": token}


def unprotect_token(stored: object) -> str:
    """Inverse of protect_token. Raises CredentialError when the token is unusable."""
    if not isinstance(stored, dict) or not isinstance(stored.get("value"), str):
        raise CredentialError("malformed stored token")
    scheme, value = stored.get("scheme"), str(stored["value"])
    if scheme == SCHEME_PLAIN:
        return value
    if scheme == SCHEME_DPAPI:
        # Positive platform check (not an early `!= "win32"` raise): mypy only skips
        # platform-specific code inside `if sys.platform == ...` blocks, so the early-raise
        # form made `mypy` fail on Linux (and in CI) with `_dpapi` undefined.
        if sys.platform == "win32":
            try:
                blob = base64.b64decode(value, validate=True)
            except ValueError as exc:
                raise CredentialError("corrupted DPAPI blob") from exc
            try:
                return _dpapi(blob, protect=False).decode()
            except UnicodeDecodeError as exc:
                raise CredentialError("decrypted token is not text") from exc
        raise CredentialError("DPAPI-protected token can only be read on Windows")
    raise CredentialError(f"unknown token scheme {scheme!r}")


def is_protected_at_rest() -> bool:
    return sys.platform == "win32"
