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

Fase 6C.5, macOS: el token va al Keychain a través de Security.framework (ctypes, sin
dependencias). Nunca se usa la herramienta `security` con `-w <secreto>`, porque el secreto
quedaría visible en la lista de procesos (ps) mientras se ejecuta. El daemon de launchd corre
como root y usa el keychain del sistema (/Library/Keychains/System.keychain), que solo root
puede modificar; una ejecución manual como usuario usa su keychain por defecto. identity.json
guarda solo una referencia ({"scheme": "macos-keychain", "value": "<cuenta>"}), nunca el token.

Si el Keychain no está disponible el agente falla de forma explícita (no enrola y no guarda
el token en claro por su cuenta). Solo si la configuración elige `credential_store = "file"`
el token se guarda en identity.json con permisos 0600 dentro de un directorio de estado 0700
del mismo propietario (root en el daemon): es la misma protección que en Linux y la decisión
es del administrador, nunca un respaldo silencioso.

Decisión documentada (pendiente de validación en un Mac real): se usa la API clásica de
keychains de fichero (SecKeychain*), marcada como obsoleta por Apple pero la única que
permite elegir el keychain del sistema desde un proceso sin entitlements; el keychain de
"data protection" (SecItem con kSecUseDataProtectionKeychain) exige una aplicación firmada
con entitlements y una sesión de usuario, que un daemon root no tiene.
"""

import base64
import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

SCHEME_DPAPI = "dpapi-user"
SCHEME_PLAIN = "plain"
SCHEME_KEYCHAIN = "macos-keychain"
# Almacenes que puede elegir la configuración (credential_store). "auto": DPAPI en Windows,
# Keychain en macOS y fichero protegido en el resto.
CREDENTIAL_STORES = ("auto", "keychain", "file")
KEYCHAIN_SERVICE = "com.sentra.agent"
SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
SECURITY_FRAMEWORK = "/System/Library/Frameworks/Security.framework/Security"
COREFOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
# Extra secret mixed into the DPAPI key derivation. It is not a password (it lives in this
# source file); it only scopes the blob to Sentra so another program running as the same user
# cannot decrypt it by accident with a bare CryptUnprotectData call.
_ENTROPY = b"sentra-agent/agent-token/v1"


class CredentialError(Exception):
    """The stored token cannot be decrypted (other user/machine, corrupted blob)."""


class CredentialStoreUnavailableError(CredentialError):
    """El almacén elegido no se puede usar (Keychain bloqueado, ausente o sin permiso).

    A diferencia de un token ilegible, no se resuelve enrolando de nuevo: el agente se
    detiene con un error explícito hasta que un administrador lo corrija.
    """


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


def resolve_store(store: str = "auto", platform: str | None = None) -> str:
    """Almacén efectivo: "dpapi", "keychain" o "file". ValueError si no aplica aquí."""
    platform = platform or sys.platform
    if store not in CREDENTIAL_STORES:
        raise ValueError(f"credential_store must be one of {', '.join(CREDENTIAL_STORES)}")
    if platform == "win32":
        if store != "auto":
            # En Windows el token siempre se cifra con DPAPI: no hay motivo para guardarlo en
            # claro ni existe un Keychain.
            raise ValueError("on Windows credential_store must be auto (DPAPI)")
        return "dpapi"
    if store == "keychain" and platform != "darwin":
        raise ValueError("credential_store = keychain is only available on macOS")
    if store == "auto":
        return "keychain" if platform == "darwin" else "file"
    return store


class Keychain(Protocol):
    """Lo que el agente necesita de un keychain (implementación real o falsa en tests)."""

    def check(self) -> None: ...

    def get(self, account: str) -> str | None: ...

    def set(self, account: str, secret: str) -> None: ...

    def delete(self, account: str) -> None: ...


def _default_keychain() -> Keychain:
    if sys.platform == "darwin":
        # Daemon root: keychain del sistema. Usuario: su keychain por defecto (login).
        return SecurityKeychain(SYSTEM_KEYCHAIN if os.geteuid() == 0 else None)
    raise CredentialStoreUnavailableError("the macOS Keychain is only available on macOS")


# Los tests sustituyen esta fábrica por un keychain en memoria.
keychain_factory: Callable[[], Keychain] = _default_keychain


def check_store(store: str = "auto", state_dir: Path | None = None) -> None:
    """Comprueba antes de enrolar que el almacén elegido funciona; si no, lo dice claro."""
    kind = resolve_store(store)
    if kind == "keychain":
        keychain_factory().check()
    elif kind == "file" and store == "file" and sys.platform == "darwin" and state_dir:
        ensure_private_dir(state_dir)


def ensure_private_dir(path: Path) -> None:
    """Directorio de estado 0700 del usuario del agente (root en el daemon de macOS).

    Con `credential_store = "file"` el token queda en claro en identity.json (0600): solo es
    aceptable si nadie más puede entrar en el directorio ni cambiarlo de sitio.
    """
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise CredentialStoreUnavailableError(f"state directory {path} is not a directory")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise CredentialStoreUnavailableError(
            f"state directory {path} is not owned by the agent's user; refusing to store the"
            " token in a file there"
        )
    if info.st_mode & 0o077:
        os.chmod(path, 0o700)


def protect_token(token: str, store: str = "auto", account: str = "agent") -> dict[str, str]:
    """Return the JSON-serializable stored form of a token.

    Con Keychain el valor devuelto es solo la cuenta bajo la que se guardó (una referencia),
    nunca el token.
    """
    kind = resolve_store(store)
    if kind == "dpapi" and sys.platform == "win32":
        blob = _dpapi(token.encode(), protect=True)
        return {"scheme": SCHEME_DPAPI, "value": base64.b64encode(blob).decode()}
    if kind == "keychain":
        keychain_factory().set(account, token)
        return {"scheme": SCHEME_KEYCHAIN, "value": account}
    return {"scheme": SCHEME_PLAIN, "value": token}


def stored_scheme(store: str = "auto") -> str:
    """Esquema con el que protect_token guardaría un token con este almacén."""
    return {"dpapi": SCHEME_DPAPI, "keychain": SCHEME_KEYCHAIN}.get(
        resolve_store(store), SCHEME_PLAIN
    )


def unprotect_token(stored: object) -> str:
    """Inverse of protect_token. Raises CredentialError when the token is unusable."""
    if not isinstance(stored, dict) or not isinstance(stored.get("value"), str):
        raise CredentialError("malformed stored token")
    scheme, value = stored.get("scheme"), str(stored["value"])
    if scheme == SCHEME_PLAIN:
        return value
    if scheme == SCHEME_KEYCHAIN:
        secret = keychain_factory().get(value)
        if secret is None:
            # Borrado del Keychain o identity.json copiado de otro Mac: se enrola de nuevo.
            raise CredentialError("agent token not found in the Keychain")
        return secret
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


def forget_token(stored: object) -> None:
    """Borra la copia del token que no vive en identity.json (la del Keychain)."""
    if isinstance(stored, dict) and stored.get("scheme") == SCHEME_KEYCHAIN:
        account = stored.get("value")
        if isinstance(account, str) and account:
            keychain_factory().delete(account)


def is_protected_at_rest(store: str = "auto") -> bool:
    try:
        return resolve_store(store) in ("dpapi", "keychain")
    except ValueError:
        return False


# --- macOS: Security.framework ---------------------------------------------------------------

# Códigos OSStatus de Security.framework (SecBase.h).
ERR_SEC_ITEM_NOT_FOUND = -25300
ERR_SEC_DUPLICATE_ITEM = -25299
ERR_SEC_NO_SUCH_KEYCHAIN = -25294
ERR_SEC_INTERACTION_NOT_ALLOWED = -25308
ERR_SEC_AUTH_FAILED = -25293
ERR_SEC_NOT_AVAILABLE = -25291
# SecKeychainStatus: desbloqueado y con permiso de escritura.
_UNLOCKED = 0x1
_WRITABLE = 0x4


def keychain_error(operation: str, status: int) -> CredentialError:
    """Error legible de un OSStatus; nunca incluye el secreto."""
    reasons = {
        ERR_SEC_NO_SUCH_KEYCHAIN: "keychain not found",
        ERR_SEC_INTERACTION_NOT_ALLOWED: "keychain locked or needs user interaction",
        ERR_SEC_AUTH_FAILED: "access to the keychain item denied",
        ERR_SEC_NOT_AVAILABLE: "keychain services not available",
    }
    message = f"Keychain {operation} failed: {reasons.get(status, 'OSStatus')} ({status})"
    if status in reasons:
        return CredentialStoreUnavailableError(message)
    return CredentialError(message)


class SecurityKeychain:
    """Keychain real vía Security.framework (ctypes). Solo se instancia en macOS.

    El secreto se pasa a la API como buffer de memoria: nunca toca una línea de comandos,
    una variable de entorno ni un fichero temporal. La interacción con el usuario se
    desactiva: un daemon no puede responder a un diálogo y debe fallar en su lugar.

    VALIDACIÓN EN macOS REAL PENDIENTE (Keychain del sistema como root, ACL del elemento
    tras actualizar Python: la ACL por defecto confía en el binario que creó el elemento).
    """

    # Bibliotecas cargadas con ctypes (sin tipos): declaradas aquí para que mypy en otras
    # plataformas, donde el cuerpo de __init__ es inalcanzable, conozca los atributos.
    _sec: Any
    _cf: Any
    _ctypes: Any
    _ref: Any

    def __init__(self, path: str | None) -> None:
        self.path = path
        if sys.platform != "darwin":
            raise CredentialStoreUnavailableError("Security.framework is only on macOS")
        import ctypes

        try:
            self._sec = ctypes.CDLL(SECURITY_FRAMEWORK)
            self._cf = ctypes.CDLL(COREFOUNDATION)
        except OSError as exc:
            raise CredentialStoreUnavailableError(f"cannot load Security.framework: {exc}") from exc
        self._ctypes = ctypes
        c_void_p, c_uint32, c_char_p = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p
        pointer = ctypes.POINTER
        sec = self._sec
        sec.SecKeychainOpen.argtypes = [c_char_p, pointer(c_void_p)]
        sec.SecKeychainOpen.restype = ctypes.c_int32
        sec.SecKeychainCopyDefault.argtypes = [pointer(c_void_p)]
        sec.SecKeychainCopyDefault.restype = ctypes.c_int32
        sec.SecKeychainGetStatus.argtypes = [c_void_p, pointer(c_uint32)]
        sec.SecKeychainGetStatus.restype = ctypes.c_int32
        sec.SecKeychainSetUserInteractionAllowed.argtypes = [ctypes.c_ubyte]
        sec.SecKeychainSetUserInteractionAllowed.restype = ctypes.c_int32
        sec.SecKeychainFindGenericPassword.argtypes = [
            c_void_p, c_uint32, c_char_p, c_uint32, c_char_p,
            pointer(c_uint32), pointer(c_void_p), pointer(c_void_p),
        ]  # fmt: skip
        sec.SecKeychainFindGenericPassword.restype = ctypes.c_int32
        sec.SecKeychainAddGenericPassword.argtypes = [
            c_void_p, c_uint32, c_char_p, c_uint32, c_char_p, c_uint32, c_void_p,
            pointer(c_void_p),
        ]  # fmt: skip
        sec.SecKeychainAddGenericPassword.restype = ctypes.c_int32
        sec.SecKeychainItemModifyAttributesAndData.argtypes = [
            c_void_p, c_void_p, c_uint32, c_void_p,
        ]  # fmt: skip
        sec.SecKeychainItemModifyAttributesAndData.restype = ctypes.c_int32
        sec.SecKeychainItemDelete.argtypes = [c_void_p]
        sec.SecKeychainItemDelete.restype = ctypes.c_int32
        sec.SecKeychainItemFreeContent.argtypes = [c_void_p, c_void_p]
        sec.SecKeychainItemFreeContent.restype = ctypes.c_int32
        self._cf.CFRelease.argtypes = [c_void_p]
        self._cf.CFRelease.restype = None
        # Sin diálogos: el daemon corre sin sesión gráfica.
        sec.SecKeychainSetUserInteractionAllowed(0)
        self._ref: Any = None

    def _keychain(self) -> Any:
        if self._ref is None:
            ref = self._ctypes.c_void_p()
            if self.path is not None:
                status = self._sec.SecKeychainOpen(self.path.encode(), self._ctypes.byref(ref))
            else:
                status = self._sec.SecKeychainCopyDefault(self._ctypes.byref(ref))
            if status != 0:
                raise keychain_error("open", status)
            self._ref = ref
        return self._ref

    def check(self) -> None:
        state = self._ctypes.c_uint32()
        status = self._sec.SecKeychainGetStatus(self._keychain(), self._ctypes.byref(state))
        if status != 0:
            raise keychain_error("status", status)
        if not state.value & _UNLOCKED or not state.value & _WRITABLE:
            raise CredentialStoreUnavailableError(
                f"Keychain {self.path or 'default'} is locked or not writable"
            )

    def _find(self, account: str, want_data: bool) -> tuple[Any, str | None]:
        ctypes = self._ctypes
        service, name = KEYCHAIN_SERVICE.encode(), account.encode()
        length = ctypes.c_uint32()
        data = ctypes.c_void_p()
        item = ctypes.c_void_p()
        status = self._sec.SecKeychainFindGenericPassword(
            self._keychain(), len(service), service, len(name), name,
            ctypes.byref(length) if want_data else None,
            ctypes.byref(data) if want_data else None,
            ctypes.byref(item),
        )  # fmt: skip
        if status == ERR_SEC_ITEM_NOT_FOUND:
            return None, None
        if status != 0:
            raise keychain_error("read", status)
        secret = None
        if want_data and data.value:
            try:
                secret = ctypes.string_at(data.value, length.value).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CredentialError("Keychain item is not text") from exc
            finally:
                self._sec.SecKeychainItemFreeContent(None, data)
        return item, secret

    def get(self, account: str) -> str | None:
        item, secret = self._find(account, want_data=True)
        if item is not None:
            self._cf.CFRelease(item)
        return secret

    def set(self, account: str, secret: str) -> None:
        ctypes = self._ctypes
        data = secret.encode("utf-8")
        buffer = ctypes.create_string_buffer(data, len(data))
        item, _ = self._find(account, want_data=False)
        if item is not None:
            try:
                status = self._sec.SecKeychainItemModifyAttributesAndData(
                    item, None, len(data), buffer
                )
            finally:
                self._cf.CFRelease(item)
        else:
            service, name = KEYCHAIN_SERVICE.encode(), account.encode()
            status = self._sec.SecKeychainAddGenericPassword(
                self._keychain(), len(service), service, len(name), name, len(data), buffer,
                None,
            )  # fmt: skip
        # Se sobrescribe la copia en memoria del buffer de ctypes tras usarla.
        ctypes.memset(buffer, 0, len(data))
        if status != 0:
            raise keychain_error("write", status)

    def delete(self, account: str) -> None:
        item, _ = self._find(account, want_data=False)
        if item is None:
            return
        try:
            status = self._sec.SecKeychainItemDelete(item)
        finally:
            self._cf.CFRelease(item)
        if status not in (0, ERR_SEC_ITEM_NOT_FOUND):
            raise keychain_error("delete", status)
