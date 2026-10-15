"""Ficheros y directorios privados del sensor, en POSIX y en Windows.

El directorio de datos guarda la credencial, el spool (observaciones de la red interna del
site) y el estado. Nadie salvo la cuenta que ejecuta el sensor y la administración del host
debe poder leerlos.

* POSIX: modo 0700 en directorios y 0600 en ficheros (bits de `st_mode`).
* Windows: los bits de `st_mode` NO describen quién puede leer un fichero en NTFS (Python
  devuelve 0666/0444 según el atributo de solo lectura). Lo que cuenta es la DACL. Se lee la
  DACL real (GetNamedSecurityInfoW) y se considera privada solo si todas sus entradas de
  permiso son de principales de confianza:
    - SYSTEM (S-1-5-18) y Administradores (S-1-5-32-544): pueden tomar posesión de
      cualquier fichero, así que excluirlos no protege nada y rompería copias y soporte;
    - la cuenta que ejecuta el proceso (la cuenta virtual NT SERVICE\\SentraSensor en el
      servicio, el usuario en pruebas manuales);
    - la cuenta virtual del servicio, si existe (un administrador que ejecuta `status` no
      debe dejar al servicio sin acceso al endurecer la DACL);
    - el propietario del objeto (y CREATOR OWNER / OWNER RIGHTS), salvo que sea un grupo amplio.
  Cualquier entrada de Everyone, Users, Authenticated Users u otro principal hace que el
  objeto NO sea privado; una DACL nula (sin DACL) tampoco lo es. Las entradas de denegación
  solo restringen y se ignoran; un tipo de entrada que no se sabe leer cuenta como no privado.

Si el objeto no es privado se escribe una DACL protegida (sin herencia del padre) con esos
principales y control total. Si no se puede (sistema de ficheros sin ACL, sin permiso
WRITE_DAC...), se lanza PrivacyError: el sensor no escribe secretos ni observaciones en un
sitio que no puede proteger (fail-closed).

Sin dependencias (ctypes) y sin cifrado propio: la credencial sigue además cifrada con DPAPI.
"""

import errno
import functools
import os
import stat
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600

SID_SYSTEM = "S-1-5-18"
SID_ADMINISTRATORS = "S-1-5-32-544"
SID_CREATOR_OWNER = "S-1-3-0"
SID_OWNER_RIGHTS = "S-1-3-4"
SERVICE_ACCOUNT = "NT SERVICE\\SentraSensor"
# Grupos amplios: nunca son de confianza, ni siquiera como propietario del objeto.
BROAD_SIDS = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-2-0",  # LOCAL
        "S-1-2-1",  # CONSOLE LOGON
        "S-1-5-2",  # NETWORK
        "S-1-5-4",  # INTERACTIVE
        "S-1-5-6",  # SERVICE
        "S-1-5-7",  # ANONYMOUS LOGON
        "S-1-5-11",  # Authenticated Users
        "S-1-5-32-545",  # Users
        "S-1-5-32-546",  # Guests
        "S-1-5-32-547",  # Power Users
        "S-1-15-2-1",  # ALL APPLICATION PACKAGES
    }
)

ACCESS_ALLOWED_ACE_TYPE = 0
# Denegaciones (normal, de objeto y callback): solo quitan permisos.
DENY_ACE_TYPES = frozenset({1, 6, 10, 12})


class PrivacyError(OSError):
    """No se puede garantizar que un fichero o directorio sea privado."""

    def __init__(self, message: str) -> None:
        super().__init__(errno.EACCES, message)


@dataclass(frozen=True)
class Ace:
    ace_type: int
    flags: int
    mask: int
    # None si el tipo de entrada no es uno de los que se saben leer.
    sid: str | None


@dataclass(frozen=True)
class AclSnapshot:
    owner: str | None
    # False = DACL nula: Windows concede acceso total a todo el mundo.
    present: bool
    aces: tuple[Ace, ...]


def acl_is_private(snapshot: AclSnapshot, trusted: Iterable[str]) -> bool:
    """¿Solo principales de confianza tienen algún permiso? (función pura, probada en Linux)."""
    if not snapshot.present:
        return False
    allowed = set(trusted)
    owner = snapshot.owner
    if owner and owner not in BROAD_SIDS:
        allowed |= {owner, SID_CREATOR_OWNER, SID_OWNER_RIGHTS}
    for ace in snapshot.aces:
        if ace.ace_type in DENY_ACE_TYPES:
            continue
        if ace.ace_type != ACCESS_ALLOWED_ACE_TYPE or ace.sid is None:
            return False
        if ace.mask and ace.sid not in allowed:
            return False
    return True


def dacl_sddl(principals: Sequence[str], directory: bool) -> str:
    """DACL protegida (P: sin herencia del padre) con control total para cada principal.

    En directorios, OICI hace que ficheros y subdirectorios nuevos hereden esas mismas
    entradas: lo que el sensor (o SQLite, con sus -wal/-shm) cree dentro nace privado.
    """
    inherit = "OICI" if directory else ""
    seen: list[str] = []
    for sid in principals:
        if sid not in seen:
            seen.append(sid)
    return "D:P" + "".join(f"(A;{inherit};FA;;;{sid})" for sid in seen)


def is_private(path: Path) -> bool:
    """¿El fichero o directorio solo es accesible para el sensor y la administración?"""
    if sys.platform == "win32":
        try:
            snapshot = _read_acl(path)
        except OSError:
            return False
        return acl_is_private(snapshot, _principals())
    # Se siguen los enlaces: las rutas ya se resolvieron dentro de data_dir (resolve_inside)
    # y data_dir puede ser legítimamente un enlace a otro disco.
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return (stat.S_IMODE(mode) & 0o077) == 0


def make_private_dir(path: Path) -> None:
    """Crea `path` si hace falta y garantiza que es privado (o lanza PrivacyError)."""
    path.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    _make_private(path, directory=True)


def make_private_file(path: Path) -> None:
    """Garantiza que un fichero existente es privado (o lanza PrivacyError)."""
    _make_private(path, directory=False)


def _make_private(path: Path, directory: bool) -> None:
    if sys.platform == "win32":
        # Solo se reescribe la DACL si no es privada: la que pone el instalador (con la
        # cuenta virtual del servicio) se respeta tal cual.
        if is_private(path):
            return
        try:
            _write_dacl(path, dacl_sddl(_principals(), directory))
        except OSError as exc:
            raise PrivacyError(f"cannot restrict the ACL of {path}: {exc}") from exc
        if not is_private(path):
            raise PrivacyError(f"the ACL of {path} is still not private")
        return
    try:
        os.chmod(path, DIR_MODE if directory else FILE_MODE)
    except OSError as exc:
        raise PrivacyError(f"cannot restrict the permissions of {path}: {exc}") from exc
    if not is_private(path):
        raise PrivacyError(f"the permissions of {path} are still not private")


@functools.cache
def _principals() -> tuple[str, ...]:
    """SYSTEM, Administradores, la cuenta actual y la del servicio (si está instalado)."""
    principals = [SID_SYSTEM, SID_ADMINISTRATORS, current_user_sid()]
    service = lookup_account_sid(SERVICE_ACCOUNT)
    if service:
        principals.append(service)
    return tuple(dict.fromkeys(principals))


def read_acl(path: Path) -> AclSnapshot:
    """Propietario y DACL reales de `path` (solo Windows)."""
    return _read_acl(path)


def write_dacl(path: Path, sddl: str) -> None:
    """Sustituye la DACL de `path` por la descrita en SDDL (solo Windows)."""
    _write_dacl(path, sddl)


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    _SE_FILE_OBJECT = 1
    _SDDL_REVISION_1 = 1
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _ACL_SIZE_INFORMATION = 2
    _PVOID = ctypes.POINTER(ctypes.c_void_p)
    _PDWORD = ctypes.POINTER(wintypes.DWORD)

    class _AceHeader(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
        ]

    class _AclSizeInformation(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    # Firmas explícitas: la conversión por defecto de ctypes truncaría punteros de 64 bits.
    _advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        _PVOID,
        _PVOID,
        _PVOID,
        _PVOID,
        _PVOID,
    ]
    _advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    _advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    _advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    _advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    _advapi32.GetAclInformation.restype = wintypes.BOOL
    _advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, _PVOID]
    _advapi32.GetAce.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        _PVOID,
        _PDWORD,
    ]
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        _PVOID,
        ctypes.POINTER(wintypes.BOOL),
    ]
    _advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        _PDWORD,
    ]
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.LookupAccountNameW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        _PDWORD,
        ctypes.c_void_p,
        _PDWORD,
        _PDWORD,
    ]
    _advapi32.LookupAccountNameW.restype = wintypes.BOOL
    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    def _last_error() -> OSError:
        return ctypes.WinError(ctypes.get_last_error())

    def _sid_to_str(psid: int) -> str:
        text = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(psid, ctypes.byref(text)):
            raise _last_error()
        try:
            return str(text.value)
        finally:
            _kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))

    def _read_acl(path: Path) -> AclSnapshot:
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        error = _advapi32.GetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if error:
            raise ctypes.WinError(error)
        try:
            owner_sid = _sid_to_str(owner.value) if owner.value else None
            if not dacl.value:
                return AclSnapshot(owner_sid, False, ())
            info = _AclSizeInformation()
            if not _advapi32.GetAclInformation(
                dacl.value, ctypes.byref(info), ctypes.sizeof(info), _ACL_SIZE_INFORMATION
            ):
                raise _last_error()
            aces: list[Ace] = []
            for index in range(info.AceCount):
                entry = ctypes.c_void_p()
                if not _advapi32.GetAce(dacl.value, index, ctypes.byref(entry)):
                    raise _last_error()
                address = entry.value or 0
                header = _AceHeader.from_address(address)
                if header.AceType in (ACCESS_ALLOWED_ACE_TYPE, 1):
                    # ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE: cabecera (4), máscara (4), SID.
                    mask = int(wintypes.DWORD.from_address(address + 4).value)
                    aces.append(
                        Ace(header.AceType, header.AceFlags, mask, _sid_to_str(address + 8))
                    )
                else:
                    aces.append(Ace(header.AceType, header.AceFlags, 0, None))
            return AclSnapshot(owner_sid, True, tuple(aces))
        finally:
            _kernel32.LocalFree(descriptor.value)

    def _write_dacl(path: Path, sddl: str) -> None:
        descriptor = ctypes.c_void_p()
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), None
        ):
            raise _last_error()
        try:
            present = wintypes.BOOL()
            defaulted = wintypes.BOOL()
            dacl = ctypes.c_void_p()
            if not _advapi32.GetSecurityDescriptorDacl(
                descriptor.value, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
            ):
                raise _last_error()
            if not present.value or not dacl.value:
                raise PrivacyError("refusing to write a NULL DACL")
            # PROTECTED: corta la herencia del padre (p. ej. Users:Read de ProgramData).
            error = _advapi32.SetNamedSecurityInfoW(
                str(path),
                _SE_FILE_OBJECT,
                _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                dacl.value,
                None,
            )
            if error:
                raise ctypes.WinError(error)
        finally:
            _kernel32.LocalFree(descriptor.value)

    @functools.cache
    def current_user_sid() -> str:
        """SID de la cuenta del proceso (la cuenta virtual del servicio, o el usuario)."""
        token = wintypes.HANDLE()
        if not _advapi32.OpenProcessToken(
            _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
        ):
            raise _last_error()
        try:
            size = wintypes.DWORD(0)
            _advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            if not _advapi32.GetTokenInformation(
                token, _TOKEN_USER, buffer, size, ctypes.byref(size)
            ):
                raise _last_error()
            # TOKEN_USER empieza por SID_AND_ATTRIBUTES, cuyo primer campo es el puntero al SID.
            psid = ctypes.c_void_p.from_buffer(buffer).value
            if not psid:
                raise PrivacyError("the process token has no user SID")
            return _sid_to_str(psid)
        finally:
            _kernel32.CloseHandle(token)

    @functools.cache
    def lookup_account_sid(name: str) -> str | None:
        """SID de una cuenta por nombre, o None si no existe (servicio no instalado)."""
        sid_size = wintypes.DWORD(0)
        domain_size = wintypes.DWORD(0)
        use = wintypes.DWORD(0)
        _advapi32.LookupAccountNameW(
            None,
            name,
            None,
            ctypes.byref(sid_size),
            None,
            ctypes.byref(domain_size),
            ctypes.byref(use),
        )
        if not sid_size.value:
            return None
        sid = ctypes.create_string_buffer(sid_size.value)
        domain = ctypes.create_unicode_buffer(max(domain_size.value, 1))
        if not _advapi32.LookupAccountNameW(
            None,
            name,
            ctypes.addressof(sid),
            ctypes.byref(sid_size),
            ctypes.addressof(domain),
            ctypes.byref(domain_size),
            ctypes.byref(use),
        ):
            return None
        return _sid_to_str(ctypes.addressof(sid))

else:

    def _read_acl(path: Path) -> AclSnapshot:
        raise PrivacyError("NTFS ACLs only exist on Windows")

    def _write_dacl(path: Path, sddl: str) -> None:
        raise PrivacyError("NTFS ACLs only exist on Windows")

    def current_user_sid() -> str:
        raise PrivacyError("Windows SIDs only exist on Windows")

    def lookup_account_sid(name: str) -> str | None:
        return None
