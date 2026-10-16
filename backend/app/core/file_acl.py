"""Comprobación fail-closed de la DACL de NTFS del fichero de claves SNMP (Fase 6B, fix 2).

Por qué hace falta: en Windows el modo 0600 que pide Python al crear un fichero no restringe
nada (solo decide el atributo de solo lectura). Quién puede leer un fichero lo decide su DACL,
que por defecto se hereda del directorio: `C:\\ProgramData` concede lectura a Users. Un fichero
de claves legible por cualquier usuario local entrega todas las credenciales SNMP.

Política explícita (por SID, nunca por nombres localizados):

- Confianza total: SYSTEM, Administradores, TrustedInstaller y la cuenta que ejecuta este
  proceso (la del servicio de la API, o el administrador que ejecuta la CLI).
- Solo lectura: la cuenta virtual del servicio de la API (`NT SERVICE\\SentraAPI`, SID
  calculado, ver service_sid) y los SID de SNMP_CREDENTIAL_KEY_READERS (cuenta local del
  servicio si no se usa la virtual).
- Cualquier otro principal (Everyone, Users, Authenticated Users, otros usuarios) no puede
  tener sobre el fichero ningún derecho salvo leer atributos, leer la DACL y SYNCHRONIZE.
- El propietario de fichero, directorio y antecesores debe ser de confianza total: el
  propietario puede reescribir la DACL aunque ninguna entrada se lo conceda.
- Directorio contenedor: nadie fuera de la confianza total puede crear, borrar ni renombrar
  dentro, ni cambiar su DACL o propietario. Antecesores: nadie puede borrar o renombrar el
  siguiente componente (DELETE, DELETE_CHILD) ni cambiar su DACL o propietario; si no, podría
  sustituir el directorio entero por otro con un fichero de claves suyo.
- Se evalúan entradas explícitas y heredadas por igual (la herencia de un directorio bien
  protegido es válida). Las entradas solo de herencia (INHERIT_ONLY) no se aplican al objeto.
  Una entrada DENY anterior para el mismo SID o para Everyone resta derechos; las de otros
  grupos no se acreditan (no se resuelve pertenencia a grupos): ante la duda, inseguro.
- Una DACL nula, un tipo de entrada desconocido para un principal no confiable, un punto de
  reanálisis (symlink, junction) en la ruta o cualquier error al leer la seguridad hacen que
  el fichero se rechace. Los mensajes llevan SID y máscaras, nunca contenido del fichero.

La lógica de evaluación es pura (evaluate) y se prueba en cualquier sistema; la lectura real
de la DACL usa la API de seguridad de Windows por ctypes (sin dependencias).
"""

import hashlib
import os
import re
import struct
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

# --- derechos de acceso (winnt.h) ----------------------------------------------------------
FILE_READ_DATA = 0x0001  # en directorios: listar
FILE_WRITE_DATA = 0x0002  # en directorios: crear ficheros
FILE_APPEND_DATA = 0x0004  # en directorios: crear subdirectorios
FILE_READ_EA = 0x0008
FILE_EXECUTE = 0x0020  # en directorios: atravesar
FILE_DELETE_CHILD = 0x0040
FILE_READ_ATTRIBUTES = 0x0080
DELETE = 0x0001_0000
READ_CONTROL = 0x0002_0000
WRITE_DAC = 0x0004_0000
WRITE_OWNER = 0x0008_0000
SYNCHRONIZE = 0x0010_0000
GENERIC_ALL = 0x1000_0000
GENERIC_EXECUTE = 0x2000_0000
GENERIC_WRITE = 0x4000_0000
GENERIC_READ = 0x8000_0000
ALL_RIGHTS = 0xFFFF_FFFF
FILE_GENERIC_READ = (
    READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE
)

# Lo que cualquiera puede tener sin riesgo: no da acceso al contenido ni a cambiar nada.
HARMLESS = SYNCHRONIZE | FILE_READ_ATTRIBUTES | READ_CONTROL
# Lo que un lector autorizado puede tener sobre el fichero.
READER_RIGHTS = FILE_GENERIC_READ | FILE_EXECUTE | GENERIC_READ | GENERIC_EXECUTE
# Directorio contenedor: crear, borrar o renombrar entradas, o cambiar su seguridad.
PARENT_UNSAFE = (
    FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL
)
# Antecesores: renombrar o borrar el siguiente componente, o cambiar su seguridad.
ANCESTOR_UNSAFE = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL

# --- entradas de la DACL -------------------------------------------------------------------
ACCESS_ALLOWED_ACE_TYPE = 0x0
ACCESS_DENIED_ACE_TYPE = 0x1
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x5
ACCESS_DENIED_OBJECT_ACE_TYPE = 0x6
ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x9
ACCESS_DENIED_CALLBACK_ACE_TYPE = 0xA
ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xB
ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0xC
DENY_ACE_TYPES = frozenset(
    {
        ACCESS_DENIED_ACE_TYPE,
        ACCESS_DENIED_OBJECT_ACE_TYPE,
        ACCESS_DENIED_CALLBACK_ACE_TYPE,
        ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
    }
)
INHERITED_ACE = 0x10
INHERIT_ONLY_ACE = 0x08

# --- SID conocidos ---------------------------------------------------------------------------
SID_EVERYONE = "S-1-1-0"
SID_OWNER_RIGHTS = "S-1-3-4"
SID_SYSTEM = "S-1-5-18"
SID_ADMINISTRATORS = "S-1-5-32-544"
SID_USERS = "S-1-5-32-545"
SID_AUTHENTICATED_USERS = "S-1-5-11"
SID_TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
API_SERVICE_NAME = "SentraAPI"
_SID_RE = re.compile(r"^S-1-\d+(-\d+){1,14}$")

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class AclError(Exception):
    """La seguridad del fichero o de su ruta no permite usarlo (o no se pudo comprobar)."""


@dataclass(frozen=True)
class Ace:
    ace_type: int
    flags: int
    mask: int
    sid: str | None


@dataclass(frozen=True)
class SecuritySnapshot:
    owner: str | None
    # False = DACL nula: todo el mundo tiene control total.
    dacl_present: bool
    aces: tuple[Ace, ...]


@dataclass(frozen=True)
class AclPolicy:
    """SID con confianza total y SID lectores (solo lectura sobre el fichero)."""

    trusted: frozenset[str]
    readers: frozenset[str]

    def allowed(self, sid: str, kind: str) -> int:
        if sid in self.trusted:
            return ALL_RIGHTS
        if kind == "file":
            return HARMLESS | (READER_RIGHTS if sid in self.readers else 0)
        unsafe = PARENT_UNSAFE if kind == "parent" else ANCESTOR_UNSAFE
        return ALL_RIGHTS & ~unsafe


def is_valid_sid(value: str) -> bool:
    return bool(_SID_RE.fullmatch(value))


def service_sid(service_name: str) -> str:
    """SID de la cuenta virtual `NT SERVICE\\<nombre>` (S-1-5-80-...), sin consultar al sistema.

    Windows lo deriva del SHA-1 del nombre del servicio en mayúsculas (UTF-16LE): cinco
    enteros de 32 bits little-endian. Así se reconoce la cuenta del servicio de la API
    aunque el servicio aún no esté instalado.
    """
    digest = hashlib.sha1(service_name.upper().encode("utf-16-le")).digest()  # noqa: S324
    parts = struct.unpack("<5I", digest)
    return "S-1-5-80-" + "-".join(str(part) for part in parts)


def evaluate(snapshot: SecuritySnapshot, policy: AclPolicy, kind: str, label: str) -> list[str]:
    """Infracciones de la política en un objeto (fichero, directorio o antecesor)."""
    problems: list[str] = []
    owner = snapshot.owner
    if owner is None or owner not in policy.trusted:
        # El propietario puede reescribir la DACL aunque ninguna entrada se lo conceda.
        problems.append(f"{label}: owner {owner or 'unknown'} is not trusted")
    if not snapshot.dacl_present:
        problems.append(f"{label}: has no DACL (full access for everyone)")
        return problems
    denied: dict[str, int] = {}
    for ace in snapshot.aces:
        if ace.flags & INHERIT_ONLY_ACE:
            continue  # solo se hereda hacia hijos nuevos; no se aplica a este objeto
        sid = ace.sid
        if sid == SID_OWNER_RIGHTS and owner is not None:
            sid = owner  # OWNER RIGHTS describe los derechos del propietario
        if ace.ace_type in DENY_ACE_TYPES:
            if sid is not None:
                denied[sid] = denied.get(sid, 0) | ace.mask
            continue
        if sid is None:
            problems.append(f"{label}: entry without a readable SID")
            continue
        allowed = policy.allowed(sid, kind)
        if allowed == ALL_RIGHTS:
            continue
        if ace.ace_type != ACCESS_ALLOWED_ACE_TYPE:
            # Entradas condicionales o de objeto: su efecto no se puede acotar aquí.
            problems.append(f"{label}: unsupported entry type 0x{ace.ace_type:x} for {sid}")
            continue
        effective = ace.mask & ~(denied.get(sid, 0) | denied.get(SID_EVERYONE, 0))
        excess = effective & ~allowed
        if excess:
            origin = "inherited" if ace.flags & INHERITED_ACE else "explicit"
            problems.append(f"{label}: {sid} has {origin} access 0x{excess:08x}")
    return problems


class SecurityReader(Protocol):
    def file_security(self, fd: int) -> SecuritySnapshot: ...

    def path_security(self, path: Path) -> SecuritySnapshot: ...

    def is_reparse_point(self, path: Path) -> bool: ...

    def process_sid(self) -> str: ...


def build_policy(reader: SecurityReader, extra_readers: Iterable[str] = ()) -> AclPolicy:
    readers = {service_sid(API_SERVICE_NAME), *extra_readers}
    trusted = {SID_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER, reader.process_sid()}
    return AclPolicy(frozenset(trusted), frozenset(readers - trusted))


def check_location(path: Path, policy: AclPolicy, reader: SecurityReader) -> None:
    """Directorio contenedor y antecesores seguros, sin puntos de reanálisis. Lanza AclError."""
    absolute = Path(os.path.abspath(path))
    problems: list[str] = []
    chain = [absolute, *absolute.parents]
    try:
        for component in chain:
            if component == absolute and not os.path.lexists(component):
                continue  # el fichero aún no existe (creación): solo cuenta su ruta
            if reader.is_reparse_point(component):
                problems.append(f"{component}: is a symbolic link, junction or mount point")
        parent = absolute.parent
        problems += evaluate(reader.path_security(parent), policy, "parent", f"directory {parent}")
        for ancestor in parent.parents:
            snapshot = reader.path_security(ancestor)
            problems += evaluate(snapshot, policy, "ancestor", f"directory {ancestor}")
    except OSError as exc:
        raise AclError(f"cannot verify the security of {absolute}: {exc}") from exc
    if problems:
        raise AclError("; ".join(problems))


def check_open_file(fd: int, path: Path, policy: AclPolicy, reader: SecurityReader) -> None:
    """DACL del fichero ya abierto (la misma que se va a leer, sin carrera). Lanza AclError."""
    try:
        snapshot = reader.file_security(fd)
    except OSError as exc:
        raise AclError(f"cannot read the DACL of {path}: {exc}") from exc
    problems = evaluate(snapshot, policy, "file", f"key file {path}")
    if problems:
        raise AclError("; ".join(problems))


def same_file(fd: int, path: Path) -> bool:
    """¿El descriptor abierto es el mismo fichero que la ruta (sin sustitución intermedia)?"""
    opened = os.fstat(fd)
    current = os.lstat(path)
    return (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino)


def creation_sddl(
    policy: AclPolicy, process_sid: str, process_is_admin: bool, readers: Mapping[str, int]
) -> str:
    """Descriptor de seguridad para un fichero de claves nuevo (protegido, sin herencia).

    Un administrador elevado crea el fichero con propietario Administradores y sin entrada
    propia: así la API (otra cuenta) acepta luego al propietario y a todas las entradas.
    """
    entries = [f"(A;;FA;;;{SID_SYSTEM})", f"(A;;FA;;;{SID_ADMINISTRATORS})"]
    owner = ""
    if process_is_admin:
        owner = f"O:{SID_ADMINISTRATORS}"
    elif process_sid not in (SID_SYSTEM, SID_ADMINISTRATORS):
        entries.append(f"(A;;FA;;;{process_sid})")
    for sid, mask in readers.items():
        if sid not in policy.trusted:
            entries.append(f"(A;;0x{mask:x};;;{sid})")
    return f"{owner}D:P{''.join(entries)}"


if sys.platform == "win32":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)

    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x1
    _DACL_SECURITY_INFORMATION = 0x4
    _ACL_SIZE_INFORMATION = 2
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _SDDL_REVISION_1 = 1
    _GENERIC_READ_WRITE = GENERIC_READ | GENERIC_WRITE
    _CREATE_NEW = 1
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _ERROR_FILE_EXISTS = 80
    _INVALID_HANDLE = wintypes.HANDLE(-1).value

    class _AclSizeInformation(ctypes.Structure):
        _fields_ = (
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        )

    class _AceHeader(ctypes.Structure):
        _fields_ = (
            ("AceType", wintypes.BYTE),
            ("AceFlags", wintypes.BYTE),
            ("AceSize", wintypes.WORD),
        )

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = (
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        )

    _advapi32.GetSecurityInfo.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    )
    _advapi32.GetSecurityInfo.restype = wintypes.DWORD
    _advapi32.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    )
    _advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    _advapi32.GetAclInformation.argtypes = (
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_int,
    )
    _advapi32.GetAclInformation.restype = wintypes.BOOL
    _advapi32.GetAce.argtypes = (wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID))
    _advapi32.GetAce.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = (
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    )
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    )
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
    _kernel32.LocalFree.restype = wintypes.HLOCAL
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _shell32.IsUserAnAdmin.restype = wintypes.BOOL

    def _winerror(code: int, what: str) -> OSError:
        return ctypes.WinError(code, what)

    def _sid_string(psid: int | None) -> str | None:
        if not psid:
            return None
        text = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(psid, ctypes.byref(text)):
            return None
        try:
            return text.value
        finally:
            _kernel32.LocalFree(ctypes.cast(text, wintypes.HLOCAL))

    def _ace_sid_offset(ace_type: int, address: int) -> int:
        # ACE básico y de callback: cabecera (4) + máscara (4) + SID. ACE de objeto: además
        # flags (4) y hasta dos GUID (16 cada uno) según esos flags.
        if ace_type in (
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
            ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
        ):
            object_flags = ctypes.c_uint32.from_address(address + 8).value
            return 12 + 16 * bool(object_flags & 1) + 16 * bool(object_flags & 2)
        return 8

    def _snapshot(owner: wintypes.LPVOID, dacl: wintypes.LPVOID) -> SecuritySnapshot:
        if not dacl.value:
            return SecuritySnapshot(_sid_string(owner.value), False, ())
        info = _AclSizeInformation()
        if not _advapi32.GetAclInformation(
            dacl, ctypes.byref(info), ctypes.sizeof(info), _ACL_SIZE_INFORMATION
        ):
            raise _winerror(ctypes.get_last_error(), "GetAclInformation")
        aces: list[Ace] = []
        for index in range(info.AceCount):
            pace = wintypes.LPVOID()
            if not _advapi32.GetAce(dacl, index, ctypes.byref(pace)):
                raise _winerror(ctypes.get_last_error(), "GetAce")
            address = int(pace.value or 0)
            header = _AceHeader.from_address(address)
            mask = ctypes.c_uint32.from_address(address + 4).value
            sid = _sid_string(address + _ace_sid_offset(header.AceType, address))
            aces.append(Ace(header.AceType, header.AceFlags, mask, sid))
        return SecuritySnapshot(_sid_string(owner.value), True, tuple(aces))

    class WindowsSecurityReader:
        """Lectura real de propietario y DACL con la API de seguridad de Windows."""

        def file_security(self, fd: int) -> SecuritySnapshot:
            handle = msvcrt.get_osfhandle(fd)
            owner, dacl, descriptor = wintypes.LPVOID(), wintypes.LPVOID(), wintypes.LPVOID()
            code = _advapi32.GetSecurityInfo(
                handle,
                _SE_FILE_OBJECT,
                _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                ctypes.byref(owner),
                None,
                ctypes.byref(dacl),
                None,
                ctypes.byref(descriptor),
            )
            if code != 0:
                raise _winerror(code, "GetSecurityInfo")
            try:
                return _snapshot(owner, dacl)
            finally:
                _kernel32.LocalFree(descriptor.value)

        def path_security(self, path: Path) -> SecuritySnapshot:
            owner, dacl, descriptor = wintypes.LPVOID(), wintypes.LPVOID(), wintypes.LPVOID()
            code = _advapi32.GetNamedSecurityInfoW(
                str(path),
                _SE_FILE_OBJECT,
                _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                ctypes.byref(owner),
                None,
                ctypes.byref(dacl),
                None,
                ctypes.byref(descriptor),
            )
            if code != 0:
                raise _winerror(code, f"GetNamedSecurityInfoW({path})")
            try:
                return _snapshot(owner, dacl)
            finally:
                _kernel32.LocalFree(descriptor.value)

        def is_reparse_point(self, path: Path) -> bool:
            attributes = getattr(os.lstat(path), "st_file_attributes", 0)
            return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)

        def process_sid(self) -> str:
            token = wintypes.HANDLE()
            if not _advapi32.OpenProcessToken(
                _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
            ):
                raise _winerror(ctypes.get_last_error(), "OpenProcessToken")
            try:
                size = wintypes.DWORD()
                _advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
                buffer = ctypes.create_string_buffer(size.value)
                if not _advapi32.GetTokenInformation(
                    token, _TOKEN_USER, buffer, size, ctypes.byref(size)
                ):
                    raise _winerror(ctypes.get_last_error(), "GetTokenInformation")
                # TOKEN_USER empieza por SID_AND_ATTRIBUTES, cuyo primer campo es el PSID.
                psid = ctypes.c_void_p.from_buffer(buffer).value
                sid = _sid_string(psid)
                if sid is None:
                    raise OSError("cannot read the SID of the current process")
                return sid
            finally:
                _kernel32.CloseHandle(token)

    def process_is_admin() -> bool:
        return bool(_shell32.IsUserAnAdmin())

    def create_private_file(path: Path, sddl: str) -> int:
        """Crea `path` (nunca existente) con ese descriptor de seguridad desde el primer byte.

        La DACL se fija en la propia creación (CreateFileW con SECURITY_ATTRIBUTES): no hay
        ningún instante con la DACL heredada del directorio. Devuelve un descriptor de
        escritura; lanza FileExistsError si ya existe.
        """
        descriptor = wintypes.LPVOID()
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), None
        ):
            raise _winerror(ctypes.get_last_error(), "ConvertStringSecurityDescriptor")
        try:
            attributes = _SecurityAttributes(
                ctypes.sizeof(_SecurityAttributes), descriptor.value, False
            )
            handle = _kernel32.CreateFileW(
                str(path),
                _GENERIC_READ_WRITE,
                0,
                ctypes.byref(attributes),
                _CREATE_NEW,
                _FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if handle == _INVALID_HANDLE or handle is None:
                code = ctypes.get_last_error()
                if code == _ERROR_FILE_EXISTS:
                    raise FileExistsError(str(path))
                raise _winerror(code, f"CreateFileW({path})")
        finally:
            _kernel32.LocalFree(descriptor.value)
        try:
            return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
        except OSError:
            _kernel32.CloseHandle(handle)
            raise

    def default_reader() -> SecurityReader:
        return WindowsSecurityReader()

else:

    def process_is_admin() -> bool:
        return False

    def create_private_file(path: Path, sddl: str) -> int:
        raise OSError("NTFS security descriptors only exist on Windows")

    def default_reader() -> SecurityReader:
        raise AclError("NTFS DACL checks only run on Windows")
