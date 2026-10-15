"""Almacenamiento de la credencial del sensor.

La credencial es un bearer token: quien la tenga puede hacerse pasar por el sensor y subir
observaciones al site. Por eso:

* Linux: fichero creado con os.open(..., 0o600) desde el primer byte (no chmod a posteriori,
  que deja una ventana en la que otro usuario podría leerlo) y escritura atómica
  (tmp + fsync + os.replace) para que un corte de luz nunca deje media credencial.
* Windows: además se cifra con DPAPI (ámbito del usuario que ejecuta el sensor) vía ctypes,
  sin depender de pywin32. Copiar el fichero a otra máquina u otra cuenta no sirve de nada.
  El fichero temporal recibe una DACL privada (fsperm) ANTES de escribir el secreto, y el
  rename la conserva; si no se puede proteger, no se escribe (fail-closed).

Nunca se imprime ni se loggea: el dataclass oculta el valor en repr y se registra en el
redactor de logs al cargarlo.
"""

import base64
import contextlib
import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentra_sensor.fsperm import (
    FILE_MODE,
    is_private,
    make_private_dir,
    make_private_file,
)
from sentra_sensor.logs import register_secret

SCHEME_DPAPI = "dpapi-user"
SCHEME_PLAIN = "plain"
# Entropía adicional para DPAPI: no es una contraseña (vive en el código); solo acota el blob a
# Sentra para que otro programa del mismo usuario no lo descifre con una llamada genérica.
_ENTROPY = b"sentra-sensor/credential/v1"


class CredentialError(Exception):
    """La credencial no existe, está corrupta o no se puede descifrar."""


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _CRYPTPROTECT_UI_FORBIDDEN = 0x1  # nunca mostrar diálogos: el sensor es desatendido

    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Firmas explícitas: la conversión por defecto de ctypes truncaría punteros de 64 bits.
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
        buffer = ctypes.create_string_buffer(data, len(data))
        return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer

    def _dpapi(data: bytes, protect: bool) -> bytes:
        source, _source_buffer = _blob(data)
        entropy, _entropy_buffer = _blob(_ENTROPY)
        result = _DataBlob()
        call = _crypt32.CryptProtectData if protect else _crypt32.CryptUnprotectData
        description = "Sentra sensor credential" if protect else None
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
            _kernel32.LocalFree(ctypes.cast(result.pbData, ctypes.c_void_p))


def protect_secret(secret: str) -> dict[str, str]:
    """Forma serializable del secreto en reposo (DPAPI en Windows, texto + 0600 en Linux)."""
    if sys.platform == "win32":
        blob = _dpapi(secret.encode(), protect=True)
        return {"scheme": SCHEME_DPAPI, "value": base64.b64encode(blob).decode()}
    return {"scheme": SCHEME_PLAIN, "value": secret}


def unprotect_secret(stored: object) -> str:
    if not isinstance(stored, dict) or not isinstance(stored.get("value"), str):
        raise CredentialError("malformed stored credential")
    scheme, value = stored.get("scheme"), str(stored["value"])
    if scheme == SCHEME_PLAIN:
        return value
    if scheme == SCHEME_DPAPI:
        if sys.platform == "win32":
            try:
                blob = base64.b64decode(value, validate=True)
                return _dpapi(blob, protect=False).decode()
            except (ValueError, UnicodeDecodeError) as exc:
                raise CredentialError("corrupted DPAPI credential") from exc
        raise CredentialError("DPAPI-protected credential can only be read on Windows")
    raise CredentialError("unknown credential scheme")


def atomic_write_bytes(path: Path, data: bytes, mode: int = FILE_MODE) -> None:
    """Escritura atómica con permisos restrictivos desde la creación del fichero."""
    make_private_dir(path.parent)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)  # no seguir un symlink plantado en su lugar
    fd = os.open(tmp, flags, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            # Antes del primer byte: POSIX fija el modo aunque la umask fuera más
            # permisiva; Windows fija una DACL privada (los bits de modo no la describen).
            make_private_file(tmp)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    if sys.platform != "win32":
        # fsync del directorio: sin él, el rename podría perderse tras un corte de luz.
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_bytes(path, json.dumps(payload, indent=2, sort_keys=True).encode())


@dataclass(frozen=True)
class SensorIdentity:
    sensor_id: str
    site_id: str
    site_name: str
    server_url: str
    credential_issued_at: str | None
    enrolled_at: str
    # repr=False: un print() o un log accidental del objeto no revela el secreto.
    credential: str = field(repr=False)


class CredentialStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def exists(self) -> bool:
        return self.path.is_file()

    def save(self, identity: SensorIdentity) -> None:
        register_secret(identity.credential)
        payload = {
            "format": 1,
            "sensor_id": identity.sensor_id,
            "site_id": identity.site_id,
            "site_name": identity.site_name,
            "server_url": identity.server_url,
            "credential_issued_at": identity.credential_issued_at,
            "enrolled_at": identity.enrolled_at,
            "credential": protect_secret(identity.credential),
        }
        atomic_write_json(self.path, payload)

    def load(self) -> SensorIdentity:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise CredentialError("sensor is not enrolled (no credential file)") from exc
        except (OSError, ValueError) as exc:
            raise CredentialError("credential file is unreadable or corrupted") from exc
        if not isinstance(data, dict):
            raise CredentialError("credential file is corrupted")
        try:
            identity = SensorIdentity(
                sensor_id=str(uuid.UUID(str(data["sensor_id"]))),
                site_id=str(uuid.UUID(str(data["site_id"]))),
                site_name=str(data.get("site_name") or ""),
                server_url=str(data["server_url"]),
                credential_issued_at=data.get("credential_issued_at"),
                enrolled_at=str(data.get("enrolled_at") or ""),
                credential=unprotect_secret(data.get("credential")),
            )
        except (KeyError, ValueError) as exc:
            raise CredentialError("credential file is missing fields") from exc
        if not identity.credential:
            raise CredentialError("credential is empty")
        register_secret(identity.credential)
        return identity

    def permissions_ok(self) -> bool:
        """Solo el sensor y la administración pueden leerlo (0600 en POSIX, DACL en Windows)."""
        return is_private(self.path)

    def mtime(self) -> float | None:
        try:
            return self.path.stat().st_mtime
        except OSError:
            return None
