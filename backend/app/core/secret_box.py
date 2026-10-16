"""Almacén cifrado de secretos recuperables (Fase 6B: credenciales SNMP).

Por qué no un hash: las credenciales de agentes y sensores se guardan como SHA-256 porque el
servidor solo tiene que COMPROBARLAS. Una passphrase SNMPv3 o una comunidad v2c hay que
ENVIARLA al sensor para que consulte el equipo, así que debe poder recuperarse. Se guarda
cifrada y autenticada con AES-256-GCM (biblioteca `cryptography`, sin criptografía propia).

Diseño (on-prem, sin KMS externo):
- La clave maestra vive en un fichero fuera del repositorio y de la base de datos
  (SNMP_CREDENTIAL_KEY_FILE). Un volcado de PostgreSQL o un backup de la base sin ese fichero
  no revela ningún secreto. El fichero se respalda aparte (docs, sección Respaldo).
- Formato del fichero: una clave por línea, `<kid>:<base64 de 32 bytes>`. La PRIMERA línea es
  la clave activa (cifra lo nuevo); las demás solo descifran. Rotar la clave maestra = añadir
  una línea nueva al principio y ejecutar `python -m app.cli snmp-rekey`, que vuelve a cifrar
  todos los perfiles con la activa; después la antigua puede retirarse.
- Cada valor cifrado lleva el kid y un nonce aleatorio de 96 bits, y su AAD (datos asociados)
  lo liga al registro concreto: copiar el blob de un perfil a otro (o a otro site) hace que el
  descifrado falle en lugar de entregar el secreto equivocado.
- En POSIX se rechaza un fichero de claves legible por grupo u otros (como ssh con sus
  claves). En Windows los bits de modo no describen la ACL: desde el fix 2 de 6B se comprueba
  la DACL real del fichero (ya abierto, sin carrera), de su directorio y de sus antecesores
  antes de leer nada (app/core/file_acl.py) y se crea con una DACL protegida desde el primer
  byte; si no es segura o no se puede comprobar, no se usa (fail-closed).

Nada de este módulo registra en logs ni devuelve en errores el contenido de una clave o de un
secreto.
"""

import base64
import binascii
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core import file_acl

FORMAT_VERSION = "v1"
_KID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_NONCE_BYTES = 12
# Tope defensivo del fichero de claves: uno real ocupa unos cientos de bytes.
_MAX_KEYRING_BYTES = 64 * 1024


class SecretStoreError(Exception):
    """El almacén no está configurado o no puede usarse (fichero ausente, permisos, formato).

    El mensaje describe el problema de configuración, nunca el contenido de una clave.
    """


class SecretDecryptError(Exception):
    """Un valor no se pudo descifrar: clave retirada, blob manipulado o AAD distinto."""


@dataclass(frozen=True)
class Keyring:
    active_kid: str
    keys: dict[str, bytes]


# Puntos de extensión para los tests (en Linux se simula la seguridad de Windows); en
# producción son la lectura real de la DACL y CreateFileW con descriptor de seguridad.
ACL_READER_FACTORY: Callable[[], file_acl.SecurityReader] = file_acl.default_reader
CREATE_PRIVATE_FILE: Callable[[Path, str], int] = file_acl.create_private_file
# Lo que reciben los lectores (cuenta del servicio de la API) en un fichero nuevo.
_READER_MASK = file_acl.FILE_GENERIC_READ


def _is_windows() -> bool:
    # Función propia para que los tests simulen Windows solo en este módulo.
    return sys.platform == "win32"


def _check_permissions(path: Path) -> None:
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SecretStoreError(f"{path} is accessible by group or others; run: chmod 600 {path}")


def _windows_policy(readers: Iterable[str]) -> tuple[file_acl.SecurityReader, file_acl.AclPolicy]:
    reader = ACL_READER_FACTORY()
    return reader, file_acl.build_policy(reader, readers)


def _read_windows(path: Path, readers: Iterable[str]) -> bytes:
    """Lee el fichero solo si su DACL, su directorio y sus antecesores son seguros."""
    reader, policy = _windows_policy(readers)
    file_acl.check_location(path, policy, reader)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        # Se comprueba la DACL del descriptor abierto, que es lo que se va a leer: si alguien
        # sustituyó el fichero entre la comprobación de la ruta y la apertura, se rechaza.
        if not file_acl.same_file(fd, path):
            raise file_acl.AclError(f"{path} changed while it was being opened")
        file_acl.check_open_file(fd, path, policy, reader)
        chunks: list[bytes] = []
        size = 0
        while size <= _MAX_KEYRING_BYTES:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _read_validated(path: Path, readers: Iterable[str]) -> bytes:
    try:
        if not path.is_file():
            raise SecretStoreError(f"SNMP credential key file not found: {path}")
        if _is_windows():
            return _read_windows(path, readers)
        _check_permissions(path)
        return path.read_bytes()
    except file_acl.AclError as exc:
        # Solo SID, máscaras y rutas: nunca contenido del fichero.
        raise SecretStoreError(f"SNMP credential key file is not private: {exc}") from exc
    except OSError as exc:
        raise SecretStoreError(f"cannot read SNMP credential key file: {path}") from exc


def _parse_keyring(raw: bytes) -> Keyring:
    if len(raw) > _MAX_KEYRING_BYTES:
        raise SecretStoreError("SNMP credential key file is too large")
    keys: dict[str, bytes] = {}
    active: str | None = None
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SecretStoreError("SNMP credential key file is not valid UTF-8") from exc
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        kid, sep, encoded = line.partition(":")
        if not sep or not _KID.fullmatch(kid):
            raise SecretStoreError(f"SNMP credential key file: invalid key id on line {number}")
        try:
            key = base64.b64decode(encoded.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SecretStoreError(
                f"SNMP credential key file: invalid base64 on line {number}"
            ) from exc
        if len(key) != 32:
            raise SecretStoreError(
                f"SNMP credential key file: key on line {number} must be 32 bytes (AES-256)"
            )
        if kid in keys:
            raise SecretStoreError(f"SNMP credential key file: duplicate key id {kid!r}")
        keys[kid] = key
        active = active or kid
    if active is None:
        raise SecretStoreError("SNMP credential key file has no keys")
    return Keyring(active, keys)


def load_keyring(path: Path, readers: Iterable[str] = ()) -> Keyring:
    """Lee y valida el fichero de claves. Lanza SecretStoreError si no es utilizable.

    `readers`: SID con permiso de solo lectura además de la política fija (Windows).
    """
    return _parse_keyring(_read_validated(path, readers))


def generate_key_line(kid: str) -> str:
    """Línea nueva para el fichero de claves (la usa la CLI snmp-keygen)."""
    if not _KID.fullmatch(kid):
        raise ValueError("key id must match [A-Za-z0-9_-]{1,32}")
    return f"{kid}:{base64.b64encode(secrets.token_bytes(32)).decode()}"


def _create_key_file(path: Path, readers: Iterable[str]) -> int:
    """Crea `path` (nunca existente) ya protegido y devuelve un descriptor de escritura.

    POSIX: 0600 desde la creación (O_EXCL). Windows: primero se exige un directorio seguro
    (precondición que prepara el administrador, docs/snmp-network-intelligence.md) y luego
    el fichero nace con una DACL protegida, sin herencia y sin instante intermedio con la
    DACL del directorio.
    """
    if not _is_windows():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        return os.open(path, flags, 0o600)
    reader, policy = _windows_policy(readers)
    try:
        file_acl.check_location(path, policy, reader)
        sddl = file_acl.creation_sddl(
            policy,
            reader.process_sid(),
            file_acl.process_is_admin(),
            dict.fromkeys(sorted(policy.readers), _READER_MASK),
        )
    except file_acl.AclError as exc:
        raise SecretStoreError(f"refusing to create {path}: {exc}") from exc
    return CREATE_PRIVATE_FILE(path, sddl)


def _write_all(fd: int, text: str) -> None:
    """Escribe y fuerza a disco; cierra el descriptor siempre."""
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


_HEADER = "# Sentra: claves AES-256 de credenciales SNMP. La primera es la activa.\n"


def write_new_keyring(path: Path, kid: str, readers: Iterable[str] = ()) -> None:
    """Crea un fichero de claves nuevo, protegido desde el primer byte (sin carrera).

    Nunca sobrescribe: si existe, falla (perder la clave activa deja ilegibles todos los
    perfiles guardados). Tras escribirlo se vuelve a cargar con las mismas comprobaciones
    que usará la API; si no las pasa se borra (su clave aún no cifró nada).
    """
    readers = tuple(readers)
    line = generate_key_line(kid)
    fd = _create_key_file(path, readers)
    try:
        _write_all(fd, _HEADER + line + "\n")
        load_keyring(path, readers)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def add_key(path: Path, kid: str, readers: Iterable[str] = ()) -> None:
    """Rotación de la clave maestra: añade una clave nueva AL PRINCIPIO (pasa a ser la activa).

    Conserva las anteriores para descifrar lo ya guardado hasta que `snmp-rekey` lo vuelva a
    cifrar. El fichero actual se valida antes (seguridad y formato); la versión nueva se
    escribe en un temporal del mismo directorio, creado ya protegido, se fuerza a disco, se
    verifica con las mismas comprobaciones que la API y solo entonces sustituye al original
    de forma atómica. Ante cualquier fallo el original queda intacto y el temporal se borra.
    """
    readers = tuple(readers)
    raw = _read_validated(path, readers)
    current = _parse_keyring(raw)
    if kid in current.keys:
        raise ValueError(f"key id {kid!r} already exists")
    lines = [
        line.strip()
        for line in raw.decode("utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    new_line = generate_key_line(kid)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    created = False
    try:
        fd = _create_key_file(tmp, readers)
        created = True
        _write_all(fd, _HEADER + "".join(entry + "\n" for entry in [new_line, *lines]))
        rotated = load_keyring(tmp, readers)
        if set(rotated.keys) != {kid, *current.keys} or rotated.active_kid != kid:
            raise SecretStoreError("rotated key file does not contain every previous key")
        os.replace(tmp, path)
    finally:
        # Solo el temporal propio (creado con O_EXCL/CREATE_NEW); tras os.replace ya no existe.
        if created:
            tmp.unlink(missing_ok=True)
    load_keyring(path, readers)


class SecretBox:
    """Cifra y descifra diccionarios de secretos ligados a un contexto (AAD)."""

    def __init__(self, keyring: Keyring) -> None:
        self._keyring = keyring

    @property
    def active_kid(self) -> str:
        return self._keyring.active_kid

    def encrypt(self, values: dict[str, str], context: str) -> tuple[str, str]:
        """Devuelve (blob, kid). `context` es el AAD: identifica el registro dueño del blob."""
        kid = self._keyring.active_kid
        nonce = secrets.token_bytes(_NONCE_BYTES)
        plaintext = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
        aad = f"{FORMAT_VERSION}:{kid}:{context}".encode()
        ciphertext = AESGCM(self._keyring.keys[kid]).encrypt(nonce, plaintext, aad)
        encoded = base64.b64encode(nonce + ciphertext).decode()
        return f"{FORMAT_VERSION}.{kid}.{encoded}", kid

    def decrypt(self, blob: str, context: str) -> dict[str, str]:
        version, _, rest = blob.partition(".")
        kid, _, encoded = rest.partition(".")
        if version != FORMAT_VERSION or not kid or not encoded:
            raise SecretDecryptError("unsupported secret format")
        key = self._keyring.keys.get(kid)
        if key is None:
            # La clave se retiró del fichero antes de re-cifrar (snmp-rekey): el secreto se
            # pierde; el admin debe rotar la credencial del perfil.
            raise SecretDecryptError("secret encrypted with a key that is no longer available")
        try:
            raw = base64.b64decode(encoded, validate=True)
            nonce, ciphertext = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
            aad = f"{FORMAT_VERSION}:{kid}:{context}".encode()
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
            data = json.loads(plaintext)
        except (binascii.Error, ValueError, InvalidTag) as exc:
            raise SecretDecryptError("secret could not be decrypted") from exc
        if not isinstance(data, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in data.items()
        ):
            raise SecretDecryptError("secret has an unexpected shape")
        return data


def open_secret_box(path: str | None, readers: Iterable[str] = ()) -> SecretBox:
    """SecretBox del fichero configurado. Sin configurar = SecretStoreError (503 en la API)."""
    if not path:
        raise SecretStoreError("SNMP_CREDENTIAL_KEY_FILE is not configured")
    return SecretBox(load_keyring(Path(path), readers))
