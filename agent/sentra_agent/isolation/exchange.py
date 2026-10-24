"""Intercambio local agente <-> helper de aislamiento (sin red).

Directorio (contrato 6E): Windows `%ProgramData%\\Sentra\\Agent\\isolation\\`, Linux
`/var/lib/sentra-agent/isolation/`.

- `request.json` lo crea el agente: `{"session_id", "action", "expires_at", "requested_at"}`.
  El helper lo lee una vez (tamaño máximo 4 KiB) y lo borra; cualquier otra clave invalida la
  petición. No hay campo de direcciones: el helper nunca las acepta de fuera.
- `status.json` y `state.json` los escribe solo el helper. `state.json` aquí es una copia
  informativa: el estado que el helper usa para revertir vive en su directorio privado, al
  que el agente no tiene acceso (un agente comprometido no puede fabricarle un estado).

Permisos (los fija el instalador o el propio helper al arrancar):
- Linux: directorio `root:sentra-agent` modo 1770 (sticky). El agente puede crear
  request.json; no puede borrar ni sustituir ficheros de root. El helper trabaja con el
  descriptor del directorio (`dir_fd`) y `O_NOFOLLOW`, y comprueba que el directorio es de
  root: un enlace simbólico plantado no le hace escribir fuera.
- Windows: SYSTEM y Administradores control total; la cuenta del servicio del agente puede
  leer y crear ficheros (sin heredar escritura sobre lo que crea el helper).
"""

import contextlib
import json
import os
import stat
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sentra_agent.identity import write_atomic
from sentra_agent.isolation import IsolationError

REQUEST_FILE = "request.json"
STATUS_FILE = "status.json"
STATE_FILE = "state.json"
REQUEST_MAX_BYTES = 4096
REQUEST_KEYS = frozenset({"session_id", "action", "expires_at", "requested_at"})
ACTIONS = frozenset({"isolate", "release"})
# Una petición que todavía no es JSON válido puede estar a medio escribir: se espera esto.
PARTIAL_GRACE_SECONDS = 5.0


def parse_iso(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("timestamp must be an ISO 8601 string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class Request:
    session_id: UUID
    action: str
    expires_at: datetime | None
    requested_at: datetime


def request_payload(
    session_id: UUID, action: str, expires_at: datetime | None, requested_at: datetime
) -> dict[str, Any]:
    return {
        "session_id": str(session_id),
        "action": action,
        "expires_at": expires_at.astimezone(UTC).isoformat() if expires_at else None,
        "requested_at": requested_at.astimezone(UTC).isoformat(),
    }


def parse_request(raw: bytes) -> Request:
    """Validación estricta del lado del helper: claves exactas y tipos."""
    if len(raw) > REQUEST_MAX_BYTES:
        raise IsolationError("invalid_request", "request too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise IsolationError("invalid_request", "request is not JSON") from exc
    if not isinstance(data, dict) or set(data) != REQUEST_KEYS:
        raise IsolationError("invalid_request", "request keys must be exactly the contract ones")
    action = data["action"]
    if action not in ACTIONS:
        raise IsolationError("invalid_request", "unknown action")
    try:
        session_id = UUID(str(data["session_id"]))
        requested_at = parse_iso(data["requested_at"])
        expires = data["expires_at"]
        expires_at = parse_iso(expires) if expires is not None else None
    except ValueError as exc:
        raise IsolationError("invalid_request", str(exc)) from exc
    if action == "isolate" and expires_at is None:
        raise IsolationError("invalid_request", "isolate needs expires_at")
    return Request(session_id, action, expires_at, requested_at)


def _secure_default() -> bool:
    return sys.platform != "win32" and hasattr(os, "geteuid") and os.geteuid() == 0


class ExchangeDir:
    """E/S del helper sobre el directorio de intercambio."""

    def __init__(
        self, path: Path, secure: bool | None = None, group: str | None = "sentra-agent"
    ) -> None:
        self.path = path
        self.secure = _secure_default() if secure is None else secure
        self.group = group

    def prepare(self) -> None:
        """Crea el directorio y, en POSIX como root, fija dueño y permisos (o se niega)."""
        if not self.secure or sys.platform == "win32":
            # Windows: las ACL las fija el instalador (icacls); aquí solo se crea.
            self.path.mkdir(parents=True, exist_ok=True)
            return
        with contextlib.suppress(FileExistsError):
            os.mkdir(self.path, 0o700)
        # Todo sobre el descriptor abierto sin seguir enlaces: entre comprobar y cambiar
        # permisos nadie puede cambiar el directorio por un enlace (sin carreras TOCTOU).
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags)
        except OSError as exc:
            raise IsolationError("exchange_dir_insecure", f"{self.path}: {exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
                # Directorio de otro usuario: el helper no escribe ahí (ver docs).
                raise IsolationError(
                    "exchange_dir_insecure", f"{self.path} is not a root-owned directory"
                )
            gid = self._group_id()
            if gid is not None:
                os.fchown(fd, 0, gid)
                # Sticky + grupo del agente: crea su petición, no toca lo de root.
                os.fchmod(fd, 0o1770)
            else:
                os.fchmod(fd, 0o700)
        finally:
            os.close(fd)

    def _group_id(self) -> int | None:
        if not self.group or sys.platform == "win32":
            return None
        import grp

        try:
            return grp.getgrnam(self.group).gr_gid
        except KeyError:
            return None

    def _dir_fd(self) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags)
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            os.close(fd)
            raise IsolationError("exchange_dir_insecure", "exchange dir changed owner")
        return fd

    def take_request(self, now: float | None = None) -> bytes | None:
        """Lee y borra request.json; None si no hay o si parece a medio escribir."""
        now = time.time() if now is None else now
        if not self.secure:
            path = self.path / REQUEST_FILE
            try:
                info = path.lstat()
            except FileNotFoundError:
                return None
            if not stat.S_ISREG(info.st_mode) or info.st_size > REQUEST_MAX_BYTES:
                path.unlink(missing_ok=True)
                raise IsolationError("invalid_request", "request is not a small regular file")
            raw = path.read_bytes()
            if not _complete(raw) and now - info.st_mtime < PARTIAL_GRACE_SECONDS:
                return None
            path.unlink(missing_ok=True)
            return raw
        dir_fd = self._dir_fd()
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            try:
                fd = os.open(REQUEST_FILE, flags, dir_fd=dir_fd)
            except FileNotFoundError:
                return None
            except OSError as exc:
                # ELOOP: es un enlace simbólico. Se borra sin seguirlo.
                os.unlink(REQUEST_FILE, dir_fd=dir_fd)
                raise IsolationError("invalid_request", "request is not a regular file") from exc
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > REQUEST_MAX_BYTES:
                    os.unlink(REQUEST_FILE, dir_fd=dir_fd)
                    raise IsolationError("invalid_request", "request is not a small regular file")
                raw = os.read(fd, REQUEST_MAX_BYTES + 1)
            finally:
                os.close(fd)
            if not _complete(raw) and now - info.st_mtime < PARTIAL_GRACE_SECONDS:
                return None
            os.unlink(REQUEST_FILE, dir_fd=dir_fd)
            return raw
        finally:
            os.close(dir_fd)

    def write(self, name: str, data: dict[str, Any]) -> None:
        content = json.dumps(data, indent=2, sort_keys=True)
        if not self.secure:
            write_atomic(self.path / name, content, private=False)
            return
        dir_fd = self._dir_fd()
        try:
            tmp = f".{name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(tmp, flags, 0o644, dir_fd=dir_fd)
            try:
                os.write(fd, content.encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        finally:
            os.close(dir_fd)


def _complete(raw: bytes) -> bool:
    try:
        json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    return True


def read_json(path: Path, limit: int = 256 * 1024) -> dict[str, Any] | None:
    """Lee un JSON pequeño; None si no existe, es grande o no es un objeto."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError:
        return None
    if len(raw) > limit:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def create_request(directory: Path, payload: dict[str, Any]) -> None:
    """Lado del agente: crea request.json en exclusiva (nunca sustituye uno pendiente).

    Escritura directa con creación exclusiva en lugar de escribir-y-renombrar: en Windows la
    cuenta del agente solo puede crear ficheros en ese directorio, no borrar ni renombrar.
    """
    path = directory / REQUEST_FILE
    data = json.dumps(payload).encode()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o640)
    except FileExistsError as exc:
        raise IsolationError("helper_busy", "a previous request is still pending") from exc
    except OSError as exc:
        raise IsolationError("helper_absent", f"cannot write the request: {exc}") from exc
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
