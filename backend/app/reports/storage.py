"""Almacenamiento de artefactos de informes en disco (Fase 5E). Ver docs/report-storage.md.

- Raíz: REPORT_OUTPUT_DIR (absoluta, fuera del repositorio y del webroot). Sin valor, la
  carpeta de datos de la aplicación del usuario del servicio: %LOCALAPPDATA%\\Sentra\\reports
  en Windows, $XDG_STATE_HOME/sentra/reports (o ~/.local/state/sentra/reports) en Linux.
- Nombres y rutas los genera el servidor: "<año>/<mes>/<uuid>.<ext>". El cliente solo
  conoce el id del informe; nunca envía rutas ni nombres de fichero.
- Escritura atómica: fichero temporal en la misma carpeta → write + flush + fsync → cierre
  → os.replace (atómico en el mismo volumen, también en Windows). Un artefacto a medias
  nunca tiene el nombre final ni llega a la base de datos.
- Lectura defensiva: la clave se valida (sin "..", sin absolutas, sin barras invertidas, sin
  UNC, sin nombres reservados de Windows), la ruta resuelta debe seguir dentro de la raíz y
  no puede ser un enlace simbólico. Si algo no cuadra, falla cerrado.
"""

import os
import re
import stat
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from uuid import UUID

_KEY = re.compile(
    r"^(?P<year>\d{4})/(?P<month>\d{2})/(?P<name>[0-9a-f]{32})\.(?P<ext>html|pdf|csv|zip)$"
)
_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
TMP_DIR = ".tmp"
TMP_SUFFIX = ".part"


class StorageError(Exception):
    """Ruta inválida, fuera de la raíz, enlace simbólico o fichero ausente."""


def default_root() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "Sentra" / "reports"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "sentra" / "reports"


def _repo_root() -> Path:
    # backend/app/reports/storage.py → raíz del repositorio (tres niveles por encima de app).
    return Path(__file__).resolve().parents[3]


def validate_key(key: str) -> str:
    """La clave guardada en la BD debe tener exactamente la forma que genera `new_key`."""
    if not isinstance(key, str) or len(key) > 200 or "\x00" in key or "\\" in key:
        raise StorageError("invalid storage key")
    match = _KEY.match(key)
    if match is None or key.startswith("/") or ".." in key.split("/"):
        raise StorageError("invalid storage key")
    if match["name"].lower() in _RESERVED:
        raise StorageError("invalid storage key")
    return key


def new_key(created_at: datetime, artifact_id: UUID, extension: str) -> str:
    return validate_key(f"{created_at:%Y}/{created_at:%m}/{artifact_id.hex}.{extension}")


class ArtifactStorage:
    def __init__(self, root: str | None) -> None:
        self._configured = root
        self._root = Path(root) if root else default_root()

    @property
    def root(self) -> Path:
        return self._root

    def ensure_root(self) -> Path:
        """Crea la raíz (0700) y comprueba que no está dentro del repositorio."""
        root = self._root
        if not root.is_absolute():
            raise StorageError("REPORT_OUTPUT_DIR must be absolute")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved = root.resolve()
        if resolved.is_relative_to(_repo_root()):
            # Dentro del repo los informes acabarían en un commit o servidos por el webroot
            # (frontend/public, frontend/dist).
            raise StorageError("REPORT_OUTPUT_DIR must be outside the Sentra repository")
        (resolved / TMP_DIR).mkdir(exist_ok=True, mode=0o700)
        return resolved

    def path_for(self, key: str) -> Path:
        root = self.ensure_root()
        path = root.joinpath(*validate_key(key).split("/"))
        # resolve() sigue enlaces: si alguno de los componentes es un enlace que sale de la
        # raíz, la ruta resuelta ya no está dentro y se rechaza.
        if not path.resolve().is_relative_to(root):
            raise StorageError("storage path escapes the report directory")
        return path

    def write_atomic(self, key: str, data: bytes) -> Path:
        final = self.path_for(key)
        final.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp_dir = self.ensure_root() / TMP_DIR
        fd, tmp_name = tempfile.mkstemp(dir=tmp_dir, suffix=TMP_SUFFIX)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, final)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise
        return final

    def read(self, key: str, max_bytes: int) -> bytes:
        path = self.path_for(key)
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            raise StorageError("artifact file is missing") from None
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise StorageError("artifact is not a regular file")
        if info.st_size > max_bytes:
            raise StorageError("artifact larger than allowed")
        with open(path, "rb") as handle:
            return handle.read(max_bytes + 1)

    def delete(self, key: str) -> bool:
        try:
            root = self.ensure_root()
            path = root.joinpath(*validate_key(key).split("/"))
            # Solo la carpeta contenedora se resuelve: el último componente puede ser un
            # enlace simbólico manipulado y se borra el enlace, nunca su destino.
            if not path.parent.resolve().is_relative_to(root):
                return False
        except StorageError:
            return False
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(info.st_mode):
            # Nunca se sigue un enlace al borrar: se elimina el enlace, no su destino.
            path.unlink()
            return True
        path.unlink(missing_ok=True)
        return True

    def purge_temp(self, older_than_seconds: float, now: float) -> int:
        """Borra temporales huérfanos (proceso caído a mitad de escritura)."""
        tmp_dir = self.ensure_root() / TMP_DIR
        removed = 0
        for entry in tmp_dir.iterdir():
            if entry.is_symlink() or not entry.name.endswith(TMP_SUFFIX):
                continue
            if now - entry.stat().st_mtime > older_than_seconds:
                entry.unlink(missing_ok=True)
                removed += 1
        return removed
