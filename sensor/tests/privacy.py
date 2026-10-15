"""Comprobaciones de privacidad por plataforma para los tests.

POSIX: bits de modo (0600 / 0700). Windows: la DACL real de NTFS (los bits de `st_mode` no
dicen quién puede leer un fichero allí), sin entradas de grupos amplios y aceptada por
fsperm.is_private. Ninguna de las dos ramas es un skip: cada plataforma comprueba lo suyo.
"""

import stat
import sys
from pathlib import Path

from sentra_sensor import fsperm

# Users (BU): el principal típico que hereda lectura de %ProgramData%.
SID_USERS = "S-1-5-32-545"


def assert_private(path: Path, directory: bool = False) -> None:
    if sys.platform == "win32":
        snapshot = fsperm.read_acl(path)
        assert snapshot.present, f"{path} has a NULL DACL"
        broad = {
            ace.sid
            for ace in snapshot.aces
            if ace.ace_type == fsperm.ACCESS_ALLOWED_ACE_TYPE and ace.sid in fsperm.BROAD_SIDS
        }
        assert not broad, f"{path} grants access to {sorted(broad)}"
        assert fsperm.is_private(path), f"{path} ACL is not private: {snapshot}"
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    expected = fsperm.DIR_MODE if directory else fsperm.FILE_MODE
    assert mode & 0o077 == 0, f"{path} mode is {oct(mode)}"
    assert mode == expected, f"{path} mode is {oct(mode)}, expected {oct(expected)}"


def loosen(path: Path, directory: bool = False) -> None:
    """Deja `path` accesible para otros usuarios del host (lo que debe corregir el sensor)."""
    if sys.platform == "win32":
        inherit = "OICI" if directory else ""
        me = fsperm.current_user_sid()
        fsperm.write_dacl(path, f"D:P(A;{inherit};FA;;;{me})(A;{inherit};FR;;;{SID_USERS})")
        assert not fsperm.is_private(path)
        return
    path.chmod(0o755 if directory else 0o644)
    assert not fsperm.is_private(path)
