"""Identidad estable del equipo (Fase 5C.1), solo para detectar duplicados.

Por qué existe: al reinstalar el agente (nuevo agent_id) el servidor crea otro activo para el
mismo equipo. Con un identificador del sistema operativo que sobrevive a la reinstalación del
agente, el servidor puede proponer "este agente parece corresponder a un activo existente".

Cómo se protege:
- se lee un identificador que el sistema ya genera (Linux /etc/machine-id, Windows
  MachineGuid); no se crea nada, no hace falta privilegio y no se leen números de serie;
- nunca sale del equipo en claro: se envía HMAC-SHA256(clave=id, mensaje=APP_ID), el mismo
  esquema que systemd recomienda para identificadores derivados por aplicación
  (sd_id128_get_machine_app_specific). Otra aplicación con el mismo id obtiene otro valor;
- NO es una credencial: el servidor solo lo usa para sugerir duplicados, nunca para
  autenticar ni para fusionar sin que un administrador decida. Un equipo clonado sin
  regenerar su machine-id da el mismo valor (por eso solo se sugiere).
"""

import hashlib
import hmac
import logging
import re
import sys
from pathlib import Path

logger = logging.getLogger("sentra_agent")

APP_ID = b"sentra-agent/machine-identity/v1"
LINUX_PATHS = (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id"))
_LINUX_ID = re.compile(r"^[0-9a-f]{32}$")
_WINDOWS_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def derive(raw: str) -> str | None:
    """Hash por aplicación de un identificador ya validado; None si no es utilizable."""
    value = raw.strip().lower()
    if not (_LINUX_ID.match(value) or _WINDOWS_GUID.match(value)):
        return None
    # Un id todo ceros (imágenes sin inicializar) identificaría a muchos equipos a la vez.
    if set(value.replace("-", "")) == {"0"}:
        return None
    return hmac.new(value.encode("ascii"), APP_ID, hashlib.sha256).hexdigest()


def _linux_raw(paths: tuple[Path, ...] = LINUX_PATHS) -> str | None:
    for path in paths:
        try:
            # Fichero de 33 bytes; se acota la lectura por si fuese otra cosa.
            text = path.read_text(encoding="ascii", errors="replace")[:64].strip()
        except OSError:
            continue
        if text and text != "uninitialized":
            return text
    return None


def _windows_raw() -> str | None:
    if sys.platform != "win32":  # mypy en Linux no comprueba las llamadas a winreg
        return None
    import winreg

    # 🪟 VALIDACIÓN LOCAL EN WINDOWS. Vista de 64 bits: un Python de 32 bits leería la
    # rama WOW6432Node, que no tiene MachineGuid.
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            value = winreg.QueryValueEx(key, "MachineGuid")[0]
    except OSError:
        return None
    return value if isinstance(value, str) else None


_cached: tuple[bool, str | None] = (False, None)


def machine_id_hash() -> str | None:
    """Hash del identificador del equipo, o None si no hay uno fiable (se calcula una vez)."""
    global _cached
    if _cached[0]:
        return _cached[1]
    raw = _windows_raw() if sys.platform == "win32" else _linux_raw()
    result = derive(raw) if raw else None
    if result is None:
        logger.info("machine identity not available; duplicate detection uses other evidence")
    _cached = (True, result)
    return result
