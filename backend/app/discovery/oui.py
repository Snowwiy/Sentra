"""Fabricante de la tarjeta de red a partir del prefijo de la MAC (OUI).

El prefijo de una MAC identifica a quien fabricó la interfaz de red, NO necesariamente al
fabricante del dispositivo: un Nintendo Switch con un adaptador USB-Ethernet muestra
"Realtek", un PC Dell suele mostrar "Intel". Por eso este módulo solo responde "quién hizo la
NIC"; decidir si eso dice algo del dispositivo es trabajo de app/discovery/vendors.py.

Fuente de datos: ficheros locales del registro público del IEEE (oui.csv / mam.csv /
oui36.csv), configurados con DISCOVERY_OUI_FILE. Sentra no consulta ninguna API externa
durante un scan: el descubrimiento debe funcionar sin Internet y no filtrar a terceros qué
dispositivos hay en la red. Sin fichero configurado, el fabricante queda desconocido (null);
nunca se inventa.
"""

import csv
import logging
import re
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

# Prefijos de 24, 28 y 36 bits (MA-L, MA-M, MA-S) expresados en dígitos hexadecimales.
_PREFIX_LENGTHS = (9, 7, 6)
_HEX = re.compile(r"^[0-9A-F]+$")
# Línea "AA-BB-CC   (hex)\t\tOrganización" del formato oui.txt del IEEE.
_TXT_LINE = re.compile(r"^\s*([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){2})\s+\(hex\)\s+(.+?)\s*$")
# Tamaño máximo aceptado por fichero: el oui.csv completo ronda 4 MB. Un límite evita que
# una ruta mal configurada (un log enorme, un disco) bloquee el arranque del scan.
MAX_FILE_BYTES = 64 * 1024 * 1024

# Prefijos que no son asignaciones del IEEE pero sí convenciones fijas y documentadas.
# 52:54:00 es localmente administrado (bit 0x02) y por eso pasaría por "MAC aleatoria",
# pero es el prefijo por defecto de las interfaces virtuales de QEMU/KVM (libvirt, Proxmox
# antiguos): reconocerlo evita clasificar como "privada" la MAC de una máquina virtual.
KNOWN_LOCAL_PREFIXES = {"525400": "QEMU/KVM virtual NIC"}


def mac_hex(mac: str | None) -> str | None:
    """ "aa:bb:cc:dd:ee:ff" → "AABBCCDDEEFF", o None si no es una MAC de 48 bits."""
    if not mac:
        return None
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    return digits if len(digits) == 12 else None


def is_locally_administered(mac: str | None) -> bool:
    """MAC aleatoria/privada (bit U/L activo): el prefijo no identifica a ningún fabricante.

    Móviles, tablets y portátiles modernos usan MACs aleatorias por red para privacidad.
    Buscar su prefijo en el registro del IEEE daría un fabricante falso, así que se trata
    como "sin fabricante" y queda como evidencia propia.
    """
    digits = mac_hex(mac)
    if digits is None or digits[:6] in KNOWN_LOCAL_PREFIXES:
        return False
    return bool(int(digits[:2], 16) & 0x02)


class OuiDatabase:
    """Prefijo → organización registrada, con búsqueda por el prefijo más largo."""

    def __init__(self, entries: dict[str, str] | None = None) -> None:
        self._entries: dict[str, str] = {}
        for prefix, organization in (entries or {}).items():
            self.add(prefix, organization)

    def __len__(self) -> int:
        return len(self._entries)

    def add(self, prefix: str, organization: str) -> None:
        digits = prefix.replace("-", "").replace(":", "").strip().upper()
        name = _clean_organization(organization)
        if len(digits) in _PREFIX_LENGTHS and _HEX.match(digits) and name:
            self._entries[digits] = name

    def lookup(self, mac: str | None) -> str | None:
        digits = mac_hex(mac)
        if digits is None:
            return None
        if digits[:6] in KNOWN_LOCAL_PREFIXES:
            return KNOWN_LOCAL_PREFIXES[digits[:6]]
        if is_locally_administered(mac):
            return None
        # Los bloques MA-S/MA-M están dentro de prefijos MA-L del propio IEEE (que figuran
        # como "IEEE Registration Authority"): el más largo es el fabricante real.
        for length in _PREFIX_LENGTHS:
            found = self._entries.get(digits[:length])
            if found:
                return found
        return None

    def load_file(self, path: Path) -> int:
        """Añade un fichero CSV (formato IEEE) o TXT (oui.txt). Devuelve entradas leídas."""
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"{path} is larger than {MAX_FILE_BYTES} bytes")
        before = len(self._entries)
        with path.open(encoding="utf-8", errors="replace", newline="") as handle:
            if path.suffix.lower() == ".csv":
                # Registry,Assignment,Organization Name,Organization Address
                for row in csv.reader(handle):
                    if len(row) >= 3 and row[1].strip().lower() != "assignment":
                        self.add(row[1], row[2])
            else:
                for line in handle:
                    match = _TXT_LINE.match(line)
                    if match:
                        self.add(match.group(1), match.group(2))
        return len(self._entries) - before


def _clean_organization(value: str) -> str:
    # Texto de un fichero externo: sin caracteres de control y acotado como la columna.
    text = "".join(ch for ch in value if ch.isprintable()).strip()
    return re.sub(r"\s+", " ", text)[:128]


def parse_paths(value: str | None) -> tuple[str, ...]:
    """DISCOVERY_OUI_FILE admite varias rutas separadas por coma (oui.csv,mam.csv,...)."""
    return tuple(p.strip() for p in (value or "").split(",") if p.strip())


def load_database(paths: Iterable[str]) -> OuiDatabase:
    """Carga los ficheros indicados (cacheado: ver configured_database)."""
    return _load_cached(tuple(_with_mtime(paths)))


def _with_mtime(paths: Iterable[str]) -> Iterable[tuple[str, float]]:
    # La fecha de modificación entra en la clave de caché: actualizar el fichero OUI se
    # aplica en el siguiente scan sin reiniciar la API ni releerlo en cada consulta.
    for raw in paths:
        try:
            yield raw, Path(raw).stat().st_mtime
        except OSError:
            yield raw, -1.0


@lru_cache(maxsize=4)
def _load_cached(paths: tuple[tuple[str, float], ...]) -> OuiDatabase:
    database = OuiDatabase()
    for raw, mtime in paths:
        if mtime < 0:
            logger.warning("OUI file not found; MAC vendors stay unknown", extra={"path": raw})
            continue
        try:
            count = database.load_file(Path(raw))
        except (OSError, ValueError, csv.Error) as exc:
            # Un fichero OUI roto no debe parar el discovery: solo se pierde el fabricante.
            logger.warning("OUI file unreadable", extra={"path": raw, "error": str(exc)})
            continue
        logger.info("OUI file loaded", extra={"path": raw, "entries": count})
    return database
