"""Configuración local del sensor (TOML) y rutas por defecto por plataforma.

La configuración local solo describe CÓMO conectarse y dónde guardar estado. QUÉ redes se
pueden sondear no se configura aquí: lo decide el servidor (allowed_networks en SensorConfig).
Así un operador del host del sensor no puede ampliar el alcance editando un fichero local.
"""

import ipaddress
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field, fields, replace
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import urlsplit

from sentra_sensor.fsperm import make_private_dir

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
# Fase 6E (sensor 0.6.0): ficheros de leases DHCP que el operador del host autoriza a leer.
# El servidor solo puede pedir uno por su nombre; nunca envía rutas.
DHCP_FORMATS = ("dnsmasq", "isc_dhcpd", "kea_csv", "windows_dhcp_csv", "generic_csv")
DHCP_SOURCE_NAME_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
_DHCP_SOURCE_KEYS = frozenset({"name", "path", "format"})


class ConfigError(ValueError):
    """La configuración local no es válida; el sensor no debe arrancar con ella."""


def default_data_dir(platform: str | None = None, env: dict[str, str] | None = None) -> Path:
    """Directorio de datos por defecto (credencial, spool, estado, logs).

    Linux: /var/lib/sentra-sensor si se ejecuta como root o servicio, si no ~/.local/state.
    Windows: %ProgramData%\\Sentra\\Sensor (el instalador restringe su ACL); para pruebas
    manuales sin privilegios, usar --data-dir.
    """
    platform = platform or sys.platform
    env = env if env is not None else dict(os.environ)
    if platform == "win32":
        base = env.get("PROGRAMDATA") or env.get("LOCALAPPDATA") or "C:\\ProgramData"
        return Path(base) / "Sentra" / "Sensor"
    if env.get("SENTRA_SENSOR_SERVICE") == "1" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        return Path("/var/lib/sentra-sensor")
    base = env.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "sentra-sensor"


def default_config_path(platform: str | None = None, env: dict[str, str] | None = None) -> Path:
    platform = platform or sys.platform
    env = env if env is not None else dict(os.environ)
    if platform == "win32":
        base = env.get("PROGRAMDATA") or "C:\\ProgramData"
        return Path(base) / "Sentra" / "Sensor" / "sensor.toml"
    return Path("/etc/sentra-sensor/sensor.toml")


def validate_server_url(url: str) -> str:
    """Solo HTTPS; http:// únicamente contra loopback (servidor de desarrollo en 127.0.0.1).

    El sensor envía su credencial en cada petición: en claro por una red real cualquiera
    en el camino podría robarla. No existe opción para relajar esto.
    """
    parts = urlsplit(url.strip())
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ConfigError("server_url must be an https:// URL")
    if parts.username or parts.password:
        raise ConfigError("server_url must not embed credentials")
    if parts.query or parts.fragment:
        raise ConfigError("server_url must not have a query or fragment")
    if parts.scheme == "http" and parts.hostname.lower() not in LOOPBACK_HOSTS:
        raise ConfigError("http:// is only allowed for 127.0.0.1, ::1 or localhost")
    return url.strip().rstrip("/")


def resolve_inside(base: Path, value: str | Path, what: str) -> Path:
    """Resuelve `value` (relativa a `base` o absoluta) y exige que quede dentro de `base`.

    Rechaza componentes `..` aunque el resultado final cayera dentro: una ruta con `..` en
    un fichero de configuración es casi siempre un error o un intento de escapar del
    directorio de datos (p. ej. que el spool sobrescriba un fichero del sistema).
    """
    raw = PurePath(value)
    if ".." in raw.parts:
        raise ConfigError(f"{what} must not contain '..'")
    if "\x00" in str(value):
        raise ConfigError(f"{what} contains a NUL byte")
    candidate = Path(value) if raw.is_absolute() else base / raw
    base_resolved = base.resolve()
    resolved = candidate.resolve()
    if not resolved.is_relative_to(base_resolved) or resolved == base_resolved:
        raise ConfigError(f"{what} must be a file inside the data directory {base_resolved}")
    return resolved


@dataclass(frozen=True)
class DhcpLeaseFile:
    """Una entrada `[[dhcp_lease_files]]`: fichero local de leases que el job puede leer."""

    name: str
    path: Path
    format: str


def parse_dhcp_lease_files(raw: object) -> tuple[DhcpLeaseFile, ...]:
    """Valida la lista `[[dhcp_lease_files]]` completa al cargar la configuración.

    Se valida aquí y no al ejecutar el job para que una errata (formato mal escrito, ruta
    relativa, nombre repetido) impida arrancar el sensor en vez de fallar en silencio horas
    después, cuando el servidor pida esa fuente. La existencia del fichero NO se exige: el
    servidor DHCP puede crearlo más tarde y `diagnostics` lo muestra.
    """
    if not isinstance(raw, list):
        raise ConfigError("dhcp_lease_files must be an array of tables ([[dhcp_lease_files]])")
    sources: list[DhcpLeaseFile] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw):
        where = f"dhcp_lease_files[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be a table")
        unknown = set(entry) - _DHCP_SOURCE_KEYS
        missing = _DHCP_SOURCE_KEYS - set(entry)
        if unknown:
            raise ConfigError(f"{where} has unknown keys: {sorted(unknown)}")
        if missing:
            raise ConfigError(f"{where} is missing keys: {sorted(missing)}")
        name, path, fmt = entry["name"], entry["path"], entry["format"]
        if not isinstance(name, str) or not DHCP_SOURCE_NAME_RE.fullmatch(name):
            raise ConfigError(f"{where}.name must match ^[a-z0-9_-]{{1,64}}$")
        if name in seen:
            raise ConfigError(f"{where}.name {name!r} is duplicated")
        seen.add(name)
        if not isinstance(fmt, str) or fmt not in DHCP_FORMATS:
            raise ConfigError(f"{where}.format must be one of {list(DHCP_FORMATS)}")
        if not isinstance(path, str) or not path.strip():
            raise ConfigError(f"{where}.path must be a non-empty string")
        if "\x00" in path:
            raise ConfigError(f"{where}.path contains a NUL byte")
        # Ruta absoluta obligatoria: una relativa dependería del directorio de trabajo del
        # servicio (distinto en systemd, en el SCM de Windows y en una prueba manual).
        resolved = Path(path)
        if not resolved.is_absolute():
            raise ConfigError(f"{where}.path must be an absolute path")
        sources.append(DhcpLeaseFile(name=name, path=resolved, format=fmt))
    return tuple(sources)


@dataclass(frozen=True)
class LocalConfig:
    server_url: str | None = None
    data_dir: Path = field(default_factory=default_data_dir)
    # Relativas a data_dir (o absolutas dentro de él).
    credential_path: str = "credential.json"
    spool_path: str = "spool.sqlite3"
    state_path: str = "state.json"
    log_dir: Path | None = None
    # CA privada del servidor (PEM). Se AÑADE a la verificación; nunca la desactiva.
    ca_bundle: Path | None = None
    # Valores iniciales: el servidor manda los efectivos en `config` en cada heartbeat.
    poll_interval_seconds: int = 30
    heartbeat_interval_seconds: int = 30
    request_timeout_seconds: float = 15.0
    spool_max_mb: int = 64
    spool_max_items: int = 10_000
    spool_max_age_hours: int = 72
    retry_max_delay_seconds: int = 300
    log_level: str = "INFO"
    # Interruptores locales para no usar binarios del sistema (ping, arp) aunque el job los
    # pida: el operador del host puede ser más restrictivo que el servidor, nunca menos.
    allow_system_ping: bool = True
    allow_system_arp: bool = True
    # Fase 6E: fuentes DHCP locales y tope de tamaño de cada fichero (KiB). El tope protege
    # la memoria del sensor si alguien apunta una fuente a un fichero enorme.
    dhcp_lease_files: tuple[DhcpLeaseFile, ...] = ()
    dhcp_max_file_kb: int = 4096

    def dhcp_source(self, name: str) -> DhcpLeaseFile | None:
        for source in self.dhcp_lease_files:
            if source.name == name:
                return source
        return None

    def validate(self) -> "LocalConfig":
        if self.server_url is not None:
            object.__setattr__(self, "server_url", validate_server_url(self.server_url))
        checks: list[tuple[str, float, float, float]] = [
            ("poll_interval_seconds", self.poll_interval_seconds, 5, 3600),
            ("heartbeat_interval_seconds", self.heartbeat_interval_seconds, 5, 3600),
            ("request_timeout_seconds", self.request_timeout_seconds, 1, 300),
            ("spool_max_mb", self.spool_max_mb, 1, 10_240),
            ("spool_max_items", self.spool_max_items, 10, 1_000_000),
            ("spool_max_age_hours", self.spool_max_age_hours, 1, 24 * 30),
            ("retry_max_delay_seconds", self.retry_max_delay_seconds, 5, 86_400),
            ("dhcp_max_file_kb", self.dhcp_max_file_kb, 1, 65_536),
        ]
        for name, value, low, high in checks:
            if not low <= value <= high:
                raise ConfigError(f"{name} must be between {low:g} and {high:g}")
        if self.log_level.upper() not in LOG_LEVELS:
            raise ConfigError(f"log_level must be one of {sorted(LOG_LEVELS)}")
        if self.ca_bundle is not None and not self.ca_bundle.is_file():
            raise ConfigError(f"ca_bundle {self.ca_bundle} does not exist")
        # Fuerzan el error temprano si alguna ruta escapa del directorio de datos.
        self.credential_file()
        self.spool_file()
        self.state_file()
        return self

    def credential_file(self) -> Path:
        return resolve_inside(self.data_dir, self.credential_path, "credential_path")

    def spool_file(self) -> Path:
        return resolve_inside(self.data_dir, self.spool_path, "spool_path")

    def state_file(self) -> Path:
        return resolve_inside(self.data_dir, self.state_path, "state_path")

    def logs_dir(self) -> Path:
        return self.log_dir or self.data_dir / "logs"

    def ensure_data_dir(self) -> Path:
        """Crea data_dir solo accesible para el sensor (credencial, spool, estado).

        mkdir(parents=True) crea los padres con el modo por defecto; por eso se fija la
        protección de data_dir de forma explícita aunque ya existiera más abierto: 0700 en
        POSIX, DACL privada en Windows (fsperm). Si no se puede, PrivacyError (OSError).
        """
        make_private_dir(self.data_dir)
        return self.data_dir


_PATH_FIELDS = {"data_dir", "log_dir", "ca_bundle"}
_INT_FIELDS = {
    "poll_interval_seconds",
    "heartbeat_interval_seconds",
    "spool_max_mb",
    "spool_max_items",
    "spool_max_age_hours",
    "retry_max_delay_seconds",
    "dhcp_max_file_kb",
}
_BOOL_FIELDS = {"allow_system_ping", "allow_system_arp"}


def _check_type(key: str, value: Any) -> None:
    # TOML ya tipa los valores; se comprueba para dar un error claro en vez de un TypeError
    # en mitad del arranque (y bool no cuenta como int aunque Python lo permita).
    if value is None or key == "dhcp_lease_files":
        # dhcp_lease_files tiene su propia validación (parse_dhcp_lease_files).
        return
    if key in _INT_FIELDS:
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif key in _BOOL_FIELDS:
        ok = isinstance(value, bool)
    elif key == "request_timeout_seconds":
        ok = isinstance(value, int | float) and not isinstance(value, bool)
    else:
        ok = isinstance(value, str | Path)
    if not ok:
        raise ConfigError(f"{key} has an invalid type")


def load_config(path: Path | None, overrides: dict[str, Any] | None = None) -> LocalConfig:
    """Carga TOML (opcional) + overrides de CLI. Claves desconocidas = error (erratas)."""
    values: dict[str, Any] = {}
    if path is not None and path.exists():
        with path.open("rb") as handle:
            try:
                data = tomllib.load(handle)
            except tomllib.TOMLDecodeError as exc:
                # Error típico en Windows: "C:\Users\..." sin escapar (\U es un escape TOML).
                raise ConfigError(
                    f"{path} is not valid TOML ({exc}); write Windows paths as"
                    ' "C:\\\\ProgramData\\\\Sentra" or "C:/ProgramData/Sentra"'
                ) from exc
        section = data.get("sensor", data)
        if not isinstance(section, dict):
            raise ConfigError("[sensor] must be a table")
        values.update(section)
        # `[[dhcp_lease_files]]` se escribe normalmente al nivel superior (después de
        # [sensor]); también se admite `[[sensor.dhcp_lease_files]]`, pero no ambos a la vez
        # (no habría forma clara de saber cuál manda).
        if section is not data and "dhcp_lease_files" in data:
            if "dhcp_lease_files" in section:
                raise ConfigError(
                    "dhcp_lease_files is defined both at top level and inside [sensor]"
                )
            values["dhcp_lease_files"] = data["dhcp_lease_files"]
    for key, value in (overrides or {}).items():
        if value is not None:
            values[key] = value
    known = {f.name for f in fields(LocalConfig)}
    unknown = set(values) - known
    if unknown:
        raise ConfigError(f"unknown configuration keys: {sorted(unknown)}")
    for key, value in values.items():
        _check_type(key, value)
    for key in _PATH_FIELDS & set(values):
        if values[key] is not None:
            values[key] = Path(values[key])
    if values.get("dhcp_lease_files") is not None and not isinstance(
        values["dhcp_lease_files"], tuple
    ):
        values["dhcp_lease_files"] = parse_dhcp_lease_files(values["dhcp_lease_files"])
    try:
        config = replace(LocalConfig(), **values)
    except TypeError as exc:
        raise ConfigError(str(exc)) from exc
    return config.validate()


def is_loopback_url(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
