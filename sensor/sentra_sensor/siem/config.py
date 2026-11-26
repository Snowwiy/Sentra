"""Configuración SIEM: lo que declara el operador del host y lo que aprueba el servidor.

Doble control (Fase 7F, igual que NDR en 7E.1):
* sensor.toml declara las entradas que PUEDEN existir, cada una con un alias:
  `[[siem.inputs]] name = "fw-syslog", type = "syslog", protocol = "tls", port = 6514, ...`.
  Sin `[siem] enabled = true` el sensor no declara la capacidad ni abre ningún puerto.
* El servidor (un admin) registra fuentes que apuntan a esos alias. Solo se escucha en una
  entrada cuando su alias está declarado localmente Y aprobado por el servidor. El servidor
  nunca envía puertos, direcciones, rutas, certificados ni órdenes.

Reglas de seguridad que no se pueden relajar desde el servidor:
* UDP solo con `allow_udp = true` explícito: la dirección de origen de un datagrama se
  falsifica sin esfuerzo y no autentica a nadie (docs/fase-7f-syslog.md).
* Sin TLS, los pares permitidos tienen que ser direcciones privadas, de loopback o de enlace
  local: una fuente remota por Internet exige TLS.
* `allowed_peers` es obligatorio y nunca puede ser /0.
"""

import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Any

SIEM_ALIAS_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SOURCE_TYPE_RE = re.compile(r"^[a-z0-9_]{1,24}$")
PROTOCOLS = ("tcp", "tls", "udp")
MAX_INPUTS = 16
MAX_PEERS = 64
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class SiemConfigError(ValueError):
    """La sección [siem] de sensor.toml no es válida."""


_DRIVE_RE = re.compile(r"^[A-Za-z]:$")


def _windows() -> bool:
    """Semántica de rutas del sistema donde corre el sensor (los tests la sustituyen para
    comprobar las reglas de Windows en Linux y al revés)."""
    return sys.platform == "win32"


def _local_absolute(where: str, value: object) -> Path:
    """Ruta local absoluta del host del sensor para certificados, claves y directorios de logs.

    El operador del host es quien declara estas rutas; esta validación evita que una ruta
    ambigua acabe resolviéndose contra el directorio de trabajo del servicio o contra un
    recurso de red:
    * Se usa la semántica de la plataforma en ejecución. En Windows "/etc/sentra/x.crt" NO es
      absoluta (no tiene unidad: se resolvería contra la unidad actual) y se rechaza con un
      mensaje claro, en vez de intentar abrir una ruta de Linux que no existe.
    * Windows: solo rutas con letra de unidad (`C:/ProgramData/...`). Se rechazan las rutas
      UNC y las de dispositivo (prefijos de doble barra invertida): un certificado, una clave
      o un directorio de logs en un recurso de red no es una ruta local controlada por el
      operador del host.
    * Nunca `..` (traversal) ni NUL.
    """
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SiemConfigError(f"{where} must be a non-empty path")
    pure: PurePath = PureWindowsPath(value) if _windows() else PurePosixPath(value)
    if not pure.is_absolute():
        hint = " with a drive letter (C:/ProgramData/...)" if _windows() else ""
        raise SiemConfigError(f"{where} must be an absolute path{hint}")
    if _windows() and not _DRIVE_RE.fullmatch(pure.drive):
        raise SiemConfigError(f"{where} must be a local drive path, not UNC or device")
    if ".." in pure.parts:
        raise SiemConfigError(f"{where} must not contain '..'")
    return Path(value)


@dataclass(frozen=True)
class SyslogInput:
    name: str
    protocol: str
    bind: str
    port: int
    allowed_peers: tuple[IPNetwork, ...]
    max_message_bytes: int = 8192
    max_connections: int = 32
    max_records_per_second: int = 2000
    idle_timeout_seconds: int = 300
    tls_cert: Path | None = None
    tls_key: Path | None = None
    type: str = "syslog"

    def peer_allowed(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            return False
        # IPv4 mapeada en IPv6 (socket dual-stack): se compara como IPv4.
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return any(ip in network for network in self.allowed_peers)


FILE_FORMATS = ("suricata_eve", "zeek_json", "wazuh_alerts", "json_lines")
MAX_FILES = 16


@dataclass(frozen=True)
class FileInput:
    """Entrada `type = "file"` (7F.3): ficheros JSON Lines que el sensor lee de forma
    incremental. Solo ficheros dentro de `allowed_dir`; nunca enlaces simbólicos."""

    name: str
    format: str
    allowed_dir: Path
    paths: tuple[Path, ...]
    start_at: str = "end"
    max_line_bytes: int = 65_536
    max_records_per_second: int = 2000
    poll_interval_ms: int = 1000
    type: str = "file"


SiemInput = SyslogInput | FileInput


@dataclass(frozen=True)
class SiemLocalConfig:
    enabled: bool = False
    inputs: tuple[SiemInput, ...] = ()
    # Disco que el host concede al spool SIEM (aparte del de jobs y del de NDR: una avalancha
    # de Syslog no puede desplazar resultados de discovery ni flujos).
    spool_max_mb: int = 128

    def input(self, name: str) -> SiemInput | None:
        for item in self.inputs:
            if item.name == name:
                return item
        return None


def _int(where: str, value: object, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise SiemConfigError(f"{where} must be an integer between {low} and {high}")
    return value


def _networks(where: str, raw: object) -> tuple[IPNetwork, ...]:
    if not isinstance(raw, list) or not raw:
        raise SiemConfigError(f"{where}.allowed_peers must be a non-empty list of CIDRs")
    if len(raw) > MAX_PEERS:
        raise SiemConfigError(f"{where}.allowed_peers has more than {MAX_PEERS} entries")
    out: list[IPNetwork] = []
    for item in raw:
        if not isinstance(item, str):
            raise SiemConfigError(f"{where}.allowed_peers items must be strings")
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as exc:
            raise SiemConfigError(f"{where}.allowed_peers has an invalid CIDR {item!r}") from exc
        if network.prefixlen == 0:
            raise SiemConfigError(f"{where}.allowed_peers must not contain /0")
        out.append(network)
    return tuple(out)


# Rangos en los que se admite Syslog sin TLS. Lista explícita (y no `is_private`, que en
# Python incluye también redes de documentación y otros rangos reservados).
_LOCAL_RANGES = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def _is_local_network(network: IPNetwork) -> bool:
    return any(
        network.version == local.version and network.subnet_of(local)  # type: ignore[arg-type]
        for local in _LOCAL_RANGES
    )


def _syslog_input(where: str, item: dict[str, Any]) -> SyslogInput:
    allowed = {
        "name",
        "type",
        "protocol",
        "bind",
        "port",
        "allowed_peers",
        "allow_udp",
        "max_message_bytes",
        "max_connections",
        "max_records_per_second",
        "idle_timeout_seconds",
        "tls_cert",
        "tls_key",
    }
    unknown = set(item) - allowed
    if unknown:
        raise SiemConfigError(f"{where} has unknown keys: {sorted(unknown)}")
    protocol = item.get("protocol")
    if protocol not in PROTOCOLS:
        raise SiemConfigError(f"{where}.protocol must be one of {list(PROTOCOLS)}")
    if protocol == "udp" and item.get("allow_udp") is not True:
        raise SiemConfigError(
            f"{where}: UDP needs allow_udp = true (the source address of UDP is not"
            " authenticated; prefer tcp or tls)"
        )
    bind = item.get("bind", "127.0.0.1")
    try:
        ipaddress.ip_address(bind)
    except (ValueError, TypeError) as exc:
        raise SiemConfigError(f"{where}.bind must be an IP address") from exc
    port = _int(f"{where}.port", item.get("port"), 1, 65_535)
    peers = _networks(where, item.get("allowed_peers"))
    if protocol != "tls" and not all(_is_local_network(n) for n in peers):
        raise SiemConfigError(
            f"{where}: peers outside private, loopback or link-local ranges need protocol = tls"
        )
    cert = key = None
    if protocol == "tls":
        for field_name in ("tls_cert", "tls_key"):
            value = item.get(field_name)
            if not isinstance(value, str) or not value or "\x00" in value:
                raise SiemConfigError(f"{where}.{field_name} is required for protocol = tls")
        cert = _local_absolute(f"{where}.tls_cert", item["tls_cert"])
        key = _local_absolute(f"{where}.tls_key", item["tls_key"])
    elif "tls_cert" in item or "tls_key" in item:
        raise SiemConfigError(f"{where}: tls_cert/tls_key only apply to protocol = tls")
    return SyslogInput(
        name=item["name"],
        protocol=protocol,
        bind=bind,
        port=port,
        allowed_peers=peers,
        max_message_bytes=_int(
            f"{where}.max_message_bytes", item.get("max_message_bytes", 8192), 480, 65_536
        ),
        max_connections=_int(f"{where}.max_connections", item.get("max_connections", 32), 1, 512),
        max_records_per_second=_int(
            f"{where}.max_records_per_second",
            item.get("max_records_per_second", 2000),
            1,
            100_000,
        ),
        idle_timeout_seconds=_int(
            f"{where}.idle_timeout_seconds", item.get("idle_timeout_seconds", 300), 10, 86_400
        ),
        tls_cert=cert,
        tls_key=key,
    )


def _file_input(where: str, item: dict[str, Any]) -> FileInput:
    allowed = {
        "name",
        "type",
        "format",
        "allowed_dir",
        "paths",
        "start_at",
        "max_line_bytes",
        "max_records_per_second",
        "poll_interval_ms",
    }
    unknown = set(item) - allowed
    if unknown:
        raise SiemConfigError(f"{where} has unknown keys: {sorted(unknown)}")
    fmt = item.get("format")
    if fmt not in FILE_FORMATS:
        raise SiemConfigError(f"{where}.format must be one of {list(FILE_FORMATS)}")
    base = item.get("allowed_dir")
    if not isinstance(base, str) or not base or "\x00" in base:
        raise SiemConfigError(f"{where}.allowed_dir must be a non-empty string")
    allowed_dir = _local_absolute(f"{where}.allowed_dir", base)
    raw_paths = item.get("paths")
    if not isinstance(raw_paths, list) or not raw_paths or len(raw_paths) > MAX_FILES:
        raise SiemConfigError(f"{where}.paths must be a list of 1 to {MAX_FILES} file names")
    paths: list[Path] = []
    for value in raw_paths:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise SiemConfigError(f"{where}.paths items must be non-empty strings")
        candidate = Path(value)
        if ".." in candidate.parts:
            raise SiemConfigError(f"{where}.paths must not contain '..'")
        full = candidate if candidate.is_absolute() else allowed_dir / candidate
        # Comprobación léxica aquí; la real (enlaces, junctions) se repite al abrir.
        if not full.is_relative_to(allowed_dir) or full == allowed_dir:
            raise SiemConfigError(f"{where}.paths must be files inside allowed_dir")
        if full in paths:
            raise SiemConfigError(f"{where}.paths has a duplicated file {value!r}")
        paths.append(full)
    start_at = item.get("start_at", "end")
    if start_at not in ("end", "beginning"):
        raise SiemConfigError(f"{where}.start_at must be 'end' or 'beginning'")
    return FileInput(
        name=item["name"],
        format=fmt,
        allowed_dir=allowed_dir,
        paths=tuple(paths),
        start_at=start_at,
        max_line_bytes=_int(
            f"{where}.max_line_bytes", item.get("max_line_bytes", 65_536), 1024, 1_048_576
        ),
        max_records_per_second=_int(
            f"{where}.max_records_per_second",
            item.get("max_records_per_second", 2000),
            1,
            100_000,
        ),
        poll_interval_ms=_int(
            f"{where}.poll_interval_ms", item.get("poll_interval_ms", 1000), 100, 60_000
        ),
    )


_INPUT_PARSERS: dict[str, Any] = {"syslog": _syslog_input, "file": _file_input}


def parse_local_siem(raw: object) -> SiemLocalConfig:
    if raw is None:
        return SiemLocalConfig()
    if not isinstance(raw, dict):
        raise SiemConfigError("[siem] must be a table")
    unknown = set(raw) - {"enabled", "inputs", "spool_max_mb"}
    if unknown:
        raise SiemConfigError(f"[siem] has unknown keys: {sorted(unknown)}")
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise SiemConfigError("siem.enabled must be a boolean")
    spool_max_mb = _int("siem.spool_max_mb", raw.get("spool_max_mb", 128), 1, 10_240)
    items = raw.get("inputs", [])
    if not isinstance(items, list):
        raise SiemConfigError("siem.inputs must be an array of tables ([[siem.inputs]])")
    if len(items) > MAX_INPUTS:
        raise SiemConfigError(f"at most {MAX_INPUTS} siem.inputs")
    inputs: list[SiemInput] = []
    seen_names: set[str] = set()
    seen_listeners: set[tuple[str, str, int]] = set()
    seen_files: set[Path] = set()
    for index, item in enumerate(items):
        where = f"siem.inputs[{index}]"
        if not isinstance(item, dict):
            raise SiemConfigError(f"{where} must be a table")
        name = item.get("name")
        if not isinstance(name, str) or not SIEM_ALIAS_RE.fullmatch(name):
            raise SiemConfigError(f"{where}.name must match ^[a-z0-9_-]{{1,32}}$")
        if name in seen_names:
            raise SiemConfigError(f"{where}.name {name!r} is duplicated")
        parser = _INPUT_PARSERS.get(str(item.get("type")))
        if parser is None:
            raise SiemConfigError(f"{where}.type must be one of {sorted(_INPUT_PARSERS)}")
        parsed = parser(where, item)
        if isinstance(parsed, FileInput):
            # Un fichero leído por dos entradas entraría dos veces (y con dos offsets).
            for path in parsed.paths:
                if path in seen_files:
                    raise SiemConfigError(f"{where} reads {path} already read by another input")
                seen_files.add(path)
        if isinstance(parsed, SyslogInput):
            # UDP y TCP pueden compartir número de puerto; dos receptores iguales, no.
            kind = "udp" if parsed.protocol == "udp" else "tcp"
            listener = (kind, parsed.bind, parsed.port)
            if listener in seen_listeners:
                raise SiemConfigError(f"{where} reuses {kind} {parsed.bind}:{parsed.port}")
            seen_listeners.add(listener)
        seen_names.add(name)
        inputs.append(parsed)
    if enabled and not inputs:
        raise SiemConfigError("siem.enabled = true needs at least one [[siem.inputs]]")
    return SiemLocalConfig(enabled, tuple(inputs), spool_max_mb)


def _bounded(data: dict[str, Any], key: str, low: int, high: int, default: int) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        return default
    return max(low, min(high, value))


@dataclass(frozen=True)
class SiemServerSource:
    source_id: str
    input: str
    source_type: str
    revision: int


@dataclass(frozen=True)
class SiemServerConfig:
    """Bloque `config.siem` del heartbeat: fuentes que un admin habilitó para ESTE sensor."""

    enabled: bool
    revision: int
    sources: tuple[SiemServerSource, ...]
    max_records_per_batch: int = 1000
    max_batch_bytes: int = 1024 * 1024
    max_record_bytes: int = 16_384
    flush_interval_seconds: int = 5
    spool_max_mb: int = 128
    spool_max_age_hours: int = 24

    def source_for(self, alias: str) -> SiemServerSource | None:
        for source in self.sources:
            if source.input == alias:
                return source
        return None

    @classmethod
    def parse(cls, raw: object) -> "SiemServerConfig | None":
        """None si el servidor no envía SIEM (anterior a 7F) o el bloque no tiene forma."""
        if not isinstance(raw, dict):
            return None
        revision = raw.get("revision")
        items = raw.get("sources")
        if (
            not isinstance(revision, int)
            or isinstance(revision, bool)
            or not isinstance(items, list)
        ):
            return None
        sources: list[SiemServerSource] = []
        seen: set[str] = set()
        for item in items[:MAX_INPUTS]:
            if not isinstance(item, dict):
                continue
            source_id, alias = item.get("source_id"), item.get("input")
            source_type, rev = item.get("source_type"), item.get("revision")
            if (
                isinstance(source_id, str)
                and _UUID_RE.fullmatch(source_id)
                and isinstance(alias, str)
                and SIEM_ALIAS_RE.fullmatch(alias)
                and alias not in seen
                and isinstance(source_type, str)
                and _SOURCE_TYPE_RE.fullmatch(source_type)
                and isinstance(rev, int)
            ):
                seen.add(alias)
                sources.append(SiemServerSource(source_id, alias, source_type, max(0, rev)))
        return cls(
            enabled=raw.get("enabled") is True and bool(sources),
            revision=max(0, revision),
            sources=tuple(sources),
            max_records_per_batch=_bounded(raw, "max_records_per_batch", 10, 5000, 1000),
            max_batch_bytes=_bounded(raw, "max_batch_bytes", 64 * 1024, 16 << 20, 1 << 20),
            max_record_bytes=_bounded(raw, "max_record_bytes", 1024, 65_536, 16_384),
            flush_interval_seconds=_bounded(raw, "flush_interval_seconds", 1, 300, 5),
            spool_max_mb=_bounded(raw, "spool_max_mb", 1, 10_240, 128),
            spool_max_age_hours=_bounded(raw, "spool_max_age_hours", 1, 168, 24),
        )

    def to_json(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        data["sources"] = [dict(source.__dict__) for source in self.sources]
        return data
