"""Catálogo cerrado de jobs y validación estricta antes de ejecutar nada.

El sensor está dentro de una red ajena y ejecuta lo que le pide un servidor remoto: si ese
servidor (o alguien con acceso a él) pudiera mandar cualquier cosa, el sensor sería una
puerta de entrada al site. Por eso:

* Solo existen `discovery_basic`, (Fase 6A) `discovery_advanced` y (Fase 6B) `snmp_inventory`
  de solo lectura. No hay tipos genéricos, ni comandos, ni scripts, ni binarios enviados por
  el servidor, ni OIDs: un job SNMP solo nombra módulos del catálogo del propio sensor.
* El esquema es exacto: claves desconocidas = rechazo (un campo nuevo no se ignora en
  silencio, porque podría cambiar el significado del job).
* El target se vuelve a comprobar contra las redes permitidas que mandó el servidor
  (defensa en profundidad: el servidor ya lo valida, pero un bug allí no debe bastar).
"""

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sentra_sensor.protocol import IPNetwork, ServerConfig

JOB_TYPE_DISCOVERY_BASIC = "discovery_basic"
JOB_TYPE_DISCOVERY_ADVANCED = "discovery_advanced"
JOB_TYPE_SNMP_INVENTORY = "snmp_inventory"
KNOWN_JOB_TYPES = frozenset(
    {JOB_TYPE_DISCOVERY_BASIC, JOB_TYPE_DISCOVERY_ADVANCED, JOB_TYPE_SNMP_INVENTORY}
)
SNMP_SCHEMA_VERSION = 1
SNMP_MODULES = ("system", "entity", "interfaces", "lldp", "cdp", "bridge", "vlan")
SNMP_AUTH_PROTOCOLS = frozenset({"sha", "sha224", "sha256", "sha384", "sha512"})
SNMP_PRIV_PROTOCOLS = frozenset({"aes128", "aes192", "aes256"})
SNMP_PARAMETER_KEYS = frozenset(
    {
        "schema_version",
        "target",
        "port",
        "snmp_version",
        "profile_id",
        "secret_revision",
        "auth_protocol",
        "priv_protocol",
        "modules",
        "timeout_ms",
        "retries",
        "max_repetitions",
        "max_varbinds",
        "max_rows_per_table",
        "deadline_seconds",
    }
)
# Única versión del esquema de discovery_advanced que entiende este sensor.
ADVANCED_SCHEMA_VERSION = 1
ADVANCED_PROFILES = frozenset({"quick", "standard", "deep"})

JOB_KEYS = frozenset(
    {
        "job_id",
        "site_id",
        "sensor_id",
        "job_type",
        "parameters",
        "created_at",
        "expires_at",
        "lease_expires_at",
        "attempt",
        "idempotency_key",
    }
)
PARAMETER_KEYS = frozenset(
    {
        "target",
        "ports",
        "timeout_ms",
        "concurrency",
        "max_probes_per_second",
        "icmp",
        "reverse_dns",
        "arp",
        "deadline_seconds",
    }
)
ADVANCED_PARAMETER_KEYS = frozenset(
    {
        "schema_version",
        "profile",
        "target",
        "ports",
        "timeout_ms",
        "dns_timeout_ms",
        "concurrency",
        "max_probes_per_second",
        "tcp_retries",
        "icmp",
        "arp",
        "reverse_dns",
        "forward_dns",
        "max_dns_queries",
        "deadline_seconds",
        "max_hosts",
    }
)
MAX_DEADLINE_SECONDS = 24 * 3600


class JobRejectedError(Exception):
    """El job no supera la validación: NO se ejecuta y se informa como failed."""

    def __init__(
        self, code: str, detail: str, job_id: str | None = None, attempt: int | None = None
    ) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.job_id = job_id
        self.attempt = attempt

    @property
    def short_error(self) -> str:
        # Mensaje corto y sin datos del servidor reflejados de forma arbitraria.
        return f"job_rejected:{self.code}"


@dataclass(frozen=True)
class DiscoveryParameters:
    target: IPNetwork
    ports: tuple[int, ...]
    timeout_ms: int
    concurrency: int
    max_probes_per_second: int
    icmp: bool
    reverse_dns: bool
    arp: bool
    deadline_seconds: int
    # Fase 6A (solo discovery_advanced). Los valores por defecto son exactamente el
    # comportamiento básico: sin reintentos, sin DNS directo y sin presupuesto DNS.
    profile: str | None = None
    tcp_retries: int = 0
    forward_dns: bool = False
    dns_timeout_ms: int | None = None
    max_dns_queries: int | None = None


@dataclass(frozen=True)
class SnmpParameters:
    """snmp_inventory v1: sin secretos ni OIDs (la credencial llega aparte, en el start)."""

    target: IPNetwork
    port: int
    snmp_version: str
    profile_id: str
    secret_revision: int
    auth_protocol: str | None
    priv_protocol: str | None
    modules: tuple[str, ...]
    timeout_ms: int
    retries: int
    max_repetitions: int
    max_varbinds: int
    max_rows_per_table: int
    deadline_seconds: int

    @property
    def address(self) -> str:
        return str(self.target.network_address)


@dataclass(frozen=True)
class DiscoveryJob:
    job_id: str
    site_id: str
    sensor_id: str
    job_type: str
    attempt: int
    created_at: datetime
    expires_at: datetime
    lease_expires_at: datetime | None
    idempotency_key: str
    parameters: DiscoveryParameters | SnmpParameters


def host_count(network: IPNetwork) -> int:
    """Número de direcciones que devuelve network.hosts(), sin enumerarlas."""
    total = network.num_addresses
    if network.version == 4:
        return total if network.prefixlen >= 31 else total - 2
    return total if network.prefixlen >= 127 else total - 1


def parse_target(target: object) -> IPNetwork:
    """CIDR estricto (sin bits de host). Una IP suelta se acepta como /32 o /128."""
    if not isinstance(target, str) or not 1 <= len(target) <= 64:
        raise JobRejectedError("target_invalid", "target must be a CIDR string")
    try:
        network = ipaddress.ip_network(target.strip(), strict=True)
    except ValueError as exc:
        raise JobRejectedError("target_invalid", "target is not a valid CIDR") from exc
    if network.prefixlen == 0:
        raise JobRejectedError("target_invalid", "/0 targets are never allowed")
    if network.is_multicast or network.is_unspecified:
        raise JobRejectedError("target_invalid", "multicast/unspecified targets are not allowed")
    return network


def target_allowed(network: IPNetwork, allowed: tuple[IPNetwork, ...]) -> bool:
    for candidate in allowed:
        if candidate.version == network.version and network.subnet_of(candidate):  # type: ignore[arg-type]
            return True
    return False


def _datetime(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise JobRejectedError("invalid_schema", f"{field} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise JobRejectedError("invalid_schema", f"{field} is not ISO-8601") from exc
    if parsed.tzinfo is None:
        raise JobRejectedError("invalid_schema", f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _int(value: object, field: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise JobRejectedError("invalid_schema", f"{field} must be an integer")
    if not low <= value <= high:
        raise JobRejectedError("invalid_schema", f"{field} out of range [{low}, {high}]")
    return value


def _bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise JobRejectedError("invalid_schema", f"{field} must be a boolean")
    return value


def _uuid(value: object, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except ValueError as exc:
        raise JobRejectedError("invalid_schema", f"{field} must be a UUID") from exc


def validate_job(
    raw: object,
    *,
    sensor_id: str,
    site_id: str,
    config: ServerConfig,
    now: datetime,
) -> DiscoveryJob:
    """Valida un SensorJobOut. Lanza JobRejectedError con job_id/attempt si se conocen."""
    if not isinstance(raw, dict):
        raise JobRejectedError("invalid_schema", "job must be an object")
    # Se extraen primero job_id y attempt (si son válidos) para poder informar el rechazo.
    job_id: str | None = None
    attempt: int | None = None
    try:
        job_id = _uuid(raw.get("job_id"), "job_id")
        attempt = _int(raw.get("attempt"), "attempt", 1, 1000)
    except JobRejectedError:
        pass
    try:
        return _validate(raw, job_id, attempt, sensor_id, site_id, config, now)
    except JobRejectedError as exc:
        exc.job_id, exc.attempt = job_id, attempt
        raise


def _validate(
    raw: dict[str, Any],
    job_id: str | None,
    attempt: int | None,
    sensor_id: str,
    site_id: str,
    config: ServerConfig,
    now: datetime,
) -> DiscoveryJob:
    if raw.get("job_type") not in KNOWN_JOB_TYPES:
        raise JobRejectedError("unknown_job_type", "job type is not in the sensor catalog")
    extra = set(raw) - JOB_KEYS
    missing = (JOB_KEYS - {"lease_expires_at"}) - set(raw)
    if extra or missing:
        raise JobRejectedError("invalid_schema", "unexpected or missing job fields")
    if job_id is None or attempt is None:
        raise JobRejectedError("invalid_schema", "job_id/attempt invalid")
    if _uuid(raw["sensor_id"], "sensor_id") != str(uuid.UUID(sensor_id)):
        raise JobRejectedError("wrong_sensor", "job addressed to another sensor")
    if _uuid(raw["site_id"], "site_id") != str(uuid.UUID(site_id)):
        raise JobRejectedError("wrong_site", "job belongs to another site")
    created_at = _datetime(raw["created_at"], "created_at")
    expires_at = _datetime(raw["expires_at"], "expires_at")
    lease = raw.get("lease_expires_at")
    lease_expires_at = None if lease is None else _datetime(lease, "lease_expires_at")
    if expires_at <= now:
        raise JobRejectedError("expired", "job already expired")
    key = raw["idempotency_key"]
    if not isinstance(key, str) or not 1 <= len(key) <= 200:
        raise JobRejectedError("invalid_schema", "idempotency_key invalid")
    params = raw["parameters"]
    job_type = str(raw["job_type"])
    parameters: DiscoveryParameters | SnmpParameters
    if job_type == JOB_TYPE_SNMP_INVENTORY:
        parameters = _snmp(params, config)
    elif job_type == JOB_TYPE_DISCOVERY_ADVANCED:
        parameters = _advanced(params, config)
    else:
        parameters = _basic(params, config)
    return DiscoveryJob(
        job_id=job_id,
        site_id=site_id,
        sensor_id=sensor_id,
        job_type=job_type,
        attempt=attempt,
        created_at=created_at,
        expires_at=expires_at,
        lease_expires_at=lease_expires_at,
        idempotency_key=key,
        parameters=parameters,
    )


def _target_and_ports(
    params: dict[str, Any], config: ServerConfig, max_hosts: int, max_ports: int
) -> tuple[IPNetwork, tuple[int, ...]]:
    network = parse_target(params["target"])
    if not target_allowed(network, config.allowed_networks):
        raise JobRejectedError("target_out_of_scope", "target outside the site's networks")
    if host_count(network) > max_hosts:
        raise JobRejectedError("target_too_large", "target exceeds max_hosts_per_job")
    ports_raw = params["ports"]
    if not isinstance(ports_raw, list):
        raise JobRejectedError("invalid_schema", "ports must be a list")
    if len(ports_raw) > max_ports:
        raise JobRejectedError("ports_invalid", "too many ports")
    ports = tuple(_int(p, "ports[]", 1, 65_535) for p in ports_raw)
    if len(set(ports)) != len(ports):
        raise JobRejectedError("ports_invalid", "duplicate ports")
    return network, ports


def _advanced(params: object, config: ServerConfig) -> DiscoveryParameters:
    """discovery_advanced v1: esquema exacto y cada límite contra los topes del servidor.

    Si el servidor es anterior a 6A (sin topes avanzados en la config), los topes valen 0 y
    cualquier job avanzado se rechaza: el sensor nunca supone límites que nadie le dio.
    """
    if not isinstance(params, dict) or set(params) != ADVANCED_PARAMETER_KEYS:
        raise JobRejectedError("invalid_schema", "unexpected or missing parameters")
    if params["schema_version"] != ADVANCED_SCHEMA_VERSION or isinstance(
        params["schema_version"], bool
    ):
        raise JobRejectedError("schema_unsupported", "unsupported discovery_advanced schema")
    if params["profile"] not in ADVANCED_PROFILES:
        raise JobRejectedError("invalid_schema", "unknown scan profile")
    if config.advanced_max_timeout_ms <= 0 or config.advanced_max_ports <= 0:
        raise JobRejectedError("advanced_not_configured", "server sent no advanced limits")
    max_hosts = _int(params["max_hosts"], "max_hosts", 1, config.max_hosts_per_job)
    network, ports = _target_and_ports(params, config, max_hosts, config.advanced_max_ports)
    deadline_cap = config.max_deadline_seconds or MAX_DEADLINE_SECONDS
    parameters = DiscoveryParameters(
        target=network,
        ports=ports,
        timeout_ms=_int(params["timeout_ms"], "timeout_ms", 50, config.advanced_max_timeout_ms),
        concurrency=_int(params["concurrency"], "concurrency", 1, config.max_concurrency),
        max_probes_per_second=_int(
            params["max_probes_per_second"],
            "max_probes_per_second",
            1,
            config.max_probes_per_second,
        ),
        icmp=_bool(params["icmp"], "icmp"),
        reverse_dns=_bool(params["reverse_dns"], "reverse_dns"),
        arp=_bool(params["arp"], "arp"),
        deadline_seconds=_int(
            params["deadline_seconds"],
            "deadline_seconds",
            1,
            min(deadline_cap, MAX_DEADLINE_SECONDS),
        ),
        profile=str(params["profile"]),
        tcp_retries=_int(params["tcp_retries"], "tcp_retries", 0, config.max_tcp_retries),
        forward_dns=_bool(params["forward_dns"], "forward_dns"),
        dns_timeout_ms=_int(
            params["dns_timeout_ms"], "dns_timeout_ms", 50, max(50, config.max_dns_timeout_ms)
        ),
        max_dns_queries=_int(
            params["max_dns_queries"], "max_dns_queries", 0, config.max_dns_queries
        ),
    )
    if parameters.forward_dns and not parameters.reverse_dns:
        raise JobRejectedError("invalid_schema", "forward_dns requires reverse_dns")
    if not (parameters.ports or parameters.icmp or parameters.arp):
        raise JobRejectedError("invalid_schema", "job has no probe method")
    return parameters


def _basic(params: object, config: ServerConfig) -> DiscoveryParameters:
    if not isinstance(params, dict) or set(params) != PARAMETER_KEYS:
        raise JobRejectedError("invalid_schema", "unexpected or missing parameters")

    network, ports = _target_and_ports(
        params, config, config.max_hosts_per_job, config.max_ports_per_observation
    )

    parameters = DiscoveryParameters(
        target=network,
        ports=ports,
        timeout_ms=_int(params["timeout_ms"], "timeout_ms", 50, config.max_timeout_ms),
        concurrency=_int(params["concurrency"], "concurrency", 1, config.max_concurrency),
        max_probes_per_second=_int(
            params["max_probes_per_second"],
            "max_probes_per_second",
            1,
            config.max_probes_per_second,
        ),
        icmp=_bool(params["icmp"], "icmp"),
        reverse_dns=_bool(params["reverse_dns"], "reverse_dns"),
        arp=_bool(params["arp"], "arp"),
        deadline_seconds=_int(
            params["deadline_seconds"], "deadline_seconds", 1, MAX_DEADLINE_SECONDS
        ),
    )
    if not (parameters.ports or parameters.icmp or parameters.arp):
        raise JobRejectedError("invalid_schema", "job has no probe method")
    return parameters


def _snmp(params: object, config: ServerConfig) -> SnmpParameters:
    """snmp_inventory v1: esquema exacto, una sola dirección dentro de las redes del site y
    solo módulos y protocolos del catálogo. Sin pysnmp instalado se rechaza (el sensor no
    declara snmp.* en ese caso, así que un servidor correcto nunca lo envía)."""
    from sentra_sensor import snmp

    if not isinstance(params, dict) or set(params) != SNMP_PARAMETER_KEYS:
        raise JobRejectedError("invalid_schema", "unexpected or missing parameters")
    if params["schema_version"] != SNMP_SCHEMA_VERSION or isinstance(
        params["schema_version"], bool
    ):
        raise JobRejectedError("schema_unsupported", "unsupported snmp_inventory schema")
    if not snmp.snmp_available():
        raise JobRejectedError("snmp_unavailable", "SNMP support is not installed")
    network = parse_target(params["target"])
    if network.num_addresses != 1:
        raise JobRejectedError("target_invalid", "SNMP target must be a single address")
    if not target_allowed(network, config.allowed_networks):
        raise JobRejectedError("target_out_of_scope", "target outside the site's networks")
    version = params["snmp_version"]
    auth, priv = params["auth_protocol"], params["priv_protocol"]
    if version == "v3":
        if not snmp.v3_available():
            raise JobRejectedError("snmp_unavailable", "SNMPv3 needs the cryptography package")
        if auth not in SNMP_AUTH_PROTOCOLS or priv not in SNMP_PRIV_PROTOCOLS:
            raise JobRejectedError("invalid_schema", "SNMPv3 requires SHA auth and AES privacy")
    elif version == "v2c":
        if auth is not None or priv is not None:
            raise JobRejectedError("invalid_schema", "SNMPv2c has no auth/priv protocols")
    else:
        # SNMPv1 o cualquier otra cosa: nunca.
        raise JobRejectedError("invalid_schema", "unsupported SNMP version")
    modules_raw = params["modules"]
    if not isinstance(modules_raw, list) or not modules_raw:
        raise JobRejectedError("invalid_schema", "modules must be a non-empty list")
    if any(m not in SNMP_MODULES for m in modules_raw) or len(set(modules_raw)) != len(modules_raw):
        raise JobRejectedError("invalid_schema", "unknown or duplicate SNMP module")
    if "system" not in modules_raw or ("vlan" in modules_raw and "bridge" not in modules_raw):
        raise JobRejectedError("invalid_schema", "system is mandatory and vlan needs bridge")
    modules = tuple(m for m in SNMP_MODULES if m in modules_raw)
    return SnmpParameters(
        target=network,
        port=_int(params["port"], "port", 1, 65_535),
        snmp_version=str(version),
        profile_id=_uuid(params["profile_id"], "profile_id"),
        secret_revision=_int(params["secret_revision"], "secret_revision", 1, 2**31 - 1),
        auth_protocol=str(auth) if auth is not None else None,
        priv_protocol=str(priv) if priv is not None else None,
        modules=modules,
        timeout_ms=_int(params["timeout_ms"], "timeout_ms", 200, 10_000),
        retries=_int(params["retries"], "retries", 0, 3),
        max_repetitions=_int(params["max_repetitions"], "max_repetitions", 1, 50),
        max_varbinds=_int(params["max_varbinds"], "max_varbinds", 100, 500_000),
        max_rows_per_table=_int(params["max_rows_per_table"], "max_rows_per_table", 10, 100_000),
        deadline_seconds=_int(params["deadline_seconds"], "deadline_seconds", 10, 3600),
    )
