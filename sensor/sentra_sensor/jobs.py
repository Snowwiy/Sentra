"""Catálogo cerrado de jobs y validación estricta antes de ejecutar nada.

El sensor está dentro de una red ajena y ejecuta lo que le pide un servidor remoto: si ese
servidor (o alguien con acceso a él) pudiera mandar cualquier cosa, el sensor sería una
puerta de entrada al site. Por eso:

* Solo existe `discovery_basic`. No hay tipos genéricos, ni comandos, ni scripts.
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
KNOWN_JOB_TYPES = frozenset({JOB_TYPE_DISCOVERY_BASIC})

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
    parameters: DiscoveryParameters


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
    if not isinstance(params, dict) or set(params) != PARAMETER_KEYS:
        raise JobRejectedError("invalid_schema", "unexpected or missing parameters")

    network = parse_target(params["target"])
    if not target_allowed(network, config.allowed_networks):
        raise JobRejectedError("target_out_of_scope", "target outside the site's networks")
    if host_count(network) > config.max_hosts_per_job:
        raise JobRejectedError("target_too_large", "target exceeds max_hosts_per_job")

    ports_raw = params["ports"]
    if not isinstance(ports_raw, list):
        raise JobRejectedError("invalid_schema", "ports must be a list")
    if len(ports_raw) > config.max_ports_per_observation:
        raise JobRejectedError("ports_invalid", "too many ports")
    ports = tuple(_int(p, "ports[]", 1, 65_535) for p in ports_raw)
    if len(set(ports)) != len(ports):
        raise JobRejectedError("ports_invalid", "duplicate ports")

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
    return DiscoveryJob(
        job_id=job_id,
        site_id=site_id,
        sensor_id=sensor_id,
        job_type=JOB_TYPE_DISCOVERY_BASIC,
        attempt=attempt,
        created_at=created_at,
        expires_at=expires_at,
        lease_expires_at=lease_expires_at,
        idempotency_key=key,
        parameters=parameters,
    )
