"""Tipos del protocolo que el sensor recibe del servidor, con validación defensiva.

Aunque el servidor es la autoridad, sus respuestas se validan: un proxy roto, una versión
incompatible o un servidor comprometido no deben poder poner al sensor en un estado absurdo
(p. ej. 0 s de intervalo = busy loop, o concurrencia 10^6).
"""

import ipaddress
from dataclasses import dataclass
from typing import Any

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ProtocolError(ValueError):
    """Respuesta del servidor con forma inesperada."""


def _int(data: dict[str, Any], key: str, low: int, high: int) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProtocolError(f"config.{key} must be an integer")
    # Se acota en lugar de rechazar: mejor un valor sensato que dejar de funcionar.
    return max(low, min(high, value))


def _opt_int(data: dict[str, Any], key: str, low: int, high: int, default: int) -> int:
    """Clave nueva de la Fase 6A: un servidor anterior no la envía y se usa `default`."""
    if key not in data:
        return default
    return _int(data, key, low, high)


@dataclass(frozen=True)
class ServerConfig:
    site_id: str
    site_name: str
    allowed_networks: tuple[IPNetwork, ...]
    jobs_enabled: bool
    heartbeat_interval_seconds: int
    poll_interval_seconds: int
    max_observations_per_batch: int
    max_batch_bytes: int
    max_ports_per_observation: int
    max_hosts_per_job: int
    max_concurrency: int
    max_probes_per_second: int
    max_timeout_ms: int
    # Fase 6A: topes de discovery_advanced. Con un servidor 5F (sin estas claves) quedan en
    # valores que no permiten nada más que lo básico (0 reintentos, 0 consultas DNS).
    advanced_max_timeout_ms: int = 0
    max_dns_timeout_ms: int = 0
    max_tcp_retries: int = 0
    max_dns_queries: int = 0
    advanced_max_ports: int = 0
    max_deadline_seconds: int = 0

    @classmethod
    def parse(cls, data: object) -> "ServerConfig":
        if not isinstance(data, dict):
            raise ProtocolError("config must be an object")
        networks_raw = data.get("allowed_networks")
        if not isinstance(networks_raw, list):
            raise ProtocolError("config.allowed_networks must be a list")
        networks: list[IPNetwork] = []
        for item in networks_raw:
            if not isinstance(item, str):
                raise ProtocolError("config.allowed_networks items must be strings")
            try:
                network = ipaddress.ip_network(item, strict=True)
            except ValueError as exc:
                raise ProtocolError(f"invalid allowed network {item!r}") from exc
            # Nunca se acepta /0 como red permitida, venga de donde venga.
            if network.prefixlen == 0:
                raise ProtocolError("allowed network /0 is not acceptable")
            networks.append(network)
        jobs_enabled = data.get("jobs_enabled")
        if not isinstance(jobs_enabled, bool):
            raise ProtocolError("config.jobs_enabled must be a boolean")
        return cls(
            site_id=str(data.get("site_id") or ""),
            site_name=str(data.get("site_name") or ""),
            allowed_networks=tuple(networks),
            jobs_enabled=jobs_enabled,
            heartbeat_interval_seconds=_int(data, "heartbeat_interval_seconds", 5, 3600),
            poll_interval_seconds=_int(data, "poll_interval_seconds", 5, 3600),
            max_observations_per_batch=_int(data, "max_observations_per_batch", 1, 10_000),
            max_batch_bytes=_int(data, "max_batch_bytes", 1024, 16 * 1024 * 1024),
            max_ports_per_observation=_int(data, "max_ports_per_observation", 1, 65_535),
            max_hosts_per_job=_int(data, "max_hosts_per_job", 1, 1 << 20),
            max_concurrency=_int(data, "max_concurrency", 1, 4096),
            max_probes_per_second=_int(data, "max_probes_per_second", 1, 100_000),
            max_timeout_ms=_int(data, "max_timeout_ms", 50, 120_000),
            advanced_max_timeout_ms=_opt_int(data, "advanced_max_timeout_ms", 50, 10_000, 0),
            max_dns_timeout_ms=_opt_int(data, "max_dns_timeout_ms", 50, 10_000, 0),
            max_tcp_retries=_opt_int(data, "max_tcp_retries", 0, 3, 0),
            max_dns_queries=_opt_int(data, "max_dns_queries", 0, 100_000, 0),
            advanced_max_ports=_opt_int(data, "advanced_max_ports", 1, 1024, 0),
            max_deadline_seconds=_opt_int(data, "max_deadline_seconds", 60, 86_400, 0),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "site_name": self.site_name,
            "allowed_networks": [str(n) for n in self.allowed_networks],
            "jobs_enabled": self.jobs_enabled,
            "heartbeat_interval_seconds": self.heartbeat_interval_seconds,
            "poll_interval_seconds": self.poll_interval_seconds,
            "max_observations_per_batch": self.max_observations_per_batch,
            "max_batch_bytes": self.max_batch_bytes,
            "max_ports_per_observation": self.max_ports_per_observation,
            "max_hosts_per_job": self.max_hosts_per_job,
            "max_concurrency": self.max_concurrency,
            "max_probes_per_second": self.max_probes_per_second,
            "max_timeout_ms": self.max_timeout_ms,
            "advanced_max_timeout_ms": self.advanced_max_timeout_ms,
            "max_dns_timeout_ms": self.max_dns_timeout_ms,
            "max_tcp_retries": self.max_tcp_retries,
            "max_dns_queries": self.max_dns_queries,
            "advanced_max_ports": self.advanced_max_ports,
            "max_deadline_seconds": self.max_deadline_seconds,
        }
