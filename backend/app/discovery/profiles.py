"""Perfiles de Advanced Network Discovery (Fase 6A, docs/advanced-network-discovery.md).

Un perfil es un conjunto cerrado y validado de métodos, puertos y límites. Los tres perfiles
comparten el mismo motor (NetworkScanner en el servidor, Scanner en el sensor): solo cambian
los valores, nunca la forma de sondear. Ninguno es pentesting: TCP connect cerrado al
instante, un eco ICMP del `ping` del sistema, lectura de la tabla ARP y DNS del resolvedor
del sistema. Sin banners, sin fingerprinting, sin UDP genérico, sin SYN scan.

Límites en dos niveles:
- Topes del servidor (`caps`): salen de las variables DISCOVERY_* ya existentes (concurrencia,
  sondas por segundo, hosts por red y duración del job) más unos topes fijos en código para
  lo que no tenía variable (timeouts, reintentos, puertos, consultas DNS). Un perfil nunca
  los supera: sus valores se recortan al resolverlo.
- Ajustes por job (`limits`): solo con el permiso discovery:tune (admin) y siempre por
  debajo de los topes. Un analyst elige perfil y, como mucho, un subconjunto de sus puertos.

El sensor vuelve a validar todo con sus propios topes (defensa en profundidad): que el
servidor tenga un bug no basta para que un sensor sature la red de su site.
"""

from dataclasses import dataclass, replace
from typing import Any

from app.core.config import Settings
from app.discovery.ports import PROFILES as PORT_PROFILES
from app.discovery.scanner import ScanConfig

# Versión del esquema de parámetros de discovery_advanced. El sensor rechaza otra versión:
# un cambio de significado de un campo nunca se interpreta en silencio con el esquema viejo.
ADVANCED_SCHEMA_VERSION = 1

# Topes fijos (sin variable de entorno): por encima de esto un TCP connect o una consulta DNS
# ya no aportan evidencia útil en una red interna y solo alargan el scan.
HARD_MAX_TIMEOUT_MS = 5000
HARD_MAX_DNS_TIMEOUT_MS = 5000
# Reintentos solo de puertos sin respuesta en hosts YA vivos (ver scanner): más de 2 es
# insistir sobre un firewall que descarta, no recuperar paquetes perdidos.
HARD_MAX_TCP_RETRIES = 2
HARD_MAX_PORTS = 256
HARD_MAX_DNS_QUERIES = 4096

PROFILE_NAMES = ("quick", "standard", "deep")
DEFAULT_PROFILE = "standard"

# Ampliado pero acotado: servicios de inventario habituales en redes internas. Sin rangos
# masivos ni puertos "por si acaso".
_DEEP_EXTRA = (
    88,
    111,
    548,
    554,
    636,
    1521,
    1883,
    2049,
    5000,
    5060,
    6379,
    8000,
    8008,
    8888,
    9000,
    9090,
    9200,
    9443,
    10000,
    27017,
)
DEEP_PORTS: tuple[int, ...] = tuple(
    sorted(
        set(PORT_PROFILES["common"])
        | set(PORT_PROFILES["windows"])
        | set(PORT_PROFILES["printers"])
        | set(PORT_PROFILES["web"])
        | set(_DEEP_EXTRA)
    )
)


@dataclass(frozen=True)
class Limits:
    timeout_ms: int
    dns_timeout_ms: int
    concurrency: int
    max_probes_per_second: int
    tcp_retries: int
    max_hosts: int
    max_ports: int
    deadline_minutes: int
    max_dns_queries: int

    def as_dict(self) -> dict[str, int]:
        return {
            "timeout_ms": self.timeout_ms,
            "dns_timeout_ms": self.dns_timeout_ms,
            "concurrency": self.concurrency,
            "max_probes_per_second": self.max_probes_per_second,
            "tcp_retries": self.tcp_retries,
            "max_hosts": self.max_hosts,
            "max_ports": self.max_ports,
            "deadline_minutes": self.deadline_minutes,
            "max_dns_queries": self.max_dns_queries,
        }


# Campos que un admin puede ajustar por job (max_ports y max_dns_queries no: dependen de los
# puertos elegidos y del perfil).
TUNABLE_LIMITS = (
    "timeout_ms",
    "dns_timeout_ms",
    "concurrency",
    "max_probes_per_second",
    "tcp_retries",
    "max_hosts",
    "deadline_minutes",
)


@dataclass(frozen=True)
class ScanProfile:
    name: str
    label: str
    description: str
    ports: tuple[int, ...]
    icmp: bool
    arp: bool
    reverse_dns: bool
    forward_dns: bool
    # Sondas de nombre de la Fase 4E (mDNS/NetBIOS/UPnP): solo en el discovery local; el
    # sensor no las implementa y nunca las anuncia.
    identify: bool
    limits: Limits


def caps(settings: Settings) -> Limits:
    """Topes del servidor: ningún perfil ni ajuste por job los supera."""
    return Limits(
        timeout_ms=HARD_MAX_TIMEOUT_MS,
        dns_timeout_ms=HARD_MAX_DNS_TIMEOUT_MS,
        concurrency=settings.discovery_concurrency,
        max_probes_per_second=settings.discovery_max_probes_per_second,
        tcp_retries=HARD_MAX_TCP_RETRIES,
        max_hosts=settings.discovery_max_hosts_per_network,
        max_ports=HARD_MAX_PORTS,
        deadline_minutes=settings.discovery_job_timeout_minutes,
        max_dns_queries=HARD_MAX_DNS_QUERIES,
    )


def _clip(limits: Limits, top: Limits) -> Limits:
    return Limits(**{k: min(v, getattr(top, k)) for k, v in limits.as_dict().items()})


def profiles(settings: Settings) -> dict[str, ScanProfile]:
    """Los tres perfiles con sus valores efectivos (ya recortados a los topes)."""
    top = caps(settings)
    hosts = top.max_hosts
    base = {
        "quick": ScanProfile(
            name="quick",
            label="Quick",
            description=(
                "Reachability básica (ICMP, ARP y pocos puertos TCP), sin DNS. Bajo consumo."
            ),
            ports=PORT_PROFILES["minimal"],
            icmp=True,
            arp=True,
            reverse_dns=False,
            forward_dns=False,
            identify=False,
            limits=Limits(500, 1000, 32, 100, 0, hosts, 16, 10, 0),
        ),
        "standard": ScanProfile(
            name="standard",
            label="Standard",
            description=(
                "ICMP, TCP connect a puertos habituales, ARP en el segmento local y DNS "
                "inverso con confirmación directa."
            ),
            ports=PORT_PROFILES["common"],
            icmp=True,
            arp=True,
            reverse_dns=True,
            forward_dns=True,
            identify=True,
            limits=Limits(800, 1500, 64, 200, 1, hosts, 64, 30, 2048),
        ),
        "deep": ScanProfile(
            name="deep",
            label="Deep Inventory",
            description=(
                "Conjunto ampliado pero acotado de puertos de inventario, DNS completo y "
                "límites conservadores. No es un escaneo de vulnerabilidades."
            ),
            ports=DEEP_PORTS,
            icmp=True,
            arp=True,
            reverse_dns=True,
            forward_dns=True,
            identify=True,
            limits=Limits(1200, 2000, 32, 100, 1, hosts, 128, 60, 4096),
        ),
    }
    return {name: replace(p, limits=_clip(p.limits, top)) for name, p in base.items()}


class ProfileError(ValueError):
    """Opciones de un job avanzado no válidas. `code` es el código de error de la API."""

    def __init__(self, code: str, message: str, details: list[dict[str, Any]] | None = None):
        super().__init__(message)
        self.code = code
        self.details = details or []


@dataclass(frozen=True)
class ResolvedProfile:
    """Perfil + ajustes del job, validado. Es lo que se guarda en discovery_jobs.parameters."""

    profile: ScanProfile
    ports: tuple[int, ...]
    limits: Limits

    @property
    def name(self) -> str:
        return self.profile.name

    def parameters(self, target: str, *, for_sensor: bool = False) -> dict[str, Any]:
        """Parámetros fijos del job (esquema versionado discovery_advanced v1).

        Los genera el servidor; el sensor los valida con un esquema exacto (sin claves extra).
        """
        limits = self.limits
        params: dict[str, Any] = {
            "schema_version": ADVANCED_SCHEMA_VERSION,
            "profile": self.profile.name,
            "target": target,
            "ports": list(self.ports),
            "timeout_ms": limits.timeout_ms,
            "dns_timeout_ms": limits.dns_timeout_ms,
            "concurrency": limits.concurrency,
            "max_probes_per_second": limits.max_probes_per_second,
            "tcp_retries": limits.tcp_retries,
            "icmp": self.profile.icmp,
            "arp": self.profile.arp,
            "reverse_dns": self.profile.reverse_dns,
            "forward_dns": self.profile.forward_dns,
            "max_dns_queries": limits.max_dns_queries,
            "deadline_seconds": limits.deadline_minutes * 60,
            "max_hosts": limits.max_hosts,
        }
        if not for_sensor:
            params["identify"] = self.profile.identify
        return params


def resolve(
    settings: Settings,
    name: str,
    ports: list[int] | None = None,
    limits: dict[str, int] | None = None,
    *,
    can_tune: bool,
) -> ResolvedProfile:
    """Valida perfil, puertos y límites pedidos. Lanza ProfileError (o PermissionError).

    PermissionError = la petición pide algo que su rol no permite (403 en la API): mejor que
    recortarlo en silencio, porque el operador creería que el scan usó sus valores.
    """
    catalog = profiles(settings)
    profile = catalog.get(name)
    if profile is None:
        raise ProfileError("discovery_profile_invalid", f"Unknown scan profile {name!r}")
    top = caps(settings)
    chosen = profile.ports
    if ports is not None:
        if not ports:
            raise ProfileError("discovery_ports_invalid", "At least one port is required")
        if len(set(ports)) != len(ports) or any(not 1 <= p <= 65535 for p in ports):
            raise ProfileError("discovery_ports_invalid", "Ports must be unique and in 1-65535")
        if len(ports) > top.max_ports:
            raise ProfileError(
                "discovery_limit_exceeded",
                f"At most {top.max_ports} ports per job",
                [{"field": "ports", "max": top.max_ports}],
            )
        outside = sorted(set(ports) - set(profile.ports))
        if outside and not can_tune:
            raise PermissionError("Ports outside the profile require discovery:tune")
        chosen = tuple(sorted(ports))
    effective = profile.limits
    if limits:
        if not can_tune:
            raise PermissionError("Custom scan limits require discovery:tune")
        values = effective.as_dict()
        exceeded = []
        for key, value in limits.items():
            if key not in TUNABLE_LIMITS:
                raise ProfileError("discovery_limit_invalid", f"Unknown limit {key!r}")
            top_value = getattr(top, key)
            if value > top_value:
                exceeded.append({"field": key, "max": top_value})
            values[key] = value
        if exceeded:
            raise ProfileError(
                "discovery_limit_exceeded", "Scan limits above the server caps", exceeded
            )
        effective = Limits(**values)
    # Con puertos a medida (admin) el tope de puertos por host es el número elegido.
    if len(chosen) > effective.max_ports:
        if not can_tune:
            raise ProfileError(
                "discovery_limit_exceeded",
                f"At most {effective.max_ports} ports for this profile",
                [{"field": "ports", "max": effective.max_ports}],
            )
        effective = replace(effective, max_ports=len(chosen))
    return ResolvedProfile(profile=profile, ports=chosen, limits=effective)


def check_scope(resolved: ResolvedProfile, hosts: int) -> None:
    """Una red más grande que el max_hosts efectivo se rechaza entera (no se trunca)."""
    if hosts > resolved.limits.max_hosts:
        raise ProfileError(
            "discovery_scope_too_large",
            f"{hosts} addresses exceed the job limit of {resolved.limits.max_hosts}",
            [{"field": "max_hosts", "max": resolved.limits.max_hosts}],
        )


def scan_config(params: dict[str, Any], server: ScanConfig) -> ScanConfig:
    """ScanConfig del discovery LOCAL a partir de los parámetros guardados en el job.

    Las variables del servidor siguen mandando cuando son más restrictivas: con
    DISCOVERY_ICMP=false, DISCOVERY_REVERSE_DNS=false o DISCOVERY_IDENTIFY=false ningún perfil
    vuelve a activar ese método en el servidor.
    """
    return ScanConfig(
        ports=tuple(int(p) for p in params["ports"]),
        timeout=int(params["timeout_ms"]) / 1000,
        concurrency=int(params["concurrency"]),
        max_rate=float(params["max_probes_per_second"]),
        icmp=bool(params["icmp"]) and server.icmp,
        reverse_dns=bool(params["reverse_dns"]) and server.reverse_dns,
        identify=bool(params.get("identify", False)) and server.identify,
        deadline=float(params["deadline_seconds"]),
        tcp_retries=int(params["tcp_retries"]),
        forward_dns=bool(params["forward_dns"]) and server.reverse_dns,
        dns_timeout=int(params["dns_timeout_ms"]) / 1000,
        max_dns_queries=int(params["max_dns_queries"]),
    )
