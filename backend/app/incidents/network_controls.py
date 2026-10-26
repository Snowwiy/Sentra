"""Solicitudes de control de red (Fase 7A.6): validación del objetivo y puntos de control.

Puro (sin base de datos) para poder probarlo entero. Dos responsabilidades:

1. Normalizar y acotar el objetivo de cada tipo de control. Lo que no se puede describir con
   precisión se rechaza: un bloqueo demasiado amplio (0.0.0.0/0, un /8, un TLD) o ambiguo
   (un comodín en mitad del dominio) no es un control, es un corte de servicio.
2. Decir con honestidad qué puntos de control instalados podrían aplicarlo. Hoy Sentra no
   integra ningún firewall, proxy, resolvedor DNS ni gateway, y el agente no modifica el
   firewall del host (el aislamiento de docs/safe-isolation.md es otro flujo, con su helper
   privilegiado y su doble confirmación). Por eso `enforcement_points` devuelve una lista
   vacía para todos los tipos y la aprobación queda registrada sin ejecutar nada. Cuando
   exista una integración real, se añadirá aquí con su capacidad comprobable.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Literal, cast

# Prefijos mínimos de un bloqueo de direcciones: por debajo se cortaría media Internet o una
# red interna entera, algo que no se pide con una solicitud de control.
MIN_IPV4_PREFIX = 16
MIN_IPV6_PREFIX = 48
MAX_DOMAIN = 253
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_SERVICE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,63}$")
DIRECTIONAL = frozenset({"block_port", "block_service", "block_address"})
Direction = Literal["inbound", "outbound", "both"]


class ControlTargetError(ValueError):
    """El objetivo no es válido para el tipo de control (422 en la API)."""


def _port(value: Any, field: str = "port") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ControlTargetError(f"{field} must be an integer between 1 and 65535")
    return value


def _domain(value: Any, field: str = "domain", wildcard: bool = False) -> str:
    """Dominio en minúsculas y ASCII (IDNA). Solo `*.` al principio si se permite."""
    if not isinstance(value, str) or not value.strip():
        raise ControlTargetError(f"{field} is required")
    text = value.strip().lower().rstrip(".")
    prefix = ""
    if text.startswith("*."):
        if not wildcard:
            raise ControlTargetError(f"{field} cannot be a wildcard")
        prefix, text = "*.", text[2:]
    try:
        ascii_name = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ControlTargetError(f"{field} is not a valid domain") from exc
    labels = ascii_name.split(".")
    if len(ascii_name) > MAX_DOMAIN or len(labels) < 2:
        # Un TLD o un nombre de una sola etiqueta bloquearía demasiado o no es un dominio.
        raise ControlTargetError(f"{field} must be a fully qualified domain name")
    if not all(_LABEL.match(label) for label in labels):
        raise ControlTargetError(f"{field} is not a valid domain")
    if labels[-1].isdigit():
        raise ControlTargetError(f"{field} must be a domain, not an IP address")
    return prefix + ascii_name


def _network(value: Any) -> str:
    if not isinstance(value, str):
        raise ControlTargetError("cidr is required")
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ControlTargetError("cidr is not a valid address or network") from exc
    minimum = MIN_IPV4_PREFIX if network.version == 4 else MIN_IPV6_PREFIX
    if network.prefixlen < minimum:
        raise ControlTargetError(f"cidr is too broad (minimum /{minimum})")
    if (
        network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.is_unspecified
    ):
        raise ControlTargetError("cidr cannot be loopback, link-local, multicast or unspecified")
    return str(network)


def normalize_target(control_type: str, target: dict[str, Any]) -> dict[str, Any]:
    """Objetivo validado y normalizado. Claves exactas por tipo (nada extra se guarda)."""
    allowed: dict[str, set[str]] = {
        "block_port": {"port", "protocol"},
        "block_service": {"service", "port"},
        "block_address": {"cidr"},
        "block_domain": {"domain"},
        "restrict_site_access": {"domain"},
        "prevent_upload": {"destination"},
    }
    if control_type not in allowed:
        raise ControlTargetError("unknown control type")
    extra = set(target) - allowed[control_type]
    if extra:
        raise ControlTargetError("unexpected target keys: " + ", ".join(sorted(extra)))
    if control_type == "block_port":
        protocol = target.get("protocol")
        if protocol not in ("tcp", "udp"):
            raise ControlTargetError("protocol must be tcp or udp")
        return {"port": _port(target.get("port")), "protocol": protocol}
    if control_type == "block_service":
        service = target.get("service")
        if not isinstance(service, str) or not _SERVICE.match(service.strip().lower()):
            raise ControlTargetError("service must be a short service name (e.g. smb, rdp)")
        normalized: dict[str, Any] = {"service": service.strip().lower()}
        if target.get("port") is not None:
            normalized["port"] = _port(target.get("port"))
        return normalized
    if control_type == "block_address":
        return {"cidr": _network(target.get("cidr"))}
    if control_type == "block_domain":
        return {"domain": _domain(target.get("domain"), wildcard=True)}
    if control_type == "restrict_site_access":
        return {"domain": _domain(target.get("domain"), wildcard=True)}
    return {"destination": _domain(target.get("destination"), "destination", wildcard=True)}


def check_direction(control_type: str, direction: str | None) -> Direction | None:
    """Puertos, servicios y direcciones necesitan sentido; dominios y subidas son salientes."""
    if control_type in DIRECTIONAL:
        if direction not in ("inbound", "outbound", "both"):
            raise ControlTargetError("direction must be inbound, outbound or both")
        return cast(Direction, direction)
    if direction not in (None, "outbound"):
        raise ControlTargetError("this control only applies to outbound traffic")
    return None


@dataclass(frozen=True)
class Requirement:
    """Qué haría falta para aplicar un tipo de control y por qué no basta con menos."""

    needs: str
    note: str


REQUIREMENTS: dict[str, Requirement] = {
    "block_port": Requirement(
        "Firewall gestionable (del host o perimetral) integrado con Sentra.",
        "El agente de Sentra no modifica el firewall; el aislamiento es un flujo aparte que "
        "corta todo el tráfico salvo Sentra, no un puerto concreto.",
    ),
    "block_service": Requirement(
        "Firewall gestionable o gestión de servicios del host integrada con Sentra.",
        "Un servicio puede escuchar en puertos distintos: el control necesita saber cuál.",
    ),
    "block_address": Requirement(
        "Firewall gestionable (del host o perimetral) integrado con Sentra.",
        "Una dirección compartida (CDN, NAT) puede bloquear más de lo previsto.",
    ),
    "block_domain": Requirement(
        "Resolvedor DNS o proxy integrado con Sentra.",
        "Un bloqueo solo por DNS se salta con DNS cifrado (DoH/DoT) o conectando por IP.",
    ),
    "restrict_site_access": Requirement(
        "Proxy web o gateway con filtrado por dominio integrado con Sentra.",
        "DNS solo no distingue rutas ni usuarios; el filtrado por sitio necesita un proxy.",
    ),
    "prevent_upload": Requirement(
        "Proxy con inspección, gateway/DLP o un agente con control de subidas.",
        "DNS por sí solo no distingue una subida de una descarga hacia el mismo destino.",
    ),
}


def enforcement_points(control_type: str) -> list[str]:
    """Puntos de control instalados capaces de aplicar este tipo. Ninguno en 7A."""
    if control_type not in REQUIREMENTS:
        raise ControlTargetError("unknown control type")
    return []


def evaluate(control_type: str) -> dict[str, Any]:
    """Resultado guardado al aprobar: puntos disponibles y qué haría falta si no hay."""
    requirement = REQUIREMENTS[control_type]
    points = enforcement_points(control_type)
    return {
        "points": points,
        "applied_by_sentra": False,
        "needs": requirement.needs,
        "note": requirement.note,
    }
