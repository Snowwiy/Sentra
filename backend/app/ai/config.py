"""Configuración de la IA (Fases 4J y 4J.1) derivada de Settings, sin secretos a la vista.

Decide dos cosas que no dependen de ninguna petición:
- si la IA está utilizable (activada, con URL y modelo) y, si no, por qué;
- si el proveedor es local o externo, para aplicar AI_ALLOW_EXTERNAL.

Sentra es local-first (4J.1): el modo recomendado es un servidor de modelos en la misma
máquina o en una LAN privada AUTORIZADA. Local/externo se decide por la URL configurada,
nunca resolviendo DNS (fail closed):
- local: loopback (127.0.0.0/8, ::1), "localhost", una IP dentro de AI_LOCAL_NETWORKS o un
  nombre listado en AI_LOCAL_HOSTS;
- externo: todo lo demás, incluida una IP privada que el admin no autorizó.
Además, el proveedor comprueba la IP real a la que conectó (ver `is_authorized_local_ip`):
un nombre "local" que resuelva fuera de loopback/AI_LOCAL_NETWORKS no recibe ningún dato.
"""

import ipaddress
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from app.core.config import AINetwork, Settings, parse_ai_local_networks, parse_name_list

ProviderLocation = Literal["local", "external"]
RedactField = Literal["usernames", "hostnames", "ips", "paths"]
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _url_host(base_url: str) -> str:
    return (urlsplit(base_url).hostname or "").lower()


def literal_ip(host: str) -> IPAddress | None:
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return None
    # ::ffff:127.0.0.1 es 127.0.0.1: sin esto un IPv4 mapeado esquivaría las reglas.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def is_forbidden_ip(address: IPAddress) -> bool:
    """Destinos que nunca son un servidor de IA legítimo, ni siquiera con AI_ALLOW_EXTERNAL.

    Link-local incluye 169.254.169.254 (metadatos de nube): apuntar ahí la IA sería un SSRF.
    """
    if address.is_loopback:
        # ::1 está dentro de ::/8, que `is_reserved` marca como reservado.
        return False
    return (
        address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
    )


def is_authorized_local_ip(address: str | IPAddress, networks: tuple[AINetwork, ...]) -> bool:
    """IP real que puede recibir datos como proveedor LOCAL: loopback o AI_LOCAL_NETWORKS."""
    ip = literal_ip(address) if isinstance(address, str) else address
    if ip is None or is_forbidden_ip(ip):
        return False
    if ip.is_loopback:
        return True
    return any(ip.version == net.version and ip in net for net in networks)


def classify_location(
    base_url: str,
    local_hosts: frozenset[str],
    local_networks: tuple[AINetwork, ...] = (),
) -> ProviderLocation:
    host = _url_host(base_url)
    if not host:
        return "external"
    if host == "localhost" or host.endswith(".localhost") or host in local_hosts:
        return "local"
    address = literal_ip(host)
    if address is None:
        # Un nombre no listado es externo aunque resuelva a una IP privada.
        return "external"
    return "local" if is_authorized_local_ip(address, local_networks) else "external"


@dataclass(frozen=True)
class AIConfig:
    enabled: bool
    provider: str
    base_url: str | None
    model: str | None
    # El valor se guarda aquí solo para pasarlo al proveedor; __repr__ no lo muestra.
    api_key: str | None
    timeout_seconds: float
    connect_timeout_seconds: float
    read_timeout_seconds: float
    max_context_items: int
    max_output_tokens: int
    allow_external: bool
    location: ProviderLocation | None
    local_networks: tuple[AINetwork, ...]
    redact: frozenset[str]
    json_mode: bool
    insight_ttl_minutes: int
    rate_per_user: int
    rate_global: int
    max_concurrent: int
    max_retries: int

    def __repr__(self) -> str:
        # Nunca imprimir la clave, ni por accidente en un log de depuración.
        return (
            f"AIConfig(enabled={self.enabled}, provider={self.provider!r}, "
            f"model={self.model!r}, location={self.location!r})"
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> "AIConfig":
        key = settings.ai_api_key.get_secret_value() if settings.ai_api_key else ""
        local_hosts = frozenset(h.lower() for h in parse_name_list(settings.ai_local_hosts))
        local_networks = parse_ai_local_networks(settings.ai_local_networks)
        return cls(
            enabled=settings.ai_enabled,
            provider=settings.ai_provider,
            base_url=settings.ai_base_url,
            model=settings.ai_model,
            api_key=key or None,
            timeout_seconds=float(settings.ai_timeout_seconds),
            connect_timeout_seconds=settings.ai_connect_timeout_seconds,
            read_timeout_seconds=settings.ai_read_timeout_seconds,
            max_context_items=settings.ai_max_context_items,
            max_output_tokens=settings.ai_max_output_tokens,
            allow_external=settings.ai_allow_external,
            location=(
                classify_location(settings.ai_base_url, local_hosts, local_networks)
                if settings.ai_base_url
                else None
            ),
            local_networks=local_networks,
            redact=frozenset(parse_name_list(settings.ai_redact.lower())),
            json_mode=settings.ai_json_mode,
            insight_ttl_minutes=settings.ai_insight_ttl_minutes,
            rate_per_user=settings.ai_rate_limit_per_user_per_minute,
            rate_global=settings.ai_rate_limit_global_per_minute,
            max_concurrent=settings.ai_max_concurrent,
            max_retries=settings.ai_max_retries,
        )

    def unavailable_reason(self) -> str | None:
        """Por qué no se puede llamar al modelo (None = utilizable). Texto para la UI.

        Solo mira la configuración: nunca abre conexiones ni resuelve DNS, así que con
        AI_ENABLED=false (o un externo bloqueado) no hay ningún tráfico hacia la IA.
        """
        if not self.enabled:
            return "IA no configurada: AI_ENABLED=false."
        if not self.base_url or not self.model:
            return "IA no configurada: faltan AI_BASE_URL o AI_MODEL."
        return self.destination_blocked_reason()

    def destination_blocked_reason(self) -> str | None:
        """Motivo por el que AI_BASE_URL no puede recibir datos, o None si está permitido."""
        if not self.base_url:
            return "IA no configurada: falta AI_BASE_URL."
        host = _url_host(self.base_url)
        address = literal_ip(host)
        if address is not None and is_forbidden_ip(address):
            return "AI_BASE_URL apunta a una dirección no válida para un servidor de IA."
        if self.location == "local":
            return None
        if not self.allow_external:
            if address is not None and address.is_private:
                return (
                    "AI_BASE_URL es una IP privada fuera de AI_LOCAL_NETWORKS: añade su red "
                    "para usarla como IA local. Mientras tanto se trata como externa y está "
                    "bloqueada (AI_ALLOW_EXTERNAL=false)."
                )
            return (
                "El proveedor configurado es externo y AI_ALLOW_EXTERNAL=false: "
                "los datos no salen del servidor."
            )
        if urlsplit(self.base_url).scheme != "https":
            # Datos de seguridad (y la clave) nunca viajan en claro por Internet.
            return "Un proveedor externo requiere https en AI_BASE_URL."
        return None
