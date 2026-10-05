"""Configuración de la IA (Fase 4J) derivada de Settings, sin secretos a la vista.

Decide dos cosas que no dependen de ninguna petición:
- si la IA está utilizable (activada, con URL y modelo) y, si no, por qué;
- si el proveedor es local o externo, para aplicar AI_ALLOW_EXTERNAL.

Local/externo se decide por la URL configurada, nunca resolviendo DNS: una IP literal de
loopback, privada o link-local, "localhost" o un nombre listado en AI_LOCAL_HOSTS es local;
cualquier otro nombre se trata como externo (fail closed). Así un nombre público que
resuelve a una IP privada no puede convertir un proveedor externo en "local" por sorpresa.
"""

import ipaddress
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from app.core.config import Settings, parse_name_list

ProviderLocation = Literal["local", "external"]
RedactField = Literal["usernames", "hostnames", "ips", "paths"]


def classify_location(base_url: str, local_hosts: frozenset[str]) -> ProviderLocation:
    host = (urlsplit(base_url).hostname or "").lower()
    if not host:
        return "external"
    if host == "localhost" or host.endswith(".localhost") or host in local_hosts:
        return "local"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "external"
    # Rangos de uso interno; una IP pública siempre es externa.
    if address.is_loopback or address.is_private or address.is_link_local:
        return "local"
    return "external"


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
                classify_location(settings.ai_base_url, local_hosts)
                if settings.ai_base_url
                else None
            ),
            redact=frozenset(parse_name_list(settings.ai_redact.lower())),
            json_mode=settings.ai_json_mode,
            insight_ttl_minutes=settings.ai_insight_ttl_minutes,
            rate_per_user=settings.ai_rate_limit_per_user_per_minute,
            rate_global=settings.ai_rate_limit_global_per_minute,
            max_concurrent=settings.ai_max_concurrent,
            max_retries=settings.ai_max_retries,
        )

    def unavailable_reason(self) -> str | None:
        """Por qué no se puede llamar al modelo (None = utilizable). Texto para la UI."""
        if not self.enabled:
            return "IA no configurada: AI_ENABLED=false."
        if not self.base_url or not self.model:
            return "IA no configurada: faltan AI_BASE_URL o AI_MODEL."
        if self.location == "external" and not self.allow_external:
            return (
                "El proveedor configurado es externo y AI_ALLOW_EXTERNAL=false: "
                "los datos no salen del servidor."
            )
        return None
