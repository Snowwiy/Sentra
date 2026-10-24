"""Política local del helper de aislamiento (isolation.toml).

La escribe un administrador del equipo, no el servidor. Desactivada por defecto. Es la última
palabra: duración máxima, si se permiten los DNS y qué direcciones extra quedan abiertas.
"""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from sentra_agent.isolation.addresses import Network, parse_extra

MAX_MINUTES_LIMIT = 1440
DEFAULT_MAX_MINUTES = 240
_KEYS = {"enabled", "max_minutes", "allow_dns", "extra_allow", "agent_config"}


@dataclass(frozen=True)
class HelperPolicy:
    enabled: bool = False
    max_minutes: int = DEFAULT_MAX_MINUTES
    allow_dns: bool = True
    extra_allow: tuple[Network, ...] = ()
    agent_config: Path | None = None
    extra_allow_text: tuple[str, ...] = field(default=())


class PolicyError(ValueError):
    pass


def parse_policy(text: str) -> HelperPolicy:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"isolation.toml is not valid TOML: {exc}") from exc
    unknown = set(data) - _KEYS
    if unknown:
        raise PolicyError(f"unknown keys in isolation.toml: {sorted(unknown)}")
    enabled = data.get("enabled", False)
    max_minutes = data.get("max_minutes", DEFAULT_MAX_MINUTES)
    allow_dns = data.get("allow_dns", True)
    extra = data.get("extra_allow", [])
    agent_config = data.get("agent_config")
    if not isinstance(enabled, bool) or not isinstance(allow_dns, bool):
        raise PolicyError("enabled and allow_dns must be true or false")
    if isinstance(max_minutes, bool) or not isinstance(max_minutes, int):
        raise PolicyError("max_minutes must be an integer")
    if not 1 <= max_minutes <= MAX_MINUTES_LIMIT:
        raise PolicyError(f"max_minutes must be between 1 and {MAX_MINUTES_LIMIT}")
    if not isinstance(extra, list):
        raise PolicyError("extra_allow must be a list")
    try:
        networks = tuple(parse_extra(extra))
    except ValueError as exc:
        raise PolicyError(str(exc)) from exc
    if agent_config is not None and (not isinstance(agent_config, str) or not agent_config):
        raise PolicyError("agent_config must be a path")
    return HelperPolicy(
        enabled=enabled,
        max_minutes=max_minutes,
        allow_dns=allow_dns,
        extra_allow=networks,
        agent_config=Path(agent_config) if agent_config else None,
        extra_allow_text=tuple(str(e) for e in extra),
    )


def load_policy(path: Path) -> HelperPolicy:
    """Lee la política; sin fichero = desactivado (valores por defecto)."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return HelperPolicy()
    except OSError as exc:
        raise PolicyError(f"cannot read {path}: {exc}") from exc
    return parse_policy(text)


def render_default_policy(agent_config: str) -> str:
    """isolation.toml inicial (desactivado). agent_config va como cadena literal TOML."""
    if "'" in agent_config or "\n" in agent_config:
        raise PolicyError("agent_config path must not contain quotes or newlines")
    return (
        "# Sentra: política local del helper de aislamiento (Fase 6E.7).\n"
        "# Desactivado por defecto. Solo un administrador de ESTE equipo puede activarlo.\n"
        "# Tras cambiarlo, reinicia el helper (sentra-isolation / SentraIsolation).\n"
        "enabled = false\n"
        "# Duración máxima de un aislamiento en minutos (1-1440). El helper revierte solo.\n"
        "max_minutes = 240\n"
        "# Permitir los servidores DNS configurados en el equipo durante el aislamiento.\n"
        "allow_dns = true\n"
        "# Direcciones o redes extra que siguen accesibles (p. ej. un servidor de parches).\n"
        "extra_allow = []\n"
        "# agent.toml del agente: de su api_url sale el servidor Sentra que sigue accesible.\n"
        f"agent_config = '{agent_config}'\n"
    )
