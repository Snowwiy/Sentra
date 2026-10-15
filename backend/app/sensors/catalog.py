"""Catálogo cerrado de lo que un sensor puede declarar y ejecutar (Fase 5F).

El sensor no ejecuta nada que no esté aquí: no existe un tipo de job "comando", "script" ni
"shell" y los parámetros de cada tipo tienen un esquema fijo que validan el servidor (al crear)
y el propio sensor (al recibir). Añadir SNMP, LLDP/CDP o Wi-Fi (fases 6B/6C) será añadir un
tipo y una capacidad nuevos con su validación, nunca un campo libre.
"""

import re

# Tarea de 5F: descubrimiento básico (liveness ICMP/TCP, puertos TCP, ARP, DNS inverso).
DISCOVERY_BASIC = "discovery_basic"
# Fase 6A: descubrimiento avanzado con perfil (quick/standard/deep), esquema versionado
# (app/discovery/profiles.py) y límites explícitos. discovery_basic se mantiene sin cambios
# para los sensores 0.1.x, que no necesitan re-enrolarse.
DISCOVERY_ADVANCED = "discovery_advanced"
JOB_TYPES: frozenset[str] = frozenset({DISCOVERY_BASIC, DISCOVERY_ADVANCED})

ADVANCED_CAPABILITY = "network.discovery.advanced"
# Capacidades que el servidor reconoce. Lo que el sensor declare fuera de esta lista se
# descarta (un sensor no puede "anunciar" snmp para recibir trabajos que aún no existen).
CAPABILITIES: frozenset[str] = frozenset(
    {
        "network.discovery.basic",
        ADVANCED_CAPABILITY,
        "network.arp",
        "network.icmp",
        "network.tcp",
        "network.dns",
    }
)
# Capacidad imprescindible para recibir un job de cada tipo.
REQUIRED_CAPABILITY = {
    DISCOVERY_BASIC: "network.discovery.basic",
    DISCOVERY_ADVANCED: ADVANCED_CAPABILITY,
}

# Versión del runtime sensor/ que acompaña a este servidor.
SENSOR_RUNTIME_VERSION = "0.2.0"

_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def parse_version(value: str | None) -> tuple[int, int, int] | None:
    if not value:
        return None
    match = _VERSION.match(value)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def version_status(value: str | None, minimum: str, recommended: str) -> str:
    """current / outdated / unsupported / unknown. Solo informa: no hay auto-update en 5F."""
    parsed = parse_version(value)
    if parsed is None:
        return "unknown"
    low, rec = parse_version(minimum), parse_version(recommended)
    if low is not None and parsed < low:
        return "unsupported"
    if rec is not None and parsed < rec:
        return "outdated"
    return "current"


def filter_capabilities(declared: list[str] | None) -> list[str]:
    return sorted(set(declared or ()) & CAPABILITIES)
