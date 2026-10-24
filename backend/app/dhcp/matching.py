"""Asociación lease DHCP → activo (Fase 6E.2, docs/dhcp-identity.md).

Funciones puras: el servicio carga los candidatos y aplica la conclusión. Reglas:

1. Solo activos del mismo site y no archivados (el servicio filtra).
2. Lease activo con MAC e IP iguales a las del activo → `mac_ip`, confianza alta. Es la única
   asociación que puede dar nombre.
3. Misma MAC, IP distinta → `mac_moved`, confianza media: el lease se enlaza al activo como
   evidencia, pero no le da nombre (la IP del lease puede ser antigua o de otra red).
4. Solo IP → `ip_only`, sin activo: una IP se reasigna y no identifica a nadie.
5. MAC aleatoria (bit de administración local) sin coincidencia exacta de MAC e IP →
   `randomized_mac`, sin activo: los móviles cambian de MAC por red o por día.
6. Varios activos con la misma MAC → `ambiguous`, sin activo. Nunca se fusionan activos.
7. Lease caducado o liberado → `expired`, sin activo.

El nombre que aporta un lease `mac_ip` se descarta además si es genérico ("android",
"iphone", "localhost"...) o si la misma fuente lo da a la vez a varias MACs: un nombre
repetido no distingue a un equipo de otro.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass

from app.discovery import oui
from app.discovery.classify import is_default_name

# Nombres por defecto de móviles y tablets que no figuran en la lista general de classify
# (allí "iphone" es una pista de tipo, no un nombre por defecto de SO).
_DHCP_GENERIC = re.compile(
    r"^(localhost|unknown|none|\*|iphone|ipad|android-?[0-9a-f]{0,16}|galaxy|"
    r"dhcp[-_.]?\d.*|host[-_]?\d.*|client[-_]?\d.*)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class AssetCandidate:
    id: int
    mac: str | None
    ip: str | None


@dataclass(frozen=True)
class MatchResult:
    match: str
    asset_id: int | None
    confidence: str | None

    @property
    def names_asset(self) -> bool:
        return self.match == "mac_ip"


def usable_hostname(hostname: str | None) -> bool:
    if not hostname:
        return False
    bare = hostname.strip().rstrip(".").split(".", 1)[0]
    return bool(bare) and not is_default_name(bare) and _DHCP_GENERIC.match(bare) is None


def match_lease(*, ip: str, mac: str, state: str, by_mac: Sequence[AssetCandidate]) -> MatchResult:
    """Conclusión para un lease. `by_mac`: activos del site con esa MAC."""
    if state in ("expired", "released"):
        return MatchResult("expired", None, None)
    exact = [a for a in by_mac if a.ip == ip]
    if len(by_mac) > 1:
        # Dos activos con la misma MAC ya son un duplicado (lo resuelve 5C.2 con revisión
        # humana); el lease no decide cuál es el bueno.
        return MatchResult("ambiguous", None, None)
    if len(exact) == 1:
        return MatchResult("mac_ip", exact[0].id, "high")
    if oui.is_locally_administered(mac):
        return MatchResult("randomized_mac", None, None)
    if len(by_mac) == 1:
        return MatchResult("mac_moved", by_mac[0].id, "medium")
    return MatchResult("no_asset", None, None)


def ip_only(match: MatchResult, ip_has_asset: bool) -> MatchResult:
    """Sin activo por MAC pero con un activo en esa IP: se anota como `ip_only` (evidencia)."""
    if match.match == "no_asset" and ip_has_asset:
        return MatchResult("ip_only", None, None)
    return match
