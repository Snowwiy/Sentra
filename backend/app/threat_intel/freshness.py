"""Frescura de fuentes e indicadores (sin base de datos).

Una fuente "caducada" (stale) sigue sirviendo su última inteligencia, pero la UI y los
consumidores lo saben: el riesgo reduce su aporte y la UI muestra "Using cached
intelligence" con la fecha de la última sincronización correcta. Nunca se borra nada por
caducar.
"""

from datetime import datetime, timedelta
from typing import Protocol


class _SourceLike(Protocol):
    enabled: bool
    archived_at: datetime | None
    stale_after_hours: int | None
    last_success_at: datetime | None


def is_stale(source: _SourceLike, now: datetime) -> bool:
    """¿La última sincronización correcta es más antigua de lo esperado?

    Solo aplica a fuentes con caducidad (las que se sincronizan). Una fuente local importada a
    mano no caduca sola. Una fuente sin ninguna sincronización correcta no es "stale": es
    "never_synced" (no tiene datos que puedan estar viejos).
    """
    if source.stale_after_hours is None or source.last_success_at is None:
        return False
    return now - source.last_success_at > timedelta(hours=source.stale_after_hours)


def source_state(source: _SourceLike, now: datetime) -> str:
    """archived | disabled | never_synced | stale | fresh (estado que pinta la UI)."""
    if source.archived_at is not None:
        return "archived"
    if not source.enabled:
        return "disabled"
    if source.stale_after_hours is not None and source.last_success_at is None:
        return "never_synced"
    return "stale" if is_stale(source, now) else "fresh"


def indicator_state(
    revoked: bool, valid_from: datetime | None, valid_until: datetime | None, now: datetime
) -> str:
    """active | revoked | expired | not_yet_valid (lo declarado por la fuente, sin inventar)."""
    if revoked:
        return "revoked"
    if valid_until is not None and valid_until <= now:
        return "expired"
    if valid_from is not None and valid_from > now:
        return "not_yet_valid"
    return "active"
