"""Política de ciclo de vida de activos (Fase 5C.2): stale, candidatos a limpieza y acciones.

Funciones puras (sin base de datos) que deciden, a partir de la fila del activo y la hora,
en qué punto de su ciclo de vida está y qué acción de limpieza le corresponde. Las usan:
- AssetService (campo `lifecycle_state` del listado y del detalle);
- el preview de limpieza, el ejecutor (manual o automático) y DELETE /assets/{id}, a través
  de AssetLifecycleService.hard_delete_decision, que añade los bloqueos por historial.
El mismo código decide en el preview y en la ejecución: nunca hay dos reglas distintas.

Principios (docs/agent-asset-lifecycle.md):
- Offline != eliminado. Un descubierto solo se vuelve "stale" con pruebas de ausencia: N
  scans completos y exitosos que cubrían su red sin verlo (assets.network_misses, que solo
  avanza en esos scans) Y un tiempo mínimo sin verlo. Con el discovery parado no avanza.
- Un activo con historial de agente (Managed) o monitorizado sin agente nunca es candidato
  a borrado físico: como mucho a archivar.

`stale_condition` traduce la misma regla a SQL para filtrar y paginar en la base de datos;
tests/test_asset_lifecycle_5c2.py comprueba que ambas versiones coinciden.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import ColumnElement, and_, false, func, or_

from app.core.config import Settings
from app.models.asset import Asset, MonitoringMethod


class LifecycleSource(StrEnum):
    # Solo visto por la red y nunca con agente.
    DISCOVERED = "discovered"
    # Monitorizado sin agente (agentless). Reservado: aún no hay colectores.
    MONITORED = "monitored"
    # Tuvo agente alguna vez (aunque ya no lo tenga): conserva historial gestionado.
    MANAGED = "managed"


class LifecycleState(StrEnum):
    ACTIVE = "active"
    OFFLINE = "offline"
    STALE = "stale"
    # Stale y además fuera de la ventana de purga. Solo descubiertos.
    CLEANUP_CANDIDATE = "cleanup_candidate"
    ARCHIVED = "archived"


class CleanupAction(StrEnum):
    KEEP = "keep"
    # Stale, pero aún sin acción posible (p. ej. descubierto dentro de la ventana de purga).
    MARK_STALE = "mark_stale"
    # Se puede archivar (conserva historial); no se puede borrar.
    ARCHIVE_CANDIDATE = "archive_candidate"
    HARD_DELETE_ELIGIBLE = "hard_delete_eligible"
    # Stale pero ni siquiera archivable ahora (agente con credencial activa: revocar antes).
    BLOCKED = "blocked"


@dataclass(frozen=True)
class LifecyclePolicy:
    discovered_stale_after: timedelta = timedelta(hours=72)
    discovered_stale_missed_scans: int = 3
    discovered_purge_after: timedelta = timedelta(days=14)
    managed_stale_after: timedelta = timedelta(days=30)

    @classmethod
    def from_settings(cls, settings: Settings) -> "LifecyclePolicy":
        return cls(
            discovered_stale_after=timedelta(hours=settings.discovered_stale_after_hours),
            discovered_stale_missed_scans=settings.discovered_stale_missed_scans,
            discovered_purge_after=timedelta(days=settings.discovered_purge_after_days),
            managed_stale_after=timedelta(days=settings.managed_stale_after_days),
        )


def has_managed_history(asset: Asset) -> bool:
    # agent_id también, por si una fila se creó sin pasar por el registro (scripts, tests).
    return (
        asset.agent_id is not None
        or asset.ever_managed
        or asset.monitoring_method == MonitoringMethod.AGENT
    )


def lifecycle_source(asset: Asset) -> LifecycleSource:
    if has_managed_history(asset):
        return LifecycleSource.MANAGED
    if asset.monitoring_method == MonitoringMethod.AGENTLESS:
        return LifecycleSource.MONITORED
    return LifecycleSource.DISCOVERED


def last_activity(asset: Asset) -> datetime | None:
    """Última prueba de vida: el contacto del agente o la última vez que la red lo vio.

    Sin ninguna (descubierto creado y nunca visto después) se usa cuándo se descubrió, para
    que un registro sin fechas no parezca "eterno" ni "recién visto".
    """
    seen = [t for t in (asset.last_seen_at, asset.last_network_seen_at) if t is not None]
    if seen:
        return max(seen)
    return asset.discovered_at or asset.first_seen_at


@dataclass(frozen=True)
class LifecycleView:
    source: LifecycleSource
    state: LifecycleState
    last_activity_at: datetime | None
    # Horas desde la última actividad, solo si es stale (para la UI).
    stale_for_hours: int | None
    # Motivos por los que el tiempo/los scans aún impiden el borrado físico (vacío si no).
    timing_blockers: tuple[str, ...]


def evaluate(
    asset: Asset, now: datetime, policy: LifecyclePolicy, *, online: bool
) -> LifecycleView:
    """Estado de ciclo de vida del activo. `online`: su estado efectivo es online."""
    source = lifecycle_source(asset)
    last = last_activity(asset)
    idle = now - last if last is not None else None
    if source is LifecycleSource.DISCOVERED:
        stale = (
            asset.network_misses >= policy.discovered_stale_missed_scans
            and idle is not None
            and idle >= policy.discovered_stale_after
        )
        purgeable = stale and idle is not None and idle >= policy.discovered_purge_after
        if asset.archived_at is not None:
            # Discovery deja de seguir a un archivado (ni lo marca desaparecido ni lo
            # reactiva), así que sus scans perdidos se congelan. El admin ya decidió
            # retirarlo: basta con que haya pasado la ventana de purga sin verse.
            purgeable = idle is not None and idle >= policy.discovered_purge_after
            stale = purgeable or stale
        timing: tuple[str, ...] = ()
        if not stale:
            timing = ("not_stale",)
        elif not purgeable:
            timing = ("purge_window_not_reached",)
    else:
        stale = idle is not None and idle >= policy.managed_stale_after and not online
        purgeable = False
        timing = (
            ("managed_history",) if source is LifecycleSource.MANAGED else ("monitored_source",)
        )
    if asset.archived_at is not None:
        state = LifecycleState.ARCHIVED
    elif purgeable:
        state = LifecycleState.CLEANUP_CANDIDATE
    elif stale:
        state = LifecycleState.STALE
    elif online:
        state = LifecycleState.ACTIVE
    else:
        state = LifecycleState.OFFLINE
    stale_hours = int(idle.total_seconds() // 3600) if stale and idle is not None else None
    return LifecycleView(source, state, last, stale_hours, timing)


def cleanup_action(
    view: LifecycleView, history_blockers: list[str], *, credential_active: bool
) -> tuple[CleanupAction, list[str]]:
    """Acción de limpieza y motivos que impiden el borrado físico (fuente única).

    `history_blockers`: motivos por historial/dependencias (AssetLifecycleService). Un
    descubierto solo es HARD_DELETE_ELIGIBLE sin ningún motivo, ni de tiempo ni de historial.
    """
    reasons = list(dict.fromkeys([*view.timing_blockers, *history_blockers]))
    if view.state in (LifecycleState.ACTIVE, LifecycleState.OFFLINE):
        return CleanupAction.KEEP, reasons
    if not reasons:
        return CleanupAction.HARD_DELETE_ELIGIBLE, reasons
    if view.state is LifecycleState.ARCHIVED:
        # Ya archivado: lo único que queda es borrarlo cuando sea elegible.
        return CleanupAction.KEEP, reasons
    if credential_active:
        # Archivar exige revocar antes el agente (5C.1): no hay acción automática posible.
        return CleanupAction.BLOCKED, [*reasons, "agent_active"]
    if view.source is LifecycleSource.DISCOVERED and reasons == ["purge_window_not_reached"]:
        # Sin historial y esperando a la ventana de purga: aún no se propone nada.
        return CleanupAction.MARK_STALE, reasons
    return CleanupAction.ARCHIVE_CANDIDATE, reasons


def _activity_expr() -> Any:
    # Mismo orden que last_activity(): GREATEST ignora NULL en PostgreSQL.
    return func.coalesce(
        func.greatest(Asset.last_seen_at, Asset.last_network_seen_at),
        Asset.discovered_at,
        Asset.first_seen_at,
    )


def _discovered_expr() -> ColumnElement[bool]:
    return and_(
        Asset.agent_id.is_(None),
        Asset.ever_managed.is_(false()),
        Asset.monitoring_method == MonitoringMethod.DISCOVERED,
    )


def stale_condition(
    policy: LifecyclePolicy, now: datetime, *, purgeable_only: bool = False
) -> ColumnElement[bool]:
    """Condición SQL: activo NO archivado que está stale (o candidato a limpieza).

    Igual que evaluate() para activos no archivados, salvo el estado "online" de un
    gestionado, que aquí se aproxima con la última actividad: un gestionado sin contacto
    durante MANAGED_STALE_AFTER_DAYS no puede estar online (el timeout es de segundos).
    """
    activity = _activity_expr()
    discovered_stale = and_(
        _discovered_expr(),
        Asset.network_misses >= policy.discovered_stale_missed_scans,
        activity <= now - policy.discovered_stale_after,
    )
    if purgeable_only:
        return and_(
            Asset.archived_at.is_(None),
            discovered_stale,
            activity <= now - policy.discovered_purge_after,
        )
    other_stale = and_(
        ~_discovered_expr(),
        activity <= now - policy.managed_stale_after,
    )
    return and_(Asset.archived_at.is_(None), or_(discovered_stale, other_stale))
