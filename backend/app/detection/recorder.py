"""Puntos de ingesta -> señales. Lo único del motor que corre dentro de una petición de agente.

Cada registro va en un SAVEPOINT y dentro de try/except: si la extracción falla (dato raro,
bug), se deshace solo lo suyo, se registra el error y la petición sigue: el heartbeat, la
telemetría o el inventario válidos nunca se pierden ni se rechazan por el motor. Aquí solo
se normaliza e inserta (barato); evaluar reglas es trabajo del job (engine.py).
"""

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.detection import text
from app.detection.config import DetectionConfig
from app.detection.signals import (
    ChangeLike,
    SignalDraft,
    SignalKind,
    SourceType,
    signal_from_discovery_change,
    signals_from_events,
    signals_from_inventory_changes,
    signals_from_listeners,
    unusual_location,
)
from app.models.change import ChangeKind
from app.models.detection import DetectionBaseline, DetectionSignal
from app.models.event import SystemEvent

logger = logging.getLogger(__name__)

PROCESS_BASELINE = "process_exe"
# Señales de proceso nuevo por snapshot: una actualización grande del sistema no debe llenar
# la cola; lo que se descarte sigue en la línea base (no se repetirá como "nuevo").
MAX_PROCESS_SIGNALS = 100


class SignalRecorder:
    def __init__(self, session: Session, config: DetectionConfig | None = None) -> None:
        self._session = session
        self._config = config or DetectionConfig.from_settings(get_settings())

    def _guarded(self, source: str, action: Callable[[], None]) -> None:
        if not self._config.enabled:
            return
        # Lo pendiente de la petición se escribe ANTES: un error de esos datos no debe
        # confundirse con un fallo del motor.
        self._session.flush()
        try:
            with self._session.begin_nested():
                action()
        except Exception:
            logger.exception("detection signal extraction failed", extra={"source": source})

    def _insert(self, asset_id: int, drafts: Sequence[SignalDraft]) -> None:
        if not drafts:
            return
        now = datetime.now(UTC)
        self._session.execute(
            insert(DetectionSignal).values(
                [
                    {
                        "asset_id": asset_id,
                        "kind": draft.kind.value,
                        "subject": draft.subject[:255] if draft.subject else None,
                        "occurred_at": draft.occurred_at,
                        "source_type": draft.source_type.value,
                        "source_id": draft.source_id,
                        "data": draft.data or None,
                        "created_at": now,
                    }
                    for draft in drafts
                ]
            )
        )

    # --- Fuentes -------------------------------------------------------------------------------

    def record_events(self, asset_id: int, events: Sequence[SystemEvent]) -> None:
        """Eventos recién insertados (los reenviados ya no llegan aquí: ON CONFLICT)."""

        def action() -> None:
            not_before = datetime.now(UTC) - self._config.max_event_age
            self._insert(asset_id, signals_from_events(events, not_before))

        if events:
            self._guarded("events", action)

    def record_inventory(
        self,
        asset_id: int,
        changes: Sequence[ChangeLike],
        previous: Mapping[str, Any],
        current: Mapping[str, Any],
        collected_at: datetime,
    ) -> None:
        """Cambios entre dos snapshots (el primero es la línea base y no llega aquí)."""

        def action() -> None:
            drafts = signals_from_inventory_changes(
                changes, collected_at, self._config.security_services
            )
            drafts += signals_from_listeners(previous, current, collected_at)
            self._insert(asset_id, drafts)

        self._guarded("inventory", action)

    def record_processes(
        self, asset_id: int, processes: Iterable[Mapping[str, Any]], collected_at: datetime
    ) -> None:
        """Ejecutables nunca vistos en el activo, contra la línea base persistente."""

        def action() -> None:
            by_key: dict[str, Mapping[str, Any]] = {}
            for process in processes:
                exe = process.get("exe")
                if isinstance(exe, str) and exe.strip():
                    by_key.setdefault(exe.strip().lower()[:512], process)
            if not by_key:
                return
            has_baseline = (
                self._session.scalar(
                    select(DetectionBaseline.key)
                    .where(
                        DetectionBaseline.asset_id == asset_id,
                        DetectionBaseline.kind == PROCESS_BASELINE,
                    )
                    .limit(1)
                )
                is not None
            )
            # Un único INSERT ... ON CONFLICT DO NOTHING RETURNING actualiza la línea base y
            # dice a la vez qué rutas eran nuevas, sin leer antes toda la base del activo.
            new_keys = set(
                self._session.scalars(
                    insert(DetectionBaseline)
                    .values(
                        [
                            {
                                "asset_id": asset_id,
                                "kind": PROCESS_BASELINE,
                                "key": key,
                                "first_seen_at": collected_at,
                            }
                            for key in by_key
                        ]
                    )
                    .on_conflict_do_nothing()
                    .returning(DetectionBaseline.key)
                )
            )
            # Primer snapshot del activo: solo línea base, ninguna señal (sin avalancha).
            if not has_baseline:
                return
            drafts = []
            for key in sorted(new_keys)[:MAX_PROCESS_SIGNALS]:
                process = by_key[key]
                exe = text.clean(process.get("exe"))
                drafts.append(
                    SignalDraft(
                        kind=SignalKind.PROCESS_NEW,
                        occurred_at=collected_at,
                        source_type=SourceType.PROCESS_SNAPSHOT,
                        subject=key[:255],
                        data=text.bounded_data(
                            {
                                "name": process.get("name"),
                                "exe": exe,
                                "pid": process.get("pid"),
                                "ppid": process.get("ppid"),
                                "username": process.get("username"),
                                "started_at": process.get("started_at"),
                                "unusual_location": unusual_location(exe),
                            }
                        ),
                    )
                )
            self._insert(asset_id, drafts)

        self._guarded("processes", action)

    def record_discovery_change(
        self,
        asset_id: int,
        kind: ChangeKind,
        item: str,
        occurred_at: datetime,
        details: Mapping[str, Any] | None,
    ) -> None:
        def action() -> None:
            draft = signal_from_discovery_change(kind, item, occurred_at, details or {})
            if draft is not None:
                self._insert(asset_id, [draft])

        if kind in (ChangeKind.PORT_OPENED, ChangeKind.DISAPPEARED):
            self._guarded("discovery", action)

    def record_discovered_asset(
        self, asset_id: int, occurred_at: datetime, details: Mapping[str, Any]
    ) -> None:
        """Host nuevo tras la línea base de la red (discovery ya decide qué es "nuevo")."""

        def action() -> None:
            draft = SignalDraft(
                kind=SignalKind.ASSET_DISCOVERED,
                occurred_at=occurred_at,
                source_type=SourceType.DISCOVERY,
                subject=text.clean(details.get("address") or "", 64) or None,
                data=text.bounded_data(
                    {
                        "address": details.get("address"),
                        "mac": details.get("mac"),
                        "device_type": details.get("device_type"),
                        "device_name": details.get("device_name"),
                        "identified": bool(
                            details.get("device_type") or details.get("device_name")
                        ),
                        "open_ports": details.get("open_ports"),
                    }
                ),
            )
            self._insert(asset_id, [draft])

        self._guarded("discovery", action)
