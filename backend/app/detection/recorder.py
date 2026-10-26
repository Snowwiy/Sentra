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

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.detection import behavior, script_context, text
from app.detection.config import DetectionConfig
from app.detection.custom.runtime import active_event_channels
from app.detection.signals import (
    ChangeLike,
    SignalDraft,
    SignalKind,
    SourceType,
    raw_event_signals,
    signal_from_discovery_change,
    signals_from_events,
    signals_from_inventory_changes,
    signals_from_listeners,
    unusual_location,
)
from app.models.change import ChangeKind
from app.models.detection import DetectionBaseline, DetectionSignal
from app.models.endpoint import EndpointActivity, ProcessInstance
from app.models.event import SystemEvent

logger = logging.getLogger(__name__)

PROCESS_BASELINE = "process_exe"
# Señales de proceso nuevo por snapshot: una actualización grande del sistema no debe llenar
# la cola; lo que se descarte sigue en la línea base (no se repetirá como "nuevo").
MAX_PROCESS_SIGNALS = 100
# Señales por lote de actividad (6E.5): un lote anómalo no inunda la cola del motor.
MAX_ACTIVITY_SIGNALS = 200


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

    def _enrich(self, asset_id: int, drafts: Sequence[SignalDraft]) -> None:
        """Fase 7A.8: contexto de proceso para PowerShell y puertos expuestos (en sitio).

        Se guarda en la señal, no se calcula al leer: las excepciones comparan la señal y el
        proceso puede haber desaparecido de la telemetría cuando alguien revise la detección.
        Lo que no se encuentra se deja fuera; la regla dice qué faltó en vez de inventarlo.
        """
        for draft in drafts:
            context: dict[str, Any] | None = None
            if draft.kind == SignalKind.POWERSHELL_SUSPICIOUS:
                pid = draft.data.get("pid")
                if isinstance(pid, int):
                    context = script_context.process_context(
                        self._session, asset_id, pid, draft.occurred_at
                    )
            elif draft.kind == SignalKind.PORT_EXPOSED:
                port = draft.data.get("port")
                if isinstance(port, int):
                    context = script_context.listener_owner(self._session, asset_id, port)
            if context:
                draft.data.update(text.bounded_data(context))

    # --- Fuentes -------------------------------------------------------------------------------

    def record_events(self, asset_id: int, events: Sequence[SystemEvent]) -> None:
        """Eventos recién insertados (los reenviados ya no llegan aquí: ON CONFLICT)."""

        def action() -> None:
            not_before = datetime.now(UTC) - self._config.max_event_age
            drafts = signals_from_events(events, not_before)
            self._enrich(asset_id, drafts)
            self._insert(asset_id, drafts)

        def raw_action() -> None:
            # Fase 5A: solo canales con reglas personalizadas activas (caché por proceso con
            # comprobación periódica en BD, ver runtime.active_event_channels).
            channels = active_event_channels(self._session)
            if channels:
                not_before = datetime.now(UTC) - self._config.max_event_age
                self._insert(asset_id, raw_event_signals(events, not_before, channels))

        if events:
            self._guarded("events", action)
            # Aparte: un fallo de las reglas personalizadas no pierde las señales built-in.
            self._guarded("events_custom", raw_action)

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

    def record_activity(self, asset_id: int, events: Sequence[Any]) -> None:
        """Fase 6E.5: eventos de actividad recién insertados (los reenvíos no llegan aquí).

        `events` son ActivityEventIn ya validados. Solo los que encajan en un patrón de
        behavior.py producen señal; el resto se queda en endpoint_activity como contexto.
        """

        def action() -> None:
            not_before = datetime.now(UTC) - self._config.max_event_age
            recent = [e for e in events if e.occurred_at >= not_before]
            if not recent:
                return
            keys = {
                key
                for e in recent
                for key in (e.instance_key, e.data.get("parent_instance_key"))
                if isinstance(key, str)
            }
            facts: dict[str, behavior.ProcessFacts] = {}
            if keys:
                for key, name, exe in self._session.execute(
                    select(
                        ProcessInstance.instance_key, ProcessInstance.name, ProcessInstance.exe
                    ).where(
                        ProcessInstance.asset_id == asset_id,
                        ProcessInstance.instance_key.in_(keys),
                    )
                ):
                    facts[key] = behavior.ProcessFacts(name, exe)
            drafts: list[SignalDraft] = []
            states: dict[tuple[str, str], Mapping[str, Any] | None] = {}
            new_uids = [e.event_uid for e in recent]
            for event in sorted(recent, key=lambda e: (e.occurred_at, e.seq)):
                draft: SignalDraft | None = None
                if event.category == "process" and event.action == "start":
                    parent_key = event.data.get("parent_instance_key")
                    parent = (
                        facts.get(parent_key)
                        if event.data.get("parent_relation") in ("observed", "inferred")
                        else None
                    )
                    draft = behavior.process_start_signal(event, parent, event.occurred_at)
                elif event.category == "network":
                    process = facts.get(event.instance_key) if event.instance_key else None
                    draft = behavior.process_network_signal(event, process, event.occurred_at)
                elif event.category in ("persistence", "scheduled_task"):
                    draft = behavior.persistence_signal(event, event.occurred_at)
                elif event.category in ("protection", "firewall"):
                    state = (event.category, behavior.state_key(event.category, event.data))
                    if state not in states:
                        states[state] = self._previous_state(asset_id, event, new_uids)
                    build = (
                        behavior.protection_signal
                        if event.category == "protection"
                        else behavior.firewall_signal
                    )
                    draft = build(event, states[state], event.occurred_at)
                    states[state] = event.data
                if draft is not None:
                    drafts.append(
                        SignalDraft(
                            kind=draft.kind,
                            occurred_at=draft.occurred_at,
                            source_type=draft.source_type,
                            subject=text.clean(draft.subject, 255) if draft.subject else None,
                            source_id=draft.source_id,
                            data=text.bounded_data(draft.data),
                        )
                    )
            self._insert(asset_id, drafts[:MAX_ACTIVITY_SIGNALS])

        if events:
            self._guarded("activity", action)

    def _previous_state(
        self, asset_id: int, event: Any, exclude: Sequence[Any]
    ) -> Mapping[str, Any] | None:
        """Último estado guardado de la misma protección o perfil de firewall."""
        field = "product" if event.category == "protection" else "profile"
        value = behavior.state_key(event.category, event.data)
        row = self._session.scalar(
            select(EndpointActivity.data)
            .where(
                EndpointActivity.asset_id == asset_id,
                EndpointActivity.category == event.category,
                EndpointActivity.occurred_at <= event.occurred_at,
                EndpointActivity.event_uid.not_in(exclude),
                func.coalesce(EndpointActivity.data[field].astext, "") == value,
            )
            .order_by(EndpointActivity.occurred_at.desc(), EndpointActivity.id.desc())
            .limit(1)
        )
        return row if isinstance(row, dict) else None

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
                self._enrich(asset_id, [draft])
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
