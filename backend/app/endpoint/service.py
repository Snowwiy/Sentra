"""Ingesta y lectura de la telemetría avanzada de endpoint (Fase 6E.3/6E.4).

Ingesta (POST /agents/activity): autentica al agente, valida cada evento por separado,
inserta con ON CONFLICT DO NOTHING por (activo, event_uid) y solo lo realmente nuevo alimenta
el árbol de procesos y el motor de detección. Un reenvío del mismo lote (respuesta perdida,
cola offline del agente) cuenta como `duplicates` y no cambia nada.

Lectura: árbol de procesos por niveles (carga perezosa, nunca el árbol entero), detalle de
una instancia con sus antecesores y conexiones, actividad paginada por cursor y estado.
"""

import logging
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError
from sqlalchemy import delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import NotFoundError
from app.detection.recorder import SignalRecorder
from app.endpoint import schema
from app.models.asset import Asset
from app.models.endpoint import EndpointActivity, ProcessInstance
from app.repositories.asset_repository import AssetRepository
from app.schemas.endpoint import (
    ActivityAccepted,
    ActivityBatchIn,
    ActivityEventIn,
    ActivityEventRead,
    ActivityList,
    ActivityRejected,
    ProcessInstanceDetail,
    ProcessNode,
    ProcessTree,
    TelemetryStatus,
)
from app.services.agent_service import authenticate_agent, record_contact

logger = logging.getLogger(__name__)

# Un evento con fecha futura más allá de este margen es un reloj roto o un dato manipulado.
FUTURE_SKEW = timedelta(minutes=10)
TREE_LIMIT = 200
MAX_ANCESTORS = 32
# Sin `at`, el primer nivel enseña los procesos vivos y los terminados en esta ventana.
RECENT_ENDED = timedelta(hours=1)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _validate(raw: dict[str, Any], now: datetime) -> tuple[ActivityEventIn | None, str | None]:
    try:
        event = ActivityEventIn.model_validate(raw)
    except ValidationError:
        return None, "invalid_event"
    if event.action not in schema.ACTIONS[event.category]:
        return None, "unknown_action"
    if event.source not in schema.SOURCES:
        return None, "unknown_source"
    if event.occurred_at > now + FUTURE_SKEW:
        return None, "occurred_in_future"
    try:
        event.data = schema.clean_data(event.category, event.data)
    except schema.InvalidFieldError:
        return None, "invalid_data"
    return event, None


class ActivityIngest:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._assets = AssetRepository(session)

    def authenticate(self, batch: ActivityBatchIn, token: str | None) -> Asset:
        return authenticate_agent(self._assets, batch.agent_id, token)

    def ingest(self, batch: ActivityBatchIn, asset: Asset) -> ActivityAccepted:
        """Ingesta de un lote de un agente ya autenticado (ver `authenticate`)."""
        session = self._session
        now = datetime.now(UTC)
        policy = self._settings.telemetry_cmdline_policy
        valid: list[ActivityEventIn] = []
        rejected: list[ActivityRejected] = []
        seen: set[uuid.UUID] = set()
        for index, raw in enumerate(batch.events):
            event, code = _validate(raw, now)
            if event is None:
                rejected.append(ActivityRejected(index=index, code=code or "invalid_event"))
                continue
            if event.event_uid in seen:
                continue
            seen.add(event.event_uid)
            if event.category == "process" and "cmdline" in event.data:
                redacted = schema.redact_cmdline(event.data["cmdline"], policy)
                if redacted is None:
                    event.data.pop("cmdline")
                else:
                    event.data["cmdline"] = redacted
            valid.append(event)
        inserted: list[ActivityEventIn] = []
        if valid:
            stmt = (
                insert(EndpointActivity)
                .values(
                    [
                        {
                            "asset_id": asset.id,
                            "event_uid": e.event_uid,
                            "boot_id": batch.boot_id,
                            "seq": e.seq,
                            "category": e.category,
                            "action": e.action,
                            "source": e.source,
                            "instance_key": e.instance_key,
                            "data": e.data,
                            "occurred_at": e.occurred_at,
                            "received_at": now,
                        }
                        for e in valid
                    ]
                )
                .on_conflict_do_nothing(constraint="uq_endpoint_activity_event")
                .returning(EndpointActivity.event_uid)
            )
            new_uids = set(session.scalars(stmt))
            inserted = [e for e in valid if e.event_uid in new_uids]
        self._update_processes(asset, batch.boot_id, inserted, now)
        if batch.stats is not None:
            asset.telemetry_status = {
                **batch.stats.model_dump(mode="json", exclude_none=True),
                "boot_id": batch.boot_id,
            }
            asset.telemetry_status_at = now
        record_contact(session, asset, now)
        if inserted:
            SignalRecorder(session).record_activity(asset.id, inserted)
        session.commit()
        return ActivityAccepted(
            asset_id=asset.public_id,
            accepted=len(inserted),
            duplicates=len(valid) - len(inserted),
            rejected=rejected,
        )

    def _update_processes(
        self, asset: Asset, boot_id: str, events: Sequence[ActivityEventIn], now: datetime
    ) -> None:
        """Instancias de proceso a partir de los inicios y finales recién insertados."""
        starts: dict[str, ActivityEventIn] = {}
        stops: dict[str, ActivityEventIn] = {}
        for event in events:
            if event.category != "process" or not event.instance_key:
                continue
            target = starts if event.action == "start" else stops
            target[event.instance_key] = event
        if not starts and not stops:
            return
        session = self._session
        keys = set(starts) | set(stops)
        existing = {
            row.instance_key: row
            for row in session.scalars(
                select(ProcessInstance).where(
                    ProcessInstance.asset_id == asset.id, ProcessInstance.instance_key.in_(keys)
                )
            )
        }
        for key in keys:
            row = existing.get(key)
            start = starts.get(key)
            stop = stops.get(key)
            source_event = start or stop
            assert source_event is not None  # noqa: S101
            data = source_event.data
            if row is None:
                row = ProcessInstance(
                    asset_id=asset.id,
                    instance_key=key,
                    boot_id=boot_id,
                    pid=int(data.get("pid") or 0),
                    source=source_event.source,
                    first_seen_at=now,
                )
                session.add(row)
            if start is not None:
                d = start.data
                row.pid = int(d.get("pid") or row.pid or 0)
                row.ppid = d.get("ppid")
                row.parent_instance_key = d.get("parent_instance_key")
                row.parent_relation = d.get("parent_relation")
                row.name = d.get("name") or row.name
                row.exe = d.get("exe") or row.exe
                row.cmdline = d.get("cmdline")
                row.username = d.get("username") or row.username
                row.sha256 = d.get("sha256") or row.sha256
                row.signer = d.get("signer") or row.signer
                row.integrity = d.get("integrity") or row.integrity
                row.started_at = _parse_time(d.get("started_at")) or start.occurred_at
                row.source = start.source
            if stop is not None:
                row.name = row.name or stop.data.get("name")
                row.ended_at = _parse_time(stop.data.get("ended_at")) or stop.occurred_at
            row.last_seen_at = now


# --- lectura -------------------------------------------------------------------------------------


def _node(row: ProcessInstance, children: int) -> ProcessNode:
    return ProcessNode(
        instance_key=row.instance_key,
        pid=row.pid,
        ppid=row.ppid,
        parent_instance_key=row.parent_instance_key,
        parent_relation=row.parent_relation,
        name=row.name,
        exe=row.exe,
        cmdline=row.cmdline,
        username=row.username,
        sha256=row.sha256,
        signer=row.signer,
        integrity=row.integrity,
        source=row.source,
        started_at=row.started_at,
        ended_at=row.ended_at,
        running=row.ended_at is None,
        children_count=children,
    )


def _event(row: EndpointActivity) -> ActivityEventRead:
    return ActivityEventRead(
        id=row.id,
        event_uid=row.event_uid,
        category=row.category,
        action=row.action,
        source=row.source,
        instance_key=row.instance_key,
        data=row.data,
        occurred_at=row.occurred_at,
        received_at=row.received_at,
    )


class EndpointReadService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    def _asset(self, public_id: uuid.UUID) -> Asset:
        asset = self._session.scalars(select(Asset).where(Asset.public_id == public_id)).first()
        if asset is None:
            raise NotFoundError("Asset not found")
        return asset

    def _children_counts(self, asset_id: int, keys: Sequence[str]) -> dict[str, int]:
        if not keys:
            return {}
        rows = self._session.execute(
            select(ProcessInstance.parent_instance_key, func.count())
            .where(
                ProcessInstance.asset_id == asset_id,
                ProcessInstance.parent_instance_key.in_(keys),
                # Un hijo cuyo padre no se pudo confirmar no cuelga de él.
                ProcessInstance.parent_relation.in_(("observed", "inferred")),
            )
            .group_by(ProcessInstance.parent_instance_key)
        )
        return {key: int(total) for key, total in rows if key}

    def process_tree(
        self,
        public_id: uuid.UUID,
        parent: str | None,
        at: datetime | None,
        search: str | None,
        limit: int,
    ) -> ProcessTree:
        asset = self._asset(public_id)
        conditions: list[Any] = [ProcessInstance.asset_id == asset.id]
        if at is not None:
            conditions += [
                or_(ProcessInstance.started_at.is_(None), ProcessInstance.started_at <= at),
                or_(ProcessInstance.ended_at.is_(None), ProcessInstance.ended_at >= at),
            ]
        else:
            since = datetime.now(UTC) - RECENT_ENDED
            # Un proceso sin final de un arranque anterior del host no sigue vivo: el agente
            # no pudo enviar su fin porque el equipo se apagó.
            boot = (asset.telemetry_status or {}).get("boot_id")
            alive: Any = ProcessInstance.ended_at.is_(None)
            if isinstance(boot, str):
                alive = alive & (ProcessInstance.boot_id == boot)
            conditions.append(or_(alive, ProcessInstance.ended_at >= since))
        if search:
            needle = search.strip().lower()
            pattern = "%" + needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern += "%"
            # La búsqueda devuelve coincidencias planas (sin jerarquía): la UI las abre con el
            # detalle, que trae los antecesores.
            conditions.append(
                or_(
                    func.lower(ProcessInstance.name).like(pattern, escape="\\"),
                    func.lower(ProcessInstance.exe).like(pattern, escape="\\"),
                    ProcessInstance.pid == int(needle)
                    if needle.isdigit() and len(needle) <= 9
                    else ProcessInstance.id < 0,
                )
            )
        elif parent is not None:
            conditions += [
                ProcessInstance.parent_instance_key == parent,
                ProcessInstance.parent_relation.in_(("observed", "inferred")),
            ]
        else:
            parents = select(ProcessInstance.instance_key).where(
                ProcessInstance.asset_id == asset.id
            )
            conditions.append(
                or_(
                    ProcessInstance.parent_instance_key.is_(None),
                    ProcessInstance.parent_relation.not_in(("observed", "inferred")),
                    ProcessInstance.parent_relation.is_(None),
                    ProcessInstance.parent_instance_key.not_in(parents),
                )
            )
        rows = self._session.scalars(
            select(ProcessInstance)
            .where(*conditions)
            .order_by(ProcessInstance.started_at.asc().nulls_first(), ProcessInstance.id)
            .limit(limit + 1)
        ).all()
        page = rows[:limit]
        counts = self._children_counts(asset.id, [r.instance_key for r in page])
        return ProcessTree(
            asset_id=asset.public_id,
            parent=parent,
            at=at,
            nodes=[_node(r, counts.get(r.instance_key, 0)) for r in page],
            truncated=len(rows) > limit,
        )

    def instance(self, public_id: uuid.UUID, instance_key: str) -> ProcessInstanceDetail:
        asset = self._asset(public_id)
        session = self._session

        def load(key: str) -> ProcessInstance | None:
            return session.scalars(
                select(ProcessInstance).where(
                    ProcessInstance.asset_id == asset.id, ProcessInstance.instance_key == key
                )
            ).first()

        row = load(instance_key)
        if row is None:
            raise NotFoundError("Process instance not found")
        ancestors: list[ProcessInstance] = []
        current = row
        visited = {row.instance_key}
        while (
            len(ancestors) < MAX_ANCESTORS
            and current.parent_instance_key
            and current.parent_relation in ("observed", "inferred")
            and current.parent_instance_key not in visited
        ):
            parent = load(current.parent_instance_key)
            if parent is None:
                break
            visited.add(parent.instance_key)
            ancestors.append(parent)
            current = parent
        counts = self._children_counts(asset.id, [r.instance_key for r in [row, *ancestors]])
        connections = session.scalars(
            select(EndpointActivity)
            .where(
                EndpointActivity.asset_id == asset.id,
                EndpointActivity.instance_key == instance_key,
                EndpointActivity.category == "network",
            )
            .order_by(EndpointActivity.occurred_at.desc())
            .limit(50)
        ).all()
        return ProcessInstanceDetail(
            asset_id=asset.public_id,
            process=_node(row, counts.get(row.instance_key, 0)),
            ancestors=[_node(a, counts.get(a.instance_key, 0)) for a in ancestors],
            connections=[_event(c) for c in connections],
        )

    def activity(
        self,
        public_id: uuid.UUID,
        category: str | None,
        action: str | None,
        instance_key: str | None,
        start: datetime | None,
        end: datetime | None,
        before_id: int | None,
        limit: int,
    ) -> ActivityList:
        asset = self._asset(public_id)
        conditions: list[Any] = [EndpointActivity.asset_id == asset.id]
        if category:
            conditions.append(EndpointActivity.category == category)
        if action:
            conditions.append(EndpointActivity.action == action)
        if instance_key:
            conditions.append(EndpointActivity.instance_key == instance_key)
        if start is not None:
            conditions.append(EndpointActivity.occurred_at >= start)
        if end is not None:
            conditions.append(EndpointActivity.occurred_at <= end)
        if before_id is not None:
            conditions.append(EndpointActivity.id < before_id)
        rows = self._session.scalars(
            select(EndpointActivity)
            .where(*conditions)
            .order_by(EndpointActivity.id.desc())
            .limit(limit + 1)
        ).all()
        page = rows[:limit]
        return ActivityList(
            asset_id=asset.public_id,
            items=[_event(r) for r in page],
            next_before_id=page[-1].id if len(rows) > limit else None,
        )

    def status(self, public_id: uuid.UUID) -> TelemetryStatus:
        asset = self._asset(public_id)
        since = datetime.now(UTC) - timedelta(hours=1)
        lag = EndpointActivity.received_at - EndpointActivity.occurred_at
        seconds = func.extract("epoch", lag)
        row = self._session.execute(
            select(
                func.count(),
                func.max(EndpointActivity.occurred_at),
                func.percentile_cont(0.5).within_group(seconds),
                func.percentile_cont(0.95).within_group(seconds),
            ).where(EndpointActivity.asset_id == asset.id, EndpointActivity.received_at >= since)
        ).one()
        last = self._session.scalar(
            select(func.max(EndpointActivity.occurred_at)).where(
                EndpointActivity.asset_id == asset.id
            )
        )
        return TelemetryStatus(
            asset_id=asset.public_id,
            enabled=asset.telemetry_status is not None,
            reported_at=asset.telemetry_status_at,
            stats=asset.telemetry_status,
            last_event_at=last,
            events_last_hour=int(row[0] or 0),
            ingest_lag_p50_seconds=round(float(row[2]), 3) if row[2] is not None else None,
            ingest_lag_p95_seconds=round(float(row[3]), 3) if row[3] is not None else None,
            cmdline_policy=self._settings.telemetry_cmdline_policy,
        )


def purge_endpoint(session: Session, settings: Settings, now: datetime) -> dict[str, int]:
    """Retención de actividad y de instancias terminadas.

    Una instancia sin final solo se purga si es de un arranque anterior del host (está
    muerta aunque su fin no llegara): un servicio que lleva meses vivo sigue en el árbol.
    """
    counts: dict[str, int] = {}
    if settings.telemetry_activity_retention_days:
        cutoff = now - timedelta(days=settings.telemetry_activity_retention_days)
        result = session.execute(
            delete(EndpointActivity).where(EndpointActivity.received_at < cutoff)
        )
        counts["endpoint_activity"] = int(getattr(result, "rowcount", 0) or 0)
    if settings.process_instance_retention_days:
        cutoff = now - timedelta(days=settings.process_instance_retention_days)
        current_boot = (
            select(Asset.telemetry_status["boot_id"].astext)
            .where(Asset.id == ProcessInstance.asset_id)
            .scalar_subquery()
        )
        result = session.execute(
            delete(ProcessInstance).where(
                ProcessInstance.last_seen_at < cutoff,
                or_(
                    ProcessInstance.ended_at < cutoff,
                    ProcessInstance.boot_id.is_distinct_from(current_boot),
                ),
            )
        )
        counts["process_instances"] = int(getattr(result, "rowcount", 0) or 0)
    return counts
