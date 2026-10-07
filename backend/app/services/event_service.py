from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.detection.config import DetectionConfig
from app.detection.recorder import SignalRecorder
from app.models.asset import Asset
from app.models.event import EventLevel, SystemEvent
from app.repositories.alert_repository import escape_like
from app.repositories.asset_repository import AssetRepository
from app.risk.queue import request_recalculation
from app.schemas.event import EventBatch, EventBatchAccepted, EventList, EventRead
from app.services.agent_service import authenticate_agent, record_contact
from app.services.alert_service import AlertService, AlertThresholds


@dataclass(frozen=True)
class EventFilter:
    min_level: EventLevel | None = None
    channel: str | None = None
    event_code: int | None = None
    # Case-insensitive text in the message or the provider.
    search: str | None = None
    provider: str | None = None
    event_type: str | None = None


class EventService:
    def __init__(
        self,
        session: Session,
        thresholds: AlertThresholds,
        detection: DetectionConfig | None = None,
    ) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._alerts = AlertService(session, thresholds)
        self._signals = SignalRecorder(session, detection)

    def ingest(self, batch: EventBatch, token: str | None) -> EventBatchAccepted:
        asset = authenticate_agent(self._assets, batch.agent_id, token)
        rows = [{"asset_id": asset.id, **event.model_dump()} for event in batch.events]
        stored: list[SystemEvent] = []
        if rows:
            # ON CONFLICT DO NOTHING on the host record id: a batch resent after a lost
            # response is accepted without duplicates, so the agent can safely retry. RETURNING
            # gives only the rows really inserted, so alert rules never see the same event
            # twice. Linux: record_id es un hash estable del cursor del journal (mismo efecto).
            stmt = (
                insert(SystemEvent)
                .values(rows)
                .on_conflict_do_nothing(constraint="uq_system_events_record")
                .returning(SystemEvent)
            )
            stored = list(self._session.scalars(stmt))
        now = datetime.now(UTC)
        record_contact(self._session, asset, now)
        if batch.coverage is not None:
            self._update_coverage(asset, batch.coverage, now)
        # Same transaction as the events: an alert never points at an event rolled back.
        self._alerts.evaluate_events(asset, stored)
        # Fase 4H: solo se guardan señales (aisladas en un savepoint); las reglas las evalúa
        # el job del motor, así esta petición no espera a ninguna correlación.
        self._signals.record_events(asset.id, stored)
        self._session.commit()
        return EventBatchAccepted(asset_id=asset.public_id, received=len(rows), stored=len(stored))

    def _update_coverage(self, asset: Asset, coverage: dict[str, str], now: datetime) -> None:
        """Guarda el estado de las fuentes de eventos (Fase 5C.1).

        Si cambia, el riesgo se recalcula: su confianza depende de qué fuentes llegan (un
        journal sin permiso de lectura no es lo mismo que un equipo sin eventos).
        """
        changed = asset.event_coverage != coverage
        asset.event_coverage = coverage
        asset.event_coverage_at = now
        if changed:
            request_recalculation(self._session, [asset.id])

    def list_events(
        self,
        asset_public_id: UUID | None,
        f: EventFilter,
        limit: int,
        offset: int = 0,
    ) -> EventList:
        stmt = select(SystemEvent, Asset).join(Asset, SystemEvent.asset_id == Asset.id)
        if asset_public_id is not None:
            asset = self._assets.get_by_public_id(asset_public_id)
            if asset is None:
                raise NotFoundError("Asset not found")
            stmt = stmt.where(SystemEvent.asset_id == asset.id)
        if f.min_level is not None:
            stmt = stmt.where(SystemEvent.level.in_(_levels_at_least(f.min_level)))
        if f.channel:
            stmt = stmt.where(SystemEvent.channel == f.channel)
        if f.event_code is not None:
            stmt = stmt.where(SystemEvent.event_code == f.event_code)
        if f.provider:
            stmt = stmt.where(SystemEvent.provider == f.provider)
        if f.event_type:
            stmt = stmt.where(SystemEvent.event_type == f.event_type)
        if f.search:
            pattern = f"%{escape_like(f.search)}%"
            stmt = stmt.where(
                or_(
                    SystemEvent.message.ilike(pattern, escape="\\"),
                    SystemEvent.provider.ilike(pattern, escape="\\"),
                )
            )
        # One extra row tells whether another page exists, without counting a large table.
        stmt = (
            stmt.order_by(SystemEvent.occurred_at.desc(), SystemEvent.id.desc())
            .limit(limit + 1)
            .offset(offset)
        )
        rows = list(self._session.execute(stmt))
        items = [
            EventRead(
                event_id=event.public_id,
                asset_id=asset.public_id,
                hostname=asset.display_name,
                source=event.source,
                channel=event.channel,
                event_code=event.event_code,
                event_type=event.event_type,
                provider=event.provider,
                level=event.level,
                message=event.message,
                record_id=event.record_id,
                computer=event.computer,
                data=event.data,
                occurred_at=event.occurred_at,
            )
            for event, asset in rows[:limit]
        ]
        return EventList(items=items, total=len(items), has_more=len(rows) > limit)


_ORDER = [EventLevel.INFO, EventLevel.WARNING, EventLevel.ERROR, EventLevel.CRITICAL]


def _levels_at_least(level: EventLevel) -> list[EventLevel]:
    return _ORDER[_ORDER.index(level) :]
