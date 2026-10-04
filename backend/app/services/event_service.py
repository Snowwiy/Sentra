from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.asset import Asset
from app.models.event import EventLevel, SystemEvent
from app.repositories.asset_repository import AssetRepository
from app.schemas.event import EventBatch, EventBatchAccepted, EventList, EventRead
from app.services.agent_service import authenticate_agent, mark_seen


class EventService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._assets = AssetRepository(session)

    def ingest(self, batch: EventBatch, token: str | None) -> EventBatchAccepted:
        asset = authenticate_agent(self._assets, batch.agent_id, token)
        rows = [{"asset_id": asset.id, **event.model_dump()} for event in batch.events]
        # ON CONFLICT DO NOTHING on the host record id: a batch resent after a lost response
        # is accepted without duplicates, so the agent can safely retry.
        stmt = (
            insert(SystemEvent)
            .values(rows)
            .on_conflict_do_nothing(constraint="uq_system_events_record")
            .returning(SystemEvent.id)
        )
        stored = len(self._session.execute(stmt).all())
        mark_seen(asset, datetime.now(UTC))
        self._session.commit()
        return EventBatchAccepted(asset_id=asset.public_id, received=len(rows), stored=stored)

    def list_events(
        self,
        asset_public_id: UUID | None,
        min_level: EventLevel | None,
        limit: int,
    ) -> EventList:
        stmt = select(SystemEvent, Asset).join(Asset, SystemEvent.asset_id == Asset.id)
        if asset_public_id is not None:
            asset = self._assets.get_by_public_id(asset_public_id)
            if asset is None:
                raise NotFoundError("Asset not found")
            stmt = stmt.where(SystemEvent.asset_id == asset.id)
        if min_level is not None:
            stmt = stmt.where(SystemEvent.level.in_(_levels_at_least(min_level)))
        stmt = stmt.order_by(SystemEvent.occurred_at.desc(), SystemEvent.id.desc()).limit(limit)
        items = [
            EventRead(
                event_id=event.public_id,
                asset_id=asset.public_id,
                hostname=asset.hostname,
                source=event.source,
                channel=event.channel,
                event_code=event.event_code,
                provider=event.provider,
                level=event.level,
                message=event.message,
                occurred_at=event.occurred_at,
            )
            for event, asset in self._session.execute(stmt).all()
        ]
        return EventList(items=items, total=len(items))


_ORDER = [EventLevel.INFO, EventLevel.WARNING, EventLevel.ERROR, EventLevel.CRITICAL]


def _levels_at_least(level: EventLevel) -> list[EventLevel]:
    return _ORDER[_ORDER.index(level) :]
