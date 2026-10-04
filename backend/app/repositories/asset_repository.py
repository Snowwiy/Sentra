from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset


class AssetRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, asset: Asset) -> Asset:
        self._session.add(asset)
        return asset

    def get_by_public_id(self, public_id: UUID) -> Asset | None:
        return self._session.scalar(select(Asset).where(Asset.public_id == public_id))

    def get_by_agent_id(self, agent_id: UUID) -> Asset | None:
        return self._session.scalar(select(Asset).where(Asset.agent_id == agent_id))

    def list_all(self) -> Sequence[Asset]:
        return self._session.scalars(select(Asset).order_by(Asset.hostname, Asset.id)).all()
