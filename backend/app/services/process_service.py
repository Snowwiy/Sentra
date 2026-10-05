from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.detection.config import DetectionConfig
from app.detection.recorder import SignalRecorder
from app.models.process import AssetProcessSnapshot
from app.repositories.asset_repository import AssetRepository
from app.schemas.process import (
    ProcessSnapshotAccepted,
    ProcessSnapshotCreate,
    ProcessSnapshotRead,
)
from app.services.agent_service import authenticate_agent, record_contact


class ProcessService:
    def __init__(self, session: Session, detection: DetectionConfig | None = None) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._signals = SignalRecorder(session, detection)

    def ingest(self, data: ProcessSnapshotCreate, token: str | None) -> ProcessSnapshotAccepted:
        asset = authenticate_agent(self._assets, data.agent_id, token)
        document = {"processes": [p.model_dump(mode="json") for p in data.processes]}
        # Latest snapshot only, replaced atomically; an older one (delayed resend) loses.
        stmt = insert(AssetProcessSnapshot).values(
            asset_id=asset.id, collected_at=data.collected_at, data=document
        )
        upsert = stmt.on_conflict_do_update(
            index_elements=[AssetProcessSnapshot.asset_id],
            set_={
                "collected_at": stmt.excluded.collected_at,
                "data": stmt.excluded.data,
                "received_at": func.now(),
            },
            where=stmt.excluded.collected_at >= AssetProcessSnapshot.collected_at,
        ).returning(AssetProcessSnapshot.asset_id)
        stored = self._session.execute(upsert).first() is not None
        record_contact(self._session, asset, datetime.now(UTC))
        if stored:
            # Fase 4H: ejecutables nuevos respecto a la línea base del activo. Un snapshot
            # atrasado (no guardado) no aporta nada nuevo.
            self._signals.record_processes(asset.id, document["processes"], data.collected_at)
        self._session.commit()
        return ProcessSnapshotAccepted(
            asset_id=asset.public_id, collected_at=data.collected_at, stored=stored
        )

    def get(self, asset_public_id: UUID) -> ProcessSnapshotRead:
        asset = self._assets.get_by_public_id(asset_public_id)
        if asset is None:
            raise NotFoundError("Asset not found")
        snapshot = self._session.get(AssetProcessSnapshot, asset.id)
        if snapshot is None:
            raise NotFoundError("No process snapshot reported for this asset yet")
        return ProcessSnapshotRead(
            asset_id=asset.public_id,
            collected_at=snapshot.collected_at,
            received_at=snapshot.received_at,
            processes=snapshot.data.get("processes", []),
        )
