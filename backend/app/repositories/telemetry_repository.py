from collections.abc import Iterable
from typing import Any

from sqlalchemy import select, true
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, aliased

from app.models.asset import Asset
from app.models.telemetry import TelemetrySample


class TelemetryRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def insert_once(self, values: dict[str, Any]) -> bool:
        """Insert a sample unless its (asset_id, sample_id) already exists. Returns stored."""
        stmt = (
            insert(TelemetrySample)
            .values(**values)
            .on_conflict_do_nothing(index_elements=["asset_id", "sample_id"])
            .returning(TelemetrySample.id)
        )
        return self._session.execute(stmt).first() is not None

    def add(self, sample: TelemetrySample) -> TelemetrySample:
        self._session.add(sample)
        return sample

    def recent_for_asset(self, asset_id: int, limit: int) -> list[TelemetrySample]:
        """Most recent samples first, ordered by measurement time (not arrival time)."""
        return list(
            self._session.scalars(
                select(TelemetrySample)
                .where(TelemetrySample.asset_id == asset_id)
                .order_by(TelemetrySample.recorded_at.desc(), TelemetrySample.id.desc())
                .limit(limit)
            )
        )

    def latest_by_asset(self, asset_ids: Iterable[int]) -> dict[int, TelemetrySample]:
        """Return the most recent sample for each of the given assets in one query.

        One query for all assets avoids N+1 on the list endpoint. It uses a LATERAL subquery
        (ORDER BY ... LIMIT 1 per asset) so PostgreSQL reads a single row per asset from the
        (asset_id, recorded_at) index. A window function (row_number() OVER ...) looks
        equivalent but ranks every stored sample before filtering, so its cost grows with the
        whole telemetry history: ~600 ms at 1M rows versus <1 ms here, on every dashboard poll.
        Ties on recorded_at fall back to the newest id so the result is deterministic when an
        agent sends two samples with the same timestamp.
        """
        ids = list(asset_ids)
        if not ids:
            return {}

        newest = (
            select(TelemetrySample)
            .where(TelemetrySample.asset_id == Asset.id)
            .order_by(TelemetrySample.recorded_at.desc(), TelemetrySample.id.desc())
            .limit(1)
            .lateral("newest")
        )
        latest = aliased(TelemetrySample, newest)
        rows = self._session.scalars(
            select(latest).select_from(Asset).join(newest, true()).where(Asset.id.in_(ids))
        )
        return {sample.asset_id: sample for sample in rows}
