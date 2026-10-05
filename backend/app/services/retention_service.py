"""Opt-in deletion of old telemetry samples and host events.

Nothing is deleted unless a retention is set: TELEMETRY_RETENTION_DAYS, EVENT_RETENTION_DAYS,
CHANGE_RETENTION_DAYS (inventory change history), ALERT_RETENTION_DAYS (resolved alerts
only: an active alert is never deleted, whatever its age) and DETECTION_RETENTION_DAYS
(Fase 4H: solo detecciones resueltas, con su evidencia; una detección abierta o reconocida
nunca se borra, y su evidencia es una copia que no depende de EVENT_RETENTION_DAYS).
Process snapshots and inventory keep only the latest document per asset, so they never grow.

Rows go in small batches, each committed on its own, so the purge never holds long locks on
tables agents write to every few seconds, and a run interrupted halfway (restart, outage)
simply continues on the next sweep. Old rows are found through existing indexes (telemetry per
asset on (asset_id, recorded_at), the one history queries use; events on (occurred_at)), so no
migration is needed.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import ColumnElement, CursorResult, any_, delete, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.alert import Alert, AlertStatus
from app.models.asset import Asset
from app.models.change import AssetChange
from app.models.detection import Detection, DetectionStatus
from app.models.event import SystemEvent
from app.models.risk import RiskSnapshot
from app.models.telemetry import TelemetrySample

BATCH_SIZE = 5000


@dataclass(frozen=True)
class RetentionPolicy:
    telemetry_days: int | None
    event_days: int | None
    change_days: int | None = None
    alert_days: int | None = None
    detection_days: int | None = None
    risk_history_days: int | None = None

    @classmethod
    def from_settings(cls, settings: Settings) -> "RetentionPolicy":
        return cls(
            settings.telemetry_retention_days,
            settings.event_retention_days,
            settings.change_retention_days,
            settings.alert_retention_days,
            settings.detection_retention_days,
            settings.risk_history_retention_days,
        )

    @property
    def enabled(self) -> bool:
        return any(
            days is not None
            for days in (
                self.telemetry_days,
                self.event_days,
                self.change_days,
                self.alert_days,
                self.detection_days,
                self.risk_history_days,
            )
        )


@dataclass(frozen=True)
class PurgeResult:
    telemetry_samples: int = 0
    system_events: int = 0
    asset_changes: int = 0
    alerts: int = 0
    detections: int = 0
    risk_snapshots: int = 0

    @property
    def total(self) -> int:
        return (
            self.telemetry_samples
            + self.system_events
            + self.asset_changes
            + self.alerts
            + self.detections
            + self.risk_snapshots
        )


class RetentionService:
    def __init__(
        self, session: Session, policy: RetentionPolicy, batch_size: int = BATCH_SIZE
    ) -> None:
        self._session = session
        self._policy = policy
        self._batch_size = batch_size

    def purge(self, now: datetime | None = None) -> PurgeResult:
        """Delete what is older than the policy allows. Commits after every batch."""
        now = now or datetime.now(UTC)
        samples = events = 0
        if self._policy.telemetry_days is not None:
            cutoff = now - timedelta(days=self._policy.telemetry_days)
            # Materialized first: the loop commits, which would end a cursor iterated lazily.
            for asset_id in list(self._session.scalars(select(Asset.id))):
                samples += self._purge(
                    TelemetrySample,
                    TelemetrySample.asset_id == asset_id,
                    TelemetrySample.recorded_at < cutoff,
                )
        if self._policy.event_days is not None:
            cutoff = now - timedelta(days=self._policy.event_days)
            # Alerts that point at a deleted event keep their details (FK SET NULL).
            events = self._purge(SystemEvent, SystemEvent.occurred_at < cutoff)
        changes = alerts = 0
        if self._policy.change_days is not None:
            cutoff = now - timedelta(days=self._policy.change_days)
            changes = self._purge(AssetChange, AssetChange.detected_at < cutoff)
        if self._policy.alert_days is not None:
            cutoff = now - timedelta(days=self._policy.alert_days)
            alerts = self._purge(
                Alert, Alert.status == AlertStatus.RESOLVED, Alert.resolved_at < cutoff
            )
        detections = 0
        if self._policy.detection_days is not None:
            cutoff = now - timedelta(days=self._policy.detection_days)
            # La evidencia se borra en cascada con su detección.
            detections = self._purge(
                Detection,
                Detection.status == DetectionStatus.RESOLVED,
                Detection.resolved_at < cutoff,
            )
        snapshots = 0
        if self._policy.risk_history_days is not None:
            cutoff = now - timedelta(days=self._policy.risk_history_days)
            # Las contribuciones se borran en cascada; el riesgo actual (asset_risk) nunca.
            snapshots = self._purge(RiskSnapshot, RiskSnapshot.calculated_at < cutoff)
        return PurgeResult(
            telemetry_samples=samples,
            system_events=events,
            asset_changes=changes,
            alerts=alerts,
            detections=detections,
            risk_snapshots=snapshots,
        )

    def _purge(
        self,
        model: type[TelemetrySample]
        | type[SystemEvent]
        | type[AssetChange]
        | type[Alert]
        | type[Detection]
        | type[RiskSnapshot],
        *where: ColumnElement[bool],
    ) -> int:
        deleted = 0
        while True:
            batch = select(model.id).where(*where).limit(self._batch_size).scalar_subquery()
            # `id = ANY(ARRAY(subquery))`, not `id IN (subquery)`: PostgreSQL plans the IN form
            # as a hash join over a full scan of the table (~185 ms per batch at 1M samples),
            # while ANY(ARRAY) runs the subquery once and deletes through the primary key
            # (~9 ms per batch). Measured with EXPLAIN ANALYZE on PostgreSQL 16.
            stmt = delete(model).where(model.id == any_(func.array(batch)))
            result = cast(CursorResult[Any], self._session.execute(stmt))
            self._session.commit()
            deleted += result.rowcount
            if result.rowcount < self._batch_size:
                return deleted
