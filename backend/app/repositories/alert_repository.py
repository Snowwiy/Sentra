from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertRule, AlertStatus
from app.models.asset import Asset


class AlertRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_open(self, asset_id: int, rule: AlertRule) -> Alert | None:
        return self._session.scalar(
            select(Alert).where(
                Alert.asset_id == asset_id, Alert.rule == rule, Alert.status == AlertStatus.OPEN
            )
        )

    def try_add(self, alert: Alert) -> bool:
        """Insert an alert unless an open one for the same asset and rule already exists.

        Runs in a savepoint so losing a race on the unique index only discards this insert,
        not the caller's surrounding transaction (e.g. the telemetry sample being stored).
        """
        try:
            with self._session.begin_nested():
                self._session.add(alert)
        except IntegrityError:
            return False
        return True

    def list(
        self, status: AlertStatus | None, asset_id: int | None, limit: int
    ) -> Sequence[tuple[Alert, Asset]]:
        stmt = select(Alert, Asset).join(Asset, Alert.asset_id == Asset.id)
        if status is not None:
            stmt = stmt.where(Alert.status == status)
        if asset_id is not None:
            stmt = stmt.where(Alert.asset_id == asset_id)
        stmt = stmt.order_by(Alert.opened_at.desc(), Alert.id.desc()).limit(limit)
        return [(alert, asset) for alert, asset in self._session.execute(stmt).all()]

    def stale_assets_without_open_alert(
        self, rule: AlertRule, seen_before: datetime
    ) -> Sequence[Asset]:
        open_alert = (
            select(Alert.id)
            .where(Alert.asset_id == Asset.id, Alert.rule == rule, Alert.status == AlertStatus.OPEN)
            .exists()
        )
        return self._session.scalars(
            select(Asset).where(
                Asset.last_seen_at.is_not(None), Asset.last_seen_at < seen_before, ~open_alert
            )
        ).all()
