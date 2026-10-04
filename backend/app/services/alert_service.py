"""Basic rule-based alerting.

Deliberately simple: a fixed set of rules evaluated in-process. Each rule opens one alert when
its condition starts and resolves it when the condition clears, so the alert list reflects
incidents rather than one row per bad sample.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import NotFoundError
from app.models.alert import Alert, AlertRule, AlertSeverity, AlertStatus
from app.models.asset import Asset
from app.models.telemetry import TelemetrySample
from app.repositories.alert_repository import AlertRepository
from app.repositories.asset_repository import AssetRepository
from app.repositories.telemetry_repository import TelemetryRepository
from app.schemas.alert import AlertList, AlertRead

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AlertThresholds:
    cpu_percent: float
    ram_percent: float
    disk_percent: float
    sustained_samples: int
    offline_after: timedelta

    @classmethod
    def from_settings(cls, settings: Settings) -> "AlertThresholds":
        return cls(
            cpu_percent=settings.alert_cpu_percent,
            ram_percent=settings.alert_ram_percent,
            disk_percent=settings.alert_disk_percent,
            sustained_samples=settings.alert_sustained_samples,
            offline_after=timedelta(seconds=settings.heartbeat_timeout_seconds),
        )


@dataclass(frozen=True)
class MetricRule:
    rule: AlertRule
    metric: str
    label: str
    severity: AlertSeverity
    sustained: bool


METRIC_RULES = (
    MetricRule(AlertRule.HIGH_CPU, "cpu_percent", "CPU", AlertSeverity.WARNING, sustained=True),
    MetricRule(AlertRule.HIGH_RAM, "ram_percent", "RAM", AlertSeverity.WARNING, sustained=True),
    MetricRule(
        AlertRule.DISK_CRITICAL, "disk_percent", "Disk", AlertSeverity.CRITICAL, sustained=False
    ),
)


class AlertService:
    def __init__(self, session: Session, thresholds: AlertThresholds) -> None:
        self._session = session
        self._alerts = AlertRepository(session)
        self._assets = AssetRepository(session)
        self._telemetry = TelemetryRepository(session)
        self._thresholds = thresholds

    def _threshold(self, rule: MetricRule) -> float:
        value: float = getattr(self._thresholds, rule.metric)
        return value

    def evaluate_metrics(self, asset: Asset) -> None:
        """Open or resolve metric alerts for an asset. Does not commit (caller's transaction)."""
        samples = self._telemetry.recent_for_asset(asset.id, self._thresholds.sustained_samples)
        if not samples:
            return
        now = datetime.now(UTC)
        latest = samples[0]
        for rule in METRIC_RULES:
            threshold = self._threshold(rule)
            needed = self._thresholds.sustained_samples if rule.sustained else 1
            window = samples[:needed]
            breached = len(window) == needed and all(
                _metric(sample, rule) >= threshold for sample in window
            )
            current = _metric(latest, rule)
            existing = self._alerts.get_open(asset.id, rule.rule)

            if breached and existing is None:
                self._open(
                    asset,
                    rule.rule,
                    rule.severity,
                    f"{rule.label} at {current:.0f}% (threshold {threshold:.0f}%)",
                    current,
                    now,
                )
            # Resolve only when the latest sample is back under the threshold; a single
            # good sample is enough because opening already required a sustained breach.
            elif existing is not None and current < threshold:
                _resolve(existing, now)

    def asset_seen(self, asset: Asset, now: datetime) -> None:
        """Resolve the offline alert as soon as the agent reports again (no sweep delay)."""
        existing = self._alerts.get_open(asset.id, AlertRule.ASSET_OFFLINE)
        if existing is not None:
            _resolve(existing, now)

    def sweep_offline(self) -> int:
        """Open offline alerts for assets silent longer than the timeout. Commits.

        Runs periodically because a dead agent cannot report its own death.
        """
        now = datetime.now(UTC)
        stale = self._alerts.stale_assets_without_open_alert(
            AlertRule.ASSET_OFFLINE, now - self._thresholds.offline_after
        )
        opened = 0
        for asset in stale:
            seconds = int((now - asset.last_seen_at).total_seconds()) if asset.last_seen_at else 0
            if self._open(
                asset,
                AlertRule.ASSET_OFFLINE,
                AlertSeverity.CRITICAL,
                f"No heartbeat for {seconds} s",
                None,
                now,
            ):
                opened += 1
        self._session.commit()
        return opened

    def list_alerts(
        self, status: AlertStatus | None, asset_public_id: UUID | None, limit: int
    ) -> AlertList:
        asset_id: int | None = None
        if asset_public_id is not None:
            asset = self._assets.get_by_public_id(asset_public_id)
            if asset is None:
                raise NotFoundError("Asset not found")
            asset_id = asset.id
        rows = self._alerts.list(status, asset_id, limit)
        items = [
            AlertRead(
                alert_id=alert.public_id,
                asset_id=asset.public_id,
                hostname=asset.hostname,
                rule=alert.rule,
                severity=alert.severity,
                status=alert.status,
                message=alert.message,
                value=alert.value,
                opened_at=alert.opened_at,
                resolved_at=alert.resolved_at,
            )
            for alert, asset in rows
        ]
        return AlertList(items=items, total=len(items))

    def _open(
        self,
        asset: Asset,
        rule: AlertRule,
        severity: AlertSeverity,
        message: str,
        value: float | None,
        now: datetime,
    ) -> bool:
        created = self._alerts.try_add(
            Alert(
                asset_id=asset.id,
                rule=rule,
                severity=severity,
                status=AlertStatus.OPEN,
                message=message,
                value=value,
                opened_at=now,
            )
        )
        if created:
            logger.info(
                "alert opened",
                extra={"rule": rule.value, "asset_id": str(asset.public_id), "value": value},
            )
        return created


def _metric(sample: TelemetrySample, rule: MetricRule) -> float:
    value: float = getattr(sample, rule.metric)
    return value


def _resolve(alert: Alert, now: datetime) -> None:
    alert.status = AlertStatus.RESOLVED
    alert.resolved_at = now
    logger.info(
        "alert resolved", extra={"rule": alert.rule.value, "alert_id": str(alert.public_id)}
    )
