"""Basic rule-based alerting.

Deliberately simple: a fixed set of rules evaluated in-process. An alert reflects an incident,
not a sample or an event: while it is active (open or acknowledged) the same asset and rule
never get a second one (unique index), new occurrences update it instead.

Two kinds of rules:
- condition rules (offline, CPU/RAM/disk, watched service stopped) open when the condition
  starts and resolve when it clears;
- event rules (critical event, error burst, admin change) fire on something that happened;
  nothing "clears" them, so they resolve after ALERT_EVENT_QUIET_MINUTES without a new
  occurrence.
"""

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, parse_critical_events, parse_name_list
from app.core.exceptions import ConflictError, NotFoundError
from app.models.alert import Alert, AlertRule, AlertSeverity, AlertStatus
from app.models.asset import Asset
from app.models.event import EventLevel, SystemEvent
from app.models.telemetry import TelemetrySample
from app.repositories.alert_repository import AlertFilter, AlertRepository
from app.repositories.asset_repository import AssetRepository
from app.repositories.telemetry_repository import TelemetryRepository
from app.schemas.alert import AlertList, AlertRead

logger = logging.getLogger(__name__)

EVENT_RULES = (AlertRule.CRITICAL_EVENT, AlertRule.EVENT_BURST, AlertRule.ADMIN_CHANGED)
_SEVERITY_RANK = {AlertSeverity.INFO: 0, AlertSeverity.WARNING: 1, AlertSeverity.CRITICAL: 2}
_BURST_LEVELS = (EventLevel.ERROR, EventLevel.CRITICAL)
# Long event messages are cut in alert details; the full text stays on the event.
_EXCERPT = 300


@dataclass(frozen=True)
class AlertThresholds:
    cpu_percent: float
    ram_percent: float
    disk_percent: float
    sustained_samples: int
    offline_after: timedelta
    # Lowercased service names.
    watched_services: frozenset[str] = field(default_factory=frozenset)
    # (lowercased provider, event code).
    critical_events: frozenset[tuple[str, int]] = field(default_factory=frozenset)
    event_burst_count: int = 10
    event_burst_window: timedelta = timedelta(minutes=10)
    event_quiet: timedelta = timedelta(minutes=60)

    @classmethod
    def from_settings(cls, settings: Settings) -> "AlertThresholds":
        return cls(
            cpu_percent=settings.alert_cpu_percent,
            ram_percent=settings.alert_ram_percent,
            disk_percent=settings.alert_disk_percent,
            sustained_samples=settings.alert_sustained_samples,
            offline_after=timedelta(seconds=settings.heartbeat_timeout_seconds),
            watched_services=frozenset(
                name.lower() for name in parse_name_list(settings.alert_watched_services)
            ),
            critical_events=frozenset(
                (provider.lower(), code)
                for provider, code in parse_critical_events(settings.alert_critical_events)
            ),
            event_burst_count=settings.alert_event_burst_count,
            event_burst_window=timedelta(minutes=settings.alert_event_burst_minutes),
            event_quiet=timedelta(minutes=settings.alert_event_quiet_minutes),
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

    # --- Condition rules -------------------------------------------------------------------

    def evaluate_metrics(self, asset: Asset) -> None:
        """Open or resolve metric alerts for an asset. Does not commit (caller's transaction)."""
        samples = self._telemetry.recent_for_asset(asset.id, self._thresholds.sustained_samples)
        if not samples:
            return
        now = datetime.now(UTC)
        latest = samples[0]
        for rule in METRIC_RULES:
            threshold = self._threshold(rule)
            # A single spike never alerts CPU/RAM: the last N samples must all be over.
            needed = self._thresholds.sustained_samples if rule.sustained else 1
            window = samples[:needed]
            breached = len(window) == needed and all(
                _metric(sample, rule) >= threshold for sample in window
            )
            current = _metric(latest, rule)
            existing = self._alerts.get_active(asset.id, rule.rule)

            if breached and existing is None:
                self._open(
                    asset,
                    rule.rule,
                    rule.severity,
                    f"{rule.label} at {current:.0f}% (threshold {threshold:.0f}%)",
                    now,
                    value=current,
                )
            # Resolve only when the latest sample is back under the threshold; a single
            # good sample is enough because opening already required a sustained breach.
            elif existing is not None and current < threshold:
                _resolve(existing, now)

    def evaluate_services(self, asset: Asset, services: Sequence[dict[str, Any]]) -> None:
        """Watched services present but not running. Does not commit.

        Runs on each inventory snapshot. A service on the list that is disabled on purpose
        (e.g. Defender when another antivirus is registered) is configuration, not an
        incident, and is ignored; so is one the host does not have. An empty services
        section means the collection failed: nothing is decided from it.
        """
        watched = self._thresholds.watched_services
        if not watched or not services:
            return
        stopped = [
            service
            for service in services
            if str(service.get("name", "")).lower() in watched
            and str(service.get("status", "")).lower() != "running"
            and str(service.get("start_type") or "").lower() != "disabled"
        ]
        existing = self._alerts.get_active(asset.id, AlertRule.SERVICE_STOPPED)
        now = datetime.now(UTC)
        if not stopped:
            if existing is not None:
                _resolve(existing, now)
            return
        names = ", ".join(str(s["name"]) for s in stopped)
        details: dict[str, Any] = {
            "services": [
                {"name": s["name"], "status": s.get("status"), "start_type": s.get("start_type")}
                for s in stopped
            ]
        }
        message = f"Watched service not running: {names}"[:500]
        if existing is None:
            self._open(
                asset, AlertRule.SERVICE_STOPPED, AlertSeverity.CRITICAL, message, now, details
            )
        else:
            # Same incident while the list changes (one more stopped, one recovered).
            existing.message = message
            existing.details = details
            existing.last_triggered_at = now

    def sweep_offline(self) -> int:
        """Open offline alerts for assets silent longer than the timeout. Commits.

        Runs periodically because a dead agent cannot report its own death.
        """
        now = datetime.now(UTC)
        stale = self._alerts.stale_assets_without_active_alert(
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
                now,
                {"last_seen_at": asset.last_seen_at.isoformat() if asset.last_seen_at else None},
            ):
                opened += 1
        self._session.commit()
        return opened

    # --- Event rules -----------------------------------------------------------------------

    def evaluate_events(self, asset: Asset, events: Sequence[SystemEvent]) -> None:
        """Critical events and error bursts among newly stored host events. Does not commit.

        Only events stored by this request are passed in, so a resent batch never fires the
        same event twice.
        """
        now = datetime.now(UTC)
        for event in events:
            if (event.provider.lower(), event.event_code) in self._thresholds.critical_events:
                excerpt = " ".join(event.message.split())[:_EXCERPT]
                self._trigger(
                    asset,
                    AlertRule.CRITICAL_EVENT,
                    AlertSeverity.CRITICAL,
                    f"{event.provider} {event.event_code}: {excerpt}"[:500],
                    now,
                    {
                        "channel": event.channel,
                        "provider": event.provider,
                        "event_code": event.event_code,
                        "record_id": event.record_id,
                        "occurred_at": event.occurred_at.isoformat(),
                        "message": excerpt,
                    },
                    source_event_id=event.id,
                )
        window = self._thresholds.event_burst_window
        # Only new errors inside the window are a (new) burst: a backlog of old events (an
        # agent's first run, a flush after an outage) must not re-fire an earlier burst.
        if not any(
            event.level in _BURST_LEVELS and event.occurred_at >= now - window for event in events
        ):
            return
        count = (
            self._session.scalar(
                select(func.count())
                .select_from(SystemEvent)
                .where(
                    SystemEvent.asset_id == asset.id,
                    SystemEvent.level.in_(_BURST_LEVELS),
                    SystemEvent.occurred_at >= now - window,
                )
            )
            or 0
        )
        if count >= self._thresholds.event_burst_count:
            minutes = int(window.total_seconds() // 60)
            self._trigger(
                asset,
                AlertRule.EVENT_BURST,
                AlertSeverity.WARNING,
                f"{count} error/critical events in the last {minutes} min",
                now,
                {"count": count, "window_minutes": minutes},
            )

    def record_admin_changes(self, asset: Asset, changes: Sequence[dict[str, Any]]) -> None:
        """Accounts that gained or lost administrator rights (from inventory). No commit."""
        if not changes:
            return
        summary = ", ".join(f"{c['account']} ({c['change']})" for c in changes)
        self._trigger(
            asset,
            AlertRule.ADMIN_CHANGED,
            AlertSeverity.WARNING,
            f"Administrator membership changed: {summary}"[:500],
            datetime.now(UTC),
            {"changes": list(changes)},
        )

    def resolve_quiet_event_alerts(self) -> int:
        """Resolve event-based alerts with no new occurrence in the quiet window. Commits."""
        now = datetime.now(UTC)
        quiet = self._alerts.quiet_active(EVENT_RULES, now - self._thresholds.event_quiet)
        for alert in quiet:
            _resolve(alert, now)
        self._session.commit()
        return len(quiet)

    # --- Operator actions (CLI) ------------------------------------------------------------

    def acknowledge(self, alert_public_id: UUID) -> Alert:
        """Mark an active alert as seen. It stays active (deduplicated) until resolved."""
        alert = self._require(alert_public_id)
        if alert.status == AlertStatus.RESOLVED:
            raise ConflictError("Alert is already resolved")
        if alert.status == AlertStatus.OPEN:
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = datetime.now(UTC)
        self._session.commit()
        return alert

    def resolve(self, alert_public_id: UUID) -> Alert:
        """Close an alert by hand. A condition still present opens a new alert later."""
        alert = self._require(alert_public_id)
        if alert.status != AlertStatus.RESOLVED:
            _resolve(alert, datetime.now(UTC))
        self._session.commit()
        return alert

    def _require(self, alert_public_id: UUID) -> Alert:
        alert = self._alerts.get_by_public_id(alert_public_id)
        if alert is None:
            raise NotFoundError("Alert not found")
        return alert

    # --- Reads -----------------------------------------------------------------------------

    def list_alerts(
        self,
        f: AlertFilter,
        asset_public_id: UUID | None,
        limit: int,
        offset: int = 0,
    ) -> AlertList:
        if asset_public_id is not None:
            asset = self._assets.get_by_public_id(asset_public_id)
            if asset is None:
                raise NotFoundError("Asset not found")
            f = replace(f, asset_id=asset.id)
        rows, total = self._alerts.list(f, limit, offset)
        return AlertList(items=[_to_read(*row) for row in rows], total=total)

    def get_alert(self, alert_public_id: UUID) -> AlertRead:
        row = self._alerts.get_with_context(alert_public_id)
        if row is None:
            raise NotFoundError("Alert not found")
        return _to_read(*row)

    # --- Internals -------------------------------------------------------------------------

    def _open(
        self,
        asset: Asset,
        rule: AlertRule,
        severity: AlertSeverity,
        message: str,
        now: datetime,
        details: dict[str, Any] | None = None,
        *,
        value: float | None = None,
        source_event_id: int | None = None,
    ) -> bool:
        created = self._alerts.try_add(
            Alert(
                asset_id=asset.id,
                rule=rule,
                severity=severity,
                status=AlertStatus.OPEN,
                message=message,
                value=value,
                details=details,
                source_event_id=source_event_id,
                occurrences=1,
                last_triggered_at=now,
                opened_at=now,
            )
        )
        if created:
            logger.info(
                "alert opened",
                extra={"rule": rule.value, "asset_id": str(asset.public_id), "value": value},
            )
        return created

    def _trigger(
        self,
        asset: Asset,
        rule: AlertRule,
        severity: AlertSeverity,
        message: str,
        now: datetime,
        details: dict[str, Any],
        *,
        source_event_id: int | None = None,
    ) -> None:
        """Open the alert, or count one more occurrence on the active one."""
        for _ in range(2):  # a lost insert race means the winner now exists: bump it
            existing = self._alerts.get_active(asset.id, rule)
            if existing is not None:
                existing.occurrences += 1
                existing.last_triggered_at = now
                existing.message = message
                existing.details = details
                if source_event_id is not None:
                    existing.source_event_id = source_event_id
                # Severity only escalates: a milder occurrence must not hide the worst one.
                if _SEVERITY_RANK[severity] > _SEVERITY_RANK[existing.severity]:
                    existing.severity = severity
                return
            if self._open(
                asset, rule, severity, message, now, details, source_event_id=source_event_id
            ):
                return


def _metric(sample: TelemetrySample, rule: MetricRule) -> float:
    value: float = getattr(sample, rule.metric)
    return value


def _to_read(alert: Alert, asset: Asset, event_id: UUID | None) -> AlertRead:
    return AlertRead(
        alert_id=alert.public_id,
        asset_id=asset.public_id,
        hostname=asset.hostname,
        rule=alert.rule,
        severity=alert.severity,
        status=alert.status,
        message=alert.message,
        value=alert.value,
        details=alert.details,
        occurrences=alert.occurrences,
        last_triggered_at=alert.last_triggered_at,
        event_id=event_id,
        opened_at=alert.opened_at,
        acknowledged_at=alert.acknowledged_at,
        resolved_at=alert.resolved_at,
    )


def resolve_offline_alert(session: Session, asset_id: int, now: datetime) -> None:
    """Resolve the offline alert as soon as the agent reports again (no sweep delay)."""
    existing = AlertRepository(session).get_active(asset_id, AlertRule.ASSET_OFFLINE)
    if existing is not None:
        _resolve(existing, now)


def _resolve(alert: Alert, now: datetime) -> None:
    alert.status = AlertStatus.RESOLVED
    alert.resolved_at = now
    logger.info(
        "alert resolved", extra={"rule": alert.rule.value, "alert_id": str(alert.public_id)}
    )
