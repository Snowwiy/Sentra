from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import cast
from uuid import UUID

from sqlalchemy import Select, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertRule, AlertSeverity, AlertStatus
from app.models.asset import Asset
from app.models.event import SystemEvent


@dataclass(frozen=True)
class AlertFilter:
    status: AlertStatus | None = None
    # Open or acknowledged (not resolved); combined with `status` it is ignored.
    active: bool = False
    severity: AlertSeverity | None = None
    rule: AlertRule | None = None
    asset_id: int | None = None
    # Case-insensitive substring of the message or the hostname.
    search: str | None = None


class AlertRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_active(self, asset_id: int, rule: AlertRule) -> Alert | None:
        """The open or acknowledged alert of this asset and rule, if any (at most one)."""
        return self._session.scalar(
            select(Alert).where(
                Alert.asset_id == asset_id,
                Alert.rule == rule,
                Alert.status != AlertStatus.RESOLVED,
            )
        )

    def get_by_public_id(self, public_id: UUID) -> Alert | None:
        return self._session.scalar(select(Alert).where(Alert.public_id == public_id))

    def try_add(self, alert: Alert) -> bool:
        """Insert an alert unless an active one for the same asset and rule already exists.

        Runs in a savepoint so losing a race on the unique index only discards this insert,
        not the caller's surrounding transaction (e.g. the telemetry sample being stored).
        """
        try:
            with self._session.begin_nested():
                self._session.add(alert)
        except IntegrityError:
            return False
        return True

    def _filtered(
        self, stmt: Select[Alert, Asset, UUID], f: AlertFilter
    ) -> Select[Alert, Asset, UUID]:
        if f.status is not None:
            stmt = stmt.where(Alert.status == f.status)
        elif f.active:
            stmt = stmt.where(Alert.status != AlertStatus.RESOLVED)
        if f.severity is not None:
            stmt = stmt.where(Alert.severity == f.severity)
        if f.rule is not None:
            stmt = stmt.where(Alert.rule == f.rule)
        if f.asset_id is not None:
            stmt = stmt.where(Alert.asset_id == f.asset_id)
        if f.search:
            pattern = f"%{escape_like(f.search)}%"
            stmt = stmt.where(
                or_(
                    Alert.message.ilike(pattern, escape="\\"),
                    Asset.hostname.ilike(pattern, escape="\\"),
                    # Discovered assets have no hostname: their name or address.
                    Asset.reverse_dns.ilike(pattern, escape="\\"),
                    Asset.primary_ip.ilike(pattern, escape="\\"),
                )
            )
        return stmt

    def list(
        self, f: AlertFilter, limit: int, offset: int = 0
    ) -> tuple[list[tuple[Alert, Asset, UUID | None]], int]:
        """One page of alerts (newest first), each with its asset and source event id, and
        the number of alerts matching the filter."""
        base = (
            select(Alert, Asset, SystemEvent.public_id)
            .join(Asset, Alert.asset_id == Asset.id)
            .outerjoin(SystemEvent, Alert.source_event_id == SystemEvent.id)
        )
        stmt = self._filtered(base, f)
        total = self._session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        page = stmt.order_by(Alert.opened_at.desc(), Alert.id.desc()).limit(limit).offset(offset)
        rows = cast(list[tuple[Alert, Asset, UUID | None]], list(self._session.execute(page)))
        return rows, total

    def get_with_context(self, public_id: UUID) -> tuple[Alert, Asset, UUID | None] | None:
        row = self._session.execute(
            select(Alert, Asset, SystemEvent.public_id)
            .join(Asset, Alert.asset_id == Asset.id)
            .outerjoin(SystemEvent, Alert.source_event_id == SystemEvent.id)
            .where(Alert.public_id == public_id)
        ).first()
        return (row[0], row[1], row[2]) if row else None

    def stale_assets_without_active_alert(
        self, rule: AlertRule, seen_before: datetime
    ) -> Sequence[Asset]:
        active_alert = (
            select(Alert.id)
            .where(
                Alert.asset_id == Asset.id,
                Alert.rule == rule,
                Alert.status != AlertStatus.RESOLVED,
            )
            .exists()
        )
        # FOR UPDATE SKIP LOCKED: an asset whose row is locked is being updated by an agent
        # call right now (record_contact), so it is alive: skip it instead of waiting. A row
        # updated and committed meanwhile is re-checked by PostgreSQL against the WHERE
        # clause, so a fresh last_seen_at drops it from the result.
        return self._session.scalars(
            select(Asset)
            .where(
                Asset.last_seen_at.is_not(None),
                Asset.last_seen_at < seen_before,
                # Fase 5C.1: un activo archivado (equipo retirado, agente revocado) no debe
                # abrir alertas de "offline" nuevas: su silencio es lo esperado.
                Asset.archived_at.is_(None),
                ~active_alert,
            )
            .with_for_update(skip_locked=True, of=Asset)
        ).all()

    def quiet_active(
        self, rules: Collection[AlertRule], triggered_before: datetime
    ) -> Sequence[Alert]:
        """Active alerts of these rules that did not fire again since `triggered_before`."""
        last = func.coalesce(Alert.last_triggered_at, Alert.opened_at)
        return self._session.scalars(
            select(Alert).where(
                Alert.rule.in_(rules),
                Alert.status != AlertStatus.RESOLVED,
                last < triggered_before,
            )
        ).all()


def escape_like(text: str) -> str:
    """Make user input match literally inside a LIKE pattern."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
