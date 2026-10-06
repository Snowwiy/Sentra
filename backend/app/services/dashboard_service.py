"""Resumen agregado del dashboard (Fase 4M).

Antes el dashboard descargaba todos los activos para contarlos en el navegador (~1,5 s con
10 000 activos aunque la API ya paginaba). Aquí cada bloque es una consulta COUNT/GROUP BY
sobre índices existentes: el coste no depende de serializar filas.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session

from app.models.alert import ACTIVE_STATUSES as ALERT_ACTIVE
from app.models.alert import Alert
from app.models.asset import Asset, AssetStatus, MonitoringMethod
from app.models.detection import Detection, DetectionSeverity, DetectionStatus
from app.models.incident import ACTIVE_STATUSES as INCIDENT_ACTIVE
from app.models.incident import Incident, IncidentLevel
from app.models.risk import AssetRisk, RiskLevel
from app.repositories.asset_repository import effective_status_expr
from app.schemas.dashboard import (
    DashboardAssets,
    DashboardDetections,
    DashboardIncidents,
    DashboardRisk,
    DashboardSummary,
)

DETECTION_ACTIVE = (DetectionStatus.OPEN, DetectionStatus.ACKNOWLEDGED)


class DashboardService:
    def __init__(self, session: Session, heartbeat_timeout: timedelta) -> None:
        self._session = session
        self._timeout = heartbeat_timeout

    def summary(self, include_incidents: bool) -> DashboardSummary:
        now = datetime.now(UTC)
        assets = self.asset_summary(now)
        return DashboardSummary(
            generated_at=now,
            assets=assets,
            risk=self._risk(assets.total),
            incidents=self._incidents() if include_incidents else None,
            detections=self._detections(),
            active_alerts=self._session.scalar(
                select(func.count()).select_from(Alert).where(Alert.status.in_(ALERT_ACTIVE))
            )
            or 0,
        )

    def asset_summary(self, now: datetime) -> DashboardAssets:
        status = effective_status_expr(now, self._timeout).label("status")
        by_status = {s.value: 0 for s in AssetStatus}
        by_method = {m.value: 0 for m in MonitoringMethod}
        # Una sola pasada: estado efectivo x método.
        for state, method, count in self._session.execute(
            select(status, Asset.monitoring_method, func.count()).group_by(
                status, Asset.monitoring_method
            )
        ):
            by_status[str(state)] = by_status.get(str(state), 0) + count
            by_method[MonitoringMethod(method).value] += count
        device = func.coalesce(Asset.device_type, "unknown").label("device_type")
        by_type = {
            str(kind): count
            for kind, count in self._session.execute(select(device, func.count()).group_by(device))
        }
        return DashboardAssets(
            total=sum(by_status.values()),
            online=by_status[AssetStatus.ONLINE.value],
            offline=by_status[AssetStatus.OFFLINE.value],
            unknown=by_status[AssetStatus.UNKNOWN.value],
            by_method=by_method,
            by_device_type=dict(sorted(by_type.items())),
        )

    def _risk(self, total_assets: int) -> DashboardRisk:
        levels = {level.value: 0 for level in RiskLevel}
        for level, count in self._session.execute(
            select(cast(AssetRisk.level, String), func.count())
            .where(AssetRisk.calculated_at.is_not(None))
            .group_by(AssetRisk.level)
        ):
            levels[str(level)] = count
        return DashboardRisk(by_level=levels, unscored=max(total_assets - sum(levels.values()), 0))

    def _incidents(self) -> DashboardIncidents:
        active, critical, unassigned = self._session.execute(
            select(
                func.count(),
                func.count().filter(Incident.severity == IncidentLevel.CRITICAL),
                func.count().filter(Incident.owner_user_id.is_(None)),
            ).where(Incident.status.in_(INCIDENT_ACTIVE))
        ).one()
        return DashboardIncidents(active=active, critical=critical or 0, unassigned=unassigned or 0)

    def _detections(self) -> DashboardDetections:
        severities = {s.value: 0 for s in DetectionSeverity}
        for severity, count in self._session.execute(
            select(cast(Detection.severity, String), func.count())
            .where(Detection.status.in_(DETECTION_ACTIVE))
            .group_by(Detection.severity)
        ):
            severities[str(severity)] = count
        return DashboardDetections(active=sum(severities.values()), by_severity=severities)
