"""Vista de seguridad del dashboard (Fase 7A.7). Ver docs/security-dashboard.md.

Todo sale de datos reales y agregados en SQL, con el mismo filtro de activos actuales y de
site que /dashboard/summary (por eso hereda de DashboardService). El riesgo histórico se
reconstruye desde el ledger del Risk Engine (risk_snapshots), que solo guarda una fila cuando
el riesgo de un activo cambia: el valor de un activo en un día es su última instantánea
anterior al final de ese día.

Nada aquí inventa valores. Sin activos con riesgo calculado, la postura es `no_data` con
score null, no un cero que parecería "todo bien".
"""

from datetime import UTC, datetime, time, timedelta
from uuid import UUID

from sqlalchemy import String, case, cast, func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetCriticality
from app.models.detection import Detection
from app.models.exposure import AssetPort, PortStateValue
from app.models.incident import Incident, IncidentStatus
from app.models.risk import AssetRisk, RiskLevel, RiskSnapshot
from app.repositories.asset_repository import display_name_expr
from app.risk.config import RiskConfig
from app.schemas.dashboard import (
    ExposedPortCount,
    ExposedPortSummary,
    NewDevice,
    NewDevices,
    PostureMethod,
    RecentDetection,
    RiskHistoryPoint,
    SecurityOverview,
    SecurityPosture,
)
from app.services.dashboard_service import DETECTION_ACTIVE, DashboardService

POSTURE_FORMULA_VERSION = 1
# Un activo crítico pesa cuatro veces lo que uno de criticidad baja: la postura global debe
# reflejar sobre todo lo que más importa, sin que un único activo lo decida todo.
CRITICALITY_WEIGHTS: dict[str, int] = {
    AssetCriticality.LOW.value: 1,
    AssetCriticality.MEDIUM.value: 2,
    AssetCriticality.HIGH.value: 3,
    AssetCriticality.CRITICAL.value: 4,
}
# Por debajo de esta cobertura la media describe a una minoría de activos: se marca parcial.
PARTIAL_COVERAGE = 0.5
NEW_DEVICE_WINDOW_DAYS = 7
LIST_LIMIT = 8
MIN_DAYS = 7
MAX_DAYS = 90


class SecurityOverviewService(DashboardService):
    def __init__(
        self,
        session: Session,
        heartbeat_timeout: timedelta,
        risk_config: RiskConfig,
        site_id: int | None = None,
    ) -> None:
        super().__init__(session, heartbeat_timeout, site_id)
        self._risk_config = risk_config

    def overview(
        self,
        days: int,
        include_incidents: bool,
        site_public_id: UUID | None = None,
        now: datetime | None = None,
    ) -> SecurityOverview:
        now = now or datetime.now(UTC)
        return SecurityOverview(
            generated_at=now,
            site_id=site_public_id,
            window_days=days,
            posture=self.posture(),
            incidents_by_status=self._incidents_by_status() if include_incidents else None,
            detections_recent=self._recent_detections(),
            risk_history=self.risk_history(days, now),
            new_devices=self._new_devices(now),
            exposed_ports=self._exposed_ports(),
        )

    def _method(self) -> PostureMethod:
        low, medium, high, critical = self._risk_config.thresholds
        return PostureMethod(
            formula=(
                "Media de AssetRisk.score ponderada por la criticidad del activo: "
                "sum(score x peso) / sum(peso), redondeada al entero."
            ),
            population=(
                "Activos actuales (no archivados, del site elegido) con riesgo calculado "
                "por el Risk Engine."
            ),
            weights=dict(CRITICALITY_WEIGHTS),
            missing_data=(
                "Los activos sin riesgo calculado no cuentan como cero: quedan fuera y bajan "
                "la cobertura. Sin ninguno, score es null (no_data); con cobertura menor del "
                f"{int(PARTIAL_COVERAGE * 100)} % el estado es partial."
            ),
            thresholds={
                RiskLevel.LOW.value: low,
                RiskLevel.MEDIUM.value: medium,
                RiskLevel.HIGH.value: high,
                RiskLevel.CRITICAL.value: critical,
            },
            reference="docs/security-dashboard.md",
        )

    def posture(self) -> SecurityPosture:
        weight = case(
            *(
                (cast(Asset.criticality, String) == name, value)
                for name, value in CRITICALITY_WEIGHTS.items()
            ),
            # Una criticidad desconocida pesa como media: nunca descarta el activo.
            else_=CRITICALITY_WEIGHTS[AssetCriticality.MEDIUM.value],
        )
        weighted, weights, scored, peak, serious = self._session.execute(
            select(
                func.sum(AssetRisk.score * weight),
                func.sum(weight),
                func.count(),
                func.max(AssetRisk.score),
                func.count().filter(AssetRisk.level.in_((RiskLevel.HIGH, RiskLevel.CRITICAL))),
            )
            .join(Asset, Asset.id == AssetRisk.asset_id)
            .where(self._current, AssetRisk.calculated_at.is_not(None))
        ).one()
        current = (
            self._session.scalar(select(func.count()).select_from(Asset).where(self._current)) or 0
        )
        scored = scored or 0
        coverage = round(scored / current, 3) if current else 0.0
        score: int | None = None
        level: str | None = None
        if scored and weights:
            score = round(float(weighted) / float(weights))
            level = self._risk_config.level_for(score).value
        if not scored:
            state = "no_data"
        elif coverage < PARTIAL_COVERAGE:
            state = "partial"
        else:
            state = "ok"
        return SecurityPosture(
            formula_version=POSTURE_FORMULA_VERSION,
            state=state,
            score=score,
            level=level,
            peak_score=peak,
            high_or_critical=serious or 0,
            assets_current=current,
            assets_scored=scored,
            coverage=coverage,
            method=self._method(),
        )

    def _incidents_by_status(self) -> dict[str, int]:
        counts = {status.value: 0 for status in IncidentStatus}
        for status, count in self._session.execute(
            select(cast(Incident.status, String), func.count())
            .where(*self._incident_site())
            .group_by(Incident.status)
        ):
            counts[str(status)] = count
        return counts

    def _recent_detections(self) -> list[RecentDetection]:
        rows = self._session.execute(
            select(
                Detection.public_id,
                Detection.rule_id,
                Detection.title,
                cast(Detection.severity, String),
                cast(Detection.status, String),
                Asset.public_id,
                display_name_expr(),
                Detection.last_seen_at,
            )
            .join(Asset, Asset.id == Detection.asset_id)
            .where(Detection.status.in_(DETECTION_ACTIVE), self._current)
            .order_by(Detection.last_seen_at.desc(), Detection.id.desc())
            .limit(LIST_LIMIT)
        )
        return [
            RecentDetection(
                detection_id=detection_id,
                rule_id=rule_id,
                title=title,
                severity=severity,
                status=status,
                asset_id=asset_id,
                asset_name=name,
                last_seen_at=last_seen,
            )
            for detection_id, rule_id, title, severity, status, asset_id, name, last_seen in rows
        ]

    def risk_history(self, days: int, now: datetime) -> list[RiskHistoryPoint]:
        """Un punto por día (UTC): estado del riesgo de los activos actuales al final del día.

        Se lee una vez el estado anterior a la ventana (última instantánea de cada activo) y
        luego, en orden, las instantáneas de la ventana: coste proporcional a los cambios, no
        a días x historial completo.
        """
        first_day = datetime.combine(now.date() - timedelta(days=days - 1), time.min, tzinfo=UTC)
        state: dict[int, tuple[int, str]] = {}
        baseline = (
            select(
                RiskSnapshot.asset_id,
                RiskSnapshot.score,
                cast(RiskSnapshot.level, String),
            )
            .join(Asset, Asset.id == RiskSnapshot.asset_id)
            .where(self._current, RiskSnapshot.calculated_at < first_day)
            .order_by(
                RiskSnapshot.asset_id,
                RiskSnapshot.calculated_at.desc(),
                RiskSnapshot.id.desc(),
            )
            .ext(distinct_on(RiskSnapshot.asset_id))
        )
        for asset_id, score, level in self._session.execute(baseline):
            state[asset_id] = (score, str(level))
        changes = (
            select(
                RiskSnapshot.asset_id,
                RiskSnapshot.score,
                cast(RiskSnapshot.level, String),
                RiskSnapshot.calculated_at,
            )
            .join(Asset, Asset.id == RiskSnapshot.asset_id)
            .where(
                self._current,
                RiskSnapshot.calculated_at >= first_day,
                RiskSnapshot.calculated_at <= now,
            )
            .order_by(RiskSnapshot.calculated_at, RiskSnapshot.id)
            .execution_options(yield_per=2000)
        )
        pending = iter(self._session.execute(changes))
        upcoming = next(pending, None)
        points: list[RiskHistoryPoint] = []
        for offset in range(days):
            day = first_day + timedelta(days=offset)
            end = day + timedelta(days=1)
            while upcoming is not None and upcoming[3] < end:
                state[upcoming[0]] = (upcoming[1], str(upcoming[2]))
                upcoming = next(pending, None)
            scores = [score for score, _ in state.values()]
            levels = [level for _, level in state.values()]
            points.append(
                RiskHistoryPoint(
                    day=day,
                    assets_scored=len(scores),
                    average_score=round(sum(scores) / len(scores), 1) if scores else None,
                    high=levels.count(RiskLevel.HIGH.value),
                    critical=levels.count(RiskLevel.CRITICAL.value),
                )
            )
        return points

    def _new_devices(self, now: datetime) -> NewDevices:
        since = now - timedelta(days=NEW_DEVICE_WINDOW_DAYS)
        recent = self._current & (Asset.first_seen_at >= since)
        count = self._session.scalar(select(func.count()).select_from(Asset).where(recent)) or 0
        rows = self._session.execute(
            select(
                Asset.public_id,
                display_name_expr(),
                Asset.device_type,
                cast(Asset.monitoring_method, String),
                Asset.first_seen_at,
            )
            .where(recent)
            .order_by(Asset.first_seen_at.desc(), Asset.id.desc())
            .limit(LIST_LIMIT)
        )
        return NewDevices(
            window_days=NEW_DEVICE_WINDOW_DAYS,
            count=count,
            items=[
                NewDevice(
                    asset_id=asset_id,
                    name=name,
                    device_type=device_type,
                    monitoring_method=method,
                    first_seen_at=first_seen,
                )
                for asset_id, name, device_type, method, first_seen in rows
            ],
        )

    def _exposed_ports(self) -> ExposedPortSummary:
        open_port = (AssetPort.state == PortStateValue.OPEN) & self._current_assets(
            AssetPort.asset_id
        )
        total, assets = self._session.execute(
            select(func.count(), func.count(func.distinct(AssetPort.asset_id))).where(open_port)
        ).one()
        affected = func.count(func.distinct(AssetPort.asset_id))
        top = self._session.execute(
            select(AssetPort.port, AssetPort.protocol, affected)
            .where(open_port)
            .group_by(AssetPort.port, AssetPort.protocol)
            .order_by(affected.desc(), AssetPort.port)
            .limit(LIST_LIMIT)
        )
        return ExposedPortSummary(
            open_ports=total or 0,
            assets_with_open_ports=assets or 0,
            top=[
                ExposedPortCount(port=port, protocol=protocol, assets=count)
                for port, protocol, count in top
            ],
        )
