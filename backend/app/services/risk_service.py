"""Lecturas de riesgo para la API (Fase 4I) y cambio de criticidad de un activo.

Solo lee lo que el Risk Engine guardó (asset_risk, risk_snapshots, risk_contributions): una
petición nunca recalcula el riesgo de muchos activos, y si el job falla la API sigue
sirviendo el último valor con su fecha de cálculo.

Listados siempre paginados y filtrados en SQL (nunca se cargan todos los activos).
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import (
    ColumnElement,
    Float,
    cast,
    column,
    func,
    literal,
    nulls_last,
    or_,
    select,
)
from sqlalchemy.dialects.postgresql import JSONB, distinct_on
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.detection.rules import RULES_BY_ID
from app.models.asset import Asset, AssetCriticality, AssetStatus
from app.models.detection import Detection, DetectionStatus
from app.models.risk import (
    AssetRisk,
    RiskConfidence,
    RiskContributionRecord,
    RiskLevel,
    RiskSnapshot,
)
from app.repositories.alert_repository import escape_like
from app.repositories.asset_repository import effective_status_expr
from app.risk.config import RiskConfig
from app.risk.explain import explain
from app.schemas.risk import (
    RiskAssetDetail,
    RiskAssetList,
    RiskAssetSummary,
    RiskContributionList,
    RiskContributionRead,
    RiskDetectionRef,
    RiskFactorRead,
    RiskHistory,
    RiskLevelRange,
    RiskOverview,
    RiskRange,
    RiskSnapshotRead,
    RiskTransitionRead,
)

RiskSort = Literal["score", "changed_at", "last_seen", "name", "criticality"]

# Rangos del gráfico de tendencia: ventana y agregación (un punto por bucket, el último).
# 24 h se sirve con los puntos reales: el historial ya solo guarda cambios materiales.
RANGES: dict[str, tuple[timedelta, int | None]] = {
    "24h": (timedelta(hours=24), None),
    "7d": (timedelta(days=7), 60),
    "30d": (timedelta(days=30), 240),
}
HISTORY_LIMIT = 500
# Origen fijo de los buckets (date_bin): mismos cortes en cada petición.
_BUCKET_ORIGIN = datetime(2000, 1, 1, tzinfo=UTC)

# Etiquetas de "Top risk factors" por categoría de regla (y exposición).
CATEGORY_LABELS = {
    "authentication": "Anomalías de autenticación",
    "account": "Cambios de cuentas y privilegios",
    "scripting": "Scripts sospechosos",
    "persistence": "Persistencia (servicios nuevos)",
    "process": "Procesos inusuales",
    "network": "Cambios de red y puertos",
    "defense": "Controles de seguridad desactivados",
    "system": "Eventos críticos del sistema",
    "exposure": "Exposición sensible",
    "threat_intel": "Coincidencias con inteligencia de amenazas",
    "unknown": "Otras detecciones",
}


@dataclass(frozen=True)
class RiskFilter:
    level: RiskLevel | None = None
    confidence: RiskConfidence | None = None
    # Tipo de dispositivo o "unknown" (sin identificar).
    device_type: str | None = None
    # online / offline / unknown, con la misma regla que effective_status.
    status: AssetStatus | None = None
    criticality: AssetCriticality | None = None
    min_score: int | None = None
    search: str | None = None


class RiskService:
    def __init__(self, session: Session, config: RiskConfig, heartbeat_timeout: timedelta) -> None:
        self._session = session
        self._config = config
        self._timeout = heartbeat_timeout

    # --- Expresiones comunes ---------------------------------------------------------------

    def _status_expr(self, now: datetime) -> ColumnElement[Any]:
        """effective_status (asset_service) en SQL; expresión compartida desde la Fase 4M."""
        return effective_status_expr(now, self._timeout)

    @staticmethod
    def _last_seen_expr() -> ColumnElement[datetime]:
        # greatest() de PostgreSQL ignora los null: el contacto más reciente, sea agente o red.
        return func.greatest(Asset.last_seen_at, Asset.last_network_seen_at)

    def _summary_select(self, now: datetime) -> Any:
        return select(
            Asset.public_id,
            Asset.device_name,
            Asset.hostname,
            Asset.reverse_dns,
            Asset.primary_ip,
            Asset.device_type,
            Asset.monitoring_method,
            Asset.criticality,
            self._status_expr(now).label("effective_status"),
            self._last_seen_expr().label("last_seen"),
            AssetRisk.score,
            AssetRisk.level,
            AssetRisk.confidence,
            AssetRisk.top_factor,
            AssetRisk.calculated_at,
            AssetRisk.changed_at,
        ).outerjoin(AssetRisk, AssetRisk.asset_id == Asset.id)

    def thresholds(self) -> list[RiskLevelRange]:
        return [
            RiskLevelRange(level=RiskLevel(level), min=low, max=high)
            for level, (low, high) in self._config.level_ranges().items()
        ]

    # --- Listado -----------------------------------------------------------------------------

    def list_assets(
        self,
        f: RiskFilter,
        sort: RiskSort,
        descending: bool,
        limit: int,
        offset: int,
    ) -> RiskAssetList:
        now = datetime.now(UTC)
        stmt = self._summary_select(now)
        if f.level is not None:
            stmt = stmt.where(AssetRisk.level == f.level, AssetRisk.calculated_at.is_not(None))
        if f.confidence is not None:
            stmt = stmt.where(
                AssetRisk.confidence == f.confidence, AssetRisk.calculated_at.is_not(None)
            )
        if f.min_score is not None:
            stmt = stmt.where(AssetRisk.score >= f.min_score, AssetRisk.calculated_at.is_not(None))
        if f.device_type is not None:
            stmt = stmt.where(
                Asset.device_type.is_(None)
                if f.device_type == "unknown"
                else Asset.device_type == f.device_type
            )
        if f.criticality is not None:
            stmt = stmt.where(Asset.criticality == f.criticality)
        if f.status is not None:
            stmt = stmt.where(self._status_expr(now) == f.status.value)
        if f.search:
            pattern = f"%{escape_like(f.search)}%"
            stmt = stmt.where(
                or_(
                    Asset.device_name.ilike(pattern, escape="\\"),
                    Asset.hostname.ilike(pattern, escape="\\"),
                    Asset.reverse_dns.ilike(pattern, escape="\\"),
                    Asset.primary_ip.ilike(pattern, escape="\\"),
                )
            )
        total = self._session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = self._session.execute(
            stmt.order_by(*self._order(sort, descending)).limit(limit).offset(offset)
        ).all()
        return RiskAssetList(items=[_summary(row) for row in rows], total=total)

    def _order(self, sort: RiskSort, descending: bool) -> list[Any]:
        column: Any
        if sort == "changed_at":
            column = AssetRisk.changed_at
        elif sort == "last_seen":
            column = self._last_seen_expr()
        elif sort == "name":
            column = func.lower(
                func.coalesce(
                    Asset.device_name, Asset.hostname, Asset.reverse_dns, Asset.primary_ip
                )
            )
        elif sort == "criticality":
            column = Asset.criticality
        else:
            column = AssetRisk.score
        primary = column.desc() if descending else column.asc()
        # Los no evaluados (null) siempre al final; desempate estable por riesgo e id.
        return [nulls_last(primary), nulls_last(AssetRisk.score.desc()), Asset.id]

    # --- Overview ----------------------------------------------------------------------------

    def overview(self) -> RiskOverview:
        now = datetime.now(UTC)
        total_assets = self._session.scalar(select(func.count()).select_from(Asset)) or 0
        evaluated_q = AssetRisk.calculated_at.is_not(None)
        by_level = {level: 0 for level in RiskLevel}
        for level, count in self._session.execute(
            select(AssetRisk.level, func.count()).where(evaluated_q).group_by(AssetRisk.level)
        ):
            by_level[level] = count
        by_confidence = {confidence: 0 for confidence in RiskConfidence}
        for confidence, count in self._session.execute(
            select(AssetRisk.confidence, func.count())
            .where(evaluated_q)
            .group_by(AssetRisk.confidence)
        ):
            by_confidence[confidence] = count
        pending = (
            self._session.scalar(
                select(func.count()).select_from(AssetRisk).where(AssetRisk.dirty_at.is_not(None))
            )
            or 0
        )
        last = self._session.scalar(select(func.max(AssetRisk.calculated_at)))
        rows = self._session.scalar(select(func.count()).select_from(AssetRisk)) or 0

        top_assets = self._session.execute(
            self._summary_select(now)
            .where(evaluated_q, AssetRisk.score > 0)
            .order_by(AssetRisk.score.desc(), AssetRisk.changed_at.desc(), Asset.id)
            .limit(10)
        ).all()

        return RiskOverview(
            total_assets=total_assets,
            evaluated=sum(by_level.values()),
            # Activos sin fila todavía también están pendientes (el job los crea en su vuelta).
            pending=pending + max(0, total_assets - rows),
            by_level=by_level,
            by_confidence=by_confidence,
            top_factors=self._top_factors(),
            top_assets=[_summary(row) for row in top_assets],
            recent_transitions=self._transitions(10),
            thresholds=self.thresholds(),
            last_calculated_at=last,
        )

    def _top_factors(self, limit: int = 8) -> list[RiskFactorRead]:
        """Factores que más riesgo aportan en toda la flota, por categoría (datos reales).

        Se agregan las contribuciones vigentes guardadas en asset_risk (JSONB acotado por
        activo). Solo las positivas de detecciones y exposición: la criticidad o la
        saturación no son "factores de riesgo" sino modificadores.
        """
        item = (
            func.jsonb_array_elements(AssetRisk.contributions)
            .table_valued(column("value", JSONB))
            .alias("c")
        )
        points = cast(item.c.value["points"].astext, Float)
        category = item.c.value["category"].astext
        rows = self._session.execute(
            select(
                category.label("category"),
                func.count(func.distinct(AssetRisk.asset_id)).label("assets"),
                func.sum(points).label("points"),
            )
            .select_from(AssetRisk)
            .join(item, literal(True))
            .where(
                AssetRisk.score > 0,
                item.c.value["factor"].astext.in_(["detection", "exposure", "threat_intel"]),
                points > 0,
            )
            .group_by(category)
            .order_by(func.sum(points).desc())
            .limit(limit)
        ).all()
        return [
            RiskFactorRead(
                category=row.category,
                label=CATEGORY_LABELS.get(row.category, row.category),
                assets=row.assets,
                points=round(float(row.points or 0), 1),
            )
            for row in rows
        ]

    def _transitions(self, limit: int) -> list[RiskTransitionRead]:
        rows = self._session.execute(
            select(RiskSnapshot, Asset)
            .join(Asset, Asset.id == RiskSnapshot.asset_id)
            .where(RiskSnapshot.transition.is_not(None))
            .order_by(RiskSnapshot.calculated_at.desc(), RiskSnapshot.id.desc())
            .limit(limit)
        ).all()
        return [
            RiskTransitionRead(
                **_snapshot(snapshot).model_dump(),
                asset_id=asset.public_id,
                display_name=asset.display_name,
            )
            for snapshot, asset in rows
        ]

    # --- Detalle -----------------------------------------------------------------------------

    def _asset(self, public_id: UUID) -> Asset:
        asset = self._session.scalar(select(Asset).where(Asset.public_id == public_id))
        if asset is None:
            raise NotFoundError("Asset not found")
        return asset

    def detail(self, public_id: UUID) -> RiskAssetDetail:
        now = datetime.now(UTC)
        asset = self._asset(public_id)
        row = self._session.execute(self._summary_select(now).where(Asset.id == asset.id)).one()
        risk = self._session.get(AssetRisk, asset.id)
        evaluated = risk is not None and risk.calculated_at is not None
        contributions = (risk.contributions or []) if risk and evaluated else []

        active_filter = (
            Detection.asset_id == asset.id,
            Detection.status != DetectionStatus.RESOLVED,
        )
        detections = self._session.scalars(
            select(Detection)
            .where(*active_filter)
            # Enum de PostgreSQL: el orden es el de declaración (informational < ... < critical).
            .order_by(Detection.severity.desc(), Detection.last_seen_at.desc(), Detection.id)
            .limit(20)
        ).all()
        active_total = (
            self._session.scalar(select(func.count()).select_from(Detection).where(*active_filter))
            or 0
        )
        recent = self._session.scalars(
            select(RiskSnapshot)
            .where(RiskSnapshot.asset_id == asset.id)
            .order_by(RiskSnapshot.calculated_at.desc(), RiskSnapshot.id.desc())
            .limit(10)
        ).all()
        trend = None
        if evaluated and risk is not None:
            past = self._session.scalar(
                select(RiskSnapshot.score)
                .where(
                    RiskSnapshot.asset_id == asset.id,
                    RiskSnapshot.calculated_at <= now - timedelta(hours=24),
                )
                .order_by(RiskSnapshot.calculated_at.desc())
                .limit(1)
            )
            if past is not None:
                trend = risk.score - past

        summary = _summary(row)
        if evaluated and risk is not None:
            explanation = explain(
                risk.score, risk.level, risk.confidence, contributions, risk.breakdown
            )
        else:
            explanation = explain(0, RiskLevel.INFORMATIONAL, RiskConfidence.LOW, [], None)
            explanation.headline = "Pendiente de evaluar"
            explanation.reasons = ["El activo está en la cola del Risk Engine."]
        return RiskAssetDetail(
            **summary.model_dump(),
            formula_version=risk.formula_version if evaluated and risk else None,
            pending_recalculation=bool(risk is None or risk.dirty_at is not None),
            explanation=explanation,
            contributions=[_contribution(c) for c in contributions],
            active_detections=[_detection_ref(d) for d in detections],
            active_detections_total=active_total,
            recent_changes=[_snapshot(s) for s in recent],
            trend_24h=trend,
            breakdown=risk.breakdown if evaluated and risk else None,
            thresholds=self.thresholds(),
        )

    def history(self, public_id: UUID, range_: RiskRange) -> RiskHistory:
        """Puntos del rango pedido, acotados (nunca todo el historial de una vez)."""
        now = datetime.now(UTC)
        asset = self._asset(public_id)
        window, bucket = RANGES[range_]
        since = now - window
        where = (RiskSnapshot.asset_id == asset.id, RiskSnapshot.calculated_at >= since)
        if bucket is None:
            snapshots = list(
                self._session.scalars(
                    select(RiskSnapshot)
                    .where(*where)
                    .order_by(RiskSnapshot.calculated_at.desc(), RiskSnapshot.id.desc())
                    .limit(HISTORY_LIMIT)
                ).all()
            )
        else:
            # Un punto por bucket: el último de cada intervalo (DISTINCT ON).
            slot = func.date_bin(
                timedelta(minutes=bucket), RiskSnapshot.calculated_at, _BUCKET_ORIGIN
            )
            snapshots = list(
                self._session.scalars(
                    select(RiskSnapshot)
                    .where(*where)
                    .ext(distinct_on(slot))
                    .order_by(
                        slot.desc(), RiskSnapshot.calculated_at.desc(), RiskSnapshot.id.desc()
                    )
                    .limit(HISTORY_LIMIT)
                ).all()
            )
        snapshots.reverse()
        start = self._session.scalar(
            select(RiskSnapshot.score)
            .where(RiskSnapshot.asset_id == asset.id, RiskSnapshot.calculated_at < since)
            .order_by(RiskSnapshot.calculated_at.desc())
            .limit(1)
        )
        risk = self._session.get(AssetRisk, asset.id)
        evaluated = risk is not None and risk.calculated_at is not None
        return RiskHistory(
            asset_id=asset.public_id,
            range=range_,
            since=since,
            bucket_minutes=bucket,
            start_score=start,
            points=[_snapshot(s) for s in snapshots],
            current_score=risk.score if evaluated and risk else None,
            current_level=risk.level if evaluated and risk else None,
            calculated_at=risk.calculated_at if risk else None,
        )

    def contributions(self, public_id: UUID, snapshot_id: UUID | None) -> RiskContributionList:
        asset = self._asset(public_id)
        if snapshot_id is None:
            risk = self._session.get(AssetRisk, asset.id)
            evaluated = risk is not None and risk.calculated_at is not None
            return RiskContributionList(
                asset_id=asset.public_id,
                snapshot_id=None,
                calculated_at=risk.calculated_at if risk else None,
                score=risk.score if evaluated and risk else None,
                items=[_contribution(c) for c in (risk.contributions or [])] if risk else [],
            )
        snapshot = self._session.scalar(
            select(RiskSnapshot).where(
                RiskSnapshot.public_id == snapshot_id, RiskSnapshot.asset_id == asset.id
            )
        )
        if snapshot is None:
            raise NotFoundError("Risk snapshot not found")
        records = self._session.scalars(
            select(RiskContributionRecord)
            .where(RiskContributionRecord.snapshot_id == snapshot.id)
            .order_by(RiskContributionRecord.position)
        ).all()
        return RiskContributionList(
            asset_id=asset.public_id,
            snapshot_id=snapshot.public_id,
            calculated_at=snapshot.calculated_at,
            score=snapshot.score,
            items=[
                RiskContributionRead(
                    factor=r.factor,
                    category=r.category,
                    label=r.label,
                    points=r.points,
                    nominal_points=r.nominal_points,
                    detection_id=r.detection_public_id,
                    rule_id=r.rule_id,
                    port=r.port,
                    details=r.details or {},
                )
                for r in records
            ],
        )

    # --- Criticidad --------------------------------------------------------------------------

    def set_criticality(
        self, public_id: UUID, criticality: AssetCriticality
    ) -> tuple[Asset, AssetCriticality]:
        """Cambia la criticidad (sin commit). Devuelve el activo y el valor anterior."""
        asset = self._session.scalar(
            select(Asset).where(Asset.public_id == public_id).with_for_update()
        )
        if asset is None:
            raise NotFoundError("Asset not found")
        previous = asset.criticality
        asset.criticality = criticality
        return asset, previous


def _display_name(row: Any) -> str:
    # Misma prioridad que Asset.display_name.
    return str(row.device_name or row.hostname or row.reverse_dns or row.primary_ip)


def _summary(row: Any) -> RiskAssetSummary:
    evaluated = row.calculated_at is not None
    return RiskAssetSummary(
        asset_id=row.public_id,
        display_name=_display_name(row),
        device_name=row.device_name,
        primary_ip=row.primary_ip,
        device_type=row.device_type,
        monitoring_method=row.monitoring_method,
        status=AssetStatus(row.effective_status),
        criticality=row.criticality,
        last_seen_at=row.last_seen,
        evaluated=evaluated,
        score=row.score if evaluated else None,
        level=row.level if evaluated else None,
        confidence=row.confidence if evaluated else None,
        top_factor=row.top_factor if evaluated else None,
        calculated_at=row.calculated_at,
        changed_at=row.changed_at,
    )


def _snapshot(snapshot: RiskSnapshot) -> RiskSnapshotRead:
    return RiskSnapshotRead(
        snapshot_id=snapshot.public_id,
        calculated_at=snapshot.calculated_at,
        score=snapshot.score,
        level=snapshot.level,
        confidence=snapshot.confidence,
        previous_score=snapshot.previous_score,
        previous_level=snapshot.previous_level,
        transition="up"
        if snapshot.transition == "up"
        else "down"
        if snapshot.transition == "down"
        else None,
        reason=snapshot.reason,
        top_factor=snapshot.top_factor,
    )


def _contribution(raw: dict[str, Any]) -> RiskContributionRead:
    """JSON guardado -> API, tolerante a entradas mal formadas (no tumba el detalle)."""

    def _uuid(value: Any) -> UUID | None:
        try:
            return UUID(str(value)) if value else None
        except ValueError:
            return None

    def _int(value: Any) -> int | None:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _float(value: Any) -> float | None:
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    details = raw.get("details")
    return RiskContributionRead(
        factor=str(raw.get("factor") or "unknown")[:16],
        category=str(raw.get("category") or "unknown")[:32],
        label=str(raw.get("label") or "")[:255],
        points=_float(raw.get("points")) or 0.0,
        nominal_points=_float(raw.get("nominal_points")),
        detection_id=_uuid(raw.get("detection_id")),
        finding_id=_uuid(raw.get("finding_id")),
        threat_match_id=_uuid(raw.get("threat_match_id")),
        rule_id=str(raw["rule_id"])[:32] if raw.get("rule_id") else None,
        port=_int(raw.get("port")),
        details=details if isinstance(details, dict) else {},
    )


def _detection_ref(d: Detection) -> RiskDetectionRef:
    rule = RULES_BY_ID.get(d.rule_id)
    return RiskDetectionRef(
        detection_id=d.public_id,
        rule_id=d.rule_id,
        title=d.title,
        category=d.rule_category or (rule.meta.category if rule else "unknown"),
        severity=d.severity,
        confidence=d.confidence,
        status=d.status,
        occurrence_count=d.occurrence_count,
        last_seen_at=d.last_seen_at,
    )
