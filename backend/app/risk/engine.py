"""Persistencia del riesgo: carga entradas por lotes, calcula y guarda estado e historial.

Separación de responsabilidades:
- calculator.py: fórmula pura (sin base de datos);
- este módulo: qué activos recalcular, carga de entradas acotada y sin N+1, persistencia
  (asset_risk, risk_snapshots, risk_contributions), transiciones de nivel y alertas;
- services/risk_service.py: lecturas de la API.

Cuándo se recalcula: quien cambia algo relevante (motor de detección, resolver o reconocer
una detección, discovery al abrir o cerrar puertos, cambio de criticidad, fusión de
activos) llama a `request_recalculation`, que solo marca `asset_risk.dirty_at` en su propia
transacción. El job interno (`run_risk_engine`) procesa esa cola por lotes y además
recalcula periódicamente los activos con riesgo para aplicar el decay. Nunca en cada
heartbeat ni para todos los activos a la vez.

Aislamiento de fallos: cada activo se calcula en su propio SAVEPOINT; si falla, se deshace
solo lo suyo, se cuenta en `error_count` y se reintenta en otra vuelta. Un fallo del job
nunca afecta a la API: las lecturas sirven el último valor guardado.
"""

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, exists, func, literal, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, aliased

from app.detection.rules import RULES_BY_ID
from app.discovery.ports import SENSITIVE_PORTS
from app.models.alert import AlertRule, AlertSeverity
from app.models.asset import Asset
from app.models.detection import Detection, DetectionEvidence, DetectionStatus
from app.models.exposure import AssetPort, PortStateValue
from app.models.risk import (
    RISK_LEVEL_RANK,
    AssetRisk,
    RiskContributionRecord,
    RiskLevel,
    RiskSnapshot,
)
from app.risk.calculator import (
    AssetContext,
    DetectionInput,
    ExposureInput,
    RiskInputs,
    RiskResult,
    calculate,
)
from app.risk.config import FORMULA_VERSION, RiskConfig
from app.services.alert_service import AlertService, AlertThresholds

logger = logging.getLogger(__name__)

# Límite de activos por pasada del job (lotes x vueltas): el resto queda para la siguiente.
MAX_BATCHES = 10


@dataclass
class RiskRun:
    assets: int = 0
    snapshots: int = 0
    transitions: int = 0
    alerts: int = 0
    errors: int = 0
    failed_assets: list[int] = field(default_factory=list)

    def add(self, other: "RiskRun") -> None:
        self.assets += other.assets
        self.snapshots += other.snapshots
        self.transitions += other.transitions
        self.alerts += other.alerts
        self.errors += other.errors
        self.failed_assets.extend(other.failed_assets)


class RiskEngine:
    def __init__(
        self,
        session: Session,
        config: RiskConfig,
        thresholds: AlertThresholds | None = None,
    ) -> None:
        self._session = session
        self._config = config
        self._alerts = AlertService(session, thresholds) if thresholds is not None else None

    # --- Selección de activos ----------------------------------------------------------------

    def seed_missing(self, limit: int = 1000) -> int:
        """Crea la fila (pendiente de cálculo) de activos que aún no tienen riesgo.

        Así todo activo acaba evaluado sin enganchar cada sitio que crea activos (registro de
        agente, discovery, fusión). Acotado por `limit` por vuelta. Hace commit.
        """
        missing = (
            select(Asset.id, literal(datetime.now(UTC)).label("dirty_at"))
            .where(~exists().where(AssetRisk.asset_id == Asset.id))
            .order_by(Asset.id)
            .limit(limit)
        )
        result = self._session.execute(
            insert(AssetRisk)
            .from_select(["asset_id", "dirty_at"], missing)
            .on_conflict_do_nothing(index_elements=[AssetRisk.asset_id])
        )
        self._session.commit()
        return int(getattr(result, "rowcount", 0) or 0)

    def process_dirty(self, now: datetime | None = None, max_batches: int = MAX_BATCHES) -> RiskRun:
        """Recalcula la cola de pendientes por lotes. Commit por lote."""
        return self._process(
            [AssetRisk.dirty_at.is_not(None)], [AssetRisk.dirty_at], now, max_batches
        )

    def process_decay(self, now: datetime | None = None, max_batches: int = MAX_BATCHES) -> RiskRun:
        """Recalcula activos cuyo valor puede haber caducado: decay o refresco completo.

        - Con riesgo > 0 y calculado hace más de RISK_DECAY_INTERVAL_MINUTES: el tiempo baja
          su score aunque no llegue nada nuevo.
        - Cualquiera calculado hace más de RISK_FULL_REFRESH_HOURS: cubre cambios que no
          avisan (p. ej. un activo reclasificado como servidor).
        """
        moment = now or datetime.now(UTC)
        stale = AssetRisk.calculated_at < moment - self._config.decay_interval
        refresh = AssetRisk.calculated_at < moment - self._config.full_refresh
        return self._process(
            [AssetRisk.dirty_at.is_(None), or_(and_(stale, AssetRisk.score > 0), refresh)],
            [AssetRisk.calculated_at],
            now,
            max_batches,
        )

    def recalculate(self, asset_ids: Sequence[int], now: datetime | None = None) -> RiskRun:
        """Recalcula ya estos activos (p. ej. tras cambiar la criticidad). Sin commit."""
        rows = self._session.scalars(
            select(AssetRisk).where(AssetRisk.asset_id.in_(list(asset_ids))).with_for_update()
        ).all()
        found = {row.asset_id for row in rows}
        created = [AssetRisk(asset_id=asset_id) for asset_id in asset_ids if asset_id not in found]
        for row in created:
            self._session.add(row)
        self._session.flush()
        return self._calculate_rows([*rows, *created], now or datetime.now(UTC))

    def _process(
        self,
        where: list[Any],
        order: list[Any],
        now: datetime | None,
        max_batches: int,
    ) -> RiskRun:
        run = RiskRun()
        seen: set[int] = set()
        for _ in range(max_batches):
            moment = now or datetime.now(UTC)
            # SKIP LOCKED: varios workers reparten la cola sin esperar ni duplicar trabajo.
            rows = self._session.scalars(
                select(AssetRisk)
                .where(*where, AssetRisk.asset_id.not_in(seen) if seen else literal(True))
                .order_by(*order, AssetRisk.asset_id)
                .limit(self._config.batch_size)
                .with_for_update(skip_locked=True)
            ).all()
            if not rows:
                break
            seen.update(row.asset_id for row in rows)
            run.add(self._calculate_rows(rows, moment))
            self._session.commit()
            if len(rows) < self._config.batch_size:
                break
        if run.assets and (run.errors or run.transitions):
            logger.info(
                "risk engine run",
                extra={
                    "assets": run.assets,
                    "snapshots": run.snapshots,
                    "transitions": run.transitions,
                    "alerts": run.alerts,
                    "errors": run.errors,
                },
            )
        return run

    # --- Cálculo y persistencia --------------------------------------------------------------

    def _calculate_rows(self, rows: Sequence[AssetRisk], now: datetime) -> RiskRun:
        run = RiskRun()
        ids = [row.asset_id for row in rows]
        # Entradas de todo el lote en pocas consultas (no una por activo).
        assets = {
            asset.id: asset
            for asset in self._session.scalars(select(Asset).where(Asset.id.in_(ids)))
        }
        inputs = self.load_inputs(assets.values(), now)
        for row in rows:
            asset = assets.get(row.asset_id)
            if asset is None:  # borrado entre la selección y la carga (cascada pendiente)
                continue
            try:
                with self._session.begin_nested():
                    result = calculate(inputs[asset.id], self._config, now)
                    self._persist(asset, row, result, now, run)
                run.assets += 1
            except Exception:
                run.errors += 1
                run.failed_assets.append(asset.id)
                logger.exception("risk calculation failed", extra={"asset_id": asset.id})
                # El savepoint se deshizo; la fila vuelve a la cola, al final (dirty_at=now).
                row.error_count = (row.error_count or 0) + 1
                row.dirty_at = now
        return run

    def load_inputs(self, assets: Iterable[Asset], now: datetime) -> dict[int, RiskInputs]:
        """Entradas del cálculo de varios activos: 3 consultas por lote, todas acotadas.

        - detecciones: activas (sin límite de edad: siguen contando hasta resolverse) y
          resueltas dentro de la memoria reciente; como mucho `max_detections` por activo
          (las más recientes primero);
        - qué detecciones simples absorbe cada correlación (evidencia compartida);
        - puertos sensibles abiertos (discovery).
        """
        asset_list = list(assets)
        ids = [asset.id for asset in asset_list]
        if not ids:
            return {}
        recent_resolved = now - self._config.resolved_memory
        ranked = (
            select(
                Detection.id,
                Detection.public_id,
                Detection.asset_id,
                Detection.rule_id,
                Detection.title,
                Detection.kind,
                Detection.severity,
                Detection.confidence,
                Detection.status,
                Detection.occurrence_count,
                Detection.first_seen_at,
                Detection.last_seen_at,
                Detection.resolved_at,
                Detection.details["port"].astext.label("port"),
                func.row_number()
                .over(
                    partition_by=Detection.asset_id,
                    order_by=(Detection.last_seen_at.desc(), Detection.id.desc()),
                )
                .label("rank"),
            )
            .where(
                Detection.asset_id.in_(ids),
                or_(
                    Detection.status != DetectionStatus.RESOLVED,
                    Detection.resolved_at >= recent_resolved,
                ),
            )
            .subquery()
        )
        rows = self._session.execute(
            select(ranked).where(ranked.c.rank <= self._config.max_detections)
        ).all()
        correlations = [row.id for row in rows if row.kind == "correlation"]
        singles = [row.id for row in rows if row.kind != "correlation"]
        members = self._correlation_members(correlations, singles)

        detections: dict[int, list[DetectionInput]] = {asset_id: [] for asset_id in ids}
        for row in rows:
            rule = RULES_BY_ID.get(row.rule_id)
            detections[row.asset_id].append(
                DetectionInput(
                    id=row.id,
                    public_id=row.public_id,
                    rule_id=row.rule_id,
                    title=row.title,
                    # Una regla retirada del catálogo sigue contando con categoría genérica.
                    category=rule.meta.category if rule else "unknown",
                    kind=row.kind,
                    severity=row.severity,
                    confidence=row.confidence,
                    status=row.status,
                    occurrence_count=max(1, row.occurrence_count or 1),
                    first_seen_at=row.first_seen_at,
                    last_seen_at=row.last_seen_at,
                    resolved_at=row.resolved_at,
                    port=_port(row.port),
                    members=frozenset(members.get(row.id, ())),
                )
            )

        exposure: dict[int, list[ExposureInput]] = {asset_id: [] for asset_id in ids}
        for port in self._session.scalars(
            select(AssetPort).where(
                AssetPort.asset_id.in_(ids),
                AssetPort.state == PortStateValue.OPEN,
                AssetPort.protocol == "tcp",
                AssetPort.port.in_(sorted(SENSITIVE_PORTS)),
            )
        ):
            exposure[port.asset_id].append(
                ExposureInput(
                    port=port.port,
                    opened_at=port.opened_at,
                    protocol=port.protocol,
                    service_hint=port.service_hint,
                )
            )

        return {
            asset.id: RiskInputs(
                asset=AssetContext(
                    criticality=asset.criticality,
                    device_type=asset.device_type,
                    managed=asset.is_managed,
                    os_name=asset.os_name,
                    last_seen_at=asset.last_seen_at,
                ),
                detections=detections[asset.id],
                exposure=exposure[asset.id],
            )
            for asset in asset_list
        }

    def _correlation_members(
        self, correlations: Sequence[int], singles: Sequence[int]
    ) -> dict[int, set[int]]:
        """Detecciones simples que comparten alguna señal de evidencia con cada correlación.

        Es lo que la correlación ya cuenta (p. ej. CORR-001 incluye los fallos de AUTH-001):
        el cálculo las agrupa para no sumarlas dos veces. Una sola consulta por lote; la
        evidencia está acotada a 100 filas por detección (motor 4H).
        """
        if not correlations or not singles:
            return {}
        corr = aliased(DetectionEvidence)
        member = aliased(DetectionEvidence)
        pairs = self._session.execute(
            select(corr.detection_id, member.detection_id)
            .join(
                member,
                and_(
                    member.signal_id == corr.signal_id,
                    member.detection_id != corr.detection_id,
                ),
            )
            .where(corr.detection_id.in_(correlations), member.detection_id.in_(singles))
            .distinct()
        ).all()
        found: dict[int, set[int]] = {}
        for correlation_id, member_id in pairs:
            found.setdefault(correlation_id, set()).add(member_id)
        return found

    def _persist(
        self, asset: Asset, row: AssetRisk, result: RiskResult, now: datetime, run: RiskRun
    ) -> None:
        evaluated_before = row.calculated_at is not None
        previous_level = row.level if evaluated_before else None
        previous_ids = {
            str(c.get("detection_id"))
            for c in row.contributions or []
            if c.get("detection_id")
            and float(c.get("points") or 0) >= self._config.new_contribution_min_points
        }

        row.score = result.score
        row.level = result.level
        row.confidence = result.confidence
        row.formula_version = FORMULA_VERSION
        row.calculated_at = now
        row.top_factor = (result.top_factor or "")[:255] or None
        row.contributions = [c.to_json() for c in result.contributions]
        row.breakdown = result.breakdown
        row.dirty_at = None
        row.error_count = 0

        reason = self._snapshot_reason(row, previous_level, previous_ids, result, now)
        if reason is None:
            return
        transition = None
        if previous_level is not None and previous_level != result.level:
            transition = (
                "up" if RISK_LEVEL_RANK[result.level] > RISK_LEVEL_RANK[previous_level] else "down"
            )
            run.transitions += 1
        snapshot = RiskSnapshot(
            asset_id=asset.id,
            calculated_at=now,
            score=result.score,
            level=result.level,
            confidence=result.confidence,
            previous_score=row.last_snapshot_score,
            previous_level=previous_level,
            transition=transition,
            reason=reason,
            formula_version=FORMULA_VERSION,
            top_factor=row.top_factor,
            breakdown=result.breakdown,
        )
        # Antes del flush: así la fila se actualiza en un solo UPDATE.
        row.last_snapshot_at = now
        row.last_snapshot_score = result.score
        row.changed_at = now
        self._session.add(snapshot)
        self._session.flush()
        self._session.add_all(
            RiskContributionRecord(
                snapshot_id=snapshot.id,
                position=position,
                factor=c.factor,
                category=c.category[:32],
                label=c.label[:255],
                points=c.points,
                nominal_points=c.nominal_points,
                detection_id=c.detection_id,
                detection_public_id=c.detection_public_id,
                rule_id=c.rule_id,
                port=c.port,
                details=c.details or None,
            )
            for position, c in enumerate(result.contributions)
        )
        run.snapshots += 1
        if transition is not None:
            logger.info(
                "asset risk level changed",
                extra={
                    "asset_id": str(asset.public_id),
                    "from": previous_level.value if previous_level else None,
                    "to": result.level.value,
                    "score": result.score,
                },
            )
        self._alert(asset, row, previous_level, result, now, run)

    def _snapshot_reason(
        self,
        row: AssetRisk,
        previous_level: RiskLevel | None,
        previous_ids: set[str],
        result: RiskResult,
        now: datetime,
    ) -> str | None:
        """¿Merece este cálculo un punto en el historial? (evita un snapshot por recálculo)."""
        if row.last_snapshot_at is None or row.last_snapshot_score is None:
            return "initial"
        if previous_level != result.level:
            return "level_change"
        if abs(result.score - row.last_snapshot_score) >= self._config.snapshot_min_delta:
            return "material_change"
        if result.detection_ids(self._config.new_contribution_min_points) - previous_ids:
            return "new_contribution"
        if (
            result.score != row.last_snapshot_score
            and now - row.last_snapshot_at >= self._config.snapshot_interval
        ):
            return "interval"
        return None

    def _alert(
        self,
        asset: Asset,
        row: AssetRisk,
        previous_level: RiskLevel | None,
        result: RiskResult,
        now: datetime,
        run: RiskRun,
    ) -> None:
        """Alerta risk_critical solo al CRUZAR hacia critical; se resuelve al salir.

        No alerta por cada cambio de score, por los descensos (quedan en el timeline) ni en
        la primera evaluación de un activo (desplegar la fase no debe generar una avalancha
        de alertas por detecciones antiguas). El cooldown por activo evita el spam si el
        riesgo oscila alrededor del umbral.
        """
        if self._alerts is None:
            return
        critical = result.level == RiskLevel.CRITICAL
        if previous_level == RiskLevel.CRITICAL and not critical:
            self._alerts.resolve_rule(asset, AlertRule.RISK_CRITICAL, now)
            return
        if not self._config.alert_enabled or not critical or previous_level is None:
            return
        if previous_level == RiskLevel.CRITICAL:
            return
        if row.last_alert_at is not None and now - row.last_alert_at < self._config.alert_cooldown:
            return
        self._alerts.raise_alert(
            asset,
            AlertRule.RISK_CRITICAL,
            AlertSeverity.CRITICAL,
            f"Risk of {asset.display_name} is critical: {result.score}/100"
            f" (confidence {result.confidence.value}). Top factor: {result.top_factor or '-'}",
            now,
            {
                "score": result.score,
                "level": result.level.value,
                "confidence": result.confidence.value,
                "previous_level": previous_level.value,
                "top_factor": (result.top_factor or "")[:255],
            },
        )
        row.last_alert_at = now
        run.alerts += 1


def _port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None
