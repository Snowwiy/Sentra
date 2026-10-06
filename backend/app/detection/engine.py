"""Motor: evalúa señales pendientes, deduplica detecciones, guarda evidencia y alerta.

Desacoplado de la ingesta: los endpoints de agentes solo escriben señales (recorder.py) y un
job interno (background.py) llama a `process_pending` cada DETECTION_EVAL_INTERVAL_SECONDS.
Así una regla lenta o rota nunca retrasa un heartbeat ni hace rechazar telemetría.

Aislamiento de fallos: cada regla se evalúa en su propio SAVEPOINT; si lanza una excepción
se deshace solo lo suyo, se registra y el resto de reglas sigue. La señal se marca como
evaluada igualmente para no reintentarla en bucle (una regla rota no debe bloquear la cola).

Concurrencia: varias instancias (workers) pueden ejecutar el motor a la vez. Las señales se
reparten con FOR UPDATE SKIP LOCKED y la deduplicación la garantiza el índice único parcial
uq_detections_active_key (como las alertas).

Fase 5A: las reglas personalizadas y Sigma (custom/runtime.py) entran por el mismo camino.
Solo se evalúan las candidatas del índice (tipo de señal, canal, id de evento) y cada una
mide su tiempo y sus errores en detection_rule_stats, igual que las built-in.
"""

import logging
import time
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, any_, case, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.metrics import REGISTRY
from app.detection import text
from app.detection.config import DetectionConfig
from app.detection.custom.runtime import CustomRule, CustomRuleIndex, load_index
from app.detection.rules import (
    ANY_SUBJECT,
    RULES,
    DetectionRule,
    RuleResult,
    max_confidence,
    max_severity,
)
from app.detection.signals import SignalKind
from app.models.alert import AlertRule, AlertSeverity, AlertStatus
from app.models.asset import Asset
from app.models.asset_context import AssetBusinessContext
from app.models.detection import (
    SEVERITY_RANK,
    Detection,
    DetectionEvidence,
    DetectionSeverity,
    DetectionSignal,
    DetectionStatus,
)
from app.models.detection_rule import DetectionRuleMatch, DetectionRuleStats, RuleSource
from app.repositories.alert_repository import AlertRepository
from app.risk.queue import request_recalculation
from app.services.alert_service import AlertService, AlertThresholds

logger = logging.getLogger(__name__)

# Evidencia máxima por detección: a partir de aquí solo suben contador y last_seen. Un
# ataque de miles de eventos no debe crear miles de filas de evidencia.
MAX_EVIDENCE = 100
BATCH_SIZE = 500
PURGE_BATCH = 5000
# Una evaluación de regla más lenta que esto cuenta como lenta (estadística y aviso en log).
SLOW_EVALUATION_SECONDS = 0.05
# Errores seguidos a partir de los que se avisa en el log de una regla rota de forma
# persistente. No se desactiva sola: un atacante podría provocar errores para apagarla.
FAILING_RULE_ERRORS = 10


@dataclass
class EngineRun:
    signals: int = 0
    created: int = 0
    updated: int = 0
    rule_errors: int = 0
    failed_rules: dict[str, int] = field(default_factory=dict)


@dataclass
class _RuleStat:
    """Contadores de una regla en el lote en curso (se vuelcan a detection_rule_stats)."""

    source: str
    evaluations: int = 0
    matches: int = 0
    errors: int = 0
    slow: int = 0
    seconds: float = 0.0
    last_matched_at: datetime | None = None
    last_error: str | None = None


class _Context:
    """Implementación de RuleContext sobre la tabla de señales (consultas acotadas)."""

    def __init__(self, session: Session, config: DetectionConfig) -> None:
        self._session = session
        self.config = config
        self._os: dict[int, str] = {}
        self._assets: dict[int, Mapping[str, Any]] = {}

    def _where(
        self,
        asset_id: int,
        kinds: Sequence[SignalKind],
        start: datetime,
        end: datetime,
        subject: str | None,
    ) -> list[Any]:
        # Siempre por activo: la evidencia de activos distintos nunca se mezcla. Usa el índice
        # (asset_id, kind, occurred_at).
        clauses: list[Any] = [
            DetectionSignal.asset_id == asset_id,
            DetectionSignal.kind.in_([k.value for k in kinds]),
            DetectionSignal.occurred_at >= start,
            DetectionSignal.occurred_at <= end,
        ]
        if subject is None:
            # Sujeto desconocido (p. ej. fallos sin cuenta de un agente antiguo): se agrupan
            # aparte, nunca con los de una cuenta concreta.
            clauses.append(DetectionSignal.subject.is_(None))
        elif subject != ANY_SUBJECT:
            clauses.append(DetectionSignal.subject == subject)
        return clauses

    def signals(
        self,
        asset_id: int,
        kinds: Sequence[SignalKind],
        start: datetime,
        end: datetime,
        *,
        subject: str | None = ANY_SUBJECT,
        limit: int = 200,
    ) -> Sequence[DetectionSignal]:
        # Las más recientes primero en SQL (LIMIT acota memoria) y devueltas en orden
        # cronológico, que es como las leen las reglas.
        rows = self._session.scalars(
            select(DetectionSignal)
            .where(*self._where(asset_id, kinds, start, end, subject))
            .order_by(DetectionSignal.occurred_at.desc(), DetectionSignal.id.desc())
            .limit(limit)
        ).all()
        return list(reversed(rows))

    def count(
        self,
        asset_id: int,
        kinds: Sequence[SignalKind],
        start: datetime,
        end: datetime,
        *,
        subject: str | None = ANY_SUBJECT,
    ) -> int:
        return (
            self._session.scalar(
                select(func.count())
                .select_from(DetectionSignal)
                .where(*self._where(asset_id, kinds, start, end, subject))
            )
            or 0
        )

    def asset_os(self, asset_id: int) -> str:
        if asset_id not in self._os:
            os_name = self._session.scalar(select(Asset.os_name).where(Asset.id == asset_id))
            self._os[asset_id] = (os_name or "").lower()
        return self._os[asset_id]

    # --- Fase 5A: reglas personalizadas ------------------------------------------------------

    def asset_values(self, asset_id: int) -> Mapping[str, Any]:
        """Contexto del activo para los campos asset.* (una consulta por activo y lote)."""
        if asset_id not in self._assets:
            # Savepoint propio: el motor la llama fuera del savepoint de la regla (fast path) y
            # un fallo aquí no debe dejar abortada la transacción del lote.
            with self._session.begin_nested():
                self._assets[asset_id] = asset_values(self._session, asset_id)
        return self._assets[asset_id]

    def record_and_count_rule_match(
        self,
        rule_pk: int,
        version: int,
        asset_id: int,
        group_key: str,
        signal: DetectionSignal,
        start: datetime,
    ) -> int:
        """Registra la coincidencia y cuenta las del grupo en la ventana: un solo viaje a BD.

        En PostgreSQL la consulta principal no ve las filas que inserta su propio CTE, así que
        se suman las existentes y la recién insertada. Idempotente por señal: reevaluar no
        inserta (ON CONFLICT DO NOTHING) y la coincidencia ya está entre las existentes.
        """
        inserted = (
            insert(DetectionRuleMatch)
            .values(
                rule_id=rule_pk,
                rule_version=version,
                asset_id=asset_id,
                group_key=group_key,
                signal_id=signal.id,
                occurred_at=signal.occurred_at,
                created_at=datetime.now(UTC),
            )
            .on_conflict_do_nothing(constraint="uq_rule_match_signal")
            .returning(DetectionRuleMatch.id)
            .cte("inserted")
        )
        existing = (
            select(func.count())
            .select_from(DetectionRuleMatch)
            .where(
                *self._match_where(rule_pk, version, asset_id, group_key, start, signal.occurred_at)
            )
            .scalar_subquery()
        )
        new = select(func.count()).select_from(inserted).scalar_subquery()
        # Core sobre la conexión de la sesión: evita la maquinaria ORM de inserts masivos.
        count = self._session.connection().scalar(select(existing + new))
        return int(count or 0)

    def _match_where(
        self,
        rule_pk: int,
        version: int,
        asset_id: int,
        group_key: str,
        start: datetime,
        end: datetime,
    ) -> list[Any]:
        # Usa ix_rule_matches_window: regla, versión, activo, grupo y rango temporal.
        return [
            DetectionRuleMatch.rule_id == rule_pk,
            DetectionRuleMatch.rule_version == version,
            DetectionRuleMatch.asset_id == asset_id,
            DetectionRuleMatch.group_key == group_key,
            DetectionRuleMatch.occurred_at >= start,
            DetectionRuleMatch.occurred_at <= end,
        ]

    def rule_match_signals(
        self,
        rule_pk: int,
        version: int,
        asset_id: int,
        group_key: str,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> Sequence[DetectionSignal]:
        rows = self._session.scalars(
            select(DetectionSignal)
            .join(DetectionRuleMatch, DetectionRuleMatch.signal_id == DetectionSignal.id)
            .where(*self._match_where(rule_pk, version, asset_id, group_key, start, end))
            .order_by(DetectionRuleMatch.occurred_at.desc(), DetectionRuleMatch.id.desc())
            .limit(limit)
        ).all()
        return list(reversed(rows))


def asset_values(session: Session, asset_id: int) -> dict[str, Any]:
    """Valores de los campos asset.* del catálogo para un activo (contexto 4L incluido)."""
    row = session.execute(
        select(Asset, AssetBusinessContext)
        .outerjoin(AssetBusinessContext, AssetBusinessContext.asset_id == Asset.id)
        .where(Asset.id == asset_id)
    ).first()
    if row is None:
        return {}
    asset, ctx = row[0], row[1]
    return {
        "hostname": (asset.display_name or "").lower() or None,
        "os": (asset.os_name or "").lower() or None,
        "criticality": asset.criticality.value if asset.criticality else None,
        "role": ctx.role.value if ctx is not None else "unknown",
        "environment": ctx.environment.value if ctx is not None else "unknown",
        "network_zone": ctx.network_zone.value if ctx is not None else "unknown",
        "internet_exposed": ctx.internet_exposed if ctx is not None else None,
    }


class DetectionEngine:
    def __init__(
        self,
        session: Session,
        config: DetectionConfig,
        thresholds: AlertThresholds | None = None,
        rules: Sequence[DetectionRule] = RULES,
        custom: CustomRuleIndex | None = None,
        load_custom: bool = True,
    ) -> None:
        self._session = session
        self._config = config
        self._alerts = AlertService(session, thresholds) if thresholds is not None else None
        self._by_kind: dict[str, list[DetectionRule]] = {}
        # Activos con detecciones nuevas o actualizadas en el lote: su riesgo se recalcula
        # (Fase 4I). Se encolan una vez por lote, no por evidencia.
        self._touched: set[int] = set()
        # Fase 5A: índice de reglas personalizadas. Sin índice explícito se carga desde la
        # BD antes de cada lote (solo se reconstruye si la huella cambió: multi-worker).
        self._load_custom = custom is None and load_custom
        self._custom: CustomRuleIndex | None = custom
        self._stats: dict[str, _RuleStat] = {}
        for rule in rules:
            if rule.meta.id in config.disabled_rules:
                continue
            for kind in rule.meta.triggers:
                self._by_kind.setdefault(kind.value, []).append(rule)

    # --- Cola de señales ---------------------------------------------------------------------

    def process_pending(self, batch_size: int = BATCH_SIZE, max_batches: int = 20) -> EngineRun:
        """Evalúa señales pendientes en lotes. Hace commit por lote."""
        run = EngineRun()
        for _ in range(max_batches):
            signals = self._session.scalars(
                select(DetectionSignal)
                .where(DetectionSignal.evaluated_at.is_(None))
                .order_by(DetectionSignal.id)
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            ).all()
            if not signals:
                break
            self._refresh_custom()
            context = _Context(self._session, self._config)
            for signal in signals:
                self._evaluate(context, signal, run)
                signal.evaluated_at = datetime.now(UTC)
            run.signals += len(signals)
            if self._touched:
                request_recalculation(self._session, self._touched)
                self._touched.clear()
            self._flush_stats()
            self._session.commit()
            if len(signals) < batch_size:
                break
        if run.created or run.rule_errors:
            logger.info(
                "detection engine run",
                extra={
                    "signals": run.signals,
                    "detections_created": run.created,
                    "detections_updated": run.updated,
                    "rule_errors": run.rule_errors,
                },
            )
        return run

    def _refresh_custom(self) -> None:
        if not self._load_custom:
            return
        try:
            self._custom = load_index(self._session)
        except Exception:
            # Sin índice nuevo se sigue con el anterior (o solo built-in): nunca se para el
            # motor por no poder leer las reglas personalizadas.
            self._session.rollback()
            logger.exception("custom detection rules could not be loaded")

    def _evaluate(self, context: _Context, signal: DetectionSignal, run: EngineRun) -> None:
        rules: list[DetectionRule] = list(self._by_kind.get(signal.kind, ()))
        if self._custom is not None:
            rules.extend(self._custom.candidates(signal.kind, signal.data))
        for rule in rules:
            stat = self._stats.get(rule.meta.id)
            if stat is None:
                stat = self._stats[rule.meta.id] = _RuleStat(rule.meta.source)
            started = time.perf_counter()
            try:
                if isinstance(rule, CustomRule):
                    # Fast path: la condición se evalúa en memoria, sin savepoint (la mayoría de
                    # candidatas no coincide). Los valores del activo salen de la caché del
                    # lote. Solo una coincidencia paga el savepoint y la escritura.
                    asset = (
                        context.asset_values(signal.asset_id)
                        if rule.compiled.asset_fields
                        else None
                    )
                    if not rule.matches(signal.kind, signal.subject, signal.data, asset)[0]:
                        continue
                with self._session.begin_nested():
                    for result in rule.evaluate(context, signal):
                        stat.matches += 1
                        stat.last_matched_at = datetime.now(UTC)
                        created = self.apply(rule, signal.asset_id, result)
                        if created:
                            run.created += 1
                        elif created is False:
                            run.updated += 1
            except Exception as exc:
                # Fallo aislado: se deshizo el savepoint de esta regla; las demás siguen.
                run.rule_errors += 1
                run.failed_rules[rule.meta.id] = run.failed_rules.get(rule.meta.id, 0) + 1
                stat.errors += 1
                # Solo la categoría del error: nunca datos del evento en estadísticas.
                stat.last_error = type(exc).__name__[:200]
                logger.exception(
                    "detection rule failed",
                    extra={
                        "rule": rule.meta.id,
                        "rule_version": rule.meta.version,
                        "rule_source": rule.meta.source,
                        "error_category": type(exc).__name__,
                        "signal_id": signal.id,
                        "kind": signal.kind,
                    },
                )
            finally:
                elapsed = time.perf_counter() - started
                stat.evaluations += 1
                stat.seconds += elapsed
                if elapsed > SLOW_EVALUATION_SECONDS:
                    stat.slow += 1

    def _flush_stats(self) -> None:
        """Vuelca los contadores del lote: una sentencia, sin tocar la fila de la regla."""
        if not self._stats:
            return
        now = datetime.now(UTC)
        rows = [
            {
                "rule_uid": uid,
                "evaluations": stat.evaluations,
                "matches": stat.matches,
                "errors": stat.errors,
                "consecutive_errors": stat.errors if stat.errors == stat.evaluations else 0,
                "slow_evaluations": stat.slow,
                "eval_time_us": int(stat.seconds * 1_000_000),
                "last_evaluated_at": now,
                "last_matched_at": stat.last_matched_at,
                "last_error_at": now if stat.errors else None,
                "last_error": stat.last_error,
            }
            for uid, stat in sorted(self._stats.items())
        ]
        table = DetectionRuleStats.__table__
        stmt = insert(DetectionRuleStats)
        excluded = stmt.excluded
        stmt = stmt.on_conflict_do_update(
            index_elements=["rule_uid"],
            set_={
                "evaluations": table.c.evaluations + excluded.evaluations,
                "matches": table.c.matches + excluded.matches,
                "errors": table.c.errors + excluded.errors,
                # Todas las evaluaciones del lote fallaron: se acumula; si alguna fue bien,
                # la racha se reinicia.
                "consecutive_errors": case(
                    (
                        excluded.consecutive_errors > 0,
                        table.c.consecutive_errors + excluded.consecutive_errors,
                    ),
                    else_=0,
                ),
                "slow_evaluations": table.c.slow_evaluations + excluded.slow_evaluations,
                "eval_time_us": table.c.eval_time_us + excluded.eval_time_us,
                "last_evaluated_at": excluded.last_evaluated_at,
                "last_matched_at": func.coalesce(excluded.last_matched_at, table.c.last_matched_at),
                "last_error_at": func.coalesce(excluded.last_error_at, table.c.last_error_at),
                "last_error": func.coalesce(excluded.last_error, table.c.last_error),
            },
        )
        # Core sobre la conexión de la sesión y "executemany" (sentencia compilada una vez y
        # cacheada): un VALUES con cientos de filas por la ruta ORM costaba más que evaluar el
        # lote entero.
        self._session.connection().execute(stmt, rows)
        by_source: dict[str, list[float]] = defaultdict(lambda: [0, 0, 0, 0.0])
        for uid, stat in self._stats.items():
            totals = by_source[stat.source]
            totals[0] += stat.evaluations
            totals[1] += stat.matches
            totals[2] += stat.errors
            totals[3] += stat.seconds
            if stat.slow:
                logger.warning(
                    "detection rule slow",
                    extra={"rule": uid, "rule_source": stat.source, "slow_evaluations": stat.slow},
                )
        for source, (evaluations, matches, errors, seconds) in by_source.items():
            # Etiqueta solo por origen (builtin/custom/sigma): nunca por regla en /metrics.
            REGISTRY.observe_rules(source, int(evaluations), int(matches), int(errors), seconds)
        self._warn_failing([uid for uid, stat in self._stats.items() if stat.errors])
        self._stats.clear()

    def _warn_failing(self, uids: list[str]) -> None:
        if not uids:
            return
        failing = self._session.execute(
            select(DetectionRuleStats.rule_uid, DetectionRuleStats.consecutive_errors).where(
                DetectionRuleStats.rule_uid.in_(uids),
                DetectionRuleStats.consecutive_errors >= FAILING_RULE_ERRORS,
            )
        ).all()
        for uid, streak in failing:
            logger.warning(
                "detection rule failing repeatedly",
                extra={"rule": uid, "consecutive_errors": streak},
            )

    # --- Deduplicación y persistencia ----------------------------------------------------------

    def apply(self, rule: DetectionRule, asset_id: int, result: RuleResult) -> bool | None:
        """Crea la detección o actualiza la activa con la misma clave.

        Devuelve True si se creó, False si se actualizó y None si no había nada nuevo (toda la
        evidencia ya estaba: reevaluación o carrera entre workers).
        """
        meta = rule.meta
        now = datetime.now(UTC)
        key = text.clean(result.key, 255) or "*"
        severity = result.severity or meta.severity
        confidence = result.confidence or meta.confidence
        for _ in range(2):  # una carrera perdida en el índice único: la otra ya existe
            existing = self._session.scalar(
                select(Detection)
                .where(
                    Detection.asset_id == asset_id,
                    Detection.rule_id == meta.id,
                    Detection.dedup_key == key,
                    Detection.status != DetectionStatus.RESOLVED,
                )
                .with_for_update()
            )
            if existing is not None:
                updated = self._update(existing, rule, result, severity, confidence, now)
                if updated is not None:
                    self._touched.add(asset_id)
                return updated
            mitre = result.mitre or meta.mitre
            detection = Detection(
                asset_id=asset_id,
                rule_id=meta.id,
                rule_version=meta.version,
                rule_source=meta.source,
                rule_category=meta.category[:32],
                kind=meta.kind,
                dedup_key=key,
                severity=severity,
                confidence=confidence,
                status=DetectionStatus.OPEN,
                title=text.clean(meta.title, 255),
                summary=text.clean(result.summary, 1000),
                details=text.bounded_data(result.details) or None,
                mitre_tactic=(mitre.tactic or None) if mitre else None,
                mitre_technique=mitre.technique if mitre else None,
                mitre_subtechnique=mitre.subtechnique if mitre else None,
                occurrence_count=1,
                first_seen_at=min(e.signal.occurred_at for e in result.evidence),
                last_seen_at=result.occurred_at,
                created_at=now,
                updated_at=now,
            )
            try:
                with self._session.begin_nested():
                    self._session.add(detection)
            except IntegrityError:
                continue
            self._add_evidence(detection, result, now)
            self._maybe_alert(detection, None)
            self._touched.add(asset_id)
            logger.info(
                "detection created",
                extra={
                    "rule": meta.id,
                    "detection_id": str(detection.public_id),
                    "severity": severity.value,
                    "confidence": confidence.value,
                },
            )
            return True
        return None

    def _update(
        self,
        detection: Detection,
        rule: DetectionRule,
        result: RuleResult,
        severity: DetectionSeverity,
        confidence: Any,
        now: datetime,
    ) -> bool | None:
        added = self._add_evidence(detection, result, now)
        if not added:
            return None
        meta = rule.meta
        previous_severity = detection.severity
        # Dentro del cooldown es la misma oleada: más evidencia y last_seen, mismo contador.
        cooldown = meta.cooldown_for(self._config)
        if cooldown == timedelta(0) or result.occurred_at > detection.last_seen_at + cooldown:
            detection.occurrence_count += 1
        detection.last_seen_at = max(detection.last_seen_at, result.occurred_at)
        detection.first_seen_at = min(
            detection.first_seen_at, *(e.signal.occurred_at for e in result.evidence)
        )
        # Severidad y confianza solo suben: una coincidencia más débil no oculta la peor.
        detection.severity = max_severity(detection.severity, severity)
        detection.confidence = max_confidence(detection.confidence, confidence)
        detection.summary = text.clean(result.summary, 1000)
        if result.details:
            detection.details = text.bounded_data(result.details)
        if meta.source == RuleSource.BUILTIN:
            detection.rule_version = meta.version
        # Fase 5A: en reglas custom/Sigma la detección conserva la versión que la CREÓ (su
        # explicación sale de esa versión); la versión que añadió la última evidencia queda
        # en details.rule_version.
        detection.updated_at = now
        self._maybe_alert(detection, previous_severity)
        return False

    def _add_evidence(self, detection: Detection, result: RuleResult, now: datetime) -> int:
        """Inserta la evidencia nueva (idempotente por señal). Devuelve cuántas añadió."""
        self._session.flush()
        stored = (
            self._session.scalar(
                select(func.count())
                .select_from(DetectionEvidence)
                .where(DetectionEvidence.detection_id == detection.id)
            )
            or 0
        )
        seen: set[int] = set()
        rows: list[dict[str, Any]] = []
        for item in result.evidence:
            signal = item.signal
            if signal.id in seen:
                continue
            seen.add(signal.id)
            rows.append(
                {
                    "detection_id": detection.id,
                    "signal_id": signal.id,
                    "signal_kind": signal.kind,
                    "role": item.role,
                    "source_type": signal.source_type,
                    "source_id": signal.source_id,
                    "occurred_at": signal.occurred_at,
                    "summary": text.clean(_evidence_summary(signal), 500),
                    "data": signal.data,
                    "created_at": now,
                }
            )
        if not rows:
            return 0
        # Al llegar al tope ya no se guarda más evidencia, pero sí se detecta si había algo
        # nuevo (para contar la ocurrencia) comprobando qué señales faltaban.
        new_ids = set(seen) - set(
            self._session.scalars(
                select(DetectionEvidence.signal_id).where(
                    DetectionEvidence.detection_id == detection.id,
                    DetectionEvidence.signal_id.in_(list(seen)),
                )
            )
        )
        if not new_ids:
            return 0
        room = max(0, MAX_EVIDENCE - stored)
        pending = [row for row in rows if row["signal_id"] in new_ids]
        # Se conservan las más recientes si no cabe todo (las primeras ya están guardadas).
        pending.sort(key=lambda row: row["occurred_at"])
        if room and pending:
            self._session.execute(
                insert(DetectionEvidence)
                .values(pending[-room:])
                .on_conflict_do_nothing(constraint="uq_detection_evidence_signal")
            )
        return len(new_ids)

    def _maybe_alert(self, detection: Detection, previous: DetectionSeverity | None) -> None:
        """Abre o actualiza la alerta security_detection si la detección es grave.

        Solo cuando cruza el umbral (nueva o recién escalada): una detección que ya alertó no
        suma una ocurrencia a la alerta por cada evidencia nueva.
        """
        threshold = self._config.alert_min_severity
        if self._alerts is None or threshold is None:
            return
        rank = SEVERITY_RANK
        if rank[detection.severity] < rank[threshold]:
            return
        if previous is not None and rank[previous] >= rank[detection.severity]:
            return
        asset = self._session.get(Asset, detection.asset_id)
        if asset is None:
            return
        self._session.flush()
        self._alerts.raise_alert(
            asset,
            AlertRule.SECURITY_DETECTION,
            AlertSeverity.CRITICAL
            if detection.severity == DetectionSeverity.CRITICAL
            else AlertSeverity.WARNING,
            f"{detection.rule_id}: {detection.title} ({detection.severity.value},"
            f" confidence {detection.confidence.value})",
            datetime.now(UTC),
            {
                "detection_id": str(detection.public_id),
                "rule_id": detection.rule_id,
                "severity": detection.severity.value,
                "confidence": detection.confidence.value,
                "summary": detection.summary[:300],
            },
        )
        alert = AlertRepository(self._session).get_active(
            detection.asset_id, AlertRule.SECURITY_DETECTION
        )
        if alert is not None:
            detection.alert_id = alert.id

    # --- Mantenimiento -------------------------------------------------------------------------

    def purge_signals(self, now: datetime | None = None) -> int:
        """Borra señales ya evaluadas y más antiguas que la retención. Commit por lote."""
        cutoff = (now or datetime.now(UTC)) - self._config.signal_retention
        deleted = 0
        while True:
            batch = (
                select(DetectionSignal.id)
                .where(
                    DetectionSignal.created_at < cutoff, DetectionSignal.evaluated_at.is_not(None)
                )
                .limit(PURGE_BATCH)
                .scalar_subquery()
            )
            result = cast(
                CursorResult[Any],
                self._session.execute(
                    delete(DetectionSignal).where(DetectionSignal.id == any_(func.array(batch)))
                ),
            )
            self._session.commit()
            deleted += result.rowcount
            if result.rowcount < PURGE_BATCH:
                break
        # Coincidencias de reglas con umbral: misma retención que las señales que cuentan.
        while True:
            match_batch = (
                select(DetectionRuleMatch.id)
                .where(DetectionRuleMatch.created_at < cutoff)
                .limit(PURGE_BATCH)
                .scalar_subquery()
            )
            purged = cast(
                CursorResult[Any],
                self._session.execute(
                    delete(DetectionRuleMatch).where(
                        DetectionRuleMatch.id == any_(func.array(match_batch))
                    )
                ),
            )
            self._session.commit()
            if purged.rowcount < PURGE_BATCH:
                return deleted

    def reevaluate(self, since: datetime, asset_id: int | None = None) -> int:
        """Vuelve a poner en cola las señales recientes (tras activar o corregir una regla).

        Es seguro repetirlo: la evidencia es idempotente por señal, así que lo ya detectado
        no se duplica ni suma ocurrencias.
        """
        stmt = (
            update(DetectionSignal)
            .where(DetectionSignal.occurred_at >= since)
            .values(evaluated_at=None)
        )
        if asset_id is not None:
            stmt = stmt.where(DetectionSignal.asset_id == asset_id)
        result = cast(CursorResult[Any], self._session.execute(stmt))
        self._session.commit()
        return result.rowcount


def resolve_detection_alert(session: Session, detection: Detection, now: datetime) -> None:
    """Al resolver una detección, resuelve su alerta si ninguna otra detección grave activa
    del activo la mantiene. No hace commit."""
    if detection.alert_id is None:
        return
    others = session.scalar(
        select(func.count())
        .select_from(Detection)
        .where(
            Detection.alert_id == detection.alert_id,
            Detection.id != detection.id,
            Detection.status != DetectionStatus.RESOLVED,
        )
    )
    if others:
        return
    alert = AlertRepository(session).get_active(detection.asset_id, AlertRule.SECURITY_DETECTION)
    if alert is not None and alert.id == detection.alert_id:
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = now


def _evidence_summary(signal: DetectionSignal) -> str:
    """Una línea legible para el timeline, a partir de los datos de la señal."""
    data = signal.data if isinstance(signal.data, dict) else {}
    if signal.kind == SignalKind.EVENT.value:
        return f"Evento {data.get('code', '?')} ({data.get('channel', '?')})"
    label = _EVIDENCE_LABELS.get(signal.kind, signal.kind)
    parts = []
    for key in (
        "account",
        "service",
        "group",
        "log",
        "port",
        "process",
        "exe",
        "threat",
        "source_ip",
    ):
        value = data.get(key)
        if value not in (None, ""):
            parts.append(f"{key}={value}")
    if signal.subject and not parts:
        parts.append(signal.subject)
    return f"{label}: {', '.join(parts)}" if parts else label


_EVIDENCE_LABELS = {
    SignalKind.AUTH_FAILURE.value: "Inicio de sesión fallido",
    SignalKind.AUTH_SUCCESS.value: "Inicio de sesión correcto",
    SignalKind.ACCOUNT_LOCKOUT.value: "Cuenta bloqueada",
    SignalKind.ACCOUNT_CREATED.value: "Cuenta creada",
    SignalKind.ACCOUNT_ENABLED.value: "Cuenta habilitada",
    SignalKind.ACCOUNT_DISABLED.value: "Cuenta deshabilitada",
    SignalKind.ACCOUNT_DELETED.value: "Cuenta eliminada",
    SignalKind.ADMIN_GROUP_ADDED.value: "Añadida a grupo privilegiado",
    SignalKind.ADMIN_GROUP_REMOVED.value: "Retirada de grupo privilegiado",
    SignalKind.AUDIT_POLICY_CHANGED.value: "Política de auditoría modificada",
    SignalKind.LOG_CLEARED.value: "Registro de eventos borrado",
    SignalKind.SERVICE_INSTALLED.value: "Servicio instalado",
    SignalKind.SERVICE_ADDED.value: "Servicio nuevo en inventario",
    SignalKind.SECURITY_SERVICE_DOWN.value: "Servicio de seguridad detenido",
    SignalKind.SERVICE_CRASHED.value: "Servicio terminado inesperadamente",
    SignalKind.UNEXPECTED_SHUTDOWN.value: "Apagado inesperado",
    SignalKind.POWERSHELL_SUSPICIOUS.value: "PowerShell sospechoso (4104)",
    SignalKind.MALWARE_DETECTED.value: "Amenaza detectada",
    SignalKind.ANTIMALWARE_DISABLED.value: "Antimalware desactivado",
    SignalKind.PROCESS_NEW.value: "Proceso nuevo",
    SignalKind.LISTEN_PORT_NEW.value: "Puerto nuevo en escucha",
    SignalKind.PORT_EXPOSED.value: "Puerto expuesto",
    SignalKind.ASSET_DISCOVERED.value: "Dispositivo descubierto",
    SignalKind.ASSET_DISAPPEARED.value: "Activo desaparecido",
    SignalKind.EVENT.value: "Evento del sistema",
}
