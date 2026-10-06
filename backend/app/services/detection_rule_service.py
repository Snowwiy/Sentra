"""Gestión de reglas de detección (Fase 5A): catálogo unificado, CRUD versionado, estados,
validación, pruebas sin efectos e importación Sigma.

Reglas de diseño (docs/custom-detection-rules.md):
- las built-in viven en código y aquí solo se listan (solo lectura); las custom/Sigma viven
  en detection_rules + detection_rule_versions y la BD es la fuente de verdad;
- cada cambio de contenido crea una versión NUEVA e inmutable; restaurar v1 crea v(n+1) con
  el contenido de v1: nunca se reescribe historia;
- concurrencia optimista con `revision` (409 detection_rule_conflict), como 4K/4L;
- una regla solo se activa si compila y es soportada (partial exige confirmación); una
  importación Sigma nunca se activa sola;
- las pruebas (sintética e histórica) no escriben nada: la histórica corre en una
  transacción READ ONLY con statement_timeout, filas acotadas y un único test a la vez.
"""

import logging
import time
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import Select, func, literal, or_, select, text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import ConflictError, NotFoundError, RateLimitedError, SentraError
from app.db.locks import RULE_TEST_LOCK_KEY
from app.detection import text as clean_text
from app.detection.config import DetectionConfig
from app.detection.custom import mitre as mitre_mod
from app.detection.custom import sigma as sigma_mod
from app.detection.custom.catalog import (
    ASSET_FIELDS,
    CATEGORIES,
    COMPATIBILITY,
    DEFAULT_CATEGORY,
    LOGSOURCES,
    FieldSpec,
    LogSource,
    Support,
    fields_for,
)
from app.detection.custom.definition import (
    COOLDOWN_MINUTES,
    MAX_CHILDREN,
    MAX_DEPTH,
    MAX_GROUP_BY,
    MAX_NODES,
    MAX_REGEX_PER_RULE,
    MAX_TOTAL_VALUES,
    MAX_VALUE_LENGTH,
    MAX_VALUES_PER_LEAF,
    OPS_BY_TYPE,
    THRESHOLD_COUNT,
    WINDOW_MINUTES,
    CompiledRule,
    CompileResult,
    Issue,
    compile_definition,
    content_hash,
)
from app.detection.custom.runtime import (
    CustomRule,
    describe,
    group_key_for,
    reset_caches,
    rule_from_version,
)
from app.detection.engine import asset_values
from app.detection.rules import RULES, RULES_BY_ID, RuleMeta
from app.detection.signals import raw_event_signals
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.detection import (
    Detection,
    DetectionConfidence,
    DetectionSeverity,
    DetectionSignal,
)
from app.models.detection_rule import (
    CompileStatus,
    DetectionRuleRecord,
    DetectionRuleStats,
    DetectionRuleVersion,
    RuleSource,
    RuleStatus,
)
from app.models.event import SystemEvent
from app.repositories.alert_repository import escape_like
from app.schemas.audit import AuditEventList, AuditEventRead
from app.schemas.detection_rule import (
    CompatibilityRead,
    DetectionRuleList,
    DetectionRuleRead,
    EventTestResult,
    FieldRead,
    HistoricalGroup,
    HistoricalMatch,
    HistoricalTestIn,
    HistoricalTestResult,
    LogSourceRead,
    RuleCatalog,
    RuleChange,
    RuleContentIn,
    RuleCreate,
    RuleDetail,
    RuleDiff,
    RuleIssue,
    RuleStatsRead,
    RuleTestIn,
    RuleTestResult,
    RuleUpdate,
    RuleValidateIn,
    RuleValidation,
    RuleVersionDetail,
    RuleVersionList,
    RuleVersionRead,
    SigmaDuplicate,
    SigmaImportIn,
    SigmaImportResult,
    SigmaPreview,
    SimulatedDetection,
)
from app.services import audit_service
from app.services.audit_service import Actor

logger = logging.getLogger(__name__)

TARGET = "detection_rule"
MAX_OFFSET = 10_000
SAMPLE_GROUPS = 20
# Campos de contenido versionado (cualquier cambio en ellos crea una versión nueva).
_CONTENT_FIELDS = (
    "title",
    "description",
    "why",
    "recommendations",
    "severity",
    "confidence",
    "category",
    "mitre_tactic",
    "mitre_technique",
    "mitre_subtechnique",
    "tags",
    "definition",
)
_SEVERITY_ORDER = {severity: rank for rank, severity in enumerate(DetectionSeverity)}


class DetectionRuleConflictError(ConflictError):
    """Revisión obsoleta: otro administrador cambió la regla (sin pisar su cambio)."""

    code = "detection_rule_conflict"


class DetectionRuleStateError(ConflictError):
    """Transición no permitida (activar una regla no soportada, editar una retirada...)."""

    code = "detection_rule_invalid_state"


class DetectionRuleValidationError(SentraError):
    status_code = 422
    code = "detection_rule_invalid"


class ReadOnlyRuleError(ConflictError):
    code = "detection_rule_read_only"


@dataclass(frozen=True)
class RuleFilter:
    source: str | None = None
    status: str | None = None
    enabled: bool | None = None
    compile_status: str | None = None
    severity: DetectionSeverity | None = None
    logsource: str | None = None
    mitre: str | None = None
    search: str | None = None
    sort: str = "title"
    descending: bool = False


@dataclass(frozen=True)
class RuleText:
    """Textos de la regla que produjo una detección (por versión), para UI, riesgo e IA."""

    source: str
    category: str
    title: str
    description: str
    why: str
    recommendations: tuple[str, ...]
    required_data: tuple[str, ...]


def _issues(items: Iterable[Issue]) -> list[RuleIssue]:
    return [RuleIssue(code=i.code, message=i.message, path=i.path) for i in items]


def _builtin_logsource(meta: RuleMeta) -> str | None:
    kinds = {kind.value for kind in meta.triggers}
    for source in LOGSOURCES.values():
        if not source.is_event and kinds <= source.kinds:
            return source.name
    return None


# --- Textos de reglas para detecciones (built-in y custom por versión) -----------------------


def rule_texts(
    session: Session, pairs: Iterable[tuple[str, int]]
) -> dict[tuple[str, int], RuleText]:
    """Textos por (rule_id, versión). Built-in del código; custom/Sigma de su VERSIÓN, así una
    detección antigua se explica con la regla tal como era cuando la creó."""
    found: dict[tuple[str, int], RuleText] = {}
    custom: set[tuple[str, int]] = set()
    for rule_id, version in pairs:
        builtin = RULES_BY_ID.get(rule_id)
        if builtin is not None:
            meta = builtin.meta
            found[(rule_id, version)] = RuleText(
                "builtin",
                meta.category,
                meta.title,
                meta.description,
                meta.why,
                meta.recommendations,
                meta.required_data,
            )
        else:
            custom.add((rule_id, version))
    if custom:
        uids = {uid for uid, _ in custom}
        rows = session.execute(
            select(DetectionRuleRecord.rule_uid, DetectionRuleRecord.source, DetectionRuleVersion)
            .join(DetectionRuleVersion, DetectionRuleVersion.rule_id == DetectionRuleRecord.id)
            .where(DetectionRuleRecord.rule_uid.in_(uids))
            .where(DetectionRuleVersion.version.in_({version for _, version in custom}))
        ).all()
        for uid, source, row in rows:
            if (uid, row.version) not in custom:
                continue
            logsource = LOGSOURCES.get(str((row.definition or {}).get("logsource")))
            found[(uid, row.version)] = RuleText(
                source,
                row.category,
                row.title,
                row.description,
                row.why,
                tuple(row.recommendations or ()),
                (logsource.title,) if logsource else (),
            )
    return found


def rule_text(session: Session, rule_id: str, version: int) -> RuleText | None:
    return rule_texts(session, [(rule_id, version)]).get((rule_id, version))


# --- Servicio ---------------------------------------------------------------------------------


class DetectionRuleService:
    def __init__(
        self, session: Session, settings: Settings, config: DetectionConfig | None = None
    ) -> None:
        self._session = session
        self._settings = settings
        self._config = config or DetectionConfig.from_settings(settings)

    # --- Catálogo ---------------------------------------------------------------------------

    def catalog(self) -> RuleCatalog:
        def field_read(spec: FieldSpec) -> FieldRead:
            return FieldRead(
                name=spec.name,
                type=spec.type.value,
                description=spec.description,
                values=list(spec.values),
                operators=sorted(OPS_BY_TYPE[spec.type]),
            )

        return RuleCatalog(
            logsources=[
                LogSourceRead(
                    name=source.name,
                    title=source.title,
                    support=source.support.value,
                    platforms=list(source.platforms),
                    notes=source.notes,
                    event_codes=list(source.event_codes),
                    sigma_hint=source.sigma_hint,
                    default_category=DEFAULT_CATEGORY.get(source.name, "system"),
                    fields=[field_read(spec) for spec in source.fields.values()],
                )
                for source in LOGSOURCES.values()
            ],
            asset_fields=[field_read(spec) for spec in ASSET_FIELDS.values()],
            categories=list(CATEGORIES),
            limits={
                "max_conditions": MAX_NODES,
                "max_depth": MAX_DEPTH,
                "max_branches": MAX_CHILDREN,
                "max_values_per_condition": MAX_VALUES_PER_LEAF,
                "max_values": MAX_TOTAL_VALUES,
                "max_value_length": MAX_VALUE_LENGTH,
                "max_regex": MAX_REGEX_PER_RULE,
                "max_group_by": MAX_GROUP_BY,
                "threshold_min": THRESHOLD_COUNT[0],
                "threshold_max": THRESHOLD_COUNT[1],
                "window_min_minutes": WINDOW_MINUTES[0],
                "window_max_minutes": self._max_window(),
                "cooldown_max_minutes": COOLDOWN_MINUTES[1],
                "test_max_hours": self._settings.rule_test_max_hours,
                "test_max_events": 100,
                "sigma_max_bytes": sigma_mod.MAX_YAML_BYTES,
            },
            compatibility=[
                CompatibilityRead(
                    area=row.area,
                    support=row.support.value,
                    notes=row.notes,
                    logsources=list(row.logsources),
                )
                for row in COMPATIBILITY
            ],
            sigma_default_confidence=DetectionConfidence(self._settings.sigma_default_confidence),
        )

    def _max_window(self) -> int:
        # Las coincidencias se purgan con las señales: una ventana más larga que su retención
        # nunca podría alcanzar el umbral.
        return min(WINDOW_MINUTES[1], self._config.signal_retention // timedelta(minutes=1))

    # --- Listado ------------------------------------------------------------------------------

    def list_rules(self, f: RuleFilter, limit: int, offset: int) -> DetectionRuleList:
        offset = min(offset, MAX_OFFSET)
        builtins = [item for item in self._builtin_items() if _matches_filter(item, f)]
        stmt = self._custom_query(f)
        custom_total = self._session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = self._session.execute(self._order(stmt, f).limit(offset + limit)).all()
        customs = [self._custom_item(record, stats) for record, stats in rows]
        merged = sorted([*builtins, *customs], key=lambda item: _sort_key(item, f.sort))
        if f.descending:
            merged = _reverse_stable(merged, f.sort)
        page = merged[offset : offset + limit]
        self._fill_activity(page)
        return DetectionRuleList(
            items=page,
            total=len(builtins) + custom_total,
            windows=self._config.windows(),
            alert_min_severity=self._config.alert_min_severity,
        )

    def _builtin_items(self) -> list[DetectionRuleRead]:
        stats = self._stats_by_uid([rule.meta.id for rule in RULES])
        items = []
        for rule in RULES:
            meta = rule.meta
            enabled = self._config.enabled and meta.id not in self._config.disabled_rules
            stat = stats.get(meta.id)
            items.append(
                DetectionRuleRead(
                    rule_id=meta.id,
                    source="builtin",
                    version=meta.version,
                    status="active" if enabled else "disabled",
                    enabled=enabled,
                    compile_status="valid",
                    read_only=True,
                    kind=meta.kind,
                    category=meta.category,
                    title=meta.title,
                    description=meta.description,
                    why=meta.why,
                    severity=meta.severity,
                    confidence=meta.confidence,
                    logsource=_builtin_logsource(meta),
                    triggers=sorted(k.value for k in meta.triggers),
                    required_data=list(meta.required_data),
                    recommendations=list(meta.recommendations),
                    mitre_tactic=meta.mitre.tactic if meta.mitre else None,
                    mitre_technique=meta.mitre.technique if meta.mitre else None,
                    mitre_subtechnique=meta.mitre.subtechnique if meta.mitre else None,
                    cooldown_minutes=int(meta.cooldown_for(self._config).total_seconds() // 60),
                    last_triggered_at=stat.last_matched_at if stat else None,
                    errors=stat.errors if stat else 0,
                    consecutive_errors=stat.consecutive_errors if stat else 0,
                )
            )
        return items

    def _custom_query(self, f: RuleFilter) -> Select[DetectionRuleRecord, DetectionRuleStats]:
        stmt = select(DetectionRuleRecord, DetectionRuleStats).outerjoin(
            DetectionRuleStats, DetectionRuleStats.rule_uid == DetectionRuleRecord.rule_uid
        )
        if f.source == RuleSource.BUILTIN:
            return stmt.where(literal(False))
        if f.source:
            stmt = stmt.where(DetectionRuleRecord.source == f.source)
        if f.status:
            stmt = stmt.where(DetectionRuleRecord.status == f.status)
        if f.enabled is not None:
            stmt = stmt.where(
                (DetectionRuleRecord.status == RuleStatus.ACTIVE.value)
                if f.enabled
                else (DetectionRuleRecord.status != RuleStatus.ACTIVE.value)
            )
        if f.compile_status:
            stmt = stmt.where(DetectionRuleRecord.compile_status == f.compile_status)
        if f.severity is not None:
            stmt = stmt.where(DetectionRuleRecord.severity == f.severity)
        if f.logsource:
            stmt = stmt.where(DetectionRuleRecord.logsource == f.logsource)
        if f.mitre:
            stmt = stmt.where(
                DetectionRuleRecord.mitre_technique.ilike(f"{escape_like(f.mitre)}%", escape="\\")
            )
        if f.search:
            pattern = f"%{escape_like(f.search)}%"
            stmt = stmt.where(
                or_(
                    DetectionRuleRecord.title.ilike(pattern, escape="\\"),
                    DetectionRuleRecord.rule_uid.ilike(pattern, escape="\\"),
                )
            )
        return stmt

    def _order(
        self, stmt: Select[DetectionRuleRecord, DetectionRuleStats], f: RuleFilter
    ) -> Select[DetectionRuleRecord, DetectionRuleStats]:
        # Mismo orden que _sort_key (que fusiona con las built-in): título en orden de bytes
        # ("C") para que SQL y Python coincidan; empates por rule_uid.
        title = func.lower(DetectionRuleRecord.title).collate("C")
        column: Any
        if f.sort == "updated_at":
            column = DetectionRuleRecord.updated_at
        elif f.sort == "last_triggered":
            column = DetectionRuleStats.last_matched_at
        elif f.sort == "severity":
            column = DetectionRuleRecord.severity
        elif f.sort == "source":
            column = DetectionRuleRecord.source
        else:
            column = title
        ordered = column.desc().nulls_last() if f.descending else column.asc().nulls_last()
        return stmt.order_by(ordered, title, DetectionRuleRecord.rule_uid)

    def _custom_item(
        self, record: DetectionRuleRecord, stats: DetectionRuleStats | None
    ) -> DetectionRuleRead:
        version = self._version(record, record.current_version)
        compiled = (version.compiled or {}) if version else {}
        return DetectionRuleRead(
            rule_id=record.rule_uid,
            source=record.source,
            version=record.current_version,
            status=record.status,
            enabled=record.enabled,
            compile_status=record.compile_status,
            read_only=False,
            kind="single",
            category=record.category,
            title=record.title,
            description=version.description if version else "",
            why=version.why if version else "",
            severity=record.severity,
            confidence=record.confidence,
            logsource=record.logsource,
            triggers=sorted(LOGSOURCES[record.logsource].kinds)
            if record.logsource in LOGSOURCES
            else [],
            required_data=[LOGSOURCES[record.logsource].title]
            if record.logsource in LOGSOURCES
            else [],
            recommendations=list(version.recommendations or ()) if version else [],
            mitre_tactic=version.mitre_tactic if version else None,
            mitre_technique=version.mitre_technique if version else None,
            mitre_subtechnique=version.mitre_subtechnique if version else None,
            cooldown_minutes=int(compiled.get("cooldown_minutes") or 0),
            sigma_id=record.sigma_id,
            revision=record.revision,
            updated_at=record.updated_at,
            updated_by=record.updated_by,
            last_triggered_at=stats.last_matched_at if stats else None,
            errors=stats.errors if stats else 0,
            consecutive_errors=stats.consecutive_errors if stats else 0,
        )

    def _fill_activity(self, items: Sequence[DetectionRuleRead]) -> None:
        """Detecciones 24 h y última detección de la página (índice rule_id, last_seen_at)."""
        uids = [item.rule_id for item in items]
        if not uids:
            return
        since = datetime.now(UTC) - timedelta(hours=24)
        recent = dict(
            self._session.execute(
                select(Detection.rule_id, func.count())
                .where(Detection.rule_id.in_(uids), Detection.last_seen_at >= since)
                .group_by(Detection.rule_id)
            ).all()
        )
        last = dict(
            self._session.execute(
                select(Detection.rule_id, func.max(Detection.last_seen_at))
                .where(Detection.rule_id.in_(uids))
                .group_by(Detection.rule_id)
            ).all()
        )
        for item in items:
            item.detections_24h = int(recent.get(item.rule_id, 0))
            seen = last.get(item.rule_id)
            if seen is not None and (
                item.last_triggered_at is None or seen > item.last_triggered_at
            ):
                item.last_triggered_at = seen

    def _stats_by_uid(self, uids: Sequence[str]) -> dict[str, DetectionRuleStats]:
        if not uids:
            return {}
        rows = self._session.scalars(
            select(DetectionRuleStats).where(DetectionRuleStats.rule_uid.in_(uids))
        ).all()
        return {row.rule_uid: row for row in rows}

    # --- Detalle, versiones y diff ---------------------------------------------------------

    def get(self, uid: str) -> RuleDetail:
        builtin = RULES_BY_ID.get(uid)
        if builtin is not None:
            item = next(i for i in self._builtin_items() if i.rule_id == uid)
            self._fill_activity([item])
            return RuleDetail(
                **item.model_dump(),
                tags=[],
                definition=None,
                compiled=None,
                compile_issues=[],
                complexity=None,
                stats=self._stats_read(uid),
                detections_total=self._detections_total(uid),
                sigma_metadata=None,
                has_sigma_source=False,
                created_at=None,
                created_by=None,
                retired_at=None,
                logsource_title=LOGSOURCES[item.logsource].title if item.logsource else None,
            )
        record = self._require(uid)
        return self._detail(record)

    def _detail(self, record: DetectionRuleRecord) -> RuleDetail:
        version = self._version(record, record.current_version)
        assert version is not None  # noqa: S101  (current_version siempre existe)
        stats = self._stats_by_uid([record.rule_uid]).get(record.rule_uid)
        item = self._custom_item(record, stats)
        self._fill_activity([item])
        # Recompilar al leer: si la definición guardada ya no compila (catálogo nuevo), la UI
        # lo muestra como "invalid" aunque la fila diga otra cosa.
        result = compile_definition(version.definition)
        issues = [RuleIssue(**issue) for issue in version.compile_issues or []]
        # Una Sigma no soportada no tiene lógica ejecutable: sigue siendo "unsupported".
        if not result.ok and item.compile_status != CompileStatus.UNSUPPORTED.value:
            item.compile_status = "invalid"
            issues += _issues(result.errors)
        compiled = result.rule.summary() if result.rule else version.compiled
        complexity = result.rule.complexity_label if result.rule else None
        logsource = LOGSOURCES.get(record.logsource)
        return RuleDetail(
            **item.model_dump(),
            tags=list(version.tags or ()),
            definition=version.definition,
            compiled=compiled,
            compile_issues=issues,
            complexity=complexity,
            stats=self._stats_read(record.rule_uid, stats),
            detections_total=self._detections_total(record.rule_uid),
            sigma_metadata=version.sigma_metadata,
            has_sigma_source=bool(version.sigma_yaml),
            created_at=record.created_at,
            created_by=record.created_by,
            retired_at=record.retired_at,
            logsource_title=logsource.title if logsource else None,
        )

    def _stats_read(self, uid: str, stats: DetectionRuleStats | None = None) -> RuleStatsRead:
        row = stats or self._stats_by_uid([uid]).get(uid)
        if row is None:
            return RuleStatsRead()
        return RuleStatsRead(
            evaluations=row.evaluations,
            matches=row.matches,
            errors=row.errors,
            consecutive_errors=row.consecutive_errors,
            slow_evaluations=row.slow_evaluations,
            avg_eval_ms=round(row.eval_time_us / row.evaluations / 1000, 3)
            if row.evaluations
            else None,
            last_evaluated_at=row.last_evaluated_at,
            last_matched_at=row.last_matched_at,
            last_error_at=row.last_error_at,
            last_error=row.last_error,
        )

    def _detections_total(self, uid: str) -> int:
        return (
            self._session.scalar(
                select(func.count()).select_from(Detection).where(Detection.rule_id == uid)
            )
            or 0
        )

    def versions(self, uid: str) -> RuleVersionList:
        record = self._require_custom(uid)
        rows = self._session.scalars(
            select(DetectionRuleVersion)
            .where(DetectionRuleVersion.rule_id == record.id)
            .order_by(DetectionRuleVersion.version.desc())
        ).all()
        return RuleVersionList(items=[_version_read(row, record) for row in rows])

    def version(self, uid: str, number: int) -> RuleVersionDetail:
        record = self._require_custom(uid)
        row = self._version(record, number)
        if row is None:
            raise NotFoundError("Rule version not found")
        return RuleVersionDetail(
            **_version_read(row, record).model_dump(),
            description=row.description,
            why=row.why,
            recommendations=list(row.recommendations or ()),
            category=row.category,
            mitre_tactic=row.mitre_tactic,
            mitre_technique=row.mitre_technique,
            mitre_subtechnique=row.mitre_subtechnique,
            tags=list(row.tags or ()),
            definition=row.definition,
            compiled=row.compiled,
            compile_issues=[RuleIssue(**issue) for issue in row.compile_issues or []],
            content_hash=row.content_hash,
        )

    def diff(self, uid: str, from_version: int, to_version: int) -> RuleDiff:
        """Diff semántico campo a campo (no textual): severidad, condición, umbral..."""
        record = self._require_custom(uid)
        before = self._version(record, from_version)
        after = self._version(record, to_version)
        if before is None or after is None:
            raise NotFoundError("Rule version not found")
        a, b = _content(before), _content(after)
        changes: list[RuleChange] = []
        for name in _CONTENT_FIELDS:
            if name == "definition":
                da, db = a["definition"] or {}, b["definition"] or {}
                for key in ("logsource", "condition", "threshold", "group_by", "cooldown_minutes"):
                    if da.get(key) != db.get(key):
                        changes.append(RuleChange(field=key, before=da.get(key), after=db.get(key)))
            elif a[name] != b[name]:
                changes.append(RuleChange(field=name, before=a[name], after=b[name]))
        return RuleDiff(
            rule_id=uid, from_version=from_version, to_version=to_version, changes=changes
        )

    def export(self, uid: str) -> dict[str, Any]:
        """Formato interno seguro (JSON). No es Sigma: no se afirma una conversión fiel."""
        record = self._require_custom(uid)
        version = self._version(record, record.current_version)
        assert version is not None  # noqa: S101
        return {
            "format": "sentra-rule-export/1",
            "rule_id": record.rule_uid,
            "source": record.source,
            "sigma_id": str(record.sigma_id) if record.sigma_id else None,
            "version": version.version,
            "exported_at": datetime.now(UTC).isoformat(),
            **{name: value for name, value in _content(version).items()},
        }

    def sigma_source(self, uid: str) -> str:
        record = self._require_custom(uid)
        version = self._version(record, record.current_version)
        if version is None or not version.sigma_yaml:
            raise NotFoundError("This rule has no Sigma source")
        return version.sigma_yaml

    def audit(self, uid: str, limit: int, offset: int) -> AuditEventList:
        rows = self._session.scalars(
            select(AuditEvent)
            .where(AuditEvent.target_type == TARGET, AuditEvent.target_id == uid)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return AuditEventList(items=[AuditEventRead.model_validate(row) for row in rows])

    # --- Validación ---------------------------------------------------------------------------

    def validate(self, body: RuleValidateIn) -> RuleValidation:
        result, issues = self._compile(body.definition, body)
        status = _compile_status(result)
        return RuleValidation(
            valid=result.ok and not issues,
            compile_status="invalid" if issues else status,
            errors=_issues([*result.errors, *issues]),
            warnings=_issues(result.warnings),
            definition=result.normalized,
            compiled=result.rule.summary() if result.rule else None,
            complexity=result.rule.complexity_label if result.rule else None,
        )

    def _compile(self, definition: dict[str, Any], meta: Any) -> tuple[CompileResult, list[Issue]]:
        """Compila y añade las comprobaciones que dependen de la configuración y metadatos."""
        result = compile_definition(definition)
        extra: list[Issue] = []
        rule = result.rule
        if rule is not None and rule.window_minutes and rule.window_minutes > self._max_window():
            extra.append(
                Issue(
                    "invalid_window",
                    f"window longer than the signal retention ({self._max_window()} min)",
                    "threshold.window_minutes",
                )
            )
        _, mitre_error = mitre_mod.validate(
            getattr(meta, "mitre_tactic", None),
            getattr(meta, "mitre_technique", None),
            getattr(meta, "mitre_subtechnique", None),
        )
        if mitre_error:
            extra.append(Issue("invalid_mitre", mitre_error, "mitre"))
        category = getattr(meta, "category", None)
        if category is not None and category not in CATEGORIES:
            extra.append(Issue("invalid_category", "unknown category", "category"))
        return result, extra

    # --- Crear, editar, estados --------------------------------------------------------------

    def create(self, body: RuleCreate, actor: Actor) -> RuleDetail:
        content, result = self._content_from(body)
        now = datetime.now(UTC)
        record = self._new_record(RuleSource.CUSTOM, content, result, actor, now)
        self._add_version(record, 1, content, result, actor, now, "created")
        audit_service.record(
            self._session,
            actor,
            "rule_created",
            target_type=TARGET,
            target_id=record.rule_uid,
            details={"version": 1, "compile_status": record.compile_status},
            commit=False,
        )
        self._commit()
        return self._detail(record)

    def update(self, uid: str, body: RuleUpdate, actor: Actor) -> RuleDetail:
        record = self._lock(uid)
        self._check_revision(record, body.revision)
        if record.status == RuleStatus.RETIRED:
            raise DetectionRuleStateError("Retired rules cannot be edited; unretire it first")
        current = self._version(record, record.current_version)
        assert current is not None  # noqa: S101
        merged = _content(current)
        changes = body.model_dump(exclude_unset=True, exclude={"revision", "acknowledge_partial"})
        if record.source == RuleSource.SIGMA and "definition" in changes:
            # La lógica de una Sigma sale de su YAML: se cambia reimportándolo (update), así
            # el YAML guardado y la regla evaluada nunca divergen.
            raise DetectionRuleStateError(
                "Sigma rule logic changes through a new import of its YAML"
            )
        merged.update(changes)
        content, result = self._content_from(RuleContentIn(**merged))
        if content_hash(content) == current.content_hash:
            # Sin cambio funcional: no se crea versión (ni se toca la revisión).
            return self._detail(record)
        status = _compile_status(result)
        if (
            record.status == RuleStatus.ACTIVE
            and status == CompileStatus.PARTIAL
            and current.compile_status != CompileStatus.PARTIAL
            and not body.acknowledge_partial
        ):
            raise DetectionRuleStateError(
                "The new version only partially covers its logsource; confirm with"
                " acknowledge_partial"
            )
        now = datetime.now(UTC)
        number = record.current_version + 1
        self._add_version(record, number, content, result, actor, now, "updated", current)
        self._apply_current(record, content, result, number, actor, now)
        audit_service.record(
            self._session,
            actor,
            "rule_updated",
            target_type=TARGET,
            target_id=record.rule_uid,
            details={"version": number, "fields": sorted(changes)[:20]},
            commit=False,
        )
        self._audit_version(record, number, actor, "updated")
        self._commit()
        return self._detail(record)

    def restore(self, uid: str, number: int, revision: int, actor: Actor) -> RuleDetail:
        """Crea una versión NUEVA con el contenido de `number` (la historia no se reescribe)."""
        record = self._lock(uid)
        self._check_revision(record, revision)
        if record.status == RuleStatus.RETIRED:
            raise DetectionRuleStateError("Retired rules cannot be edited; unretire it first")
        source = self._version(record, number)
        if source is None:
            raise NotFoundError("Rule version not found")
        content = _content(source)
        result = compile_definition(content["definition"])
        if not result.ok:
            raise DetectionRuleValidationError(
                "That version no longer compiles", details=[i.as_dict() for i in result.errors]
            )
        if record.status == RuleStatus.ACTIVE and _compile_status(result) not in (
            CompileStatus.VALID,
            CompileStatus.PARTIAL,
        ):
            raise DetectionRuleStateError("Disable the rule before restoring that version")
        now = datetime.now(UTC)
        current = self._version(record, record.current_version)
        new = record.current_version + 1
        self._add_version(
            record, new, content, result, actor, now, f"restored from v{number}", source
        )
        self._apply_current(record, content, result, new, actor, now)
        self._audit_version(record, new, actor, f"restored from v{number}")
        audit_service.record(
            self._session,
            actor,
            "rule_restored",
            target_type=TARGET,
            target_id=record.rule_uid,
            details={"version": new, "restored_from": number},
            commit=False,
        )
        del current
        self._commit()
        return self._detail(record)

    def set_state(
        self, uid: str, action: str, revision: int, acknowledge_partial: bool, actor: Actor
    ) -> RuleDetail:
        if uid in RULES_BY_ID:
            raise ReadOnlyRuleError(
                "Built-in rules are read-only; use DETECTION_DISABLED_RULES on the server"
            )
        record = self._lock(uid)
        self._check_revision(record, revision)
        status = RuleStatus(record.status)
        now = datetime.now(UTC)
        if action == "enable":
            if status == RuleStatus.RETIRED:
                raise DetectionRuleStateError("Retired rules must be unretired first")
            version = self._version(record, record.current_version)
            assert version is not None  # noqa: S101
            # Se recompila AHORA: solo se activa lo que el motor podrá ejecutar.
            result = compile_definition(version.definition)
            compiled = _compile_status(result) if result.ok else CompileStatus.INVALID
            if compiled in (CompileStatus.UNSUPPORTED, CompileStatus.INVALID) or not result.ok:
                raise DetectionRuleStateError(
                    "Only valid and supported rules can be enabled",
                    details=[{"compile_status": compiled.value}],
                )
            if compiled == CompileStatus.PARTIAL and not acknowledge_partial:
                raise DetectionRuleStateError(
                    "This rule only partially covers its logsource; confirm with"
                    " acknowledge_partial",
                    details=[{"compile_status": compiled.value}],
                )
            new_status, audit_action = RuleStatus.ACTIVE, "rule_enabled"
        elif action == "disable":
            if status not in (RuleStatus.ACTIVE, RuleStatus.DRAFT):
                raise DetectionRuleStateError("Only active or draft rules can be disabled")
            new_status, audit_action = RuleStatus.DISABLED, "rule_disabled"
        elif action == "retire":
            if status == RuleStatus.RETIRED:
                raise DetectionRuleStateError("The rule is already retired")
            new_status, audit_action = RuleStatus.RETIRED, "rule_retired"
            record.retired_at = now
        elif action == "unretire":
            if status != RuleStatus.RETIRED:
                raise DetectionRuleStateError("Only retired rules can be unretired")
            # Vuelve desactivada: reactivarla es otra acción explícita (y auditada).
            new_status, audit_action = RuleStatus.DISABLED, "rule_unretired"
            record.retired_at = None
        else:  # pragma: no cover - las rutas solo pasan acciones conocidas
            raise DetectionRuleStateError("Unknown action")
        record.status = new_status.value
        record.revision += 1
        record.updated_at = now
        record.updated_by = actor.name[:64]
        audit_service.record(
            self._session,
            actor,
            audit_action,
            target_type=TARGET,
            target_id=record.rule_uid,
            details={"version": record.current_version, "from": status.value},
            commit=False,
        )
        self._commit()
        return self._detail(record)

    # --- Pruebas sin efectos ------------------------------------------------------------------

    def _rule_for_test(self, definition: dict[str, Any] | None, uid: str | None) -> CustomRule:
        if (definition is None) == (uid is None):
            raise DetectionRuleValidationError("Send either a definition or a rule_id")
        now = datetime.now(UTC)
        if uid is not None:
            if uid in RULES_BY_ID:
                raise ReadOnlyRuleError("Built-in rules cannot be dry-run here")
            record = self._require(uid)
            version = self._version(record, record.current_version)
            assert version is not None  # noqa: S101
            result = compile_definition(version.definition)
            if not result.ok or result.rule is None:
                raise DetectionRuleValidationError(
                    "The rule does not compile", details=[i.as_dict() for i in result.errors]
                )
            return rule_from_version(record, version, result.rule)
        result = compile_definition(definition)
        if not result.ok or result.rule is None:
            raise DetectionRuleValidationError(
                "The rule is not valid", details=[i.as_dict() for i in result.errors]
            )
        placeholder = DetectionRuleRecord(
            id=0, rule_uid="SENTRA-TEST-000000", source="custom", sigma_id=None
        )
        version_row = DetectionRuleVersion(
            version=0,
            title="(prueba)",
            description="",
            why="",
            recommendations=[],
            severity=DetectionSeverity.MEDIUM,
            confidence=DetectionConfidence.LOW,
            category="system",
            created_at=now,
        )
        return rule_from_version(placeholder, version_row, result.rule)

    def test_synthetic(self, body: RuleTestIn) -> RuleTestResult:
        """Evalúa eventos sintéticos en memoria: ni BD, ni detecciones, ni alertas."""
        started = time.perf_counter()
        rule = self._rule_for_test(body.definition, body.rule_id)
        compiled = rule.compiled
        known = fields_for(compiled.logsource)
        unknown = sorted({name for event in body.events for name in event.fields} - set(known))
        if unknown:
            raise DetectionRuleValidationError(
                "Unknown fields for this logsource",
                details=[{"field": name[:80]} for name in unknown[:20]],
            )
        base = datetime.now(UTC)
        results: list[EventTestResult] = []
        hits: list[tuple[str, datetime]] = []
        for index, event in enumerate(body.events):
            record = {name: _synthetic_value(value) for name, value in event.fields.items()}
            missing = sorted(n for n in compiled.required_fields if record.get(n) in (None, ""))
            matched = not missing and compiled.condition.match(record)
            group = group_key_for(compiled, record) if matched else None
            results.append(
                EventTestResult(index=index, matched=matched, group=group, missing_fields=missing)
            )
            if matched and group is not None:
                hits.append((group, event.occurred_at or base + timedelta(seconds=index)))
        return RuleTestResult(
            matched=sum(1 for r in results if r.matched),
            events=results,
            would_detect=_simulate(compiled, hits),
            threshold=compiled.threshold_count,
            window_minutes=compiled.window_minutes,
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
        )

    def test_historical(self, body: HistoricalTestIn) -> HistoricalTestResult:
        """Evalúa la regla sobre datos guardados, acotado y en solo lectura.

        Garantías: transacción READ ONLY (PostgreSQL rechaza cualquier escritura),
        statement_timeout, RULE_TEST_MAX_ROWS filas como mucho, rango <= RULE_TEST_MAX_HOURS
        y un único test histórico a la vez en todo el clúster (advisory lock). Solo se
        traducen a SQL filtros de la allowlist (canal, id de evento, tipo de señal, activo,
        rango), siempre como parámetros; el resto de la condición se evalúa en Python.
        """
        started = time.perf_counter()
        rule = self._rule_for_test(body.definition, body.rule_id)
        compiled = rule.compiled
        until = body.until or datetime.now(UTC)
        since = body.since or until - timedelta(hours=24)
        if since >= until:
            raise DetectionRuleValidationError("since must be before until")
        if until - since > timedelta(hours=self._settings.rule_test_max_hours):
            raise DetectionRuleValidationError(
                f"the range is limited to {self._settings.rule_test_max_hours} hours"
            )
        asset_pk: int | None = None
        if body.asset_id is not None:
            asset_pk = self._session.scalar(
                select(Asset.id).where(Asset.public_id == body.asset_id)
            )
            if asset_pk is None:
                raise NotFoundError("Asset not found")
        # Todo lo anterior es lectura; la transacción de la prueba empieza limpia.
        self._session.rollback()
        session = self._session
        session.execute(text("SET TRANSACTION READ ONLY"))
        timeout_ms = int(self._settings.rule_test_timeout_seconds) * 1000
        session.execute(text(f"SET LOCAL statement_timeout = {timeout_ms}"))
        acquired = session.scalar(select(func.pg_try_advisory_xact_lock(RULE_TEST_LOCK_KEY)))
        if not acquired:
            session.rollback()
            raise RateLimitedError("Another historical rule test is running", 5, "rule_test")
        try:
            outcome = self._scan(rule, compiled, since, until, asset_pk, body.limit)
        finally:
            # Nada que guardar: se deshace siempre (y libera el lock de transacción).
            session.rollback()
        outcome.duration_ms = round((time.perf_counter() - started) * 1000, 3)
        return outcome

    def _scan(
        self,
        rule: CustomRule,
        compiled: CompiledRule,
        since: datetime,
        until: datetime,
        asset_pk: int | None,
        limit: int,
    ) -> HistoricalTestResult:
        max_rows = self._settings.rule_test_max_rows
        logsource = compiled.logsource
        notes: list[str] = []
        rows: Iterable[tuple[int, datetime, str | None, str, str | None, dict[str, Any]]]
        if logsource.is_event:
            data_source = "events"
            stmt = select(SystemEvent).where(
                SystemEvent.channel == logsource.channel,
                SystemEvent.occurred_at >= since,
                SystemEvent.occurred_at <= until,
            )
            if compiled.event_codes:
                stmt = stmt.where(SystemEvent.event_code.in_(sorted(compiled.event_codes)))
            if asset_pk is not None:
                stmt = stmt.where(SystemEvent.asset_id == asset_pk)
            stmt = stmt.order_by(SystemEvent.occurred_at.desc(), SystemEvent.id.desc()).limit(
                max_rows + 1
            )
            channels = frozenset({logsource.channel or ""})
            floor = datetime.min.replace(tzinfo=UTC)

            def event_rows() -> Iterable[
                tuple[int, datetime, str | None, str, str | None, dict[str, Any]]
            ]:
                for event in self._session.scalars(stmt.execution_options(yield_per=1000)):
                    drafts = raw_event_signals([event], floor, channels)
                    if drafts:
                        draft = drafts[0]
                        yield (
                            event.asset_id,
                            event.occurred_at,
                            draft.subject,
                            draft.kind.value,
                            str(event.public_id),
                            draft.data,
                        )

            rows = event_rows()
        else:
            data_source = "signals"
            kinds = sorted(compiled.signal_kinds or logsource.kinds)
            stmt2 = select(DetectionSignal).where(
                DetectionSignal.kind.in_(kinds),
                DetectionSignal.occurred_at >= since,
                DetectionSignal.occurred_at <= until,
            )
            if asset_pk is not None:
                stmt2 = stmt2.where(DetectionSignal.asset_id == asset_pk)
            stmt2 = stmt2.order_by(
                DetectionSignal.occurred_at.desc(), DetectionSignal.id.desc()
            ).limit(max_rows + 1)
            hours = int(self._config.signal_retention.total_seconds() // 3600)
            notes.append(
                f"Las señales se conservan {hours} h (DETECTION_SIGNAL_RETENTION_HOURS): un"
                " rango anterior no tiene datos."
            )
            rows = (
                (s.asset_id, s.occurred_at, s.subject, s.kind, s.source_id, s.data or {})
                for s in self._session.scalars(stmt2.execution_options(yield_per=1000))
            )
        scanned = 0
        truncated = False
        matched = 0
        sample: list[tuple[int, datetime, str | None, str, dict[str, Any]]] = []
        hits: dict[tuple[int, str], list[datetime]] = defaultdict(list)
        assets: dict[int, Mapping[str, Any]] = {}
        for asset_id, occurred_at, subject, kind, source_id, data in rows:
            scanned += 1
            if scanned > max_rows:
                truncated = True
                break
            asset = None
            if compiled.asset_fields:
                if asset_id not in assets:
                    assets[asset_id] = asset_values(self._session, asset_id)
                asset = assets[asset_id]
            ok, record = rule.matches(kind, subject, data, asset)
            if not ok:
                continue
            matched += 1
            key = group_key_for(compiled, record)
            hits[(asset_id, key)].append(occurred_at)
            if len(sample) < limit:
                sample.append(
                    (asset_id, occurred_at, source_id, describe(record, compiled), record)
                )
        if truncated:
            notes.append(
                f"Se examinaron las {max_rows} filas más recientes del rango (RULE_TEST_MAX_ROWS)."
            )
        names = self._asset_names({a for a, *_ in sample} | {a for a, _ in hits})
        groups: list[HistoricalGroup] = []
        for (asset_id, key), times in hits.items():
            times.sort()
            best = _max_in_window(times, compiled.window_minutes)
            if compiled.threshold_count is None or best >= compiled.threshold_count:
                public, host = names.get(asset_id, (None, "?"))
                if public is not None:
                    groups.append(
                        HistoricalGroup(
                            asset_id=public,
                            hostname=host,
                            group=key,
                            max_count=best,
                            first_at=times[0],
                        )
                    )
        groups.sort(key=lambda g: (-g.max_count, g.hostname, g.group))
        return HistoricalTestResult(
            data_source=data_source,
            since=since,
            until=until,
            scanned=min(scanned, max_rows),
            matched=matched,
            truncated=truncated,
            sample=[
                HistoricalMatch(
                    occurred_at=occurred_at,
                    asset_id=names[asset_id][0],
                    hostname=names[asset_id][1],
                    source_id=source_id,
                    summary=summary,
                    fields={
                        k: clean_text.clean(v, 200) if isinstance(v, str) else v
                        for k, v in record.items()
                        if not k.startswith("asset.") and v not in (None, "")
                    },
                )
                for asset_id, occurred_at, source_id, summary, record in sample
                if asset_id in names
            ],
            would_detect=groups[:SAMPLE_GROUPS],
            threshold=compiled.threshold_count,
            duration_ms=0.0,
            notes=notes,
        )

    def _asset_names(self, ids: set[int]) -> dict[int, tuple[UUID, str]]:
        if not ids:
            return {}
        rows = self._session.scalars(select(Asset).where(Asset.id.in_(ids))).all()
        return {row.id: (row.public_id, row.display_name) for row in rows}

    # --- Sigma ------------------------------------------------------------------------------

    def sigma_preview(self, source: str) -> SigmaPreview:
        analysis = sigma_mod.analyze(source)
        return self._preview(analysis)

    def _preview(self, analysis: sigma_mod.SigmaAnalysis) -> SigmaPreview:
        mapping = analysis.mitre
        return SigmaPreview(
            outcome=analysis.outcome,
            title=analysis.title,
            sigma_id=analysis.sigma_id,
            level=analysis.level,
            severity=analysis.severity,
            confidence=DetectionConfidence(self._settings.sigma_default_confidence),
            logsource=analysis.logsource,
            sentra_logsource=analysis.sentra_logsource,
            mitre_tactic=mapping.tactic if mapping else None,
            mitre_technique=mapping.technique if mapping else None,
            mitre_subtechnique=mapping.subtechnique if mapping else None,
            tags=analysis.tags,
            metadata=analysis.metadata,
            errors=_issues(analysis.errors),
            unsupported=_issues(analysis.unsupported),
            warnings=_issues(analysis.warnings),
            definition=analysis.definition,
            compiled=analysis.compiled.summary() if analysis.compiled else None,
            duplicate=self._duplicate(analysis),
        )

    def _duplicate(self, analysis: sigma_mod.SigmaAnalysis) -> SigmaDuplicate:
        if analysis.sigma_id is None:
            return SigmaDuplicate(state="none")
        record = self._session.scalar(
            select(DetectionRuleRecord).where(DetectionRuleRecord.sigma_id == analysis.sigma_id)
        )
        if record is None:
            return SigmaDuplicate(state="none")
        state = "retired" if record.status == RuleStatus.RETIRED else "changed"
        current = self._version(record, record.current_version)
        if (
            state == "changed"
            and current is not None
            and current.content_hash == content_hash(self._sigma_content(analysis, record))
        ):
            state = "identical"
        return SigmaDuplicate(
            state=state,
            rule_id=record.rule_uid,
            current_version=record.current_version,
            revision=record.revision,
        )

    def _sigma_content(
        self, analysis: sigma_mod.SigmaAnalysis, record: DetectionRuleRecord | None = None
    ) -> dict[str, Any]:
        mapping = analysis.mitre
        current = self._version(record, record.current_version) if record is not None else None
        content: dict[str, Any] = {
            "title": analysis.title[:200],
            "description": analysis.description[:2000],
            # why/recommendations/confidence/categoría son decisiones locales del admin: una
            # reimportación del mismo YAML las conserva en lugar de borrarlas.
            "why": current.why if current else "",
            "recommendations": list(current.recommendations or ()) if current else [],
            "severity": analysis.severity.value,
            "confidence": current.confidence.value
            if current
            else self._settings.sigma_default_confidence,
            "category": current.category if current else analysis.category,
            "mitre_tactic": mapping.tactic if mapping else None,
            "mitre_technique": mapping.technique if mapping else None,
            "mitre_subtechnique": mapping.subtechnique if mapping else None,
            "tags": analysis.tags[:20],
            "definition": analysis.definition
            or {"format": "sentra-rule/1", "logsource": analysis.sentra_logsource or "-"},
        }
        return content

    def sigma_import(self, body: SigmaImportIn, actor: Actor) -> SigmaImportResult:
        analysis = sigma_mod.analyze(body.yaml)
        preview = self._preview(analysis)
        if analysis.outcome == "invalid":
            self._audit_import(actor, None, "rejected", preview)
            return SigmaImportResult(result="rejected", rule=None, preview=preview)
        duplicate = preview.duplicate
        now = datetime.now(UTC)
        if duplicate.state == "identical":
            return SigmaImportResult(
                result="unchanged", rule=self.get(duplicate.rule_id or ""), preview=preview
            )
        if duplicate.state in ("changed", "retired"):
            if body.on_duplicate != "update" or body.revision is None:
                raise ConflictError(
                    "A rule with this Sigma id already exists; import with on_duplicate=update"
                    " and its revision to create a new version",
                    details=[duplicate.model_dump()],
                )
            if duplicate.state == "retired":
                raise DetectionRuleStateError("The existing rule is retired; unretire it first")
            record = self._lock(duplicate.rule_id or "")
            self._check_revision(record, body.revision)
            content = self._sigma_content(analysis, record)
            result = self._sigma_result(analysis)
            if record.status == RuleStatus.ACTIVE and analysis.outcome != "supported":
                # Una versión nueva no soportada (o parcial) de una regla activa no puede
                # dejarla "activa pero rota": se pide desactivarla antes.
                raise DetectionRuleStateError(
                    "Disable the rule before importing a version that is not fully supported"
                )
            number = record.current_version + 1
            current = self._version(record, record.current_version)
            self._add_version(
                record,
                number,
                content,
                result,
                actor,
                now,
                "sigma update",
                current,
                sigma_yaml=body.yaml,
                sigma_metadata=analysis.metadata,
            )
            self._apply_current(record, content, result, number, actor, now)
            self._audit_version(record, number, actor, "sigma update")
            self._audit_import(actor, record.rule_uid, "updated", preview, commit=False)
            self._commit()
            return SigmaImportResult(result="updated", rule=self._detail(record), preview=preview)
        content = self._sigma_content(analysis)
        result = self._sigma_result(analysis)
        record = self._new_record(RuleSource.SIGMA, content, result, actor, now, analysis.sigma_id)
        self._add_version(
            record,
            1,
            content,
            result,
            actor,
            now,
            "sigma import",
            sigma_yaml=body.yaml,
            sigma_metadata=analysis.metadata,
        )
        outcome = (
            "unsupported"
            if analysis.outcome == "unsupported"
            else (
                "imported_with_warnings"
                if analysis.warnings or analysis.outcome == "partial"
                else "imported"
            )
        )
        self._audit_import(actor, record.rule_uid, outcome, preview, commit=False)
        self._commit()
        return SigmaImportResult(result=outcome, rule=self._detail(record), preview=preview)

    def _sigma_result(self, analysis: sigma_mod.SigmaAnalysis) -> CompileResult:
        if analysis.definition is not None:
            return compile_definition(analysis.definition)
        result = CompileResult()
        result.errors.extend(analysis.unsupported)
        return result

    def _audit_import(
        self,
        actor: Actor,
        uid: str | None,
        outcome: str,
        preview: SigmaPreview,
        commit: bool = True,
    ) -> None:
        failed = outcome == "rejected"
        audit_service.record(
            self._session,
            actor,
            "rule_import_failed" if failed else "rule_imported",
            audit_service.FAILURE if failed else audit_service.SUCCESS,
            target_type=TARGET,
            target_id=uid,
            details={
                "result": outcome,
                "sigma_id": str(preview.sigma_id) if preview.sigma_id else None,
                "outcome": preview.outcome,
                "reasons": [i.code for i in [*preview.errors, *preview.unsupported]][:10],
            },
            commit=commit,
        )

    # --- Persistencia --------------------------------------------------------------------------

    def _content_from(self, body: RuleContentIn) -> tuple[dict[str, Any], CompileResult]:
        result, extra = self._compile(body.definition, body)
        if result.errors or extra or result.normalized is None or result.rule is None:
            raise DetectionRuleValidationError(
                "The rule is not valid",
                details=[issue.as_dict() for issue in [*result.errors, *extra]],
            )
        mapping, _ = mitre_mod.validate(
            body.mitre_tactic, body.mitre_technique, body.mitre_subtechnique
        )
        content: dict[str, Any] = {
            "title": clean_text.clean(body.title, 200),
            "description": body.description.strip()[:2000],
            "why": body.why.strip()[:1000],
            "recommendations": [
                clean_text.clean(item, 300) for item in body.recommendations if item.strip()
            ],
            "severity": body.severity.value,
            "confidence": body.confidence.value,
            "category": body.category or DEFAULT_CATEGORY.get(result.rule.logsource.name, "system"),
            "mitre_tactic": mapping.tactic if mapping else None,
            "mitre_technique": mapping.technique if mapping else None,
            "mitre_subtechnique": mapping.subtechnique if mapping else None,
            "tags": sorted({clean_text.clean(tag, 64) for tag in body.tags if tag.strip()}),
            "definition": result.normalized,
        }
        return content, result

    def _new_record(
        self,
        source: RuleSource,
        content: dict[str, Any],
        result: CompileResult,
        actor: Actor,
        now: datetime,
        sigma_id: UUID | None = None,
    ) -> DetectionRuleRecord:
        number = self._session.scalar(select(func.nextval("detection_rule_uid_seq")))
        prefix = "SENTRA-SIGMA" if source == RuleSource.SIGMA else "SENTRA-CUSTOM"
        record = DetectionRuleRecord(
            rule_uid=f"{prefix}-{int(number or 0):06d}",
            source=source.value,
            sigma_id=sigma_id,
            # Nunca activa al crear o importar: draft -> validar -> probar -> activar.
            status=RuleStatus.DRAFT.value,
            revision=1,
            created_at=now,
            created_by=actor.name[:64],
            updated_at=now,
            updated_by=actor.name[:64],
        )
        _set_current(record, content, result, 1, now)
        self._session.add(record)
        self._session.flush()
        return record

    def _apply_current(
        self,
        record: DetectionRuleRecord,
        content: dict[str, Any],
        result: CompileResult,
        number: int,
        actor: Actor,
        now: datetime,
    ) -> None:
        _set_current(record, content, result, number, now)
        record.revision += 1
        record.updated_at = now
        record.updated_by = actor.name[:64]

    def _add_version(
        self,
        record: DetectionRuleRecord,
        number: int,
        content: dict[str, Any],
        result: CompileResult,
        actor: Actor,
        now: datetime,
        note: str,
        previous: DetectionRuleVersion | None = None,
        sigma_yaml: str | None = None,
        sigma_metadata: dict[str, Any] | None = None,
    ) -> None:
        if sigma_yaml is None and previous is not None:
            # Editar metadatos de una Sigma conserva su YAML original en la versión nueva.
            sigma_yaml, sigma_metadata = previous.sigma_yaml, previous.sigma_metadata
        issues = [*result.warnings, *(result.errors if not result.ok else [])]
        self._session.add(
            DetectionRuleVersion(
                rule_id=record.id,
                version=number,
                created_at=now,
                created_by=actor.name[:64],
                change_note=note[:200],
                title=content["title"],
                description=content["description"],
                why=content["why"],
                recommendations=content["recommendations"],
                severity=DetectionSeverity(content["severity"]),
                confidence=DetectionConfidence(content["confidence"]),
                category=content["category"],
                mitre_tactic=content["mitre_tactic"],
                mitre_technique=content["mitre_technique"],
                mitre_subtechnique=content["mitre_subtechnique"],
                tags=content["tags"],
                definition=content["definition"],
                compiled=result.rule.summary() if result.rule else {},
                compile_status=_compile_status(result).value,
                compile_issues=[issue.as_dict() for issue in issues],
                content_hash=content_hash(content),
                sigma_yaml=sigma_yaml,
                sigma_metadata=sigma_metadata,
            )
        )

    def _audit_version(
        self, record: DetectionRuleRecord, number: int, actor: Actor, note: str
    ) -> None:
        audit_service.record(
            self._session,
            actor,
            "rule_version_created",
            target_type=TARGET,
            target_id=record.rule_uid,
            details={"version": number, "note": note[:100]},
            commit=False,
        )

    def _commit(self) -> None:
        self._session.commit()
        # Este proceso ve el cambio al instante; los demás workers, al comparar la huella.
        reset_caches()

    def _require(self, uid: str) -> DetectionRuleRecord:
        record = self._session.scalar(
            select(DetectionRuleRecord).where(DetectionRuleRecord.rule_uid == uid)
        )
        if record is None:
            raise NotFoundError("Detection rule not found")
        return record

    def _require_custom(self, uid: str) -> DetectionRuleRecord:
        if uid in RULES_BY_ID:
            raise NotFoundError("Built-in rules have no stored versions")
        return self._require(uid)

    def _lock(self, uid: str) -> DetectionRuleRecord:
        if uid in RULES_BY_ID:
            raise ReadOnlyRuleError("Built-in rules are read-only")
        record = self._session.scalar(
            select(DetectionRuleRecord)
            .where(DetectionRuleRecord.rule_uid == uid)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if record is None:
            raise NotFoundError("Detection rule not found")
        return record

    def _check_revision(self, record: DetectionRuleRecord, revision: int) -> None:
        if record.revision != revision:
            raise DetectionRuleConflictError(
                "The rule was changed by someone else; reload it and try again",
                details=[
                    {
                        "rule_id": record.rule_uid,
                        "current_revision": record.revision,
                        "current_version": record.current_version,
                        "updated_at": record.updated_at.isoformat(),
                        "updated_by": record.updated_by,
                    }
                ],
            )

    def _version(self, record: DetectionRuleRecord, number: int) -> DetectionRuleVersion | None:
        return self._session.scalar(
            select(DetectionRuleVersion).where(
                DetectionRuleVersion.rule_id == record.id, DetectionRuleVersion.version == number
            )
        )


# --- Utilidades -------------------------------------------------------------------------------


def _compile_status(result: CompileResult) -> CompileStatus:
    if not result.ok or result.rule is None:
        return CompileStatus.UNSUPPORTED if result.errors else CompileStatus.INVALID
    if result.rule.support is Support.PARTIAL or any(
        w.code in ("sigma_partial", "partial_logsource") for w in result.warnings
    ):
        return CompileStatus.PARTIAL
    return CompileStatus.VALID


def _set_current(
    record: DetectionRuleRecord,
    content: dict[str, Any],
    result: CompileResult,
    number: int,
    now: datetime,
) -> None:
    record.current_version = number
    record.compile_status = _compile_status(result).value
    record.title = content["title"]
    record.logsource = str(content["definition"].get("logsource") or "-")[:32]
    record.severity = DetectionSeverity(content["severity"])
    record.confidence = DetectionConfidence(content["confidence"])
    record.category = content["category"]
    record.mitre_technique = content["mitre_subtechnique"] or content["mitre_technique"]
    record.last_compiled_at = now


def _content(version: DetectionRuleVersion) -> dict[str, Any]:
    return {
        "title": version.title,
        "description": version.description,
        "why": version.why,
        "recommendations": list(version.recommendations or ()),
        "severity": version.severity.value,
        "confidence": version.confidence.value,
        "category": version.category,
        "mitre_tactic": version.mitre_tactic,
        "mitre_technique": version.mitre_technique,
        "mitre_subtechnique": version.mitre_subtechnique,
        "tags": list(version.tags or ()),
        "definition": version.definition,
    }


def _version_read(row: DetectionRuleVersion, record: DetectionRuleRecord) -> RuleVersionRead:
    return RuleVersionRead(
        version=row.version,
        created_at=row.created_at,
        created_by=row.created_by,
        change_note=row.change_note,
        compile_status=row.compile_status,
        title=row.title,
        severity=row.severity,
        confidence=row.confidence,
        current=row.version == record.current_version,
    )


def _matches_filter(item: DetectionRuleRead, f: RuleFilter) -> bool:
    if f.source and item.source != f.source:
        return False
    if f.status and item.status != f.status:
        return False
    if f.enabled is not None and item.enabled != f.enabled:
        return False
    if f.compile_status and item.compile_status != f.compile_status:
        return False
    if f.severity is not None and item.severity != f.severity:
        return False
    if f.logsource and item.logsource != f.logsource:
        return False
    technique = item.mitre_subtechnique or item.mitre_technique or ""
    if f.mitre and not technique.upper().startswith(f.mitre.upper()):
        return False
    if f.search:
        needle = f.search.lower()
        if needle not in item.title.lower() and needle not in item.rule_id.lower():
            return False
    return True


_FAR = datetime.max.replace(tzinfo=UTC)


def _sort_key(item: DetectionRuleRead, sort: str) -> tuple[Any, ...]:
    title = item.title.lower().encode()
    if sort == "updated_at":
        primary: Any = (item.updated_at is None, item.updated_at or _FAR)
    elif sort == "last_triggered":
        primary = (item.last_triggered_at is None, item.last_triggered_at or _FAR)
    elif sort == "severity":
        primary = _SEVERITY_ORDER[item.severity]
    elif sort == "source":
        primary = item.source
    else:
        primary = title
    return (primary, title, item.rule_id)


def _reverse_stable(items: list[DetectionRuleRead], sort: str) -> list[DetectionRuleRead]:
    """Orden descendente con los valores vacíos (None) al final, como NULLS LAST en SQL."""
    if sort in ("updated_at", "last_triggered"):
        attr = "updated_at" if sort == "updated_at" else "last_triggered_at"
        present = [i for i in items if getattr(i, attr) is not None]
        missing = [i for i in items if getattr(i, attr) is None]
        present.sort(key=lambda i: (getattr(i, attr),), reverse=True)
        return present + missing
    return sorted(items, key=lambda i: _sort_key(i, sort)[0], reverse=True)


def _synthetic_value(value: Any) -> Any:
    if isinstance(value, str):
        return clean_text.clean(value, 1024)
    return value


def _max_in_window(times: Sequence[datetime], window_minutes: int | None) -> int:
    if window_minutes is None:
        return len(times)
    window = timedelta(minutes=window_minutes)
    best = 0
    queue: deque[datetime] = deque()
    for moment in times:
        queue.append(moment)
        while queue and moment - queue[0] > window:
            queue.popleft()
        best = max(best, len(queue))
    return best


def _simulate(compiled: CompiledRule, hits: list[tuple[str, datetime]]) -> list[SimulatedDetection]:
    by_group: dict[str, list[datetime]] = defaultdict(list)
    for group, moment in hits:
        by_group[group].append(moment)
    out = []
    for group, times in sorted(by_group.items()):
        times.sort()
        count = _max_in_window(times, compiled.window_minutes)
        if compiled.threshold_count is None or count >= compiled.threshold_count:
            out.append(
                SimulatedDetection(group=group, count=count, first_at=times[0], last_at=times[-1])
            )
    return out[:SAMPLE_GROUPS]


def logsource_of(name: str) -> LogSource | None:
    return LOGSOURCES.get(name)
