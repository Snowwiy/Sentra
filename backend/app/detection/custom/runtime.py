"""Reglas personalizadas dentro del motor 4H: carga, índice y evaluación (Fase 5A).

No es un segundo motor: CustomRule implementa el mismo contrato que las reglas built-in
(`meta` + `evaluate(ctx, signal) -> list[RuleResult]`) y DetectionEngine la trata igual:
mismo SAVEPOINT por regla, misma deduplicación (uq_detections_active_key), mismo cooldown,
misma evidencia, mismas alertas (DETECTION_ALERT_MIN_SEVERITY), mismo encolado de riesgo.

Carga y multi-worker: la base de datos es la fuente de verdad. Cada proceso guarda en
memoria el índice compilado junto con una huella barata de detection_rules (número de filas,
suma de `revision` y último `updated_at`). Antes de cada lote del motor se compara la huella
(una consulta agregada sobre una tabla pequeña): si otro worker o un admin cambió algo, el
índice se reconstruye desde la BD. No hay listas que solo conozca un proceso ni Redis.

Aislamiento: una definición guardada que ya no compila (catálogo cambiado, fila manipulada)
se omite y se registra; el resto de reglas y el arranque de Sentra siguen funcionando.
"""

import logging
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.detection import text
from app.detection.custom.catalog import EVENT_KIND, LOGSOURCES, FieldSpec, fields_for
from app.detection.custom.definition import CompiledRule, compile_definition
from app.detection.rules import (
    SINGLE,
    Evidence,
    Mitre,
    RuleContext,
    RuleMeta,
    RuleResult,
)
from app.detection.signals import SignalKind
from app.models.detection import DetectionSignal
from app.models.detection_rule import (
    CompileStatus,
    DetectionRuleRecord,
    DetectionRuleVersion,
    RuleStatus,
)

logger = logging.getLogger(__name__)

# Evidencia incluida en una detección por umbral (las últimas N coincidencias del grupo).
THRESHOLD_EVIDENCE = 10
RUNNABLE = (CompileStatus.VALID.value, CompileStatus.PARTIAL.value)


class CustomRuleContext(RuleContext, Protocol):
    """Lo que una regla personalizada puede pedir al motor, además de RuleContext."""

    def asset_values(self, asset_id: int) -> Mapping[str, Any]: ...

    def record_and_count_rule_match(
        self,
        rule_pk: int,
        version: int,
        asset_id: int,
        group_key: str,
        signal: DetectionSignal,
        start: datetime,
    ) -> int: ...

    def rule_match_signals(
        self,
        rule_pk: int,
        version: int,
        asset_id: int,
        group_key: str,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> Sequence[DetectionSignal]: ...


def _resolve(
    spec: FieldSpec,
    signal_kind: str,
    subject: str | None,
    data: Mapping[str, Any],
    asset: Mapping[str, Any] | None,
) -> Any:
    path = spec.path
    if path == "$kind":
        return signal_kind
    if path == "$subject":
        return subject
    if path.startswith("$asset."):
        return asset.get(path[7:]) if asset is not None else None
    return data.get(path)


def build_record(
    compiled: CompiledRule,
    signal_kind: str,
    subject: str | None,
    data: Mapping[str, Any] | None,
    asset: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Registro evaluable: solo los campos que usa la regla, leídos por su ruta del catálogo."""
    fields = fields_for(compiled.logsource)
    values = data if isinstance(data, Mapping) else {}
    return {
        name: _resolve(fields[name], signal_kind, subject, values, asset)
        for name in compiled.fields
    }


def group_key_for(compiled: CompiledRule, record: Mapping[str, Any]) -> str:
    """Clave de agrupación/deduplicación: valores de group_by normalizados, o "*"."""
    if not compiled.group_by:
        return "*"
    parts = []
    for name in compiled.group_by:
        value = record.get(name)
        parts.append(text.clean(value, 80).lower() if value not in (None, "") else "-")
    return text.clean("|".join(parts), 255) or "*"


def describe(record: Mapping[str, Any], compiled: CompiledRule, limit: int = 4) -> str:
    """Texto determinista con los valores que hicieron coincidir la regla (sin activo)."""
    parts = []
    for name in sorted(compiled.fields - compiled.asset_fields):
        value = record.get(name)
        if value in (None, ""):
            continue
        parts.append(f"{name}={text.clean(value, 80)}")
        if len(parts) >= limit:
            break
    return ", ".join(parts)


@dataclass
class CustomRule:
    """Regla personalizada o Sigma lista para el motor (una versión concreta)."""

    meta: RuleMeta
    pk: int
    compiled: CompiledRule
    sigma_id: str | None = None

    def matches(
        self,
        signal_kind: str,
        subject: str | None,
        data: Mapping[str, Any] | None,
        asset: Mapping[str, Any] | None,
    ) -> tuple[bool, dict[str, Any]]:
        """Evalúa solo la condición (sin umbral ni BD). Base del motor y del dry-run."""
        logsource = self.compiled.logsource
        values = data if isinstance(data, Mapping) else {}
        if logsource.is_event and values.get("channel") != logsource.channel:
            return False, {}
        record = build_record(self.compiled, signal_kind, subject, values, asset)
        for name in self.compiled.required_fields:
            if record.get(name) in (None, ""):
                return False, record
        return self.compiled.condition.match(record), record

    def evaluate(self, ctx: RuleContext, signal: DetectionSignal) -> list[RuleResult]:
        custom: CustomRuleContext = ctx  # type: ignore[assignment]
        compiled = self.compiled
        asset = custom.asset_values(signal.asset_id) if compiled.asset_fields else None
        matched, record = self.matches(signal.kind, signal.subject, signal.data, asset)
        if not matched:
            return []
        key = group_key_for(compiled, record)
        matched_text = describe(record, compiled)
        details: dict[str, Any] = {
            "rule_uid": self.meta.id,
            "rule_version": self.meta.version,
            "rule_source": self.meta.source,
            "logsource": compiled.logsource.name,
            "matched": matched_text,
        }
        if self.sigma_id:
            details["sigma_id"] = self.sigma_id
        if compiled.group_by:
            details["group"] = key
        if compiled.threshold_count is None or compiled.window_minutes is None:
            return [
                RuleResult(
                    key=key,
                    summary=f"{self.meta.title}: {matched_text or 'coincidencia'}.",
                    evidence=[Evidence(signal, "match")],
                    occurred_at=signal.occurred_at,
                    details=details,
                )
            ]
        version = self.meta.version
        window = timedelta(minutes=compiled.window_minutes)
        start = signal.occurred_at - window
        count = custom.record_and_count_rule_match(
            self.pk, version, signal.asset_id, key, signal, start
        )
        if count < compiled.threshold_count:
            return []
        recent = custom.rule_match_signals(
            self.pk, version, signal.asset_id, key, start, signal.occurred_at, THRESHOLD_EVIDENCE
        )
        evidence = [Evidence(s, "match") for s in recent if s.id != signal.id]
        evidence.append(Evidence(signal, "match"))
        details.update(
            {
                "count": count,
                "threshold": compiled.threshold_count,
                "window_minutes": compiled.window_minutes,
            }
        )
        group = f" ({key})" if compiled.group_by else ""
        return [
            RuleResult(
                key=key,
                summary=(
                    f"{self.meta.title}: {count} coincidencias en {compiled.window_minutes} min"
                    f"{group}. Última: {matched_text or 'sin campos'}."
                ),
                evidence=evidence[-THRESHOLD_EVIDENCE:],
                occurred_at=signal.occurred_at,
                details=details,
            )
        ]


def _triggers(compiled: CompiledRule) -> frozenset[SignalKind]:
    kinds = compiled.signal_kinds or compiled.logsource.kinds
    return frozenset(SignalKind(kind) for kind in kinds)


def rule_from_version(
    record: DetectionRuleRecord, version: DetectionRuleVersion, compiled: CompiledRule
) -> CustomRule:
    mitre = (
        Mitre(version.mitre_tactic or "", version.mitre_technique, version.mitre_subtechnique)
        if version.mitre_technique
        else None
    )
    meta = RuleMeta(
        id=record.rule_uid,
        version=version.version,
        kind=SINGLE,
        category=version.category,
        title=version.title,
        description=version.description,
        why=version.why,
        severity=version.severity,
        confidence=version.confidence,
        triggers=_triggers(compiled),
        required_data=(compiled.logsource.title,),
        recommendations=tuple(version.recommendations or ()),
        mitre=mitre,
        cooldown=timedelta(minutes=compiled.cooldown_minutes),
        source=record.source,
    )
    return CustomRule(
        meta=meta,
        pk=record.id,
        compiled=compiled,
        sigma_id=str(record.sigma_id) if record.sigma_id else None,
    )


@dataclass
class CustomRuleIndex:
    """Reglas activas indexadas por (tipo de señal, canal, id de evento): fast-path."""

    rules: list[CustomRule] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    _by_key: dict[tuple[str, str | None, int | None], list[CustomRule]] = field(
        default_factory=dict
    )

    def add(self, rule: CustomRule) -> None:
        self.rules.append(rule)
        compiled = rule.compiled
        if compiled.logsource.is_event:
            channel = compiled.logsource.channel
            codes: list[int | None] = list(compiled.event_codes) if compiled.event_codes else [None]
            for code in codes:
                self._by_key.setdefault((EVENT_KIND, channel, code), []).append(rule)
        else:
            for kind in compiled.signal_kinds or compiled.logsource.kinds:
                self._by_key.setdefault((kind, None, None), []).append(rule)

    def candidates(self, signal_kind: str, data: Mapping[str, Any] | None) -> list[CustomRule]:
        if not self._by_key:
            return []
        if signal_kind != EVENT_KIND:
            return self._by_key.get((signal_kind, None, None), [])
        values = data if isinstance(data, Mapping) else {}
        channel = values.get("channel")
        code = values.get("code")
        exact = self._by_key.get((EVENT_KIND, channel, code), []) if isinstance(code, int) else []
        return exact + self._by_key.get((EVENT_KIND, channel, None), [])

    @property
    def channels(self) -> frozenset[str]:
        return frozenset(
            rule.compiled.logsource.channel
            for rule in self.rules
            if rule.compiled.logsource.channel is not None
        )


Fingerprint = tuple[int, int, datetime | None]

_lock = threading.Lock()
_cache: dict[str, tuple[Fingerprint, CustomRuleIndex]] = {}
_channels_cache: dict[str, tuple[float, frozenset[str]]] = {}
# Cada cuánto la ingesta vuelve a mirar qué canales tienen reglas activas (ver recorder.py):
# una regla recién activada empieza a recibir eventos de otro worker en como mucho este tiempo.
CHANNELS_TTL_SECONDS = 5.0


def _fingerprint(session: Session) -> Fingerprint:
    row = session.execute(
        select(
            func.count(DetectionRuleRecord.id),
            func.coalesce(func.sum(DetectionRuleRecord.revision), 0),
            func.max(DetectionRuleRecord.updated_at),
        )
    ).one()
    return int(row[0]), int(row[1]), row[2]


def _cache_key(session: Session) -> str:
    # Una caché por base de datos (los tests usan otra URL que la API real).
    bind = session.get_bind()
    return str(getattr(bind, "url", "default"))


def load_index(session: Session) -> CustomRuleIndex:
    """Índice de reglas activas, reconstruido solo si la huella de la BD cambió."""
    key = _cache_key(session)
    fingerprint = _fingerprint(session)
    with _lock:
        cached = _cache.get(key)
        if cached is not None and cached[0] == fingerprint:
            return cached[1]
    index = CustomRuleIndex()
    rows = session.execute(
        select(DetectionRuleRecord, DetectionRuleVersion)
        .join(
            DetectionRuleVersion,
            (DetectionRuleVersion.rule_id == DetectionRuleRecord.id)
            & (DetectionRuleVersion.version == DetectionRuleRecord.current_version),
        )
        .where(
            DetectionRuleRecord.status == RuleStatus.ACTIVE.value,
            DetectionRuleRecord.compile_status.in_(RUNNABLE),
        )
        .order_by(DetectionRuleRecord.id)
    ).all()
    for record, version in rows:
        try:
            result = compile_definition(version.definition)
            if not result.ok or result.rule is None:
                raise ValueError(result.errors[0].code if result.errors else "invalid")
            index.add(rule_from_version(record, version, result.rule))
        except Exception as exc:
            # Una regla corrupta no impide cargar las demás ni arrancar Sentra.
            index.skipped[record.rule_uid] = type(exc).__name__
            logger.warning(
                "custom detection rule skipped: does not compile",
                extra={
                    "rule": record.rule_uid,
                    "version": version.version,
                    "error_category": str(exc)[:64],
                },
            )
    with _lock:
        _cache[key] = (fingerprint, index)
    return index


def active_event_channels(session: Session) -> frozenset[str]:
    """Canales de Windows con alguna regla activa de logsource de eventos (caché corta)."""
    key = _cache_key(session)
    now = time.monotonic()
    with _lock:
        cached = _channels_cache.get(key)
        if cached is not None and now - cached[0] < CHANNELS_TTL_SECONDS:
            return cached[1]
    names = session.scalars(
        select(DetectionRuleRecord.logsource)
        .where(
            DetectionRuleRecord.status == RuleStatus.ACTIVE.value,
            DetectionRuleRecord.compile_status.in_(RUNNABLE),
        )
        .distinct()
    ).all()
    channels = frozenset(
        channel
        for name in names
        if (source := LOGSOURCES.get(name)) is not None and (channel := source.channel)
    )
    with _lock:
        _channels_cache[key] = (now, channels)
    return channels


def reset_caches() -> None:
    """Vacía las cachés de proceso (tests y CLI)."""
    with _lock:
        _cache.clear()
        _channels_cache.clear()
