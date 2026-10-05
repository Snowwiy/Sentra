"""AIInsightService (Fase 4J): orquesta un análisis de IA de principio a fin.

Flujo (el modelo nunca decide qué datos leer ni ejecuta nada):
  petición autorizada -> alcance determinista -> context builder (lecturas cerradas)
  -> caché por huella de datos -> rate limit y concurrencia -> proveedor (sin conexión a
  la base de datos abierta) -> schema -> grounding de evidencias -> persistencia + auditoría.

Garantías operativas:
- nada de esto corre en la ingesta ni en los jobs de detección/riesgo: solo bajo demanda;
- un fallo del proveedor solo afecta a la petición que lo pidió (error controlado);
- la conexión a PostgreSQL se libera antes de llamar al modelo: un modelo lento no agota el
  pool de la API;
- auditoría ai_analysis_requested / completed / failed sin contenido sensible ni secretos.
"""

import hashlib
import json
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app.ai.config import AIConfig
from app.ai.context import AIContext, ContextBuilder
from app.ai.freshness import data_version
from app.ai.intent import resolve_scope
from app.ai.openai_compat import OpenAICompatibleProvider
from app.ai.output import ground, insufficient_result, parse_json
from app.ai.prompts import TEMPLATES, InsightKind
from app.ai.provider import (
    AIBusyError,
    AIError,
    AIInvalidResponseError,
    AINotConfiguredError,
    AIProvider,
    AIRequest,
)
from app.ai.redaction import Redactor
from app.core.config import Settings
from app.core.exceptions import NotFoundError, RateLimitedError
from app.core.rate_limit import RateLimiter
from app.models.ai import AIInsight
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.risk import RiskSnapshot
from app.risk.config import RiskConfig
from app.schemas.ai import AIStatus, InsightList, InsightRead, InsightResult
from app.services import audit_service
from app.services.audit_service import Actor

logger = logging.getLogger("sentra.ai")

ProviderFactory = Callable[[AIConfig], AIProvider]


def default_provider_factory(config: AIConfig) -> AIProvider:
    return OpenAICompatibleProvider(config)


class AIRuntime:
    """Estado por proceso: límites de frecuencia y de concurrencia (como el login)."""

    def __init__(self, config: AIConfig) -> None:
        self.per_user = RateLimiter(config.rate_per_user, 60)
        self.global_ = RateLimiter(config.rate_global, 60)
        # Acotar llamadas simultáneas: cada una ocupa un hilo del threadpool de la API
        # hasta AI_TIMEOUT_SECONDS; sin tope, un bucle de peticiones lo agotaría.
        self.slots = threading.BoundedSemaphore(config.max_concurrent)


@dataclass(frozen=True)
class Requester:
    actor: Actor
    user_id: int


class AIInsightService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        runtime: AIRuntime,
        provider_factory: ProviderFactory,
        requester: Requester,
    ) -> None:
        self._session = session
        self._settings = settings
        self._config = AIConfig.from_settings(settings)
        self._runtime = runtime
        self._factory = provider_factory
        self._requester = requester

    # --- Estado -----------------------------------------------------------------------------

    def status(self) -> AIStatus:
        c = self._config
        reason = c.unavailable_reason()
        return AIStatus(
            enabled=c.enabled,
            available=reason is None,
            reason=reason,
            provider=c.provider if c.enabled else None,
            model=c.model if c.enabled else None,
            location=c.location,
            external_allowed=c.allow_external,
            redaction=sorted(c.redact),
            max_context_items=c.max_context_items,
            rate_limit_per_user_per_minute=c.rate_per_user,
            prompt_versions={k.value: t.name for k, t in TEMPLATES.items()},
        )

    # --- Tipos de insight -------------------------------------------------------------------

    def analyze_asset(self, asset_id: UUID, refresh: bool) -> InsightRead:
        return self._run(
            InsightKind.ASSET_SUMMARY,
            lambda b: b.asset(asset_id),
            entity=str(asset_id),
            refresh=refresh,
        )

    def analyze_detection(self, detection_id: UUID, refresh: bool) -> InsightRead:
        return self._run(
            InsightKind.DETECTION_ANALYSIS,
            lambda b: b.detection(detection_id),
            entity=str(detection_id),
            refresh=refresh,
        )

    def analyze_risk(self, asset_id: UUID, refresh: bool) -> InsightRead:
        return self._run(
            InsightKind.RISK_EXPLANATION,
            # Foco en riesgo: menos detecciones, sin cambios de inventario ni alertas.
            lambda b: b.asset(asset_id, detection_limit=6, include_inventory_changes=False),
            entity=str(asset_id),
            refresh=refresh,
        )

    def soc_summary(self, window: str, refresh: bool) -> InsightRead:
        return self._run(
            InsightKind.SOC_SUMMARY,
            lambda b: b.fleet(window),
            entity=f"fleet:{window}",
            refresh=refresh,
        )

    def ask(
        self,
        question: str,
        asset_id: UUID | None,
        detection_id: UUID | None,
        refresh: bool,
    ) -> InsightRead:
        self._require_available()
        scope = resolve_scope(self._session, question, asset_id, detection_id)
        build: Callable[[ContextBuilder], AIContext]
        if scope.kind == "detection" and scope.detection_id is not None:
            detection = scope.detection_id
            build = lambda b: b.detection(detection)  # noqa: E731
            entity = str(detection)
        elif scope.kind == "asset" and scope.asset_id is not None:
            asset = scope.asset_id
            build = lambda b: b.asset(asset)  # noqa: E731
            entity = str(asset)
        else:
            build = lambda b: b.fleet(scope.window, scope.min_severity)  # noqa: E731
            entity = f"fleet:{scope.window}:{scope.min_severity.value}"
        return self._run(
            InsightKind.ASK,
            build,
            entity=entity,
            refresh=refresh,
            question=" ".join(question.split()),
            resolved_by=scope.resolved_by,
        )

    # --- Núcleo -----------------------------------------------------------------------------

    def _require_available(self) -> None:
        reason = self._config.unavailable_reason()
        if reason is not None:
            raise AINotConfiguredError(reason)

    def _audit(
        self, action: str, result: str, entity: str, details: dict[str, Any], commit: bool = True
    ) -> None:
        audit_service.record(
            self._session,
            self._requester.actor,
            action,
            result,
            target_type="ai_insight",
            target_id=entity,
            details=details,
            commit=commit,
        )

    def _cache_key(self, kind: InsightKind, entity: str, version: str, question: str | None) -> str:
        c = self._config
        parts = [
            kind.value,
            entity,
            version,
            c.provider,
            c.model,
            TEMPLATES[kind].name,
            sorted(c.redact),
            question.lower() if question else None,
            # Las preguntas son privadas: la caché de Ask no se comparte entre usuarios.
            self._requester.user_id if kind is InsightKind.ASK else None,
        ]
        return hashlib.sha256(json.dumps(parts).encode()).hexdigest()

    def _run(
        self,
        kind: InsightKind,
        build: Callable[[ContextBuilder], AIContext],
        *,
        entity: str,
        refresh: bool,
        question: str | None = None,
        resolved_by: str | None = None,
    ) -> InsightRead:
        self._require_available()
        config = self._config
        now = datetime.now(UTC)
        redactor = Redactor(config.redact)
        builder = ContextBuilder(
            self._session,
            RiskConfig.from_settings(self._settings),
            timedelta(seconds=self._settings.heartbeat_timeout_seconds),
            config.max_context_items,
            redactor,
            now,
        )
        ctx = build(builder)  # 404 si la entidad no existe (antes de auditar nada).
        version = data_version(self._session, ctx.asset_pk, ctx.detection_pk)
        cache_key = self._cache_key(kind, entity, version, question)
        base = {
            "kind": kind.value,
            "scope": ctx.scope,
            "provider": config.provider,
            "model": config.model,
            "prompt_version": TEMPLATES[kind].name,
            "context_items": ctx.items,
        }
        if question is not None:
            base["question_chars"] = len(question)
            base["resolved_by"] = resolved_by

        if not refresh:
            cached = self._session.scalar(
                select(AIInsight)
                .where(AIInsight.cache_key == cache_key, AIInsight.expires_at > now)
                .order_by(AIInsight.generated_at.desc())
                .limit(1)
            )
            if cached is not None:
                self._audit("ai_analysis_requested", audit_service.SUCCESS, entity, base)
                self._audit(
                    "ai_analysis_completed",
                    audit_service.SUCCESS,
                    entity,
                    {**base, "cached": True, "insight": str(cached.public_id)},
                )
                return self._read(cached, cached=True)

        self._check_rate_limit()
        if not self._runtime.slots.acquire(blocking=False):
            raise AIBusyError("Too many AI analyses running; retry in a few seconds")
        try:
            # El commit de la auditoría libera la conexión: la llamada al modelo (lenta)
            # ocurre sin ocupar una conexión del pool.
            self._audit("ai_analysis_requested", audit_service.SUCCESS, entity, base)
            try:
                outcome = self._infer(kind, ctx, question)
            except AIError as exc:
                self._session.rollback()
                self._audit(
                    "ai_analysis_failed", audit_service.FAILURE, entity, {**base, "error": exc.code}
                )
                logger.warning(
                    "ai analysis failed",
                    extra={"kind": kind.value, "error": exc.code, "model": config.model},
                )
                raise
        finally:
            self._runtime.slots.release()

        result, metrics = outcome
        insight = AIInsight(
            kind=kind.value,
            scope=ctx.scope,
            asset_id=ctx.asset_pk,
            detection_id=ctx.detection_pk,
            risk_snapshot_id=ctx.risk_snapshot_pk,
            question=question[:500] if question else None,
            cache_key=cache_key,
            data_version=version,
            prompt_version=TEMPLATES[kind].name,
            provider=metrics["provider"],
            model=metrics["model"],
            result=result,
            input_refs=ctx.input_refs(),
            evidence_count=len(result["evidence_refs"]),
            dropped_refs=result["dropped_refs"],
            context_items=ctx.items,
            latency_ms=metrics.get("latency_ms"),
            input_chars=metrics.get("input_chars"),
            output_chars=metrics.get("output_chars"),
            usage_input=metrics.get("usage_input"),
            usage_output=metrics.get("usage_output"),
            requested_by=self._requester.actor.name[:64],
            requested_by_user_id=self._requester.user_id,
            generated_at=now,
            expires_at=now + timedelta(minutes=config.insight_ttl_minutes),
        )
        self._session.add(insight)
        self._session.flush()
        self._audit(
            "ai_analysis_completed",
            audit_service.SUCCESS,
            entity,
            {
                **base,
                "cached": False,
                "insight": str(insight.public_id),
                "latency_ms": metrics.get("latency_ms"),
                "evidence_count": insight.evidence_count,
                "dropped_refs": insight.dropped_refs,
            },
            commit=False,
        )
        self._session.commit()
        # Métricas técnicas al log, nunca contenido (ni contexto, ni pregunta, ni respuesta).
        logger.info(
            "ai analysis completed",
            extra={
                "kind": kind.value,
                "provider": metrics["provider"],
                "model": metrics["model"],
                "context_items": ctx.items,
                "latency_ms": metrics.get("latency_ms"),
                "input_chars": metrics.get("input_chars"),
                "output_chars": metrics.get("output_chars"),
                "evidence_count": insight.evidence_count,
                "dropped_refs": insight.dropped_refs,
            },
        )
        return self._read(insight, cached=False)

    def _check_rate_limit(self) -> None:
        user_key = f"user:{self._requester.user_id}"
        wait = max(
            self._runtime.per_user.blocked_for(user_key),
            self._runtime.global_.blocked_for("global"),
        )
        if wait > 0:
            raise RateLimitedError("Too many AI analyses; retry later", wait)
        self._runtime.per_user.hit(user_key)
        self._runtime.global_.hit("global")

    def _infer(
        self, kind: InsightKind, ctx: AIContext, question: str | None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        config = self._config
        if not ctx.has_data:
            # Sin datos no se llama al modelo: no hay nada que interpretar y no se inventa.
            return insufficient_result(
                "Sentra no tiene datos sobre los que basar este análisis."
            ), {"provider": "sentra", "model": "deterministic", "latency_ms": 0}
        try:
            provider = self._factory(config)
        except ValueError:
            raise AINotConfiguredError("AI provider configuration is invalid") from None
        template = TEMPLATES[kind]
        request = AIRequest(
            system=template.system(),
            # La pregunta también se seudonimiza (puede nombrar equipos o cuentas).
            user=template.user(ctx.data, ctx.redactor.text(question) if question else None),
            max_output_tokens=config.max_output_tokens,
        )
        input_chars = len(request.system) + len(request.user)
        output_chars = 0
        latency = 0
        attempts = config.max_retries + 1
        for attempt in range(attempts):
            response = provider.complete(request)
            latency += response.latency_ms
            output_chars += len(response.content)
            try:
                raw = parse_json(response.content)
            except AIInvalidResponseError:
                if attempt + 1 >= attempts:
                    raise
                continue
            result = ground(raw, ctx)
            return result, {
                "provider": provider.name,
                "model": response.model or provider.model,
                "latency_ms": latency,
                "input_chars": input_chars * (attempt + 1),
                "output_chars": output_chars,
                "usage_input": response.usage_input,
                "usage_output": response.usage_output,
            }
        raise AIInvalidResponseError("The AI response is not valid")  # pragma: no cover

    # --- Lectura de insights ----------------------------------------------------------------

    def _base(self) -> Select[AIInsight, Asset, UUID, UUID]:
        stmt = (
            select(AIInsight, Asset, Detection.public_id, RiskSnapshot.public_id)
            .outerjoin(Asset, Asset.id == AIInsight.asset_id)
            .outerjoin(Detection, Detection.id == AIInsight.detection_id)
            .outerjoin(RiskSnapshot, RiskSnapshot.id == AIInsight.risk_snapshot_id)
        )
        # Las preguntas de Ask son privadas de quien las hizo.
        return stmt.where(
            or_(AIInsight.kind != "ask", AIInsight.requested_by_user_id == self._requester.user_id)
        )

    def list(
        self,
        kind: str | None,
        asset_id: UUID | None,
        detection_id: UUID | None,
        limit: int,
        offset: int,
    ) -> InsightList:
        stmt = self._base()
        if kind:
            stmt = stmt.where(AIInsight.kind == kind)
        if asset_id is not None:
            stmt = stmt.where(Asset.public_id == asset_id)
        if detection_id is not None:
            stmt = stmt.where(Detection.public_id == detection_id)
        total = self._session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = self._session.execute(
            stmt.order_by(AIInsight.generated_at.desc(), AIInsight.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        versions: dict[tuple[int | None, int | None], str] = {}
        return InsightList(
            items=[self._to_read(r[0], r[1], r[2], r[3], False, versions) for r in rows],
            total=total,
        )

    def get(self, insight_id: UUID) -> InsightRead:
        row = self._session.execute(self._base().where(AIInsight.public_id == insight_id)).first()
        if row is None:
            raise NotFoundError("Insight not found")
        return self._to_read(row[0], row[1], row[2], row[3], False, {})

    def _read(self, insight: AIInsight, cached: bool) -> InsightRead:
        row = self._session.execute(self._base().where(AIInsight.id == insight.id)).one()
        return self._to_read(row[0], row[1], row[2], row[3], cached, {})

    def _to_read(
        self,
        insight: AIInsight,
        asset: Asset | None,
        detection_public: UUID | None,
        snapshot_public: UUID | None,
        cached: bool,
        versions: dict[tuple[int | None, int | None], str],
    ) -> InsightRead:
        stale_reason = self._stale_reason(insight, versions)
        return InsightRead(
            insight_id=insight.public_id,
            kind=insight.kind,
            scope=insight.scope,
            asset_id=asset.public_id if asset else None,
            asset_name=asset.display_name if asset else None,
            detection_id=detection_public,
            risk_snapshot_id=snapshot_public,
            question=insight.question,
            provider=insight.provider,
            model=insight.model,
            prompt_version=insight.prompt_version,
            generated_at=insight.generated_at,
            expires_at=insight.expires_at,
            stale=stale_reason is not None,
            stale_reason=stale_reason,
            cached=cached,
            evidence_count=insight.evidence_count,
            context_items=insight.context_items,
            latency_ms=insight.latency_ms,
            requested_by=insight.requested_by,
            result=InsightResult.model_validate(insight.result),
        )

    def _stale_reason(
        self, insight: AIInsight, versions: dict[tuple[int | None, int | None], str]
    ) -> str | None:
        if insight.scope == "asset" and insight.asset_id is None:
            return "entity_deleted"
        if insight.scope == "detection" and insight.detection_id is None:
            return "entity_deleted"
        if insight.expires_at <= datetime.now(UTC):
            return "expired"
        key = (insight.asset_id, insight.detection_id if insight.scope == "detection" else None)
        if key not in versions:
            versions[key] = data_version(self._session, key[0], key[1])
        return "data_changed" if versions[key] != insight.data_version else None
