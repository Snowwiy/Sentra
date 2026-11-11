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
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, Engine, Select, cast, func, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from app.ai.config import AIConfig
from app.ai.context import AIContext, ContextBuilder
from app.ai.freshness import data_version
from app.ai.intent import resolve_scope
from app.ai.openai_compat import OpenAICompatibleProvider, ProviderHealth
from app.ai.output import (
    answer_content,
    ground,
    ground_console,
    insufficient_result,
    parse_console_json,
    parse_json,
)
from app.ai.prompts import PRIVATE_KINDS, TEMPLATES, InsightKind
from app.ai.provider import (
    AIBusyError,
    AIError,
    AIInvalidResponseError,
    AINotConfiguredError,
    AIProvider,
    AIProviderUnavailableError,
    AIRequest,
    AITimeoutError,
)
from app.ai.redaction import Redactor
from app.core.config import Settings
from app.core.evidence_policy import (
    EvidenceAccess,
    missing_permissions,
    required_permissions,
)
from app.core.exceptions import (
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
    SentraError,
)
from app.core.permissions import Permission
from app.core.rate_limit import Limiter, RateLimiter, make_limiter
from app.models.ai import AIInsight
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.incident import Incident
from app.models.risk import RiskSnapshot
from app.models.tool import ToolExecution
from app.models.vulnerability import VulnerabilityFinding
from app.risk.config import RiskConfig
from app.schemas.ai import (
    AIProviderState,
    AIStatus,
    ConsoleContextItem,
    ConsoleContextPreview,
    InsightList,
    InsightRead,
    InsightResult,
)
from app.services import audit_service
from app.services.audit_service import Actor

logger = logging.getLogger("sentra.ai")

ProviderFactory = Callable[[AIConfig], AIProvider]

# Fase 7C.2: tareas del asistente de la consola -> tipo de insight.
_CONSOLE_TASKS = {
    "summary": InsightKind.CONSOLE_SUMMARY,
    "explain_risk": InsightKind.CONSOLE_RISK,
    "hypotheses": InsightKind.CONSOLE_HYPOTHESES,
    "draft_note": InsightKind.CONSOLE_DRAFT,
}
CONSOLE_KINDS = frozenset(_CONSOLE_TASKS.values())
# Margen para la plantilla del usuario (task, pregunta, claves JSON) sobre el presupuesto.
_PROMPT_OVERHEAD = 800
# 7C-Fix2: motivos de ai_invalid_response que no se reintentan (ver _infer).
_NO_RETRY = frozenset({"truncated", "truncated_reasoning"})


class ConsoleAssistDisabledError(SentraError):
    # AI_CONSOLE_ASSIST_ENABLED=false: la IA puede estar activa para AI Insights.
    status_code = 409
    code = "ai_console_disabled"


class ConsoleExecutionNotUsableError(SentraError):
    # La ejecución no terminó bien (sin salida) o no es una lectura/investigación.
    status_code = 422
    code = "console_execution_not_usable"


class ConsoleAssistRequestError(SentraError):
    status_code = 422
    code = "console_assist_invalid"


class ConsoleLoopbackRequiredError(SentraError):
    # 7C-Security-Fix1: AI_BASE_URL no es loopback; la consola no envía nada fuera del servidor.
    status_code = 409
    code = "ai_console_loopback_required"


class ConsoleContextReviewRequiredError(SentraError):
    # 7C-Security-Fix1: falta la revisión previa (context_sha256) o la confirmación explícita.
    status_code = 422
    code = "console_context_review_required"


class ConsoleContextChangedError(SentraError):
    # Los datos cambiaron desde la revisión: no se envía algo distinto de lo revisado.
    status_code = 409
    code = "console_context_changed"


def console_digest(kind: InsightKind, data: dict[str, Any], question: str | None) -> str:
    """Huella de lo que recibe el modelo en la consola (7C-Security-Fix1).

    Cubre la tarea, la versión del prompt, la pregunta (tal como se envía) y el documento de
    datos completo salvo la hora de la petición ("now"), que cambia en cada llamada. Cualquier
    otro cambio (un resultado, el estado del activo, una contribución de riesgo) cambia la
    huella y obliga a revisar de nuevo.
    """
    document = {k: v for k, v in data.items() if k != "now"}
    payload = {
        "task": kind.value,
        "prompt": TEMPLATES[kind].name,
        "question": question,
        "data": document,
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


_INCIDENT_TASKS = {
    "summary": InsightKind.INCIDENT_SUMMARY,
    "timeline": InsightKind.INCIDENT_TIMELINE,
    "evidence": InsightKind.INCIDENT_EVIDENCE,
    "next_steps": InsightKind.INCIDENT_NEXT_STEPS,
}


def default_provider_factory(config: AIConfig) -> AIProvider:
    return OpenAICompatibleProvider(config)


# El estado del proveedor se cachea: la UI consulta /ai/status en cada página con IA y no
# queremos una conexión al modelo por cada visita.
HEALTH_TTL_SECONDS = 15.0


@dataclass(frozen=True)
class HealthResult:
    health: ProviderHealth
    checked_at: datetime


class AIRuntime:
    """Estado por proceso: límites de frecuencia y de concurrencia (como el login)."""

    def __init__(
        self,
        config: AIConfig,
        backend: str = "memory",
        engine: Callable[[], Engine] | None = None,
    ) -> None:
        # Fase 4M: con backend database los límites por minuto se comparten entre workers.
        self.per_user: Limiter = (
            make_limiter(backend, "ai_user", config.rate_per_user, 60, engine)
            if engine is not None
            else RateLimiter(config.rate_per_user, 60)
        )
        self.global_: Limiter = (
            make_limiter(backend, "ai_global", config.rate_global, 60, engine)
            if engine is not None
            else RateLimiter(config.rate_global, 60)
        )
        # Acotar llamadas simultáneas: cada una ocupa un hilo del threadpool de la API
        # hasta AI_TIMEOUT_SECONDS; sin tope, un bucle de peticiones lo agotaría. Es por
        # proceso: con N workers el máximo real es N x AI_MAX_CONCURRENT (ver
        # docs/production-deployment.md; el runtime local sigue siendo un servicio aparte).
        self.slots = threading.BoundedSemaphore(config.max_concurrent)
        self._health_lock = threading.Lock()
        self._health: tuple[float, str, HealthResult | None] | None = None

    def health(self, config: AIConfig, factory: ProviderFactory) -> HealthResult | None:
        """Health check del proveedor configurado, cacheado HEALTH_TTL_SECONDS.

        Solo se llama con la IA activada y el destino permitido (ver AIInsightService.status):
        con AI_ENABLED=false o un externo bloqueado no se abre ninguna conexión. El lock evita
        que varias pestañas disparen sondeos simultáneos; cada sondeo dura como mucho ~5 s.
        """
        key = f"{config.base_url}|{config.model}"
        with self._health_lock:
            cached = self._health
            if cached and cached[1] == key and time.monotonic() - cached[0] < HEALTH_TTL_SECONDS:
                return cached[2]
            result: HealthResult | None
            try:
                provider = factory(config)
            except (ValueError, AIError) as exc:
                detail = exc.message if isinstance(exc, AIError) else "Invalid AI configuration"
                result = HealthResult(ProviderHealth(False, 0, detail), datetime.now(UTC))
            else:
                check = getattr(provider, "check", None)
                result = HealthResult(check(), datetime.now(UTC)) if callable(check) else None
            self._health = (time.monotonic(), key, result)
            return result

    def forget_health(self) -> None:
        # Tras un fallo real del modelo, el próximo /ai/status vuelve a comprobarlo.
        with self._health_lock:
            self._health = None


@dataclass(frozen=True)
class Requester:
    actor: Actor
    user_id: int
    # Fase 7D.1 (H02/H03): permisos ACTUALES de quien pide. Deciden qué evidencia entra en el
    # contexto del modelo y qué insights guardados (caché compartida) puede leer. Vacío por
    # defecto: un llamador que no los pase obtiene la vista más restringida.
    permissions: frozenset[Permission] = frozenset()


def _provider_state(
    config: AIConfig, reason: str | None, health: HealthResult | None
) -> AIProviderState:
    """Estado legible del proveedor: Disabled, Local/External y Available/Unavailable/Blocked."""
    if not config.enabled:
        return "disabled"
    if not config.base_url or not config.model:
        return "not_configured"
    if reason is not None:
        # Destino no permitido (externo sin AI_ALLOW_EXTERNAL, IP privada no autorizada...).
        return "external_blocked"
    location = config.location or "external"
    # Sin health check (proveedor sin `check`) no afirmamos que esté caído.
    if health is None or health.health.reachable:
        return "local_available" if location == "local" else "external_available"
    return "local_unavailable" if location == "local" else "external_unavailable"


class AIInsightService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        runtime: AIRuntime,
        provider_factory: ProviderFactory,
        requester: Requester,
        config: AIConfig | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._config = config or AIConfig.from_settings(settings)
        self._runtime = runtime
        self._factory = provider_factory
        self._requester = requester
        # 7C-Fix2: diagnóstico (sin contenido) de la última respuesta inutilizable.
        self._invalid: dict[str, Any] = {}

    # --- Estado -----------------------------------------------------------------------------

    def status(self) -> AIStatus:
        c = self._config
        reason = c.unavailable_reason()
        # Sin IA activada o con el destino bloqueado no se sondea nada (cero conexiones).
        health = self._runtime.health(c, self._factory) if reason is None else None
        state = _provider_state(c, reason, health)
        return AIStatus(
            enabled=c.enabled,
            available=reason is None,
            reason=reason,
            state=state,
            mode_label=(
                ("Local AI" if c.location == "local" else "External AI")
                if c.enabled and c.location
                else None
            ),
            reachable=health.health.reachable if health else None,
            health_detail=health.health.detail if health else None,
            health_latency_ms=health.health.latency_ms if health else None,
            checked_at=health.checked_at if health else None,
            provider=c.provider if c.enabled else None,
            model=c.model if c.enabled else None,
            location=c.location,
            external_allowed=c.allow_external,
            redaction=sorted(c.effective_redact),
            max_context_items=c.max_context_items,
            rate_limit_per_user_per_minute=c.rate_per_user,
            prompt_versions={k.value: t.name for k, t in TEMPLATES.items()},
            model_source="local_manager" if c.model_source == "local_manager" else "settings",
            system_prompt_mode=(
                "user_prefix" if c.system_prompt_mode == "user_prefix" else "system"
            ),
            console_assist_available=reason is None and self._console_reason() is None,
            console_max_executions=c.console_max_executions,
            console_assist_reason=reason or self._console_reason(),
        )

    def _console_reason(self) -> str | None:
        """Por qué el asistente de la consola no se puede usar (None = utilizable)."""
        if not self._config.console_assist_enabled:
            return "El asistente de la consola está desactivado (AI_CONSOLE_ASSIST_ENABLED=false)."
        return self._config.console_destination_blocked_reason()

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

    def analyze_incident(self, incident_id: UUID, task: str, refresh: bool) -> InsightRead:
        """Fase 4K: análisis de solo lectura de un incidente.

        Solo produce un insight (tabla ai_insights) y su auditoría ai_analysis_*: nunca
        modifica el incidente (estado, owner, severidad, prioridad, resolución, merge).
        """
        kind = _INCIDENT_TASKS[task]
        return self._run(
            kind,
            lambda b: b.incident(incident_id),
            entity=f"incident:{incident_id}",
            refresh=refresh,
        )

    def analyze_vulnerability(self, finding_id: UUID, refresh: bool) -> InsightRead:
        """Fase 5B: explicación de solo lectura de un finding de vulnerabilidad.

        Nunca cambia el finding (estado, match, prioridad) ni consulta fuentes externas: solo
        interpreta lo que Sentra ya guardó.
        """
        return self._run(
            InsightKind.VULNERABILITY_ANALYSIS,
            lambda b: b.vulnerability(finding_id),
            entity=f"vulnerability:{finding_id}",
            refresh=refresh,
        )

    def _console_request(
        self,
        task: str,
        execution_ids: list[UUID],
        asset_id: UUID | None,
        detection_id: UUID | None,
        can_read_all_executions: bool,
    ) -> tuple[InsightKind, list[ToolExecution], int, str, str]:
        """Validaciones comunes de revisión y envío: (tipo, ejecuciones, presupuesto, entidad,
        huella de versión)."""
        self._require_available()
        config = self._config
        if not config.console_assist_enabled:
            raise ConsoleAssistDisabledError(
                "El asistente de la consola está desactivado (AI_CONSOLE_ASSIST_ENABLED=false)."
            )
        blocked = config.console_destination_blocked_reason()
        if blocked is not None:
            self._audit(
                "ai_console_blocked",
                audit_service.FAILURE,
                "console",
                {"reason": ConsoleLoopbackRequiredError.code, "location": config.location},
            )
            raise ConsoleLoopbackRequiredError(blocked)
        unique = list(dict.fromkeys(execution_ids))
        if len(unique) > config.console_max_executions:
            raise ConsoleAssistRequestError(
                f"Como máximo {config.console_max_executions} resultados por análisis."
            )
        if not unique and asset_id is None and detection_id is None:
            raise ConsoleAssistRequestError(
                "Elige al menos un resultado de herramienta, un activo o una detección."
            )
        if asset_id is not None and detection_id is not None:
            raise ConsoleAssistRequestError("Indica un activo o una detección, no ambos.")
        rows = self._console_executions(unique, can_read_all_executions)
        kind = _CONSOLE_TASKS[task]
        template = TEMPLATES[kind]
        # Presupuesto del documento de datos: AI_MAX_PROMPT_CHARS menos las instrucciones.
        budget = max(2_000, config.max_prompt_chars - len(template.system()) - _PROMPT_OVERHEAD)
        hashes = "|".join(f"{r.public_id}:{r.output_sha256}" for r in rows)
        entity = (
            f"console:{asset_id or ''}:{detection_id or ''}:"
            + hashlib.sha256(hashes.encode()).hexdigest()[:16]
        )
        return kind, rows, budget, entity, hashes

    def console_context(
        self,
        task: str,
        execution_ids: list[UUID],
        asset_id: UUID | None,
        detection_id: UUID | None,
        question: str | None,
        *,
        can_read_all_executions: bool,
    ) -> ConsoleContextPreview:
        """7C-Security-Fix1: lo que recibiría el modelo, para revisarlo ANTES de enviarlo.

        No llama al modelo ni guarda nada salvo la auditoría. El documento se construye igual
        que en el envío (mismas lecturas, minimización y seudonimización), así que su huella
        coincide con la del envío mientras los datos no cambien.
        """
        kind, rows, budget, entity, _ = self._console_request(
            task, execution_ids, asset_id, detection_id, can_read_all_executions
        )
        normalized = " ".join(question.split()) if question else None
        ctx = self._builder(datetime.now(UTC)).console(
            rows, asset_id=asset_id, detection_id=detection_id, max_chars=budget
        )
        sent_question = ctx.redactor.text(normalized) if normalized else None
        digest = console_digest(kind, ctx.data, sent_question)
        document = json.loads(
            json.dumps(
                {k: v for k, v in ctx.data.items() if k != "now"},
                ensure_ascii=False,
                default=str,
            )
        )
        chars = len(json.dumps(ctx.data, ensure_ascii=False, default=str))
        self._audit(
            "ai_console_context_reviewed",
            audit_service.SUCCESS,
            entity,
            {
                "kind": kind.value,
                "context_sha256": digest,
                "execution_ids": [str(r.public_id) for r in rows],
                "asset_id": str(asset_id) if asset_id else None,
                "detection_id": str(detection_id) if detection_id else None,
                "context_items": ctx.items,
                "chars": chars,
                "redacted_values": ctx.redacted_values,
                "destination": "loopback",
            },
        )
        return ConsoleContextPreview(
            task=task,
            context_sha256=digest,
            model=self._config.model,
            items=[
                ConsoleContextItem(ref=key, type=ref.type, label=ref.label)
                for key, ref in ctx.refs.items()
            ],
            redacted_values=ctx.redacted_values,
            pseudonymized=sorted(self._config.effective_redact),
            chars=chars,
            question=sent_question,
            document=document,
        )

    def console_assist(
        self,
        task: str,
        execution_ids: list[UUID],
        asset_id: UUID | None,
        detection_id: UUID | None,
        question: str | None,
        refresh: bool,
        *,
        can_read_all_executions: bool,
        context_sha256: str | None = None,
        confirm_send: bool = False,
    ) -> InsightRead:
        """Fase 7C.2: asistencia contextual de la Analyst Console. Solo lectura.

        El modelo recibe resultados de herramientas que el analista YA puede ver (propios, o de
        otros solo con tools:manage, el mismo criterio que GET /tools/executions) y el activo o
        la detección del workspace. Nunca ejecuta herramientas ni acciones: el resultado es un
        insight validado (grounding) con hipótesis y borrador etiquetados como del modelo.

        7C-Security-Fix1: solo con un modelo en loopback, solo tras revisar el documento
        (`context_sha256` de POST /ai/console/context) y con `confirm_send`. Si lo que se
        enviaría ya no coincide con lo revisado, no se envía nada (409).
        """
        kind, rows, budget, entity, hashes = self._console_request(
            task, execution_ids, asset_id, detection_id, can_read_all_executions
        )
        if not confirm_send or context_sha256 is None:
            raise ConsoleContextReviewRequiredError(
                "Revisa los datos que se enviarán al modelo (POST /ai/console/context) y "
                "confirma el envío."
            )
        normalized = " ".join(question.split()) if question else None
        reviewed = context_sha256

        def verify(ctx: AIContext) -> dict[str, Any]:
            sent_question = ctx.redactor.text(normalized) if normalized else None
            digest = console_digest(kind, ctx.data, sent_question)
            details = {
                "context_sha256": digest,
                "execution_ids": [str(r.public_id) for r in rows],
                "redacted_values": ctx.redacted_values,
                "destination": "loopback",
                "reviewed": True,
            }
            if digest != reviewed:
                self._audit(
                    "ai_console_context_mismatch",
                    audit_service.FAILURE,
                    entity,
                    {**details, "reviewed": False, "reviewed_sha256": reviewed},
                )
                raise ConsoleContextChangedError(
                    "Los datos cambiaron desde la revisión: revísalos de nuevo antes de enviar."
                )
            return details

        return self._run(
            kind,
            lambda b: b.console(
                rows, asset_id=asset_id, detection_id=detection_id, max_chars=budget
            ),
            entity=entity,
            refresh=refresh,
            question=normalized,
            extra_version=hashes,
            verify=verify,
            provider_config=self._config.console_provider_config(),
            content_permissions={p for r in rows for p in (r.read_permissions or [])},
        )

    def _console_executions(self, ids: list[UUID], read_all: bool) -> list[ToolExecution]:
        if not ids:
            return []
        rows = {
            r.public_id: r
            for r in self._session.scalars(
                select(ToolExecution).where(ToolExecution.public_id.in_(ids))
            )
        }
        ordered: list[ToolExecution] = []
        for public_id in ids:
            row = rows.get(public_id)
            # Ajena sin tools:manage = 404, igual que GET /tools/executions/{id}: no se revela
            # que existe.
            if row is None or (not read_all and row.actor_user_id != self._requester.user_id):
                raise NotFoundError("Tool execution not found")
            # Fase 7D.1 (H03): los permisos de lectura guardados con la ejecución se revalidan
            # con los ACTUALES; un usuario degradado no puede enviar al modelo (ni ver en la
            # revisión previa) un resultado que ya no puede leer.
            missing = missing_permissions(row.read_permissions, self._requester.permissions)
            if missing:
                raise PermissionDeniedError(
                    "Your current role cannot read this tool result (" + ", ".join(missing) + ")"
                )
            if row.status != "succeeded" or row.output is None:
                raise ConsoleExecutionNotUsableError(
                    "Solo se pueden analizar ejecuciones terminadas con salida."
                )
            if row.category == "action":
                # Una acción confirmada tiene salida, pero describe lo que se hizo, no
                # evidencia observada; se analiza su efecto con una lectura posterior.
                raise ConsoleExecutionNotUsableError(
                    "Las acciones no se analizan con la IA; usa una herramienta de lectura."
                )
            ordered.append(row)
        return ordered

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
            sorted(c.effective_redact),
            question.lower() if question else None,
            # Las preguntas (y la consola, Fase 7C) son privadas: su caché no se comparte.
            self._requester.user_id if kind in PRIVATE_KINDS else None,
            # Fase 7D.1: el contexto cambia con el acceso a evidencia de endpoint; un viewer y
            # un analista nunca comparten la misma entrada de caché.
            "endpoint" if self._access().endpoint else "restricted",
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
        extra_version: str | None = None,
        verify: Callable[[AIContext], dict[str, Any]] | None = None,
        provider_config: AIConfig | None = None,
        content_permissions: Iterable[str] = (),
    ) -> InsightRead:
        self._require_available()
        config = self._config
        now = datetime.now(UTC)
        builder = self._builder(now)
        ctx = build(builder)  # 404 si la entidad no existe (antes de auditar nada).
        # Fase 7D.1: permisos que exigirá leer este insight (y su caché) en el futuro.
        content = sorted(
            set(content_permissions) | set(required_permissions(builder.endpoint_content))
        )
        # 7C-Security-Fix1: la consola comprueba que lo construido es lo que se revisó.
        reviewed = verify(ctx) if verify is not None else {}
        version = data_version(
            self._session, ctx.asset_pk, ctx.detection_pk, ctx.incident_pk, ctx.vulnerability_pk
        )
        if extra_version is not None:
            # Fase 7C.2: la consola depende también de las salidas de herramientas (inmutables
            # una vez terminadas): sus hashes entran en la huella.
            version = _console_version(version, extra_version)
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
        base.update(reviewed)

        if not refresh:
            cached = self._session.scalar(
                select(AIInsight)
                .where(
                    AIInsight.cache_key == cache_key,
                    AIInsight.expires_at > now,
                    self._readable(),
                )
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
                outcome = self._infer(kind, ctx, question, provider_config)
            except AIError as exc:
                self._session.rollback()
                # 7C-Fix2: con ai_invalid_response, el motivo y los tamaños (sin contenido).
                diagnosis: dict[str, Any] = {}
                if isinstance(exc, AIInvalidResponseError):
                    # Un cuerpo HTTP inválido falla en el proveedor, antes de _infer: solo motivo.
                    diagnosis = self._invalid or {"reason": exc.reason}
                self._audit(
                    "ai_analysis_failed",
                    audit_service.FAILURE,
                    entity,
                    {**base, "error": exc.code, **diagnosis},
                )
                logger.warning(
                    "ai analysis failed",
                    extra={
                        "kind": kind.value,
                        "error": exc.code,
                        "model": config.model,
                        **{f"ai_{k}": v for k, v in diagnosis.items()},
                    },
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
            incident_id=ctx.incident_pk,
            vulnerability_finding_id=ctx.vulnerability_pk,
            risk_snapshot_id=ctx.risk_snapshot_pk,
            question=question[:500] if question else None,
            cache_key=cache_key,
            data_version=version,
            prompt_version=TEMPLATES[kind].name,
            provider=metrics["provider"],
            model=metrics["model"],
            result=result,
            input_refs=_input_refs(ctx),
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
            content_permissions=content,
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

    def _access(self) -> EvidenceAccess:
        return EvidenceAccess.of(self._requester.permissions)

    def _builder(self, now: datetime) -> ContextBuilder:
        return ContextBuilder(
            self._session,
            RiskConfig.from_settings(self._settings),
            timedelta(seconds=self._settings.heartbeat_timeout_seconds),
            self._config.max_context_items,
            Redactor(self._config.effective_redact),
            now,
            access=self._access(),
        )

    def _readable(self) -> ColumnElement[bool]:
        """Insights cuyo contenido el solicitante puede leer con sus permisos ACTUALES.

        Un insight generado con evidencia de endpoint (o con salidas de herramientas que
        exigen permisos de dominio) guarda esos permisos; quien no los tenga hoy no lo ve,
        ni en el listado ni como resultado de caché.
        """
        granted = sorted(p.value for p in self._requester.permissions)
        clause: ColumnElement[bool] = AIInsight.content_permissions.contained_by(
            cast(granted, JSONB)
        )
        return clause

    def _check_rate_limit(self) -> None:
        user_key = f"user:{self._requester.user_id}"
        wait = self._runtime.global_.blocked_for("global")
        if wait <= 0:
            wait = self._runtime.per_user.acquire(user_key)
            if wait <= 0:
                wait = self._runtime.global_.acquire("global")
        if wait > 0:
            raise RateLimitedError("Too many AI analyses; retry later", wait, "ai")

    def _infer(
        self,
        kind: InsightKind,
        ctx: AIContext,
        question: str | None,
        provider_config: AIConfig | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        config = self._config
        if not ctx.has_data:
            # Sin datos no se llama al modelo: no hay nada que interpretar y no se inventa.
            return {
                **insufficient_result("Sentra no tiene datos sobre los que basar este análisis."),
                "origin": "sentra",
            }, {"provider": "sentra", "model": "deterministic", "latency_ms": 0}
        try:
            # La consola usa su propia configuración (solo loopback); el resto, la general.
            provider = self._factory(provider_config or config)
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
            # Solo se reintenta ante JSON inválido y contra el MISMO proveedor. Un fallo de
            # conexión, timeout o error HTTP se propaga tal cual: no hay fallback a otro
            # proveedor (ni cloud) y el resto de Sentra no se ve afectado (4J.1).
            try:
                response = provider.complete(request)
            except (AIProviderUnavailableError, AITimeoutError):
                self._runtime.forget_health()
                raise
            latency += response.latency_ms
            output_chars += len(response.content)
            truncated = response.finish_reason == "length"
            try:
                content = answer_content(response)
                if kind in CONSOLE_KINDS:
                    result = ground_console(parse_console_json(content, truncated), ctx)
                else:
                    result = {**ground(parse_json(content, truncated), ctx), "origin": "model"}
            except AIInvalidResponseError as exc:
                # 7C-Fix2: métricas del fallo, nunca el texto. Una respuesta cortada por
                # max_tokens no se reintenta: con temperatura 0 y el mismo presupuesto el
                # resultado sería el mismo y solo duplicaría la espera.
                self._invalid = {
                    "reason": exc.reason,
                    "finish_reason": response.finish_reason,
                    "output_chars": len(response.content),
                    "reasoning_chars": response.reasoning_chars,
                    "usage_output": response.usage_output,
                    "attempts": attempt + 1,
                }
                if attempt + 1 >= attempts or exc.reason in _NO_RETRY:
                    raise
                continue
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

    def _base(self) -> Select[AIInsight, Asset, UUID, UUID, UUID, UUID]:
        stmt = (
            select(
                AIInsight,
                Asset,
                Detection.public_id,
                RiskSnapshot.public_id,
                Incident.public_id,
                VulnerabilityFinding.public_id,
            )
            .outerjoin(Asset, Asset.id == AIInsight.asset_id)
            .outerjoin(Detection, Detection.id == AIInsight.detection_id)
            .outerjoin(RiskSnapshot, RiskSnapshot.id == AIInsight.risk_snapshot_id)
            .outerjoin(Incident, Incident.id == AIInsight.incident_id)
            .outerjoin(
                VulnerabilityFinding,
                VulnerabilityFinding.id == AIInsight.vulnerability_finding_id,
            )
        )
        # Las preguntas de Ask son privadas de quien las hizo.
        return stmt.where(
            or_(
                AIInsight.kind.notin_([k.value for k in PRIVATE_KINDS]),
                AIInsight.requested_by_user_id == self._requester.user_id,
            ),
            self._readable(),
        )

    def list(
        self,
        kind: str | None,
        asset_id: UUID | None,
        detection_id: UUID | None,
        limit: int,
        offset: int,
        incident_id: UUID | None = None,
        vulnerability_finding_id: UUID | None = None,
    ) -> InsightList:
        stmt = self._base()
        if incident_id is not None:
            stmt = stmt.where(Incident.public_id == incident_id)
        if vulnerability_finding_id is not None:
            stmt = stmt.where(VulnerabilityFinding.public_id == vulnerability_finding_id)
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
        versions: dict[tuple[str, int | None, int | None, int | None], str] = {}
        return InsightList(
            items=[self._to_read(*r, False, versions) for r in rows],
            total=total,
        )

    def get(self, insight_id: UUID) -> InsightRead:
        row = self._session.execute(self._base().where(AIInsight.public_id == insight_id)).first()
        if row is None:
            raise NotFoundError("Insight not found")
        return self._to_read(*row, False, {})

    def _read(self, insight: AIInsight, cached: bool) -> InsightRead:
        row = self._session.execute(self._base().where(AIInsight.id == insight.id)).one()
        return self._to_read(*row, cached, {})

    def _to_read(
        self,
        insight: AIInsight,
        asset: Asset | None,
        detection_public: UUID | None,
        snapshot_public: UUID | None,
        incident_public: UUID | None,
        vulnerability_public: UUID | None,
        cached: bool,
        versions: dict[tuple[str, int | None, int | None, int | None], str],
    ) -> InsightRead:
        stale_reason = self._stale_reason(insight, versions)
        return InsightRead(
            insight_id=insight.public_id,
            kind=insight.kind,
            scope=insight.scope,
            asset_id=asset.public_id if asset else None,
            asset_name=asset.display_name if asset else None,
            detection_id=detection_public,
            incident_id=incident_public,
            vulnerability_finding_id=vulnerability_public,
            risk_snapshot_id=snapshot_public,
            question=insight.question,
            tool_execution_ids=[
                UUID(r["id"])
                for r in insight.input_refs or []
                if isinstance(r, dict) and r.get("type") == "tool_execution"
            ],
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
        self,
        insight: AIInsight,
        versions: dict[tuple[str, int | None, int | None, int | None], str],
    ) -> str | None:
        if insight.scope == "asset" and insight.asset_id is None:
            return "entity_deleted"
        if insight.scope == "incident" and insight.incident_id is None:
            return "entity_deleted"
        if insight.scope == "detection" and insight.detection_id is None:
            return "entity_deleted"
        if insight.scope == "vulnerability" and insight.vulnerability_finding_id is None:
            return "entity_deleted"
        if insight.expires_at <= datetime.now(UTC):
            return "expired"
        if insight.scope == "console":
            return self._console_stale(insight)
        # Clave de la huella: (alcance, activo, detección o incidente o finding).
        key: tuple[str, int | None, int | None, int | None]
        if insight.scope == "incident":
            key = ("incident", None, None, insight.incident_id)
        elif insight.scope == "vulnerability":
            key = ("vulnerability", None, None, insight.vulnerability_finding_id)
        else:
            key = (
                "entity",
                insight.asset_id,
                insight.detection_id if insight.scope == "detection" else None,
                None,
            )
        if key not in versions:
            if key[0] == "vulnerability":
                versions[key] = data_version(self._session, None, None, None, key[3])
            else:
                versions[key] = data_version(self._session, key[1], key[2], key[3])
        return "data_changed" if versions[key] != insight.data_version else None

    def _console_stale(self, insight: AIInsight) -> str | None:
        """Stale de la consola: activo/detección cambiados o ejecución ya no disponible.

        Las salidas de herramientas no cambian una vez terminadas, así que basta con
        comprobar que siguen existiendo (retención opt-in) con el mismo hash.
        """
        refs = [r for r in insight.input_refs or [] if isinstance(r, dict)]
        hashes = [f"{r['id']}:{r.get('sha256')}" for r in refs if r.get("type") == "tool_execution"]
        current = {
            str(public_id): digest
            for public_id, digest in self._session.execute(
                select(ToolExecution.public_id, ToolExecution.output_sha256).where(
                    ToolExecution.public_id.in_(
                        [UUID(r["id"]) for r in refs if r.get("type") == "tool_execution"]
                    )
                )
            )
        }
        for r in refs:
            if r.get("type") == "tool_execution" and current.get(r["id"]) != r.get("sha256"):
                return "entity_deleted"
        version = data_version(self._session, insight.asset_id, insight.detection_id, None)
        version = _console_version(version, "|".join(hashes))
        return "data_changed" if version != insight.data_version else None


def _console_version(base: str, extra: str) -> str:
    return hashlib.sha256(f"{base}|{extra}".encode()).hexdigest()


def _input_refs(ctx: AIContext) -> list[dict[str, Any]]:
    """Referencias de entrada; las de la consola llevan además el hash de la salida."""
    refs: list[dict[str, Any]] = list(ctx.input_refs())
    if ctx.scope == "console":
        hashes = ctx.data.get("tool_results") or []
        by_ref = {item.get("ref"): item.get("output_sha256") for item in hashes}
        for item in refs:
            if item["type"] == "tool_execution":
                item["sha256"] = by_ref.get(item["ref"])
    return refs
