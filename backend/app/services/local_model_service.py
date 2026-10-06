"""LocalModelService (Fase 4J.2): hardware, runtime, modelos, recomendaciones y benchmarks.

Principios:
- reutiliza 4J/4J.1: el destino es SIEMPRE AI_BASE_URL validado por AIConfig y todas las
  llamadas salen por OpenAICompatibleProvider (IP real verificada, sin redirecciones, sin
  proxy). El gestor solo opera runtimes LOCALES: con un proveedor externo o la IA
  desactivada no abre ninguna conexión;
- sin red no se rompe nada: hardware, registro de GGUF y recomendaciones funcionan offline;
  si el runtime está caído, la página muestra el estado y AI Insights responde su error
  controlado de 4J.1 (nunca fallback cloud);
- seleccionar un modelo solo lo marca activo cuando el runtime lo tiene y responde. Si algo
  falla, el modelo activo anterior se mantiene;
- solo ai:manage modifica; las rutas completas de ficheros solo las ve ai:manage;
- auditoría de cada cambio, sin secretos (ni URL ni clave del proveedor).
"""

import contextlib
import hashlib
import logging
import os
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ai.config import AIConfig
from app.ai.local.benchmark import (
    AIBenchmarkBusyError,
    BenchmarkCancelledError,
    BenchmarkManager,
    run_benchmark,
)
from app.ai.local.catalog import load_catalog
from app.ai.local.engine import (
    Evaluation,
    ModelSpec,
    Observed,
    Profile,
    evaluate,
    performance_class,
    rank,
)
from app.ai.local.gguf import InvalidGGUFError, read_gguf, split_parts
from app.ai.local.hardware import (
    HardwareProfile,
    SystemSource,
    profile_hardware,
    sample_memory_usage,
)
from app.ai.local.paths import ModelPathError, discover_model_files, resolve_model_path
from app.ai.local.runtimes import (
    CAPABILITIES,
    AIRuntimeUnsupportedError,
    LocalAIRuntime,
    RuntimeHealth,
    RuntimeKind,
    RuntimeModel,
    as_runtime_kind,
    default_runtime_factory,
    detect_runtime,
    file_basename,
)
from app.ai.openai_compat import OpenAICompatibleProvider
from app.ai.provider import AIError, AINotConfiguredError, AIRequest
from app.core.config import Settings, parse_model_directories, parse_performance_thresholds
from app.core.exceptions import ConflictError, NotFoundError, SentraError
from app.db.session import get_sessionmaker
from app.models.ai_local import AILocalModel, AILocalSettings, AIModelBenchmark
from app.schemas.ai_local import (
    ActiveModelRead,
    BenchmarkRead,
    CPURead,
    DiscoveredModelRead,
    EstimateRead,
    GPURead,
    HardwareRead,
    LocalModelDetail,
    LocalModelList,
    LocalModelRead,
    RecommendationList,
    RecommendationRead,
    RegisterModelRequest,
    RuntimeCapabilitiesRead,
    RuntimeStatusRead,
)
from app.services import audit_service
from app.services.audit_service import Actor

logger = logging.getLogger("sentra.ai")

RUNTIME_CACHE_SECONDS = 15.0
CHECKSUM_CHUNK = 8 * 1024 * 1024
# Comprobación de que el modelo responde antes de marcarlo activo (sin datos de Sentra).
SELECT_CHECK = AIRequest(system="Responde únicamente: OK", user="ping", max_output_tokens=16)
# Un benchmark "running" sin hilo vivo tras este margen murió con el proceso.
STALE_BENCHMARK_GRACE = timedelta(seconds=60)


class AIModelNotLoadedError(ConflictError):
    # llama-server/vLLM tienen cargado otro modelo (o ninguno): Sentra no arranca procesos.
    code = "local_model_not_loaded"


class AIModelUnavailableError(ConflictError):
    # El fichero ya no existe o el runtime ya no lista el modelo.
    code = "local_model_unavailable"


class AIModelRuntimeMismatchError(ConflictError):
    code = "local_model_runtime_mismatch"


class AIModelInvalidFileError(SentraError):
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "local_model_invalid_file"


@dataclass(frozen=True)
class RuntimeSnapshot:
    health: RuntimeHealth | None
    models: tuple[RuntimeModel, ...]
    detected: RuntimeKind | None


class LocalAIState:
    """Estado por proceso del gestor: cachés, benchmark en curso y dependencias inyectables."""

    def __init__(self) -> None:
        self.source = SystemSource()
        self.runtime_factory: Callable[[RuntimeKind, AIConfig], LocalAIRuntime] = (
            default_runtime_factory
        )
        self.detect: Callable[[AIConfig], RuntimeKind | None] = detect_runtime
        self.benchmarks = BenchmarkManager()
        # Los hilos de fondo abren su propia sesión (los tests la apuntan a su base).
        self.session_factory: Callable[[], Session] = lambda: get_sessionmaker()()
        self._executor: ThreadPoolExecutor | None = None
        self._lock = threading.Lock()
        self._hardware: HardwareProfile | None = None
        self._runtime: tuple[float, str, RuntimeSnapshot] | None = None

    def run_background(self, job: Callable[[], None]) -> None:
        """Trabajo lento (SHA-256 de GB) en un único hilo: nunca en la petición."""
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ai-checksum")
            self._executor.submit(job)

    def shutdown(self) -> None:
        with self._lock:
            if self._executor is not None:
                self._executor.shutdown(wait=False, cancel_futures=True)
                self._executor = None

    def hardware(self, disk_paths: tuple[str, ...], refresh: bool = False) -> HardwareProfile:
        # Se detecta una vez y se reutiliza: el hardware no cambia entre peticiones y una
        # detección (nvidia-smi incluido) cuesta hasta unos segundos. Refresco manual.
        with self._lock:
            if self._hardware is None or refresh:
                self._hardware = profile_hardware(self.source, disk_paths)
            return self._hardware

    def runtime_snapshot(
        self, kind: RuntimeKind, config: AIConfig, refresh: bool = False
    ) -> RuntimeSnapshot:
        key = f"{kind}|{config.base_url}"
        with self._lock:
            cached = self._runtime
            if (
                not refresh
                and cached
                and cached[1] == key
                and time.monotonic() - cached[0] < RUNTIME_CACHE_SECONDS
            ):
                return cached[2]
        snapshot = self._probe(kind, config)
        with self._lock:
            self._runtime = (time.monotonic(), key, snapshot)
        return snapshot

    def _probe(self, kind: RuntimeKind, config: AIConfig) -> RuntimeSnapshot:
        try:
            runtime = self.runtime_factory(kind, config)
        except (ValueError, AIError) as exc:
            detail = exc.message if isinstance(exc, AIError) else "Invalid AI configuration"
            return RuntimeSnapshot(RuntimeHealth(False, 0, detail), (), None)
        health = runtime.health()
        models: tuple[RuntimeModel, ...] = ()
        detected: RuntimeKind | None = None
        if health.reachable:
            try:
                models = tuple(runtime.list_models())
            except AIError:
                models = ()
            try:
                detected = self.detect(config)
            except (AIError, ValueError):
                detected = None
        return RuntimeSnapshot(health, models, detected)

    def forget_runtime(self) -> None:
        with self._lock:
            self._runtime = None


def _bench_read(row: AIModelBenchmark, model_public: UUID) -> BenchmarkRead:
    return BenchmarkRead(
        benchmark_id=row.public_id,
        model_id=model_public,
        status=row.status,
        runtime=row.runtime,
        measurement=row.measurement,
        max_tokens=row.max_tokens,
        configured_context=row.configured_context,
        load_ms=row.load_ms,
        ttft_ms=row.ttft_ms,
        prompt_tokens=row.prompt_tokens,
        output_tokens=row.output_tokens,
        prompt_tps=row.prompt_tps,
        generation_tps=row.generation_tps,
        peak_ram_bytes=row.peak_ram_bytes,
        peak_vram_bytes=row.peak_vram_bytes,
        performance_class=row.performance_class,
        error=row.error,
        requested_by=row.requested_by,
        started_at=row.started_at,
        finished_at=row.finished_at,
    )


def model_spec(model: AILocalModel) -> ModelSpec:
    return ModelSpec(
        key=f"model:{model.public_id}",
        name=model.name,
        family=model.family,
        parameter_count=model.parameter_count,
        quantization=model.quantization,
        file_size_bytes=model.file_size_bytes,
        native_context=model.native_context,
        layer_count=model.layer_count,
        kv_head_count=model.kv_head_count,
        head_dim=model.head_dim,
        on_disk=True,
        expert_count=model.expert_count,
    )


def _llama_matches(model: AILocalModel, loaded: RuntimeModel) -> bool:
    """¿El modelo que sirve llama-server es este GGUF registrado?

    Primero por número exacto de parámetros (suma de tensores en ambos lados), que no
    depende del nombre; si el runtime no lo informa, por nombre de fichero.
    """
    if model.parameter_count and loaded.parameter_count:
        if model.parameter_count != loaded.parameter_count:
            return False
        if model.file_size_bytes and loaded.size_bytes:
            # meta.size son los bytes de tensores: algo menor que el fichero, nunca mayor.
            return loaded.size_bytes <= model.file_size_bytes
        return True
    name = (loaded.file_name or "").lower()
    return bool(name) and name == model.runtime_model_id.lower()


def find_loaded(model: AILocalModel, models: tuple[RuntimeModel, ...]) -> RuntimeModel | None:
    if model.runtime == "llama_cpp":
        return next((m for m in models if _llama_matches(model, m)), None)
    return next((m for m in models if m.id == model.runtime_model_id), None)


def effective_ai_config(session: Session, settings: Settings) -> AIConfig:
    """AIConfig que usa AI Insights: AI_MODEL o, si hay uno, el modelo local ACTIVO.

    Solo cambia el nombre del modelo, nunca el destino (AI_BASE_URL y sus reglas 4J.1). Con
    un proveedor externo se ignora el modelo local: no tendría sentido enviarlo fuera.
    """
    config = AIConfig.from_settings(settings)
    if not config.enabled or config.location != "local":
        return config
    row = session.get(AILocalSettings, 1)
    if row is None or row.active_model_id is None:
        return config
    model = session.get(AILocalModel, row.active_model_id)
    if model is None or model.runtime != (row.runtime or settings.ai_runtime):
        return config
    return replace(config, model=model.runtime_model_id)


class LocalModelService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        state: LocalAIState,
        actor: Actor,
        can_manage: bool,
        on_model_changed: Callable[[], None] = lambda: None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._state = state
        self._actor = actor
        self._can_manage = can_manage
        self._config = AIConfig.from_settings(settings)
        self._on_model_changed = on_model_changed
        self._roots = parse_model_directories(settings.ai_model_directories)

    # --- Utilidades -------------------------------------------------------------------------

    def _audit(self, action: str, result: str, target: str | None, details: dict[str, Any]) -> None:
        audit_service.record(
            self._session,
            self._actor,
            action,
            result,
            target_type="ai_model",
            target_id=target,
            details=details,
        )

    def _settings_row(self) -> AILocalSettings | None:
        return self._session.get(AILocalSettings, 1)

    def _runtime_kind(self) -> tuple[RuntimeKind, str]:
        row = self._settings_row()
        kind = as_runtime_kind(row.runtime) if row is not None else None
        if kind is not None:
            return kind, "settings"
        return self._settings.ai_runtime, "env"

    def manager_reason(self) -> str | None:
        """Por qué el gestor no puede hablar con el runtime (None = puede). Sin conexiones.

        No exige AI_MODEL: precisamente el gestor sirve para elegir el modelo.
        """
        c = self._config
        if not c.enabled:
            return "IA no configurada: AI_ENABLED=false."
        if not c.base_url:
            return "IA no configurada: falta AI_BASE_URL."
        if c.location != "local":
            return (
                "El gestor de modelos solo opera con un runtime local; AI_BASE_URL no es local "
                "(loopback, AI_LOCAL_NETWORKS o AI_LOCAL_HOSTS)."
            )
        return c.destination_blocked_reason()

    def _runtime_config(self) -> AIConfig:
        reason = self.manager_reason()
        if reason is not None:
            raise AINotConfiguredError(reason)
        return self._config

    def _runtime(self, kind: RuntimeKind) -> LocalAIRuntime:
        try:
            return self._state.runtime_factory(kind, self._runtime_config())
        except ValueError:
            raise AINotConfiguredError("AI provider configuration is invalid") from None

    def _snapshot(self, refresh: bool = False) -> RuntimeSnapshot | None:
        if self.manager_reason() is not None:
            return None
        kind, _ = self._runtime_kind()
        return self._state.runtime_snapshot(kind, self._config, refresh)

    def _hardware(self, refresh: bool = False) -> HardwareProfile:
        return self._state.hardware(self._roots, refresh)

    def _model(self, model_id: UUID) -> AILocalModel:
        model = self._session.scalar(select(AILocalModel).where(AILocalModel.public_id == model_id))
        if model is None:
            raise NotFoundError("Model not found")
        return model

    def _thresholds(self) -> tuple[float, float, float]:
        return parse_performance_thresholds(self._settings.ai_performance_thresholds)

    def _latest_benchmarks(self, model_ids: list[int]) -> dict[int, AIModelBenchmark]:
        if not model_ids:
            return {}
        rows = self._session.scalars(
            select(AIModelBenchmark)
            .where(AIModelBenchmark.model_id.in_(model_ids))
            .order_by(AIModelBenchmark.started_at.desc(), AIModelBenchmark.id.desc())
        ).all()
        latest: dict[int, AIModelBenchmark] = {}
        for row in rows:
            latest.setdefault(row.model_id, row)
        return latest

    def _observed(self, bench: AIModelBenchmark | None) -> Observed | None:
        if bench is None or bench.status != "completed" or not bench.generation_tps:
            return None
        return Observed(
            bench.generation_tps, performance_class(bench.generation_tps, self._thresholds())
        )

    def _completed(self, model_ids: list[int]) -> dict[int, AIModelBenchmark]:
        if not model_ids:
            return {}
        rows = self._session.scalars(
            select(AIModelBenchmark)
            .where(AIModelBenchmark.model_id.in_(model_ids), AIModelBenchmark.status == "completed")
            .order_by(AIModelBenchmark.started_at.desc(), AIModelBenchmark.id.desc())
        ).all()
        result: dict[int, AIModelBenchmark] = {}
        for row in rows:
            result.setdefault(row.model_id, row)
        return result

    def _evaluate_models(
        self, models: list[AILocalModel], context: int, profile: Profile
    ) -> dict[int, Evaluation]:
        hardware = self._hardware()
        kind, _ = self._runtime_kind()
        traits = CAPABILITIES[kind].traits()
        completed = self._completed([m.id for m in models])
        evaluations = {
            m.id: evaluate(
                model_spec(m),
                hardware,
                CAPABILITIES[m.runtime].traits() if m.runtime in CAPABILITIES else traits,
                context,
                self._settings.ai_memory_safety_margin_percent,
                self._observed(completed.get(m.id)),
            )
            for m in models
        }
        rank(list(evaluations.values()), profile)
        return evaluations

    def _benchmark_running_elsewhere(self) -> bool:
        """Fase 4M: otro worker (u otra instancia) tiene un benchmark "running" vigente.

        El estado de BenchmarkState es por proceso; con varios workers solo la base lo ve
        todo. Un registro más viejo que plazo + margen ya lo marca fallido
        _expire_stale_benchmarks, así que aquí solo cuentan los que siguen en plazo.
        """
        self._expire_stale_benchmarks()
        return (
            self._session.scalar(
                select(func.count())
                .select_from(AIModelBenchmark)
                .where(AIModelBenchmark.status == "running")
            )
            or 0
        ) > 0

    def _expire_stale_benchmarks(self) -> None:
        limit = datetime.now(UTC) - (
            timedelta(seconds=self._settings.ai_benchmark_timeout_seconds) + STALE_BENCHMARK_GRACE
        )
        running = self._state.benchmarks.running()
        stale = self._session.scalars(
            select(AIModelBenchmark).where(
                AIModelBenchmark.status == "running", AIModelBenchmark.started_at < limit
            )
        ).all()
        changed = False
        for row in stale:
            if row.id != running:
                # El proceso que lo ejecutaba murió o se reinició: no quedará "running" siempre.
                row.status, row.error, row.finished_at = "failed", "interrupted", datetime.now(UTC)
                changed = True
        if changed:
            self._session.commit()

    # --- Hardware y runtime -----------------------------------------------------------------

    def hardware(self, refresh: bool = False) -> HardwareRead:
        profile = self._hardware(refresh)
        return HardwareRead(
            os=profile.os,
            os_version=profile.os_version,
            architecture=profile.architecture,
            cpu=CPURead(
                model=profile.cpu.model,
                physical_cores=profile.cpu.physical_cores,
                logical_cores=profile.cpu.logical_cores,
            ),
            ram_total_bytes=profile.ram_total_bytes,
            ram_available_bytes=profile.ram_available_bytes,
            gpus=[
                GPURead(
                    index=g.index,
                    vendor=g.vendor,
                    model=g.model,
                    vram_total_bytes=g.vram_total_bytes,
                    vram_free_bytes=g.vram_free_bytes,
                    memory_kind=g.memory_kind,
                    source=g.source,
                    driver=g.driver,
                )
                for g in profile.gpu_devices
            ],
            disk_free_bytes=profile.disk_free_bytes,
            disk_total_bytes=profile.disk_total_bytes,
            disk_scope=profile.disk_scope,
            detected_at=profile.detected_at,
            duration_ms=profile.duration_ms,
            warnings=list(profile.warnings),
        )

    def runtime_status(self, refresh: bool = False) -> RuntimeStatusRead:
        kind, source = self._runtime_kind()
        caps = CAPABILITIES[kind]
        reason = self.manager_reason()
        snapshot = self._snapshot(refresh)
        row = self._settings_row()
        active = (
            self._session.get(AILocalModel, row.active_model_id)
            if row is not None and row.active_model_id
            else None
        )
        health = snapshot.health if snapshot else None
        loaded = [m for m in snapshot.models if m.loaded] if snapshot else []
        effective = effective_ai_config(self._session, self._settings)
        return RuntimeStatusRead(
            kind=kind,
            label=caps.label,
            source=source,
            capabilities=RuntimeCapabilitiesRead(
                list_models=caps.list_models,
                load_model=caps.load_model,
                unload_model=caps.unload_model,
                benchmark=caps.benchmark,
                gpu_offload=caps.gpu_offload,
                multi_gpu_split=caps.multi_gpu_split,
                gguf_files=caps.gguf_files,
                notes=list(caps.notes),
            ),
            available=reason is None,
            reason=reason,
            reachable=health.reachable if health else None,
            health_detail=health.detail if health else None,
            health_latency_ms=health.latency_ms if health else None,
            version=health.version if health else None,
            detected_kind=snapshot.detected if snapshot else None,
            loaded_models=[m.file_name or m.id for m in loaded][:20],
            configured_context=next(
                (m.configured_context for m in loaded if m.configured_context), None
            ),
            active_model=(
                ActiveModelRead(
                    model_id=active.public_id,
                    name=active.name,
                    runtime_model_id=active.runtime_model_id,
                    quantization=active.quantization,
                    parameter_count=active.parameter_count,
                    selected_at=active.last_selected_at,
                )
                if active is not None
                else None
            ),
            effective_model=effective.model if effective.enabled else None,
            external_ai="allowed" if self._config.allow_external else "blocked",
            default_context_tokens=self._settings.ai_default_context_tokens,
            slots=["default"],
        )

    def update_runtime(self, runtime: RuntimeKind) -> RuntimeStatusRead:
        row = self._settings_row()
        previous, _ = self._runtime_kind()
        if row is None:
            row = AILocalSettings(id=1)
            self._session.add(row)
        cleared = None
        if previous != runtime and row.active_model_id is not None:
            # El modelo activo pertenecía al runtime anterior: dejarlo activo enviaría a un
            # runtime un nombre de modelo de otro. Sentra vuelve a AI_MODEL hasta elegir otro.
            cleared = row.active_model_id
            row.active_model_id = None
        row.runtime = runtime
        row.updated_by = self._actor.name[:64]
        row.updated_at = datetime.now(UTC)
        self._session.commit()
        self._state.forget_runtime()
        self._on_model_changed()
        self._audit(
            "ai_runtime_changed",
            audit_service.SUCCESS,
            None,
            {"previous": previous, "runtime": runtime, "active_cleared": cleared is not None},
        )
        return self.runtime_status()

    # --- Modelos ----------------------------------------------------------------------------

    def _read(
        self,
        model: AILocalModel,
        *,
        active_id: int | None,
        snapshot: RuntimeSnapshot | None,
        evaluation: Evaluation | None,
        latest: AIModelBenchmark | None,
    ) -> LocalModelRead:
        kind, _ = self._runtime_kind()
        loaded: bool | None = None
        missing_file = model.local_path is not None and not os.path.isfile(model.local_path)
        listed = None
        if (
            snapshot is not None
            and snapshot.health
            and snapshot.health.reachable
            and model.runtime == kind
        ):
            listed = find_loaded(model, snapshot.models)
            loaded = bool(listed and listed.loaded) if listed is not None else False
        if missing_file:
            state = "unavailable"
        elif listed is None and loaded is False and model.metadata_source == "runtime":
            # El runtime responde pero ya no lista este modelo.
            state = "unavailable"
        elif model.id == active_id:
            state = "active"
        elif loaded:
            state = "loaded"
        elif evaluation is not None and evaluation.status == "not_recommended":
            state = "incompatible"
        else:
            state = "registered"
        return LocalModelRead(
            model_id=model.public_id,
            name=model.name,
            family=model.family,
            architecture=model.architecture,
            parameter_count=model.parameter_count,
            quantization=model.quantization,
            file_size_bytes=model.file_size_bytes,
            native_context=model.native_context,
            runtime=model.runtime,
            runtime_model_id=model.runtime_model_id,
            file_name=file_basename(model.local_path) if model.local_path else None,
            local_path=model.local_path if self._can_manage else None,
            split_count=model.split_count,
            metadata_source=model.metadata_source,
            source=model.source,
            license=model.license,
            checksum_sha256=model.checksum_sha256,
            checksum_status=model.checksum_status,
            installed_at=model.installed_at,
            last_selected_at=model.last_selected_at,
            state=state,
            active=model.id == active_id,
            loaded=loaded,
            compatibility=evaluation.status if evaluation else None,
            recommended_for_sentra=bool(evaluation and evaluation.recommended_for_sentra),
            latest_benchmark=_bench_read(latest, model.public_id) if latest else None,
        )

    def list_models(self, limit: int, offset: int) -> LocalModelList:
        self._expire_stale_benchmarks()
        total = self._session.scalar(select(func.count()).select_from(AILocalModel)) or 0
        models = list(
            self._session.scalars(
                select(AILocalModel)
                .order_by(AILocalModel.installed_at.desc(), AILocalModel.id.desc())
                .limit(limit)
                .offset(offset)
            ).all()
        )
        snapshot = self._snapshot()
        row = self._settings_row()
        active_id = row.active_model_id if row else None
        evaluations = self._evaluate_models(
            models, self._settings.ai_default_context_tokens, "balanced"
        )
        latest = self._latest_benchmarks([m.id for m in models])
        items = [
            self._read(
                m,
                active_id=active_id,
                snapshot=snapshot,
                evaluation=evaluations.get(m.id),
                latest=latest.get(m.id),
            )
            for m in models
        ]
        return LocalModelList(
            items=items,
            total=total,
            discovered=self._discovered(snapshot) if self._can_manage else [],
        )

    def _discovered(self, snapshot: RuntimeSnapshot | None) -> list[DiscoveredModelRead]:
        registered_paths = set(
            self._session.scalars(
                select(AILocalModel.local_path).where(AILocalModel.local_path.is_not(None))
            ).all()
        )
        kind, _ = self._runtime_kind()
        registered_ids = set(
            self._session.scalars(
                select(AILocalModel.runtime_model_id).where(AILocalModel.runtime == kind)
            ).all()
        )
        found: list[DiscoveredModelRead] = [
            DiscoveredModelRead(
                kind="file",
                name=f.file_name.rsplit(".", 1)[0],
                file_name=f.file_name,
                path=f.path,
                size_bytes=f.size_bytes,
                runtime_model_id=None,
                state="downloaded",
            )
            for f in discover_model_files(self._roots)
            if f.path not in registered_paths
        ]
        if snapshot is not None and kind != "llama_cpp":
            # En llama.cpp el modelo servido es un GGUF: se registra desde su fichero.
            found += [
                DiscoveredModelRead(
                    kind="runtime",
                    name=m.id,
                    file_name=None,
                    path=None,
                    size_bytes=m.size_bytes,
                    runtime_model_id=m.id,
                    state="loaded" if m.loaded else "downloaded",
                )
                for m in snapshot.models
                if m.id not in registered_ids
            ]
        return found

    def get_model(self, model_id: UUID, context: int | None, profile: Profile) -> LocalModelDetail:
        self._expire_stale_benchmarks()
        model = self._model(model_id)
        context = context or self._settings.ai_default_context_tokens
        evaluation = self._evaluate_models([model], context, profile)[model.id]
        benchmarks = self._session.scalars(
            select(AIModelBenchmark)
            .where(AIModelBenchmark.model_id == model.id)
            .order_by(AIModelBenchmark.started_at.desc(), AIModelBenchmark.id.desc())
            .limit(20)
        ).all()
        row = self._settings_row()
        model_kind = as_runtime_kind(model.runtime)
        caps = CAPABILITIES[model_kind] if model_kind else None
        return LocalModelDetail(
            model=self._read(
                model,
                active_id=row.active_model_id if row else None,
                snapshot=self._snapshot(),
                evaluation=evaluation,
                latest=benchmarks[0] if benchmarks else None,
            ),
            evaluation=self._recommendation_read(evaluation, model=model),
            benchmarks=[_bench_read(b, model.public_id) for b in benchmarks],
            runtime_notes=list(caps.notes) if caps else [],
        )

    def register(self, body: RegisterModelRequest) -> LocalModelRead:
        if body.path is not None:
            model = self._register_file(body.path, body.name)
        else:
            model = self._register_runtime_model(body.runtime_model or "", body.name)
        self._session.add(model)
        try:
            self._session.commit()
        except IntegrityError:
            self._session.rollback()
            raise ConflictError("This model is already registered") from None
        self._audit(
            "ai_model_registered",
            audit_service.SUCCESS,
            str(model.public_id),
            {
                "name": model.name,
                "runtime": model.runtime,
                "metadata_source": model.metadata_source,
                "quantization": model.quantization,
                "parameter_count": model.parameter_count,
                "file_name": file_basename(model.local_path) if model.local_path else None,
            },
        )
        if model.local_path is not None:
            self._schedule_checksum(model.id)
        return self._read(model, active_id=None, snapshot=None, evaluation=None, latest=None)

    def _register_file(self, raw_path: str, name: str | None) -> AILocalModel:
        max_bytes = self._settings.ai_model_max_file_gb * 1024**3
        file = resolve_model_path(raw_path, self._roots, max_bytes)
        parts = split_parts(file.path)
        try:
            info = read_gguf(file.path)
            if info.split_count > 1 and parts is None:
                raise AIModelInvalidFileError(
                    "This is a part of a split GGUF model: register the first part (-00001-of-)"
                )
            size = file.size_bytes
            parameters = info.parameter_count
            if parts is not None:
                # Cada parte pasa las mismas comprobaciones de ruta; los parámetros y el tamaño
                # son la suma de todas (la metadata está en la primera).
                for part in parts[1:]:
                    extra = resolve_model_path(part, self._roots, max_bytes)
                    size += extra.size_bytes
                    parameters += read_gguf(extra.path).parameter_count
        except InvalidGGUFError as exc:
            raise AIModelInvalidFileError(str(exc)) from None
        except ModelPathError as exc:
            raise AIModelInvalidFileError(f"Split GGUF part rejected: {exc.message}") from None
        if parameters <= 0:
            raise AIModelInvalidFileError("The GGUF file declares no tensors")
        display = (name or info.name or file.file_name.rsplit(".", 1)[0]).strip()[:256]
        return AILocalModel(
            name=display,
            family=(info.basename or info.architecture or "")[:64] or None,
            architecture=info.architecture,
            parameter_count=parameters,
            quantization=info.quantization,
            file_size_bytes=size,
            native_context=info.context_length,
            layer_count=info.block_count,
            kv_head_count=info.head_count_kv,
            head_dim=info.head_dim,
            expert_count=info.expert_count,
            runtime="llama_cpp",
            runtime_model_id=file.file_name,
            local_path=file.path,
            split_count=len(parts) if parts else 1,
            metadata_source="gguf",
            source=None,
            license=info.license,
            checksum_status="pending",
            registered_by=self._actor.name[:64],
            installed_at=datetime.now(UTC),
        )

    def _register_runtime_model(self, name: str, display: str | None) -> AILocalModel:
        kind, _ = self._runtime_kind()
        runtime = self._runtime(kind)
        details = runtime.model_details(name.strip())
        if details is None:
            raise NotFoundError("The configured runtime does not list this model")
        return AILocalModel(
            name=(display or details.id).strip()[:256],
            family=details.family,
            architecture=details.architecture,
            parameter_count=details.parameter_count,
            quantization=details.quantization,
            file_size_bytes=details.size_bytes,
            native_context=details.native_context,
            layer_count=details.layer_count,
            kv_head_count=details.kv_head_count,
            head_dim=details.head_dim,
            runtime=kind,
            runtime_model_id=details.id,
            local_path=None,
            metadata_source="runtime",
            checksum_status="none",
            registered_by=self._actor.name[:64],
            installed_at=datetime.now(UTC),
        )

    def _schedule_checksum(self, model_pk: int) -> None:
        factory = self._state.session_factory

        def job() -> None:
            # Lectura secuencial por bloques: memoria constante aunque el fichero ocupe GB.
            with factory() as session:
                model = session.get(AILocalModel, model_pk)
                if model is None or model.local_path is None:
                    return
                paths = split_parts(model.local_path) or [model.local_path]
                digest = hashlib.sha256()
                try:
                    for path in paths:
                        with open(path, "rb") as handle:
                            while chunk := handle.read(CHECKSUM_CHUNK):
                                digest.update(chunk)
                except OSError:
                    model.checksum_status = "failed"
                else:
                    model.checksum_sha256 = digest.hexdigest()
                    model.checksum_status = "ok"
                session.commit()

        self._state.run_background(job)

    def unregister(self, model_id: UUID) -> None:
        model = self._model(model_id)
        running = self._state.benchmarks.running()
        if running is not None:
            bench = self._session.get(AIModelBenchmark, running)
            if bench is not None and bench.model_id == model.id:
                self._state.benchmarks.cancel(running)
        row = self._settings_row()
        was_active = row is not None and row.active_model_id == model.id
        name, public = model.name, str(model.public_id)
        self._session.delete(model)
        self._session.commit()
        if was_active:
            self._on_model_changed()
        # Solo se borra el REGISTRO: el fichero del disco no se toca nunca desde aquí.
        self._audit(
            "ai_model_unregistered",
            audit_service.SUCCESS,
            public,
            {"name": name, "was_active": was_active, "file_deleted": False},
        )

    # --- Selección --------------------------------------------------------------------------

    def select_model(self, model_id: UUID) -> RuntimeStatusRead:
        model = self._model(model_id)
        kind, _ = self._runtime_kind()
        details = {"name": model.name, "runtime": kind}
        try:
            if model.runtime != kind:
                raise AIModelRuntimeMismatchError(
                    f"This model belongs to the {model.runtime} runtime; the configured runtime"
                    f" is {kind}"
                )
            if model.local_path is not None and not os.path.isfile(model.local_path):
                raise AIModelUnavailableError("The model file no longer exists")
            config = self._runtime_config()
            runtime = self._runtime(kind)
            health = runtime.health()
            if not health.reachable:
                raise AIModelUnavailableError(
                    f"The local AI runtime is not responding ({health.detail or 'unreachable'})"
                )
            send_id = self._ensure_loaded(runtime, model)
            # Solo se marca activo si el modelo RESPONDE a una petición mínima sin datos.
            provider = OpenAICompatibleProvider(replace(config, json_mode=False), model=send_id)
            provider.complete(SELECT_CHECK)
        except (AIError, ConflictError) as exc:
            self._session.rollback()
            self._audit(
                "ai_model_load_failed",
                audit_service.FAILURE,
                str(model.public_id),
                {**details, "error": exc.code},
            )
            # El activo anterior no se ha tocado: sigue siendo el que usa AI Insights.
            raise
        row = self._settings_row()
        previous = None
        if row is None:
            row = AILocalSettings(id=1)
            self._session.add(row)
        else:
            previous = row.active_model_id
        row.active_model_id = model.id
        row.updated_by = self._actor.name[:64]
        row.updated_at = datetime.now(UTC)
        model.last_selected_at = datetime.now(UTC)
        self._session.commit()
        self._state.forget_runtime()
        self._on_model_changed()
        self._audit(
            "ai_model_selected",
            audit_service.SUCCESS,
            str(model.public_id),
            {**details, "slot": "default", "previous_changed": previous != model.id},
        )
        return self.runtime_status()

    def _ensure_loaded(self, runtime: LocalAIRuntime, model: AILocalModel) -> str:
        """Carga el modelo si el runtime sabe hacerlo; si no, verifica que ya lo sirve.

        Devuelve el nombre de modelo que hay que enviar al runtime.
        """
        caps = runtime.capabilities()
        models = tuple(runtime.list_models())
        listed = find_loaded(model, models)
        if model.runtime == "llama_cpp":
            if listed is None:
                served = ", ".join(m.file_name or m.id for m in models) or "ninguno"
                raise AIModelNotLoadedError(
                    f"llama-server is serving {served}; restart it with -m {model.runtime_model_id}"
                )
            return listed.id
        if listed is None:
            raise AIModelUnavailableError("The configured runtime does not list this model")
        if caps.load_model and not listed.loaded:
            with contextlib.suppress(AIRuntimeUnsupportedError):
                runtime.load_model(listed.id)
        return listed.id

    # --- Benchmark --------------------------------------------------------------------------

    def start_benchmark(self, model_id: UUID) -> BenchmarkRead:
        model = self._model(model_id)
        kind, _ = self._runtime_kind()
        if model.runtime != kind:
            raise AIModelRuntimeMismatchError("The model does not belong to the configured runtime")
        runtime = self._runtime(kind)
        if self._state.benchmarks.running() is not None or self._benchmark_running_elsewhere():
            raise AIBenchmarkBusyError("Another benchmark is running; wait or cancel it")
        if not runtime.health().reachable:
            raise AIModelUnavailableError("The local AI runtime is not responding")
        models = tuple(runtime.list_models())
        listed = find_loaded(model, models)
        if listed is None:
            if model.runtime == "llama_cpp":
                raise AIModelNotLoadedError(
                    f"llama-server is not serving this model; restart it with -m "
                    f"{model.runtime_model_id}"
                )
            raise AIModelUnavailableError("The configured runtime does not list this model")
        load_first = runtime.capabilities().load_model and not listed.loaded
        now = datetime.now(UTC)
        bench = AIModelBenchmark(
            model_id=model.id,
            status="running",
            runtime=kind,
            max_tokens=self._settings.ai_benchmark_max_tokens,
            configured_context=listed.configured_context,
            requested_by=self._actor.name[:64],
            started_at=now,
        )
        self._session.add(bench)
        self._session.commit()
        self._audit(
            "ai_model_benchmark_started",
            audit_service.SUCCESS,
            str(model.public_id),
            {"name": model.name, "runtime": kind, "benchmark": str(bench.public_id)},
        )
        job = self._benchmark_job(
            bench.id, model.public_id, runtime, listed.id, load_first, model.name
        )
        try:
            self._state.benchmarks.start(bench.id, job)
        except AIError:
            bench.status, bench.error, bench.finished_at = "failed", "busy", datetime.now(UTC)
            self._session.commit()
            raise
        return _bench_read(bench, model.public_id)

    def _benchmark_job(
        self,
        bench_pk: int,
        model_public: UUID,
        runtime: LocalAIRuntime,
        send_id: str,
        load_first: bool,
        name: str,
    ) -> Callable[[threading.Event], None]:
        factory = self._state.session_factory
        source = self._state.source
        actor = self._actor
        max_tokens = self._settings.ai_benchmark_max_tokens
        timeout = float(self._settings.ai_benchmark_timeout_seconds)
        thresholds = self._thresholds()

        def job(cancel: threading.Event) -> None:
            result, error = "completed", None
            outcome = None
            try:
                outcome = run_benchmark(
                    runtime,
                    send_id,
                    max_tokens=max_tokens,
                    timeout_seconds=timeout,
                    cancel=cancel,
                    sampler=lambda: sample_memory_usage(source),
                    load_first=load_first,
                )
            except BenchmarkCancelledError:
                result, error = "cancelled", None
            except AIError as exc:
                result, error = "failed", exc.code
            except Exception:
                # Un fallo inesperado del benchmark nunca afecta a la API ni a AI Insights.
                logger.exception("ai benchmark crashed")
                result, error = "failed", "internal_error"
            with factory() as session:
                bench = session.get(AIModelBenchmark, bench_pk)
                if bench is None:
                    return  # el registro del modelo se quitó mientras tanto
                bench.status, bench.error = result, error
                bench.finished_at = datetime.now(UTC)
                if outcome is not None:
                    bench.measurement = outcome.measurement
                    bench.load_ms = outcome.load_ms
                    bench.ttft_ms = outcome.ttft_ms
                    bench.prompt_tokens = outcome.prompt_tokens
                    bench.output_tokens = outcome.output_tokens
                    bench.prompt_tps = outcome.prompt_tps
                    bench.generation_tps = outcome.generation_tps
                    bench.peak_ram_bytes = outcome.peak_ram_bytes
                    bench.peak_vram_bytes = outcome.peak_vram_bytes
                    if outcome.generation_tps:
                        bench.performance_class = performance_class(
                            outcome.generation_tps, thresholds
                        )
                session.commit()
                audit_service.record(
                    session,
                    actor,
                    "ai_model_benchmark_completed",
                    audit_service.SUCCESS if result == "completed" else audit_service.FAILURE,
                    target_type="ai_model",
                    target_id=str(model_public),
                    details={
                        "name": name,
                        "status": result,
                        "error": error,
                        "generation_tps": bench.generation_tps,
                        "performance_class": bench.performance_class,
                        "benchmark": str(bench.public_id),
                    },
                )

        return job

    def _benchmark(self, benchmark_id: UUID) -> tuple[AIModelBenchmark, UUID]:
        row = self._session.execute(
            select(AIModelBenchmark, AILocalModel.public_id)
            .join(AILocalModel, AILocalModel.id == AIModelBenchmark.model_id)
            .where(AIModelBenchmark.public_id == benchmark_id)
        ).first()
        if row is None:
            raise NotFoundError("Benchmark not found")
        return row[0], row[1]

    def get_benchmark(self, benchmark_id: UUID) -> BenchmarkRead:
        self._expire_stale_benchmarks()
        bench, model_public = self._benchmark(benchmark_id)
        return _bench_read(bench, model_public)

    def cancel_benchmark(self, benchmark_id: UUID) -> BenchmarkRead:
        bench, model_public = self._benchmark(benchmark_id)
        if bench.status != "running":
            raise ConflictError("The benchmark is not running")
        if not self._state.benchmarks.cancel(bench.id):
            # Ningún hilo lo ejecuta (proceso reiniciado): se cierra como cancelado.
            bench.status, bench.finished_at = "cancelled", datetime.now(UTC)
            self._session.commit()
        return _bench_read(bench, model_public)

    # --- Recomendaciones --------------------------------------------------------------------

    def _recommendation_read(
        self,
        ev: Evaluation,
        *,
        model: AILocalModel | None = None,
        catalog_id: str | None = None,
        license: str | None = None,
        source: str | None = None,
    ) -> RecommendationRead:
        e, f = ev.estimate, ev.fit
        return RecommendationRead(
            key=ev.spec.key,
            origin="registered" if model is not None else "catalog",
            model_id=model.public_id if model is not None else None,
            catalog_id=catalog_id,
            name=ev.spec.name,
            family=ev.spec.family,
            parameter_count=ev.spec.parameter_count,
            quantization=ev.spec.quantization,
            native_context=ev.spec.native_context,
            license=model.license if model is not None else license,
            source=model.source if model is not None else source,
            status=ev.status,
            quality=ev.quality,
            speed=ev.speed,
            speed_source=ev.speed_source,
            estimate=EstimateRead(
                weights_bytes=e.weights_bytes,
                weights_source=e.weights_source,
                kv_cache_bytes=e.kv_cache_bytes,
                overhead_bytes=e.overhead_bytes,
                total_bytes=e.total_bytes,
                context_tokens=e.context_tokens,
                kv_type=e.kv_type,
                complete=e.complete,
                missing=list(e.missing),
                placement=f.placement,
                vram_bytes=f.vram_bytes,
                ram_bytes=f.ram_bytes,
                gpu_fraction=round(f.gpu_fraction, 3) if f.gpu_fraction is not None else None,
                usable_vram_bytes=f.usable_vram_bytes,
                usable_ram_bytes=f.usable_ram_bytes,
                safety_margin_percent=f.safety_margin_percent,
            ),
            reasons=ev.reasons,
            warnings=ev.warnings,
            limitations=ev.limitations,
            recommended_for_sentra=ev.recommended_for_sentra,
            score=round(ev.score, 3) if ev.score is not None else None,
            observed_tps=ev.observed.generation_tps if ev.observed else None,
            performance_class=ev.observed.performance_class if ev.observed else None,
        )

    def recommendations(
        self, profile: Profile, context: int | None, include_catalog: bool, limit: int
    ) -> RecommendationList:
        context = context or self._settings.ai_default_context_tokens
        hardware = self._hardware()
        kind, _ = self._runtime_kind()
        traits = CAPABILITIES[kind].traits()
        margin = self._settings.ai_memory_safety_margin_percent
        models = list(
            self._session.scalars(
                select(AILocalModel).order_by(AILocalModel.installed_at.desc()).limit(200)
            ).all()
        )
        completed = self._completed([m.id for m in models])
        evaluations: list[Evaluation] = []
        meta: dict[str, dict[str, Any]] = {}
        for m in models:
            ev = evaluate(
                model_spec(m),
                hardware,
                CAPABILITIES[m.runtime].traits() if m.runtime in CAPABILITIES else traits,
                context,
                margin,
                self._observed(completed.get(m.id)),
            )
            evaluations.append(ev)
            meta[ev.spec.key] = {"model": m}
        if include_catalog:
            for entry in load_catalog(self._settings.ai_model_catalog_file):
                for spec in entry.specs():
                    ev = evaluate(spec, hardware, traits, context, margin)
                    evaluations.append(ev)
                    meta[spec.key] = {
                        "catalog_id": entry.id,
                        "license": entry.license,
                        "source": entry.source,
                    }
        ranked = rank(evaluations, profile)
        items = [self._recommendation_read(ev, **meta[ev.spec.key]) for ev in ranked]
        return RecommendationList(
            profile=profile,
            context_tokens=context,
            runtime=kind,
            hardware_detected_at=hardware.detected_at,
            items=items[:limit],
            total=len(items),
            sentra_pick=next((i.key for i in items if i.recommended_for_sentra), None),
            profile_pick=next((i.key for i in items if i.status == "recommended"), None),
        )
