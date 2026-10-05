"""Contratos de la API del gestor de modelos locales (Fase 4J.2).

Nunca se acepta un comando, una URL ni parámetros del runtime desde el navegador: como
mucho una ruta de fichero (validada contra AI_MODEL_DIRECTORIES) o el nombre de un modelo
que el runtime configurado ya lista. Las rutas completas solo se devuelven a ai:manage.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from app.schemas.common import RequestModel, ResponseModel

RuntimeKindName = Literal["llama_cpp", "ollama", "vllm", "openai_compatible"]
ModelState = Literal[
    "available", "downloaded", "registered", "loaded", "active", "unavailable", "incompatible"
]
CompatibilityStatus = Literal[
    "recommended", "compatible", "compatible_with_offload", "slow", "not_recommended"
]
RecommendationProfile = Literal["low_resource", "balanced", "quality", "max_speed", "sentra"]
SpeedClassName = Literal["fast", "moderate", "slow", "unknown"]
PlacementName = Literal["full_gpu", "partial_offload", "cpu_only", "does_not_fit", "unknown"]
PerformanceClassName = Literal["excellent", "good", "usable", "slow"]
BenchmarkStatus = Literal["running", "completed", "failed", "cancelled"]
QualityLabel = Literal["basic", "medium", "high", "very_high"]


class CPURead(ResponseModel):
    model: str | None
    physical_cores: int | None
    logical_cores: int | None


class GPURead(ResponseModel):
    index: int
    vendor: Literal["nvidia", "amd", "intel", "other"]
    model: str | None
    vram_total_bytes: int | None
    vram_free_bytes: int | None
    memory_kind: Literal["dedicated", "shared", "unknown"]
    source: str
    driver: str | None


class HardwareRead(ResponseModel):
    os: str
    os_version: str | None
    architecture: str
    cpu: CPURead
    ram_total_bytes: int | None
    ram_available_bytes: int | None
    gpus: list[GPURead]
    disk_free_bytes: int | None
    disk_total_bytes: int | None
    disk_scope: str
    detected_at: datetime
    duration_ms: int
    warnings: list[str]


class RuntimeCapabilitiesRead(ResponseModel):
    list_models: bool
    load_model: bool
    unload_model: bool
    benchmark: Literal["runtime_timings", "end_to_end"]
    gpu_offload: bool
    multi_gpu_split: bool
    gguf_files: bool
    notes: list[str]


class ActiveModelRead(ResponseModel):
    model_id: UUID
    name: str
    runtime_model_id: str
    quantization: str | None
    parameter_count: int | None
    selected_at: datetime | None


class RuntimeStatusRead(ResponseModel):
    kind: RuntimeKindName
    label: str
    # settings (elegido en la UI) o env (AI_RUNTIME).
    source: Literal["settings", "env"]
    capabilities: RuntimeCapabilitiesRead
    # La IA está activada, configurada y es LOCAL (el gestor solo opera runtimes locales).
    available: bool
    reason: str | None
    reachable: bool | None
    health_detail: str | None
    health_latency_ms: int | None
    version: str | None
    # Runtime que parece haber detrás de AI_BASE_URL (sondeo solo de ese endpoint).
    detected_kind: RuntimeKindName | None
    loaded_models: list[str]
    configured_context: int | None
    active_model: ActiveModelRead | None
    # Modelo que usa AI Insights ahora (el activo o, si no hay, AI_MODEL).
    effective_model: str | None
    external_ai: Literal["blocked", "allowed"]
    default_context_tokens: int
    # Preparación de routing futuro: hoy solo existe el slot "default".
    slots: list[Literal["default"]]


class BenchmarkRead(ResponseModel):
    benchmark_id: UUID
    model_id: UUID
    status: BenchmarkStatus
    runtime: str
    measurement: Literal["runtime_timings", "end_to_end"] | None
    max_tokens: int
    configured_context: int | None
    load_ms: int | None
    ttft_ms: int | None
    prompt_tokens: int | None
    output_tokens: int | None
    prompt_tps: float | None
    generation_tps: float | None
    peak_ram_bytes: int | None
    peak_vram_bytes: int | None
    performance_class: PerformanceClassName | None
    error: str | None
    requested_by: str
    started_at: datetime
    finished_at: datetime | None


class LocalModelRead(ResponseModel):
    model_id: UUID
    name: str
    family: str | None
    architecture: str | None
    parameter_count: int | None
    quantization: str | None
    file_size_bytes: int | None
    native_context: int | None
    runtime: str
    runtime_model_id: str
    file_name: str | None
    # Solo para ai:manage (revela la estructura de carpetas del servidor).
    local_path: str | None
    split_count: int
    metadata_source: Literal["gguf", "runtime"]
    source: str | None
    license: str | None
    checksum_sha256: str | None
    checksum_status: Literal["none", "pending", "ok", "failed"]
    installed_at: datetime
    last_selected_at: datetime | None
    state: ModelState
    active: bool
    loaded: bool | None
    compatibility: CompatibilityStatus | None
    recommended_for_sentra: bool
    latest_benchmark: BenchmarkRead | None


class DiscoveredModelRead(ResponseModel):
    # file: GGUF en AI_MODEL_DIRECTORIES sin registrar; runtime: listado por el runtime.
    kind: Literal["file", "runtime"]
    name: str
    file_name: str | None
    path: str | None
    size_bytes: int | None
    runtime_model_id: str | None
    state: Literal["downloaded", "loaded"]


class LocalModelList(ResponseModel):
    items: list[LocalModelRead]
    total: int
    # Vacío para quien no tiene ai:manage.
    discovered: list[DiscoveredModelRead]


class EstimateRead(ResponseModel):
    weights_bytes: int | None
    weights_source: Literal["file", "quantization_estimate"] | None
    kv_cache_bytes: int | None
    overhead_bytes: int | None
    total_bytes: int | None
    context_tokens: int
    kv_type: str
    complete: bool
    missing: list[str]
    placement: PlacementName
    vram_bytes: int | None
    ram_bytes: int | None
    gpu_fraction: float | None
    usable_vram_bytes: int
    usable_ram_bytes: int | None
    safety_margin_percent: int


class RecommendationRead(ResponseModel):
    key: str
    origin: Literal["registered", "catalog"]
    model_id: UUID | None
    catalog_id: str | None
    name: str
    family: str | None
    parameter_count: int | None
    quantization: str | None
    native_context: int | None
    license: str | None
    source: str | None
    status: CompatibilityStatus
    quality: QualityLabel | None
    speed: SpeedClassName
    speed_source: Literal["estimate", "benchmark"]
    estimate: EstimateRead
    reasons: list[str]
    warnings: list[str]
    limitations: list[str]
    recommended_for_sentra: bool
    score: float | None
    observed_tps: float | None
    performance_class: PerformanceClassName | None


class RecommendationList(ResponseModel):
    profile: RecommendationProfile
    context_tokens: int
    runtime: RuntimeKindName
    hardware_detected_at: datetime
    items: list[RecommendationRead]
    total: int
    sentra_pick: str | None
    profile_pick: str | None


class LocalModelDetail(ResponseModel):
    model: LocalModelRead
    evaluation: RecommendationRead
    benchmarks: list[BenchmarkRead]
    runtime_notes: list[str]


class RegisterModelRequest(RequestModel):
    # Exactamente uno: ruta absoluta a un .gguf dentro de AI_MODEL_DIRECTORIES, o el nombre
    # de un modelo que el runtime configurado ya lista.
    path: str | None = Field(default=None, max_length=1024)
    runtime_model: str | None = Field(default=None, max_length=256)
    # Nombre visible opcional (no cambia lo que se envía al runtime).
    name: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def _one_source(self) -> "RegisterModelRequest":
        if (self.path is None) == (self.runtime_model is None):
            raise ValueError("Provide exactly one of path or runtime_model")
        return self


class LocalSettingsUpdate(RequestModel):
    runtime: RuntimeKindName
