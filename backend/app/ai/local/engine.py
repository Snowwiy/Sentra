"""Estimación de memoria y motor de recomendación DETERMINISTA (Fase 4J.2).

Ningún LLM decide qué modelo ejecutar: mismas entradas (hardware, modelo, runtime, contexto,
perfil y benchmarks) producen siempre la misma salida, con las razones en texto.

Estimación de memoria (cifras ESTIMADAS, se muestran como tales):
  total = pesos + KV cache + overhead del runtime
  - pesos: tamaño real del fichero GGUF (los tensores se cargan tal cual) o, para un modelo
    del catálogo aún no descargado, parámetros x bits por peso de la cuantización;
  - KV cache: 2 (K y V) x capas x contexto x cabezas KV x dimensión por cabeza x bytes por
    elemento (f16 = 2) x secuencias en paralelo. Crece LINEAL con el contexto: a 100K+
    puede superar a los pesos. Sin capas/cabezas conocidas NO se estima (datos incompletos);
  - overhead: contexto del runtime/CUDA y buffers de cómputo. Heurística documentada:
    512 MiB + 2 % de los pesos + 8 MiB por cada 1K de contexto.

Colocación (con margen de seguridad AI_MEMORY_SAFETY_MARGIN_PERCENT):
  full_gpu (todo en VRAM) > partial_offload (capas en GPU, resto en RAM; solo runtimes que lo
  admiten) > cpu_only (todo en RAM) > no cabe. A la RAM se le reserva además lo que usan el
  sistema, PostgreSQL y Sentra (máx(2 GiB, 15 %)).

Nada de límites por tamaño: un 27B/32B se clasifica igual que un 7B, por memoria, contexto y
rendimiento. Lo que decide es si cabe y a qué velocidad, nunca el número de parámetros solo.
"""

import math
from dataclasses import dataclass, field
from typing import Literal

from app.ai.local.hardware import GIB, MIB, HardwareProfile
from app.ai.local.quant import BITS_PER_WEIGHT, QUALITY_FACTOR

Placement = Literal["full_gpu", "partial_offload", "cpu_only", "does_not_fit", "unknown"]
SpeedClass = Literal["fast", "moderate", "slow", "unknown"]
Status = Literal["recommended", "compatible", "compatible_with_offload", "slow", "not_recommended"]
Profile = Literal["low_resource", "balanced", "quality", "max_speed", "sentra"]
PerformanceClass = Literal["excellent", "good", "usable", "slow"]
KVType = Literal["f16", "q8_0", "q4_0"]

PROFILES: tuple[Profile, ...] = ("low_resource", "balanced", "quality", "max_speed", "sentra")
# Bytes por elemento del KV cache. Solo f16 se usa por defecto: la cuantización del KV solo
# se aplicaría si el runtime confirma que la tiene activada (hoy ningún adapter lo verifica).
KV_BYTES: dict[KVType, float] = {"f16": 2.0, "q8_0": 1.0625, "q4_0": 0.5625}
# Reserva de RAM para el sistema operativo, PostgreSQL y la propia API de Sentra.
RAM_RESERVE_MIN = 2 * GIB
RAM_RESERVE_FRACTION = 0.15
# Por debajo de esto, un modelo no sigue de forma fiable el esquema JSON y el grounding de
# Sentra (parámetros efectivos). No es un límite superior: solo un mínimo para Sentra.
SENTRA_MIN_EFFECTIVE_PARAMS = 3e9
# Contexto a partir del cual el procesado del prompt es caro fuera de la GPU.
LONG_CONTEXT = 65_536
VERY_LONG_CONTEXT = 131_072
_STATUS_ORDER = {
    "recommended": 0,
    "compatible": 1,
    "compatible_with_offload": 2,
    "slow": 3,
    "not_recommended": 4,
}


@dataclass(frozen=True)
class ModelSpec:
    """Lo que el motor necesita saber de un modelo, venga de un GGUF, del runtime o del catálogo."""

    key: str
    name: str
    family: str | None
    parameter_count: int | None
    quantization: str | None
    # Tamaño real en disco (fichero registrado o informado por el runtime). None = estimar.
    file_size_bytes: int | None
    native_context: int | None
    layer_count: int | None
    kv_head_count: int | None
    head_dim: int | None
    on_disk: bool
    # Mixture-of-experts: solo una parte de los pesos se lee por token (más rápido).
    expert_count: int | None = None

    @property
    def effective_params(self) -> float | None:
        if not self.parameter_count or not self.quantization:
            return None
        factor = QUALITY_FACTOR.get(self.quantization)
        return self.parameter_count * factor if factor is not None else None


@dataclass(frozen=True)
class RuntimeTraits:
    """Capacidades del runtime que cambian la estimación (ver runtimes.py)."""

    kind: str
    gpu: bool
    gpu_offload: bool
    # vLLM y similares cargan el modelo en UNA GPU salvo tensor parallel configurado fuera.
    multi_gpu_split: bool
    kv_type: KVType = "f16"
    parallel_sequences: int = 1


@dataclass(frozen=True)
class MemoryEstimate:
    weights_bytes: int | None
    weights_source: Literal["file", "quantization_estimate"] | None
    kv_cache_bytes: int | None
    overhead_bytes: int | None
    total_bytes: int | None
    context_tokens: int
    kv_type: KVType
    complete: bool
    missing: tuple[str, ...]


@dataclass(frozen=True)
class Fit:
    placement: Placement
    vram_bytes: int | None
    ram_bytes: int | None
    gpu_fraction: float | None
    usable_vram_bytes: int
    usable_ram_bytes: int | None
    safety_margin_percent: int


@dataclass(frozen=True)
class Observed:
    """Último benchmark completado del modelo: pesa más que cualquier estimación."""

    generation_tps: float
    performance_class: PerformanceClass


@dataclass
class Evaluation:
    spec: ModelSpec
    estimate: MemoryEstimate
    fit: Fit
    speed: SpeedClass
    speed_source: Literal["estimate", "benchmark"]
    status: Status
    quality: str | None
    reasons: list[str]
    warnings: list[str]
    score: float | None = None
    recommended_for_sentra: bool = False
    observed: Observed | None = None
    limitations: list[str] = field(default_factory=list)


def gib(value: int | float | None) -> str:
    return "?" if value is None else f"{value / GIB:.1f} GB"


def quality_label(effective: float | None) -> str | None:
    if effective is None:
        return None
    if effective < 4e9:
        return "basic"
    if effective < 10e9:
        return "medium"
    if effective < 20e9:
        return "high"
    return "very_high"


def performance_class(tps: float, thresholds: tuple[float, float, float]) -> PerformanceClass:
    excellent, good, usable = thresholds
    if tps >= excellent:
        return "excellent"
    if tps >= good:
        return "good"
    if tps >= usable:
        return "usable"
    return "slow"


def estimate_memory(spec: ModelSpec, context: int, traits: RuntimeTraits) -> MemoryEstimate:
    missing: list[str] = []
    weights: int | None = None
    weights_source: Literal["file", "quantization_estimate"] | None = None
    if spec.file_size_bytes:
        weights, weights_source = spec.file_size_bytes, "file"
    elif spec.parameter_count and spec.quantization in BITS_PER_WEIGHT:
        weights = int(spec.parameter_count * BITS_PER_WEIGHT[spec.quantization] / 8)
        weights_source = "quantization_estimate"
    else:
        missing.append("weights")
    kv: int | None = None
    if spec.layer_count and spec.kv_head_count and spec.head_dim:
        kv = int(
            2
            * spec.layer_count
            * context
            * spec.kv_head_count
            * spec.head_dim
            * KV_BYTES[traits.kv_type]
            * max(traits.parallel_sequences, 1)
        )
    else:
        # Sin arquitectura no se inventa el KV cache: con contextos grandes sería el error
        # más grave posible (un 100K "cabe" cuando no cabe).
        missing.append("kv_cache")
    overhead = (
        int(512 * MIB + weights * 0.02 + context / 1024 * 8 * MIB) if weights is not None else None
    )
    total = weights + kv + overhead if weights is not None and kv is not None and overhead else None
    return MemoryEstimate(
        weights_bytes=weights,
        weights_source=weights_source,
        kv_cache_bytes=kv,
        overhead_bytes=overhead,
        total_bytes=total,
        context_tokens=context,
        kv_type=traits.kv_type,
        complete=total is not None,
        missing=tuple(missing),
    )


def usable_ram(hardware: HardwareProfile) -> int | None:
    if not hardware.ram_total_bytes:
        return None
    reserve = max(RAM_RESERVE_MIN, int(hardware.ram_total_bytes * RAM_RESERVE_FRACTION))
    return max(hardware.ram_total_bytes - reserve, 0)


def usable_vram(hardware: HardwareProfile, traits: RuntimeTraits, margin_percent: int) -> int:
    if not traits.gpu:
        return 0
    sizes = [g.vram_total_bytes or 0 for g in hardware.gpu_devices if g.usable_for_offload]
    if not sizes:
        return 0
    raw = sum(sizes) if traits.multi_gpu_split else max(sizes)
    return int(raw * (1 - margin_percent / 100))


def place(
    estimate: MemoryEstimate, hardware: HardwareProfile, traits: RuntimeTraits, margin: int
) -> Fit:
    vram = usable_vram(hardware, traits, margin)
    ram_raw = usable_ram(hardware)
    ram = int(ram_raw * (1 - margin / 100)) if ram_raw is not None else None
    total = estimate.total_bytes
    if total is None:
        return Fit("unknown", None, None, None, vram, ram, margin)
    if vram and total <= vram:
        return Fit("full_gpu", total, None, 1.0, vram, ram, margin)
    if vram and traits.gpu_offload and ram is not None and total - vram <= ram:
        return Fit("partial_offload", vram, total - vram, vram / total, vram, ram, margin)
    if ram is not None and total <= ram:
        return Fit("cpu_only", None, total, 0.0, vram, ram, margin)
    if ram is None:
        return Fit("unknown", None, None, None, vram, ram, margin)
    return Fit("does_not_fit", None, None, None, vram, ram, margin)


def estimate_speed(spec: ModelSpec, estimate: MemoryEstimate, fit: Fit) -> SpeedClass:
    """Velocidad esperada SIN benchmark. Heurística documentada, se sustituye al medir.

    La generación está limitada por el ancho de banda de memoria: en GPU es rápida; con
    offload depende de qué fracción queda en CPU; en CPU depende del tamaño de los pesos.
    Un contexto largo fuera de la GPU baja una clase (procesado del prompt lento).
    """
    weights = estimate.weights_bytes or 0
    if spec.expert_count and spec.expert_count > 1:
        # MoE: por token se leen solo algunos expertos; aproximación prudente (1/4).
        weights = weights // 4
    order: list[SpeedClass] = ["fast", "moderate", "slow"]
    if fit.placement == "full_gpu":
        speed: SpeedClass = "fast"
    elif fit.placement == "partial_offload":
        speed = "moderate" if (fit.gpu_fraction or 0) >= 0.8 else "slow"
    elif fit.placement == "cpu_only":
        speed = "moderate" if weights <= 5 * GIB else "slow"
    else:
        return "unknown"
    if estimate.context_tokens >= LONG_CONTEXT and fit.placement != "full_gpu":
        speed = order[min(order.index(speed) + 1, 2)]
    return speed


def evaluate(
    spec: ModelSpec,
    hardware: HardwareProfile,
    traits: RuntimeTraits,
    context: int,
    margin: int,
    observed: Observed | None = None,
) -> Evaluation:
    """Clasificación de UN modelo (sin comparar con otros; eso es `rank`)."""
    estimate = estimate_memory(spec, context, traits)
    fit = place(estimate, hardware, traits, margin)
    reasons: list[str] = []
    warnings: list[str] = []
    limitations = [
        "Cifras de memoria estimadas; el consumo real depende del runtime y su configuración."
    ]
    status: Status
    speed: SpeedClass = "unknown"
    speed_source: Literal["estimate", "benchmark"] = "estimate"
    effective = spec.effective_params
    quality = quality_label(effective)

    if spec.quantization is None:
        status = "not_recommended"
        reasons.append(
            "Cuantización desconocida: no se puede estimar calidad ni memoria con fiabilidad."
        )
    elif not spec.parameter_count:
        status = "not_recommended"
        reasons.append("Número de parámetros desconocido.")
    elif not estimate.complete:
        status = "not_recommended"
        if "kv_cache" in estimate.missing:
            reasons.append(
                "Faltan capas/cabezas KV del modelo: no se puede estimar el KV cache para "
                f"{context:,} tokens."
            )
        if "weights" in estimate.missing:
            reasons.append("Tamaño de los pesos desconocido.")
    elif spec.native_context is not None and context > spec.native_context:
        status = "not_recommended"
        reasons.append(
            f"El modelo declara {spec.native_context:,} tokens de contexto; "
            f"se pidieron {context:,}."
        )
    elif fit.placement == "unknown":
        status = "not_recommended"
        reasons.append("RAM del servidor desconocida: no se puede comprobar si cabe.")
    elif fit.placement == "does_not_fit":
        status = "not_recommended"
        reasons.append(
            f"Necesita ~{gib(estimate.total_bytes)} y el servidor dispone de "
            f"~{gib(fit.usable_vram_bytes)} de VRAM y ~{gib(fit.usable_ram_bytes)} de RAM "
            "utilizables."
        )
    elif (
        not spec.on_disk
        and hardware.disk_free_bytes is not None
        and (estimate.weights_bytes or 0) > hardware.disk_free_bytes * (1 - margin / 100)
    ):
        status = "not_recommended"
        reasons.append(
            f"Espacio en disco insuficiente: ocupa ~{gib(estimate.weights_bytes)} y hay "
            f"{gib(hardware.disk_free_bytes)} libres."
        )
    else:
        speed = estimate_speed(spec, estimate, fit)
        if observed is not None:
            # La medición real manda sobre la estimación previa.
            speed_source = "benchmark"
            speed = {
                "excellent": "fast",
                "good": "fast",
                "usable": "moderate",
                "slow": "slow",
            }[observed.performance_class]  # type: ignore[assignment]
            reasons.append(
                f"Benchmark local: {observed.generation_tps:.1f} tokens/s "
                f"({observed.performance_class})."
            )
        if fit.placement == "full_gpu":
            status = "compatible"
            reasons.append(
                f"Cabe entero en VRAM (~{gib(estimate.total_bytes)} de "
                f"~{gib(fit.usable_vram_bytes)})."
            )
        elif fit.placement == "partial_offload":
            status = "compatible_with_offload"
            reasons.append(
                f"Excede la VRAM ({gib(fit.usable_vram_bytes)} utilizables), pero el runtime "
                f"admite offload: ~{gib(fit.vram_bytes)} en GPU y ~{gib(fit.ram_bytes)} en RAM."
            )
        else:
            status = "compatible"
            reasons.append(
                f"Se ejecuta en CPU/RAM (~{gib(estimate.total_bytes)} de "
                f"~{gib(fit.usable_ram_bytes)})."
            )
        if speed == "slow":
            status = "slow"
            if observed is None:
                reasons.append(
                    "Se espera generación lenta (pesos grandes fuera de la GPU); un benchmark "
                    "lo confirmará."
                )
        if (
            hardware.ram_available_bytes is not None
            and (fit.ram_bytes or 0) > hardware.ram_available_bytes
        ):
            warnings.append(
                f"Ahora mismo hay {gib(hardware.ram_available_bytes)} de RAM libre: puede no "
                "cargar hasta liberar memoria."
            )
        free_vram = [g.vram_free_bytes for g in hardware.gpu_devices if g.usable_for_offload]
        if (
            fit.vram_bytes
            and free_vram
            and None not in free_vram
            and fit.vram_bytes > sum(v or 0 for v in free_vram)
        ):
            warnings.append("La VRAM libre actual es menor que la estimada (otro proceso la usa).")
    if spec.native_context is None and status != "not_recommended":
        warnings.append("El modelo no declara su contexto máximo: no se garantiza el solicitado.")
    if context >= LONG_CONTEXT and estimate.kv_cache_bytes is not None:
        warnings.append(
            f"Contexto {context:,}: el KV cache ocupa ~{gib(estimate.kv_cache_bytes)} y el "
            "procesado del prompt será lento. Soportado no significa eficiente."
        )
    if context >= VERY_LONG_CONTEXT:
        limitations.append(
            "No se aplica cuantización del KV cache ni flash attention: el runtime no permite "
            "verificar que estén activos."
        )
    return Evaluation(
        spec=spec,
        estimate=estimate,
        fit=fit,
        speed=speed,
        speed_source=speed_source,
        status=status,
        quality=quality,
        reasons=reasons,
        warnings=warnings,
        observed=observed,
        limitations=limitations,
    )


def _score(ev: Evaluation, profile: Profile) -> float | None:
    """Puntuación para elegir "recommended" dentro de un perfil. None = no elegible."""
    if ev.status not in ("compatible", "compatible_with_offload"):
        return None
    effective = ev.spec.effective_params or 0
    total_gib = (ev.estimate.total_bytes or 0) / GIB
    log_q = math.log2(max(effective, 1e8) / 1e9)
    speed_bonus = {"fast": 1.5, "moderate": 0.0}.get(ev.speed, -3.0)
    gpu_bonus = 0.3 if ev.fit.placement == "full_gpu" else 0.0
    if profile == "low_resource":
        # Menor memoria con una calidad mínima razonable.
        return -total_gib if effective >= SENTRA_MIN_EFFECTIVE_PARAMS else -total_gib - 1000
    if profile == "balanced":
        return log_q + speed_bonus * 0.7 + gpu_bonus
    if profile == "quality":
        return log_q + gpu_bonus * 0.1
    if profile == "max_speed":
        rank = {"fast": 2, "moderate": 1}.get(ev.speed, 0)
        tps = ev.observed.generation_tps if ev.observed else 0.0
        return rank * 100 + tps / 10 - total_gib * 0.5
    # sentra: el Detection/Correlation/Risk Engine ya estructuran la evidencia, así que más
    # allá de ~32B efectivos no se gana tanto como se pierde en latencia. La velocidad pesa
    # mucho: un 14B rápido supera a un 32B con offload, pero un 32B que cabe entero en GPU
    # gana a ambos.
    if effective < SENTRA_MIN_EFFECTIVE_PARAMS:
        return None
    capped = math.log2(min(effective, 32e9) / 1e9)
    return capped + speed_bonus + gpu_bonus


def rank(evaluations: list[Evaluation], profile: Profile) -> list[Evaluation]:
    """Marca el mejor candidato del perfil como "recommended" y el mejor para Sentra.

    Determinista: empates por clave del modelo. Solo puede recomendarse un modelo que cabe y
    no es lento; si ninguno lo cumple, no hay recomendación (no se fuerza una).
    """

    def best(target: Profile) -> Evaluation | None:
        scored = [(s, ev) for ev in evaluations if (s := _score(ev, target)) is not None]
        if not scored:
            return None
        scored.sort(key=lambda item: (-item[0], item[1].spec.key))
        return scored[0][1]

    # Ambos ganadores se eligen ANTES de cambiar estados: marcar "recommended" primero
    # sacaría a ese modelo de la elección del otro perfil.
    for ev in evaluations:
        ev.score = _score(ev, profile)
    winner = best(profile)
    sentra = best("sentra")
    if winner is not None:
        winner.status = "recommended"
        winner.reasons.insert(0, f"Mejor opción para el perfil {profile} en este hardware.")
    if sentra is not None:
        sentra.recommended_for_sentra = True
    return sorted(
        evaluations,
        key=lambda ev: (
            _STATUS_ORDER[ev.status],
            -(ev.score if ev.score is not None else -1e9),
            ev.spec.key,
        ),
    )
