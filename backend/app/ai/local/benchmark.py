"""Benchmark local controlado (Fase 4J.2).

Diseño:
- prompt FIJO y no sensible (nunca datos de Sentra) y límite de tokens por pasada;
- se ejecuta en un hilo aparte (BenchmarkManager), nunca en el hilo de la petición: la API
  responde 202 al momento y la UI consulta el estado;
- concurrencia 1 por proceso: un segundo benchmark recibe "ocupado";
- plazo máximo total (AI_BENCHMARK_TIMEOUT_SECONDS): cada llamada al runtime se acota con
  el tiempo que queda;
- cancelación cooperativa: se comprueba entre pasos. Una llamada en curso no se interrumpe
  a la fuerza (http.client no lo permite de forma segura), pero está acotada por el plazo;
- nada sale del servidor: solo se habla con el runtime local configurado;
- nunca se ejecuta al arrancar Sentra: solo por acción explícita de un admin.

Métricas: tiempo de carga (si el runtime puede cargar), TTFT, tokens/s de prompt y de
generación (según el runtime: medidos por él o extremo a extremo por Sentra) y picos de RAM
y VRAM del SISTEMA muestreados cada segundo (observados, no atribuidos al runtime).
"""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from app.ai.local.runtimes import BenchmarkSample, LocalAIRuntime
from app.ai.provider import AIError, AITimeoutError

# Texto neutro: ningún dato de activos, usuarios ni red sale hacia el modelo.
BENCHMARK_PROMPT = (
    "Explica en español, en un párrafo breve, qué es el principio de mínimo privilegio en "
    "seguridad informática y por qué reduce el impacto de una cuenta comprometida."
)
BENCHMARK_RUNS = 2
SAMPLE_INTERVAL_SECONDS = 1.0

MemorySampler = Callable[[], tuple[int | None, int | None]]


class BenchmarkCancelledError(Exception):
    pass


@dataclass(frozen=True)
class BenchmarkOutcome:
    measurement: str
    load_ms: int | None
    ttft_ms: int | None
    prompt_tokens: int | None
    output_tokens: int | None
    prompt_tps: float | None
    generation_tps: float | None
    peak_ram_bytes: int | None
    peak_vram_bytes: int | None


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 2) if values else None


class _Sampler:
    """Muestrea memoria del sistema en segundo plano y guarda los picos."""

    def __init__(self, sample: MemorySampler) -> None:
        self._sample = sample
        self._stop = threading.Event()
        self.peak_ram: int | None = None
        self.peak_vram: int | None = None
        self._thread = threading.Thread(target=self._run, name="ai-benchmark-sampler", daemon=True)

    def _take(self) -> None:
        try:
            ram, vram = self._sample()
        except Exception:
            # Una sonda de memoria rota no invalida la medición de velocidad.
            return
        if ram is not None:
            self.peak_ram = max(self.peak_ram or 0, ram)
        if vram is not None:
            self.peak_vram = max(self.peak_vram or 0, vram)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._take()
            self._stop.wait(SAMPLE_INTERVAL_SECONDS)

    def __enter__(self) -> "_Sampler":
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._take()


def run_benchmark(
    runtime: LocalAIRuntime,
    model_id: str,
    *,
    max_tokens: int,
    timeout_seconds: float,
    cancel: threading.Event,
    sampler: MemorySampler,
    load_first: bool,
) -> BenchmarkOutcome:
    """Ejecuta el benchmark. Lanza BenchmarkCancelledError, AITimeoutError o AIError."""
    deadline = time.monotonic() + timeout_seconds

    def remaining() -> float:
        if cancel.is_set():
            raise BenchmarkCancelledError
        left = deadline - time.monotonic()
        if left <= 0:
            raise AITimeoutError("The benchmark exceeded AI_BENCHMARK_TIMEOUT_SECONDS")
        return left

    samples: list[BenchmarkSample] = []
    load_ms: int | None = None
    with _Sampler(sampler) as memory:
        if load_first:
            remaining()
            load_ms = runtime.load_model(model_id)
        for _ in range(BENCHMARK_RUNS):
            samples.append(runtime.benchmark(model_id, BENCHMARK_PROMPT, max_tokens, remaining()))
        remaining()
    if not samples or not any(s.generation_tps for s in samples):
        raise AIError("The runtime did not report generation speed")
    # La primera pasada puede incluir la carga perezosa del modelo: si hay varias, la carga
    # se toma de la primera y las métricas de velocidad de las pasadas "calientes".
    warm = samples[1:] or samples
    if load_ms is None:
        load_ms = samples[0].load_ms
    return BenchmarkOutcome(
        measurement=samples[-1].measurement,
        load_ms=load_ms,
        ttft_ms=int(v)
        if (v := _mean([s.ttft_ms for s in warm if s.ttft_ms is not None]))
        else None,
        prompt_tokens=warm[-1].prompt_tokens,
        output_tokens=warm[-1].output_tokens,
        prompt_tps=_mean([s.prompt_tps for s in warm if s.prompt_tps]),
        generation_tps=_mean([s.generation_tps for s in warm if s.generation_tps]),
        peak_ram_bytes=memory.peak_ram,
        peak_vram_bytes=memory.peak_vram,
    )


class AIBenchmarkBusyError(AIError):
    status_code = 409
    code = "ai_benchmark_busy"


class BenchmarkManager:
    """Un benchmark a la vez por proceso, en un hilo propio y cancelable."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._current: tuple[int, threading.Event, threading.Thread] | None = None

    def start(self, benchmark_pk: int, job: Callable[[threading.Event], None]) -> None:
        with self._lock:
            if self._current is not None and self._current[2].is_alive():
                raise AIBenchmarkBusyError("Another benchmark is running; wait or cancel it")
            cancel = threading.Event()

            def target() -> None:
                try:
                    job(cancel)
                finally:
                    with self._lock:
                        if self._current is not None and self._current[0] == benchmark_pk:
                            self._current = None

            thread = threading.Thread(target=target, name="ai-benchmark", daemon=True)
            self._current = (benchmark_pk, cancel, thread)
            thread.start()

    def running(self) -> int | None:
        with self._lock:
            if self._current is not None and self._current[2].is_alive():
                return self._current[0]
            return None

    def cancel(self, benchmark_pk: int) -> bool:
        with self._lock:
            if self._current is None or self._current[0] != benchmark_pk:
                return False
            self._current[1].set()
            return True

    def wait(self, timeout: float = 30.0) -> None:
        """Espera al benchmark en curso (tests y apagado ordenado)."""
        with self._lock:
            current = self._current
        if current is not None:
            current[2].join(timeout)
