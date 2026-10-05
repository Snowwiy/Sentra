"""Runtimes de IA local (Fase 4J.2): modelo y runtime son cosas separadas.

`LocalAIRuntime` es el contrato; cada adapter declara en `CAPABILITIES` lo que REALMENTE
sabe hacer, y el gestor nunca finge una operación que el runtime no tiene:

| runtime            | listar | cargar | descargar | benchmark            | offload GPU |
|--------------------|--------|--------|-----------|----------------------|-------------|
| llama_cpp (server) | sí     | no (*) | no (*)    | timings del runtime  | sí          |
| ollama             | sí     | sí     | sí        | timings del runtime  | sí          |
| vllm               | sí     | no (*) | no (*)    | extremo a extremo    | no          |
| openai_compatible  | sí     | no     | no        | extremo a extremo    | desconocido |

(*) llama-server y vLLM cargan UN modelo al arrancar (`-m fichero.gguf`, `--model`). Sentra
no arranca procesos: seleccionar un modelo verifica que es el que el runtime tiene cargado.
Lanzar procesos desde la API sería ejecución remota, fuera del alcance de esta fase.

Seguridad (4J.1 intacta): todas las llamadas salen por `OpenAICompatibleProvider` contra
AI_BASE_URL, así que heredan la validación de destino, la comprobación de la IP real antes
de enviar nada, sin redirecciones ni proxy, timeouts y tope de tamaño. No hay descubrimiento
de red: solo se consulta el endpoint configurado. Las rutas son constantes de este módulo.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from fastapi import status

from app.ai.config import AIConfig
from app.ai.local.engine import RuntimeTraits
from app.ai.local.quant import normalize_quantization
from app.ai.openai_compat import OpenAICompatibleProvider
from app.ai.provider import AIError, AIProviderUnavailableError

RuntimeKind = Literal["openai_compatible", "llama_cpp", "ollama", "vllm"]
RUNTIME_KINDS: tuple[RuntimeKind, ...] = ("llama_cpp", "ollama", "vllm", "openai_compatible")
BenchmarkMeasurement = Literal["runtime_timings", "end_to_end"]

PROBE_TIMEOUT = 5.0
LIST_TIMEOUT = 8.0
LOAD_TIMEOUT = 300.0


def as_runtime_kind(value: str | None) -> RuntimeKind | None:
    """Valor guardado en BD -> RuntimeKind (None si no es uno conocido)."""
    return next((kind for kind in RUNTIME_KINDS if kind == value), None)


class AIRuntimeUnsupportedError(AIError):
    # La operación no existe en este runtime (p. ej. cargar un modelo en llama-server).
    status_code = status.HTTP_409_CONFLICT
    code = "ai_runtime_operation_unsupported"


@dataclass(frozen=True)
class RuntimeCapabilities:
    kind: RuntimeKind
    label: str
    list_models: bool
    load_model: bool
    unload_model: bool
    benchmark: BenchmarkMeasurement
    gpu: bool
    gpu_offload: bool
    multi_gpu_split: bool
    gguf_files: bool
    notes: tuple[str, ...] = field(default_factory=tuple)

    def traits(self) -> RuntimeTraits:
        return RuntimeTraits(
            kind=self.kind,
            gpu=self.gpu,
            gpu_offload=self.gpu_offload,
            multi_gpu_split=self.multi_gpu_split,
        )


CAPABILITIES: dict[RuntimeKind, RuntimeCapabilities] = {
    "llama_cpp": RuntimeCapabilities(
        kind="llama_cpp",
        label="llama.cpp",
        list_models=True,
        load_model=False,
        unload_model=False,
        benchmark="runtime_timings",
        gpu=True,
        gpu_offload=True,
        multi_gpu_split=True,
        gguf_files=True,
        notes=(
            "llama-server carga el GGUF al arrancar (-m). Para cambiar de modelo, reinícialo "
            "con el fichero registrado y pulsa Seleccionar: Sentra verifica que es el cargado.",
            "Offload a GPU con -ngl; varias GPU se reparten por capas.",
        ),
    ),
    "ollama": RuntimeCapabilities(
        kind="ollama",
        label="Ollama",
        list_models=True,
        load_model=True,
        unload_model=True,
        benchmark="runtime_timings",
        gpu=True,
        gpu_offload=True,
        multi_gpu_split=True,
        gguf_files=False,
        notes=(
            "Los modelos se gestionan con Ollama (ollama pull/create); Sentra los registra "
            "desde su lista. Importar un GGUF suelto requiere un Modelfile en Ollama.",
        ),
    ),
    "vllm": RuntimeCapabilities(
        kind="vllm",
        label="vLLM",
        list_models=True,
        load_model=False,
        unload_model=False,
        benchmark="end_to_end",
        gpu=True,
        gpu_offload=False,
        multi_gpu_split=False,
        gguf_files=False,
        notes=(
            "vLLM sirve el modelo indicado al arrancar y exige que quepa en la GPU (sin "
            "offload a RAM por defecto). Tensor parallel no se configura desde Sentra.",
        ),
    ),
    "openai_compatible": RuntimeCapabilities(
        kind="openai_compatible",
        label="OpenAI-compatible",
        list_models=True,
        load_model=False,
        unload_model=False,
        benchmark="end_to_end",
        gpu=True,
        gpu_offload=False,
        multi_gpu_split=False,
        gguf_files=False,
        notes=(
            "Servidor genérico (LM Studio...): solo /v1/models y /v1/chat/completions. Las "
            "estimaciones asumen GPU sin offload; elige el runtime concreto si lo conoces.",
        ),
    ),
}


@dataclass(frozen=True)
class RuntimeHealth:
    reachable: bool
    latency_ms: int
    detail: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class RuntimeModel:
    """Un modelo tal como lo informa el runtime (sin rutas: solo el nombre de fichero)."""

    id: str
    loaded: bool | None
    size_bytes: int | None = None
    parameter_count: int | None = None
    quantization: str | None = None
    family: str | None = None
    architecture: str | None = None
    native_context: int | None = None
    configured_context: int | None = None
    layer_count: int | None = None
    kv_head_count: int | None = None
    head_dim: int | None = None
    file_name: str | None = None
    vram_bytes: int | None = None


@dataclass(frozen=True)
class BenchmarkSample:
    total_ms: int
    measurement: BenchmarkMeasurement
    load_ms: int | None = None
    ttft_ms: int | None = None
    prompt_tokens: int | None = None
    output_tokens: int | None = None
    prompt_tps: float | None = None
    generation_tps: float | None = None


class LocalAIRuntime(Protocol):
    kind: RuntimeKind

    def capabilities(self) -> RuntimeCapabilities: ...

    def health(self) -> RuntimeHealth: ...

    def list_models(self) -> list[RuntimeModel]: ...

    def model_details(self, model_id: str) -> RuntimeModel | None: ...

    def load_model(self, model_id: str) -> int: ...

    def unload_model(self, model_id: str) -> None: ...

    def benchmark(
        self, model_id: str, prompt: str, max_tokens: int, timeout: float
    ) -> BenchmarkSample: ...


# --- Utilidades ------------------------------------------------------------------------------


def _pos_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return value if isinstance(value, int) and value > 0 else None


def _text(value: Any, limit: int = 256) -> str | None:
    return value.strip()[:limit] or None if isinstance(value, str) else None


def file_basename(path: Any) -> str | None:
    """Solo el nombre del fichero (el runtime puede informar la ruta completa)."""
    text = _text(path, 1024)
    return re.split(r"[\\/]", text)[-1][:255] or None if text else None


def _ns_to_ms(value: Any) -> int | None:
    number = _pos_int(value)
    return number // 1_000_000 if number is not None else None


def _rate(tokens: Any, duration_ns: Any) -> float | None:
    count, ns = _pos_int(tokens), _pos_int(duration_ns)
    return round(count / (ns / 1e9), 2) if count and ns else None


def _ok(status_code: int, what: str) -> None:
    if status_code != 200:
        raise AIProviderUnavailableError(
            f"The local AI runtime refused {what} (HTTP {status_code})"
        )


def _parameter_size(value: Any) -> int | None:
    """'8.0B' / '770M' (Ollama) -> número aproximado de parámetros."""
    text = _text(value, 16)
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([BMK])", text or "", re.I)
    if not match:
        return None
    scale = {"B": 1e9, "M": 1e6, "K": 1e3}[match.group(2).upper()]
    return int(float(match.group(1)) * scale)


class _HttpRuntime:
    kind: RuntimeKind

    def __init__(self, config: AIConfig) -> None:
        # El provider exige un nombre de modelo; para operaciones del runtime no se usa (cada
        # petición lleva el suyo), así que basta uno simbólico.
        self._http = OpenAICompatibleProvider(config, model=config.model or "sentra-runtime")

    def capabilities(self) -> RuntimeCapabilities:
        return CAPABILITIES[self.kind]

    def _get(self, path: str, timeout: float = LIST_TIMEOUT) -> tuple[int, Any, int]:
        return self._http.call_json("GET", path, None, timeout)

    def _post(self, path: str, payload: dict[str, Any], timeout: float) -> tuple[int, Any, int]:
        return self._http.call_json("POST", path, payload, timeout)

    def _probe(self, path: str) -> RuntimeHealth:
        try:
            status_code, body, latency = self._get(path, PROBE_TIMEOUT)
        except AIError as exc:
            return RuntimeHealth(False, 0, exc.message)
        if status_code == 503:
            return RuntimeHealth(False, latency, "The runtime is loading a model")
        if status_code != 200:
            return RuntimeHealth(False, latency, f"The runtime answered HTTP {status_code}")
        version = _text(body.get("version"), 64) if isinstance(body, dict) else None
        return RuntimeHealth(True, latency, None, version)

    def _openai_models(self) -> list[dict[str, Any]]:
        status_code, body, _ = self._get(self._http.base_path + "/models")
        _ok(status_code, "the model list")
        data = body.get("data") if isinstance(body, dict) else None
        return (
            [m for m in data if isinstance(m, dict) and _text(m.get("id"))][:500]
            if isinstance(data, list)
            else []
        )

    def model_details(self, model_id: str) -> RuntimeModel | None:
        return next((m for m in self.list_models() if m.id == model_id), None)

    def list_models(self) -> list[RuntimeModel]:
        raise NotImplementedError

    def load_model(self, model_id: str) -> int:
        raise AIRuntimeUnsupportedError(
            f"{CAPABILITIES[self.kind].label} cannot load models on demand"
        )

    def unload_model(self, model_id: str) -> None:
        raise AIRuntimeUnsupportedError(
            f"{CAPABILITIES[self.kind].label} cannot unload models on demand"
        )

    def _chat_benchmark(
        self, model_id: str, prompt: str, max_tokens: int, timeout: float
    ) -> BenchmarkSample:
        """Medición extremo a extremo: tokens generados / tiempo total (incluye el prompt)."""
        status_code, body, latency = self._post(
            self._http.base_path + "/chat/completions",
            {
                "model": model_id,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": 0,
                "stream": False,
            },
            timeout,
        )
        _ok(status_code, "the benchmark request")
        usage = body.get("usage") if isinstance(body, dict) else None
        usage = usage if isinstance(usage, dict) else {}
        output = _pos_int(usage.get("completion_tokens"))
        return BenchmarkSample(
            total_ms=latency,
            measurement="end_to_end",
            prompt_tokens=_pos_int(usage.get("prompt_tokens")),
            output_tokens=output,
            generation_tps=round(output / (latency / 1000), 2) if output and latency else None,
        )


class LlamaCppRuntime(_HttpRuntime):
    kind: RuntimeKind = "llama_cpp"

    def health(self) -> RuntimeHealth:
        return self._probe(self._http.root_path + "/health")

    def list_models(self) -> list[RuntimeModel]:
        models = self._openai_models()
        props: dict[str, Any] = {}
        try:
            status_code, body, _ = self._get(self._http.root_path + "/props", PROBE_TIMEOUT)
            if status_code == 200 and isinstance(body, dict):
                props = body
        except AIError:
            props = {}
        settings = props.get("default_generation_settings")
        n_ctx = _pos_int(settings.get("n_ctx")) if isinstance(settings, dict) else None
        n_ctx = n_ctx or _pos_int(props.get("n_ctx"))
        file_name = file_basename(props.get("model_path"))
        result = []
        for model in models:
            raw_meta = model.get("meta")
            meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
            result.append(
                RuntimeModel(
                    id=str(model["id"])[:256],
                    # llama-server solo sirve el modelo con el que arrancó: siempre cargado.
                    loaded=True,
                    size_bytes=_pos_int(meta.get("size")),
                    parameter_count=_pos_int(meta.get("n_params")),
                    native_context=_pos_int(meta.get("n_ctx_train")),
                    configured_context=n_ctx,
                    file_name=file_name or file_basename(model.get("id")),
                )
            )
        return result

    def benchmark(
        self, model_id: str, prompt: str, max_tokens: int, timeout: float
    ) -> BenchmarkSample:
        status_code, body, latency = self._post(
            self._http.root_path + "/completion",
            # cache_prompt=false: cada pasada procesa el prompt entero (medición comparable).
            {"prompt": prompt, "n_predict": max_tokens, "temperature": 0, "cache_prompt": False},
            timeout,
        )
        _ok(status_code, "the benchmark request")
        timings = body.get("timings") if isinstance(body, dict) else None
        if not isinstance(timings, dict):
            return BenchmarkSample(total_ms=latency, measurement="end_to_end")

        def number(key: str) -> float | None:
            value = timings.get(key)
            return float(value) if isinstance(value, int | float) and value > 0 else None

        prompt_ms = number("prompt_ms")
        return BenchmarkSample(
            total_ms=latency,
            measurement="runtime_timings",
            # Sin streaming, el primer token llega tras procesar el prompt.
            ttft_ms=int(prompt_ms) if prompt_ms is not None else None,
            prompt_tokens=_pos_int(timings.get("prompt_n")),
            output_tokens=_pos_int(timings.get("predicted_n")),
            prompt_tps=round(v, 2) if (v := number("prompt_per_second")) else None,
            generation_tps=round(v, 2) if (v := number("predicted_per_second")) else None,
        )


class OllamaRuntime(_HttpRuntime):
    kind: RuntimeKind = "ollama"

    def health(self) -> RuntimeHealth:
        return self._probe(self._http.root_path + "/api/version")

    def _loaded(self) -> dict[str, dict[str, Any]]:
        status_code, body, _ = self._get(self._http.root_path + "/api/ps", PROBE_TIMEOUT)
        if (
            status_code != 200
            or not isinstance(body, dict)
            or not isinstance(body.get("models"), list)
        ):
            return {}
        return {
            str(m.get("name")): m for m in body["models"] if isinstance(m, dict) and m.get("name")
        }

    def list_models(self) -> list[RuntimeModel]:
        status_code, body, _ = self._get(self._http.root_path + "/api/tags")
        _ok(status_code, "the model list")
        loaded = self._loaded()
        result = []
        raw = body.get("models") if isinstance(body, dict) else None
        for model in (raw if isinstance(raw, list) else [])[:500]:
            if not isinstance(model, dict) or not _text(model.get("name")):
                continue
            name = str(model["name"])[:256]
            raw_details = model.get("details")
            details: dict[str, Any] = raw_details if isinstance(raw_details, dict) else {}
            running = loaded.get(name)
            result.append(
                RuntimeModel(
                    id=name,
                    loaded=running is not None,
                    size_bytes=_pos_int(model.get("size")),
                    parameter_count=_parameter_size(details.get("parameter_size")),
                    quantization=normalize_quantization(_text(details.get("quantization_level"))),
                    family=_text(details.get("family"), 64),
                    configured_context=_pos_int(running.get("context_length")) if running else None,
                    vram_bytes=_pos_int(running.get("size_vram")) if running else None,
                )
            )
        return result

    def model_details(self, model_id: str) -> RuntimeModel | None:
        base = next((m for m in self.list_models() if m.id == model_id), None)
        if base is None:
            return None
        status_code, body, _ = self._post(
            self._http.root_path + "/api/show", {"model": model_id}, LIST_TIMEOUT
        )
        info = body.get("model_info") if status_code == 200 and isinstance(body, dict) else None
        if not isinstance(info, dict):
            return base
        arch = _text(info.get("general.architecture"), 64)

        def arch_int(suffix: str) -> int | None:
            return _pos_int(info.get(f"{arch}.{suffix}")) if arch else None

        heads = arch_int("attention.head_count")
        embedding = arch_int("embedding_length")
        head_dim = arch_int("attention.key_length") or (
            embedding // heads if embedding and heads else None
        )
        return RuntimeModel(
            id=base.id,
            loaded=base.loaded,
            size_bytes=base.size_bytes,
            # El recuento exacto de model_info manda sobre "8.0B" de la lista.
            parameter_count=_pos_int(info.get("general.parameter_count")) or base.parameter_count,
            quantization=base.quantization,
            family=base.family,
            architecture=arch,
            native_context=arch_int("context_length"),
            configured_context=base.configured_context,
            layer_count=arch_int("block_count"),
            kv_head_count=arch_int("attention.head_count_kv") or heads,
            head_dim=head_dim,
            vram_bytes=base.vram_bytes,
        )

    def load_model(self, model_id: str) -> int:
        # Prompt vacío = Ollama solo carga el modelo en memoria (no genera nada).
        status_code, _, latency = self._post(
            self._http.root_path + "/api/generate",
            {"model": model_id, "prompt": "", "stream": False, "keep_alive": "30m"},
            LOAD_TIMEOUT,
        )
        _ok(status_code, "to load the model")
        return latency

    def unload_model(self, model_id: str) -> None:
        status_code, _, _ = self._post(
            self._http.root_path + "/api/generate",
            {"model": model_id, "prompt": "", "stream": False, "keep_alive": 0},
            LIST_TIMEOUT,
        )
        _ok(status_code, "to unload the model")

    def benchmark(
        self, model_id: str, prompt: str, max_tokens: int, timeout: float
    ) -> BenchmarkSample:
        status_code, body, latency = self._post(
            self._http.root_path + "/api/generate",
            {
                "model": model_id,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": max_tokens, "temperature": 0},
            },
            timeout,
        )
        _ok(status_code, "the benchmark request")
        body = body if isinstance(body, dict) else {}
        load_ms = _ns_to_ms(body.get("load_duration"))
        prompt_ms = _ns_to_ms(body.get("prompt_eval_duration"))
        return BenchmarkSample(
            total_ms=latency,
            measurement="runtime_timings",
            load_ms=load_ms,
            ttft_ms=(load_ms or 0) + prompt_ms if prompt_ms is not None else None,
            prompt_tokens=_pos_int(body.get("prompt_eval_count")),
            output_tokens=_pos_int(body.get("eval_count")),
            prompt_tps=_rate(body.get("prompt_eval_count"), body.get("prompt_eval_duration")),
            generation_tps=_rate(body.get("eval_count"), body.get("eval_duration")),
        )


class VLLMRuntime(_HttpRuntime):
    kind: RuntimeKind = "vllm"

    def health(self) -> RuntimeHealth:
        health = self._probe(self._http.root_path + "/health")
        if health.reachable:
            version = self._probe(self._http.root_path + "/version")
            return RuntimeHealth(True, health.latency_ms, None, version.version)
        return health

    def list_models(self) -> list[RuntimeModel]:
        return [
            RuntimeModel(
                id=str(m["id"])[:256],
                loaded=True,
                configured_context=_pos_int(m.get("max_model_len")),
            )
            for m in self._openai_models()
        ]

    def benchmark(
        self, model_id: str, prompt: str, max_tokens: int, timeout: float
    ) -> BenchmarkSample:
        return self._chat_benchmark(model_id, prompt, max_tokens, timeout)


class GenericRuntime(_HttpRuntime):
    kind: RuntimeKind = "openai_compatible"

    def health(self) -> RuntimeHealth:
        check = self._http.check()
        return RuntimeHealth(check.reachable, check.latency_ms, check.detail)

    def list_models(self) -> list[RuntimeModel]:
        return [RuntimeModel(id=str(m["id"])[:256], loaded=None) for m in self._openai_models()]

    def benchmark(
        self, model_id: str, prompt: str, max_tokens: int, timeout: float
    ) -> BenchmarkSample:
        return self._chat_benchmark(model_id, prompt, max_tokens, timeout)


_ADAPTERS: dict[RuntimeKind, type[_HttpRuntime]] = {
    "llama_cpp": LlamaCppRuntime,
    "ollama": OllamaRuntime,
    "vllm": VLLMRuntime,
    "openai_compatible": GenericRuntime,
}


def default_runtime_factory(kind: RuntimeKind, config: AIConfig) -> LocalAIRuntime:
    """Crea el adapter. Lanza AIDestinationBlockedError/ValueError si el destino no vale."""
    return _ADAPTERS[kind](config)  # type: ignore[return-value]


def detect_runtime(config: AIConfig) -> RuntimeKind | None:
    """Qué runtime hay detrás de AI_BASE_URL, probando SOLO ese endpoint (sin escanear red).

    Cada sonda es un GET de solo lectura con timeout corto. Devuelve None si no responde.
    """
    http = OpenAICompatibleProvider(config, model=config.model or "sentra-runtime")
    probes: list[tuple[RuntimeKind, str, str]] = [
        ("ollama", "/api/version", "version"),
        ("llama_cpp", "/props", "default_generation_settings"),
        ("vllm", "/version", "version"),
    ]
    for kind, path, key in probes:
        try:
            status_code, body, _ = http.call_json("GET", http.root_path + path, None, PROBE_TIMEOUT)
        except AIError:
            return None
        if status_code == 200 and isinstance(body, dict) and key in body:
            return kind
    return "openai_compatible"
