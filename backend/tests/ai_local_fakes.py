"""Fakes deterministas de la Fase 4J.2: GGUF sintéticos, hardware y runtimes locales.

Nada aquí necesita GPU, Internet ni modelos reales:
- `write_gguf` escribe una cabecera GGUF v3 válida (metadata + tabla de tensores) seguida de
  bytes de relleno, suficiente para el lector de Sentra;
- `FakeSource` simula /proc, /sys, nvidia-smi y el registro de Windows;
- `FakeRuntimeServer` es un servidor HTTP en 127.0.0.1 que imita llama-server u Ollama, así
  los tests pasan por el proveedor real (comprobaciones de 4J.1 incluidas).
"""

import json
import struct
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from app.ai.local.hardware import GIB, SystemSource

# --- GGUF -----------------------------------------------------------------------------------


def _string(value: str) -> bytes:
    raw = value.encode()
    return struct.pack("<Q", len(raw)) + raw


def _kv(key: str, value: Any) -> bytes:
    if isinstance(value, str):
        return _string(key) + struct.pack("<I", 8) + _string(value)
    if isinstance(value, list):
        # Array de strings (como el vocabulario), para probar que se salta sin leerlo.
        body = b"".join(_string(v) for v in value)
        return _string(key) + struct.pack("<IIQ", 9, 8, len(value)) + body
    return _string(key) + struct.pack("<I", 4) + struct.pack("<I", value)


def write_gguf(
    path: Path,
    *,
    arch: str = "llama",
    name: str | None = "Test Model",
    file_type: int | None = 15,
    tensors: list[tuple[int, ...]] | None = None,
    tensor_type: int = 12,
    context: int | None = 32768,
    layers: int | None = 32,
    heads: int = 32,
    kv_heads: int | None = 8,
    embedding: int = 4096,
    padding: int = 4096,
    extra: dict[str, Any] | None = None,
) -> Path:
    """Escribe un GGUF v3 mínimo. Los tensores por defecto suman ~8.0B de parámetros."""
    tensors = tensors if tensors is not None else [(4096, 976_563), (4096, 976_563)]
    meta: dict[str, Any] = {"general.architecture": arch}
    if name:
        meta["general.name"] = name
    if file_type is not None:
        meta["general.file_type"] = file_type
    if context:
        meta[f"{arch}.context_length"] = context
    if layers:
        meta[f"{arch}.block_count"] = layers
    meta[f"{arch}.attention.head_count"] = heads
    if kv_heads:
        meta[f"{arch}.attention.head_count_kv"] = kv_heads
    meta[f"{arch}.embedding_length"] = embedding
    meta["tokenizer.ggml.tokens"] = ["<s>", "</s>", "hola"]
    meta.update(extra or {})
    out = b"GGUF" + struct.pack("<IQQ", 3, len(tensors), len(meta))
    out += b"".join(_kv(k, v) for k, v in meta.items())
    for i, dims in enumerate(tensors):
        out += _string(f"blk.{i}.weight") + struct.pack("<I", len(dims))
        out += b"".join(struct.pack("<Q", d) for d in dims)
        out += struct.pack("<IQ", tensor_type, 0)
    path.write_bytes(out + b"\0" * padding)
    return path


# --- Hardware --------------------------------------------------------------------------------


@dataclass
class FakeSource(SystemSource):
    """Sistema simulado. Por defecto: Linux x86_64, 8 núcleos, 32 GB y sin GPU."""

    os_name: str = "Linux"
    ram_total: int = 32 * GIB
    ram_available: int = 24 * GIB
    files: dict[str, str] = field(default_factory=dict)
    dirs: dict[str, list[str]] = field(default_factory=dict)
    smi: str | None = None
    adapters: list[dict[str, object]] = field(default_factory=list)
    disk: tuple[int, int] | None = (1000 * GIB, 500 * GIB)
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def system(self) -> str:
        return self.os_name

    def release(self) -> str | None:
        return "6.1"

    def machine(self) -> str:
        return "x86_64"

    def logical_cores(self) -> int | None:
        return 16

    def read_text(self, path: str, limit: int = 1024 * 1024) -> str | None:
        if path == "/proc/meminfo":
            return (
                f"MemTotal: {self.ram_total // 1024} kB\n"
                f"MemAvailable: {self.ram_available // 1024} kB\n"
            )
        if path == "/proc/cpuinfo" and path not in self.files:
            blocks = [
                f"processor\t: {i}\nmodel name\t: Test CPU 8-Core\nphysical id\t: 0\n"
                f"core id\t: {i % 8}\n"
                for i in range(16)
            ]
            return "\n".join(blocks)
        return self.files.get(path)

    def list_dir(self, path: str) -> list[str]:
        return self.dirs.get(path, [])

    def nvidia_smi(self, query: tuple[str, ...]) -> str | None:
        self.calls.append(query)
        if self.smi is None:
            return None
        if "memory.used" in query[0]:
            return "\n".join("1000" for _ in self.smi.strip().splitlines())
        return self.smi

    def disk_usage(self, path: str) -> tuple[int, int] | None:
        return self.disk

    def windows_memory(self) -> tuple[int, int] | None:
        return (self.ram_total, self.ram_available) if self.os_name == "Windows" else None

    def windows_physical_cores(self) -> int | None:
        return 8 if self.os_name == "Windows" else None

    def windows_cpu_name(self) -> str | None:
        return "Test CPU Windows" if self.os_name == "Windows" else None

    def windows_display_adapters(self) -> list[dict[str, object]]:
        return self.adapters


def nvidia(*vram_gb: int) -> str:
    """Salida de nvidia-smi para una o varias GPU NVIDIA (MiB)."""
    return "\n".join(
        f"{i}, NVIDIA GeForce RTX Test {i}, {gb * 1024}, {gb * 1024 - 500}, 555.85"
        for i, gb in enumerate(vram_gb)
    )


# --- Runtime HTTP local -----------------------------------------------------------------------


class FakeRuntimeServer:
    """Imita llama-server (`kind="llama_cpp"`) u Ollama (`kind="ollama"`) en 127.0.0.1."""

    def __init__(self, kind: str = "llama_cpp") -> None:
        self.kind = kind
        self.requests: list[tuple[str, str, Any]] = []
        self.healthy = True
        self.fail_chat = False
        self.fail_completion = False
        self.slow_seconds = 0.0
        # llama.cpp: fichero cargado y parámetros; Ollama: modelos disponibles y cargados.
        self.loaded_file = "model-Q4_K_M.gguf"
        self.n_params: int | None = None
        self.ollama_models = ["qwen-test:8b"]
        self.ollama_loaded: set[str] = set()
        server = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status: int, payload: Any) -> None:
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                server.requests.append(("GET", self.path, None))
                self._send(*server.get(self.path))

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"null")
                server.requests.append(("POST", self.path, payload))
                self._send(*server.post(self.path, payload))

            def log_message(self, *args: Any) -> None:
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}/v1"

    def get(self, path: str) -> tuple[int, Any]:
        if not self.healthy:
            return 503, {"error": "loading"}
        if self.kind == "llama_cpp":
            if path == "/health":
                return 200, {"status": "ok"}
            if path == "/props":
                return 200, {
                    "model_path": f"D:\\Models\\{self.loaded_file}",
                    "default_generation_settings": {"n_ctx": 16384},
                }
            if path == "/v1/models":
                meta = {"n_params": self.n_params} if self.n_params else {}
                return 200, {"data": [{"id": self.loaded_file, "meta": meta}]}
        if self.kind == "ollama":
            if path == "/api/version":
                return 200, {"version": "0.9.0"}
            if path == "/api/tags":
                return 200, {
                    "models": [
                        {
                            "name": name,
                            "size": 5 * GIB,
                            "details": {
                                "family": "qwen3",
                                "parameter_size": "8.2B",
                                "quantization_level": "Q4_K_M",
                            },
                        }
                        for name in self.ollama_models
                    ]
                }
            if path == "/api/ps":
                return 200, {
                    "models": [
                        {"name": n, "size_vram": 5 * GIB, "context_length": 8192}
                        for n in self.ollama_loaded
                    ]
                }
            if path == "/v1/models":
                return 200, {"data": [{"id": n} for n in self.ollama_models]}
        return 404, {"error": "not found"}

    def post(self, path: str, payload: Any) -> tuple[int, Any]:
        if self.slow_seconds:
            threading.Event().wait(self.slow_seconds)
        if path == "/v1/chat/completions":
            if self.fail_chat or not self.healthy:
                return 500, {"error": "boom"}
            return 200, {
                "model": payload.get("model"),
                "choices": [{"message": {"content": "OK"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2},
            }
        if self.kind == "llama_cpp" and path == "/completion":
            if self.fail_completion:
                return 500, {"error": "out of memory"}
            return 200, {
                "content": "texto",
                "timings": {
                    "prompt_n": 40,
                    "prompt_ms": 80.0,
                    "prompt_per_second": 500.0,
                    "predicted_n": payload["n_predict"],
                    "predicted_ms": 2000.0,
                    "predicted_per_second": 42.5,
                },
            }
        if self.kind == "ollama" and path == "/api/generate":
            model = payload["model"]
            if model not in self.ollama_models:
                return 404, {"error": "model not found"}
            if payload.get("keep_alive") == 0:
                self.ollama_loaded.discard(model)
                return 200, {"done": True}
            self.ollama_loaded.add(model)
            if not payload.get("prompt"):
                return 200, {"done": True}
            return 200, {
                "response": "texto",
                "load_duration": 1_500_000_000,
                "prompt_eval_count": 40,
                "prompt_eval_duration": 100_000_000,
                "eval_count": payload["options"]["num_predict"],
                "eval_duration": 4_000_000_000,
            }
        if self.kind == "ollama" and path == "/api/show":
            return 200, {
                "model_info": {
                    "general.architecture": "qwen3",
                    "general.parameter_count": 8_190_000_000,
                    "qwen3.block_count": 36,
                    "qwen3.attention.head_count": 32,
                    "qwen3.attention.head_count_kv": 8,
                    "qwen3.attention.key_length": 128,
                    "qwen3.context_length": 40960,
                    "qwen3.embedding_length": 4096,
                }
            }
        return 404, {"error": "not found"}

    @contextmanager
    def running(self) -> Iterator["FakeRuntimeServer"]:
        thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield self
        finally:
            self._httpd.shutdown()
            self._httpd.server_close()
