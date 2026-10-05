"""Fase 4J.2: hardware, GGUF, rutas, catálogo y motor de recomendación (sin BD ni red).

Todo con fuentes y ficheros sintéticos: CI no necesita GPU, modelos reales ni Internet.
"""

import json
import os
import sys
import threading
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.ai.local.benchmark import BenchmarkCancelledError, BenchmarkManager, run_benchmark
from app.ai.local.catalog import load_catalog
from app.ai.local.engine import (
    ModelSpec,
    Observed,
    estimate_memory,
    evaluate,
    performance_class,
    rank,
)
from app.ai.local.gguf import InvalidGGUFError, read_gguf, split_parts
from app.ai.local.hardware import (
    GIB,
    CPUInfo,
    GPUDevice,
    HardwareProfile,
    profile_hardware,
    sample_memory_usage,
)
from app.ai.local.paths import ModelPathError, discover_model_files, resolve_model_path
from app.ai.local.quant import quantization_from_filename
from app.ai.local.runtimes import CAPABILITIES, BenchmarkSample, RuntimeCapabilities
from app.core.config import parse_model_directories, parse_performance_thresholds
from tests.ai_local_fakes import FakeSource, nvidia, write_gguf

LLAMA_CPP = CAPABILITIES["llama_cpp"].traits()
VLLM = CAPABILITIES["vllm"].traits()


def hw(
    ram_gb: float = 64, vram_gb: tuple[float, ...] = (), disk_gb: float = 500
) -> HardwareProfile:
    return HardwareProfile(
        os="Linux",
        os_version=None,
        architecture="x86_64",
        cpu=CPUInfo("Test CPU", 8, 16),
        ram_total_bytes=int(ram_gb * GIB),
        ram_available_bytes=int(ram_gb * GIB * 0.8),
        gpu_devices=tuple(
            GPUDevice(i, "nvidia", "Test GPU", int(v * GIB), int(v * GIB), "dedicated", "test")
            for i, v in enumerate(vram_gb)
        ),
        disk_free_bytes=int(disk_gb * GIB),
        disk_total_bytes=int(disk_gb * 2 * GIB),
        disk_scope="model_directory",
        detected_at=datetime.now(UTC),
        duration_ms=1,
    )


def spec(
    params_b: float,
    quant: str | None = "Q4_K_M",
    *,
    key: str | None = None,
    layers: int | None = 64,
    kv_heads: int | None = 8,
    head_dim: int | None = 128,
    context: int | None = 131072,
    on_disk: bool = True,
) -> ModelSpec:
    return ModelSpec(
        key=key or f"m{params_b}-{quant}",
        name=f"Model {params_b}B {quant}",
        family="test",
        parameter_count=int(params_b * 1e9),
        quantization=quant,
        file_size_bytes=None,
        native_context=context,
        layer_count=layers,
        kv_head_count=kv_heads,
        head_dim=head_dim,
        on_disk=on_disk,
    )


# --- Hardware --------------------------------------------------------------------------------


def test_cpu_only_linux_profile_never_fails_without_gpu() -> None:
    profile = profile_hardware(FakeSource(), ())
    assert profile.cpu.model == "Test CPU 8-Core"
    assert (profile.cpu.physical_cores, profile.cpu.logical_cores) == (8, 16)
    assert profile.ram_total_bytes == 32 * GIB
    assert profile.gpu_devices == ()
    assert profile.offload_vram_bytes == 0
    assert any("Sin GPU" in w for w in profile.warnings)
    assert profile.disk_free_bytes == 500 * GIB and profile.disk_scope == "server"


def test_nvidia_and_multiple_gpus_are_read_from_fixed_nvidia_smi_query() -> None:
    source = FakeSource(smi=nvidia(24, 12))
    profile = profile_hardware(source, ("/models",))
    assert [g.vram_total_bytes for g in profile.gpu_devices] == [24 * GIB, 12 * GIB]
    assert all(g.vendor == "nvidia" and g.memory_kind == "dedicated" for g in profile.gpu_devices)
    assert profile.gpu_devices[0].vram_free_bytes == (24 * 1024 - 500) * 1024 * 1024
    assert profile.offload_vram_bytes == 36 * GIB
    assert profile.disk_scope == "model_directory"
    # Argumentos fijos: nada de la petición llega al comando.
    assert source.calls[0][0].startswith("--query-gpu=index,name,memory.total")


def test_amd_dedicated_and_apu_and_intel_from_sysfs() -> None:
    files = {
        "/sys/class/drm/card0/device/vendor": "0x1002\n",
        "/sys/class/drm/card0/device/device": "0x744c\n",
        "/sys/class/drm/card0/device/mem_info_vram_total": str(16 * GIB),
        "/sys/class/drm/card0/device/mem_info_vram_used": str(1 * GIB),
        "/sys/class/drm/card1/device/vendor": "0x1002\n",
        "/sys/class/drm/card1/device/mem_info_vram_total": str(512 * 1024 * 1024),
        "/sys/class/drm/card2/device/vendor": "0x8086\n",
    }
    source = FakeSource(
        files=files,
        dirs={"/sys/class/drm": ["card0", "card0-DP-1", "card1", "card2", "renderD128"]},
    )
    gpus = profile_hardware(source, ()).gpu_devices
    assert [(g.vendor, g.memory_kind) for g in gpus] == [
        ("amd", "dedicated"),
        ("amd", "shared"),
        ("intel", "unknown"),
    ]
    assert gpus[0].vram_free_bytes == 15 * GIB
    # Una APU no aporta VRAM para offload.
    assert gpus[1].vram_total_bytes is None


def test_nvidia_without_nvidia_smi_reports_unknown_vram() -> None:
    source = FakeSource(
        files={"/proc/driver/nvidia/gpus/0000:01:00.0/information": "Model: \t RTX Test\n"},
        dirs={"/proc/driver/nvidia/gpus": ["0000:01:00.0"]},
    )
    profile = profile_hardware(source, ())
    assert profile.gpu_devices[0].model == "RTX Test"
    assert profile.gpu_devices[0].vram_total_bytes is None
    assert profile.offload_vram_bytes == 0


def test_windows_registry_adapters_and_basic_display_is_ignored() -> None:
    source = FakeSource(
        os_name="Windows",
        adapters=[
            {
                "DriverDesc": "Microsoft Basic Display Adapter",
                "MatchingDeviceId": "root\\basicdisplay",
            },
            {
                "DriverDesc": "AMD Radeon Test",
                "MatchingDeviceId": "PCI\\VEN_1002&DEV_744C",
                "HardwareInformation.qwMemorySize": 20 * GIB,
            },
            {"DriverDesc": "Intel UHD Test", "MatchingDeviceId": "PCI\\VEN_8086&DEV_A780"},
        ],
    )
    profile = profile_hardware(source, ())
    assert profile.cpu.model == "Test CPU Windows"
    assert profile.ram_total_bytes == 32 * GIB
    assert [(g.vendor, g.memory_kind, g.vram_total_bytes) for g in profile.gpu_devices] == [
        ("amd", "dedicated", 20 * GIB),
        ("intel", "shared", None),
    ]


def test_memory_sampler_reads_system_ram_and_vram() -> None:
    ram, vram = sample_memory_usage(FakeSource(smi=nvidia(24, 12)))
    assert ram == 8 * GIB
    assert vram == 2000 * 1024 * 1024


# --- GGUF ------------------------------------------------------------------------------------


def test_gguf_metadata_comes_from_the_header_not_the_filename(tmp_path: Path) -> None:
    path = write_gguf(tmp_path / "engañoso-Q8_0.gguf", file_type=15)
    info = read_gguf(str(path))
    assert info.quantization == "Q4_K_M"  # general.file_type manda sobre el nombre
    assert quantization_from_filename(path.name) == "Q8_0"
    assert info.parameter_count == 2 * 4096 * 976_563
    assert (info.context_length, info.block_count, info.head_count_kv) == (32768, 32, 8)
    assert info.head_dim == 128
    assert info.architecture == "llama" and info.name == "Test Model"


def test_gguf_without_file_type_infers_dominant_tensor_type(tmp_path: Path) -> None:
    info = read_gguf(str(write_gguf(tmp_path / "m.gguf", file_type=None, tensor_type=14)))
    assert (info.quantization, info.quantization_source) == ("Q6_K", "tensor_types")


@pytest.mark.parametrize(
    "content",
    [b"NOPE" + b"\0" * 64, b"GGUF" + (99).to_bytes(4, "little") + b"\0" * 32, b"GGUF\x03\0\0"],
)
def test_invalid_gguf_is_rejected(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "bad.gguf"
    path.write_bytes(content)
    with pytest.raises(InvalidGGUFError):
        read_gguf(str(path))


def test_truncated_or_oversized_header_is_rejected(tmp_path: Path) -> None:
    good = write_gguf(tmp_path / "m.gguf", padding=0)
    data = good.read_bytes()
    good.write_bytes(data[: len(data) // 2])
    with pytest.raises(InvalidGGUFError, match="truncated"):
        read_gguf(str(good))
    other = write_gguf(tmp_path / "n.gguf")
    with pytest.raises(InvalidGGUFError, match="limit"):
        read_gguf(str(other), max_header_bytes=64)


def test_split_parts_only_for_the_first_part() -> None:
    parts = split_parts(os.path.join("models", "big-00001-of-00003.gguf"))
    assert parts is not None and len(parts) == 3 and parts[2].endswith("big-00003-of-00003.gguf")
    assert split_parts(os.path.join("models", "big-00002-of-00003.gguf")) is None
    assert split_parts("model.gguf") is None


# --- Rutas -----------------------------------------------------------------------------------


def test_path_must_be_inside_allowed_roots(tmp_path: Path) -> None:
    root = tmp_path / "models"
    root.mkdir()
    outside = tmp_path / "secret"
    outside.mkdir()
    write_gguf(outside / "x.gguf")
    model = write_gguf(root / "ok.gguf")
    roots = (str(root),)
    assert resolve_model_path(str(model), roots, 10**12).path == os.path.realpath(model)
    for attempt in (
        str(outside / "x.gguf"),
        str(root / ".." / "secret" / "x.gguf"),
        "relative/ok.gguf",
        "//server/share/m.gguf",
        str(root / "ok.gguf") + "\x00",
    ):
        with pytest.raises(ModelPathError):
            resolve_model_path(attempt, roots, 10**12)
    # Sin raíces configuradas no se puede importar nada.
    with pytest.raises(ModelPathError, match="No model directories"):
        resolve_model_path(str(model), (), 10**12)


# Windows devuelve WinError 1314 (ERROR_PRIVILEGE_NOT_HELD) al crear un symlink sin Developer
# Mode ni privilegios de administrador. Eso es una limitación del entorno de test, no un éxito:
# solo en ese caso exacto se hace skip; cualquier otro fallo sigue rompiendo el test.
WINDOWS_PRIVILEGE_NOT_HELD = 1314


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as exc:
        if sys.platform == "win32" and getattr(exc, "winerror", None) == WINDOWS_PRIVILEGE_NOT_HELD:
            pytest.skip(
                "Windows no permite crear symlinks en este entorno (WinError 1314: requiere "
                "Developer Mode o administrador); el escape por junction se prueba aparte"
            )
        raise


def test_symlink_escaping_the_root_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "models"
    root.mkdir()
    secret = tmp_path / "passwd.gguf"
    secret.write_bytes(b"GGUF" + b"\0" * 64)
    _symlink_or_skip(root / "link.gguf", secret)
    write_gguf(root / "ok.gguf")
    with pytest.raises(ModelPathError, match="not inside"):
        resolve_model_path(str(root / "link.gguf"), (str(root),), 10**12)
    # El descubrimiento tampoco lista el enlace que sale de la raíz.
    assert [f.file_name for f in discover_model_files((str(root),))] == ["ok.gguf"]


def test_windows_junction_escaping_the_root_is_rejected(tmp_path: Path) -> None:
    # Una junction no necesita privilegios, así que en Windows el escape de la raíz se prueba
    # siempre, aunque el entorno no permita crear symlinks. El skip va dentro (y no en un
    # decorador) para que mypy solo compruebe _winapi al analizar para win32.
    if sys.platform != "win32":
        pytest.skip("las junctions solo existen en Windows")
    import _winapi

    root = tmp_path / "models"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    write_gguf(outside / "secret.gguf")
    _winapi.CreateJunction(str(outside), str(root / "escape"))
    with pytest.raises(ModelPathError, match="not inside"):
        resolve_model_path(str(root / "escape" / "secret.gguf"), (str(root),), 10**12)
    assert discover_model_files((str(root),)) == []


def test_non_gguf_and_oversized_files_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "models"
    root.mkdir()
    (root / "notes.txt").write_text("x" * 100)
    with pytest.raises(ModelPathError, match=r"\.gguf"):
        resolve_model_path(str(root / "notes.txt"), (str(root),), 10**12)
    with pytest.raises(ModelPathError, match="exceeds"):
        resolve_model_path(str(write_gguf(root / "big.gguf")), (str(root),), 64)


def test_discovery_is_bounded_and_skips_secondary_split_parts(tmp_path: Path) -> None:
    (tmp_path / "a" / "b" / "c").mkdir(parents=True)
    write_gguf(tmp_path / "top.gguf")
    write_gguf(tmp_path / "a" / "big-00001-of-00002.gguf")
    write_gguf(tmp_path / "a" / "big-00002-of-00002.gguf")
    write_gguf(tmp_path / "a" / "b" / "c" / "too-deep.gguf")
    names = sorted(f.file_name for f in discover_model_files((str(tmp_path),)))
    assert names == ["big-00001-of-00002.gguf", "top.gguf"]


def test_settings_parsers(tmp_path: Path) -> None:
    # Rutas absolutas reales del sistema actual: "/a" no es absoluta en Windows y "C:\\a" no
    # lo es en Linux, y el parser solo debe aceptar rutas absolutas de la plataforma.
    a, b = str(tmp_path / "a"), str(tmp_path / "b")
    assert parse_model_directories(f"{a}; {b} ;") == (a, b)
    assert parse_model_directories(f" ;{a};;\n{b}\n") == (a, b)
    assert parse_model_directories(" ; ; ") == ()
    for bad in ("relative/models", os.path.join("models", "gguf"), f"{a}\x00evil"):
        with pytest.raises(ValueError):
            parse_model_directories(f"{a};{bad}")
    assert parse_performance_thresholds("30,15,7") == (30, 15, 7)
    with pytest.raises(ValueError):
        parse_performance_thresholds("7,15,30")


# --- Catálogo --------------------------------------------------------------------------------


def test_catalog_is_extensible_and_not_tied_to_one_family(tmp_path: Path) -> None:
    builtin = load_catalog()
    families = {e.family for e in builtin}
    assert len(families) >= 4
    assert any(e.parameter_count > 30e9 for e in builtin)
    extra = tmp_path / "catalog.json"
    extra.write_text(
        json.dumps(
            {
                "models": [
                    {
                        "id": "qwen3-8b",
                        "name": "Qwen3 8B (actualizado)",
                        "parameter_count": 8e9,
                        "quantizations": ["Q4_K_M"],
                    },
                    {
                        "id": "nuevo-20b",
                        "name": "Nuevo 20B",
                        "parameter_count": 20_000_000_000,
                        "quantizations": ["Q4_K_M", "RAREQ"],
                    },
                    {"id": "roto"},
                ]
            }
        )
    )
    merged = {e.id: e for e in load_catalog(str(extra))}
    assert merged["nuevo-20b"].quantizations == ("Q4_K_M",)  # cuantización desconocida fuera
    assert "roto" not in merged
    # parameter_count no entero -> entrada inválida: no reemplaza la incluida.
    assert merged["qwen3-8b"].name == "Qwen3 8B"
    bad = tmp_path / "bad.json"
    bad.write_text("{no json")
    assert len(load_catalog(str(bad))) == len(builtin)


# --- Memoria ---------------------------------------------------------------------------------


def test_kv_cache_grows_with_context_and_is_never_ignored() -> None:
    model = spec(32)
    small = estimate_memory(model, 8192, LLAMA_CPP)
    large = estimate_memory(model, 102400, LLAMA_CPP)
    # 2 x 64 capas x 8 cabezas KV x 128 dim x 2 bytes = 256 KiB por token.
    assert small.kv_cache_bytes == 8192 * 262144
    assert large.kv_cache_bytes == 102400 * 262144
    assert large.total_bytes is not None and small.total_bytes is not None
    assert large.total_bytes - small.total_bytes > 20 * GIB


def test_missing_architecture_means_no_kv_estimate_and_no_recommendation() -> None:
    model = spec(8, layers=None)
    estimate = estimate_memory(model, 100_000, LLAMA_CPP)
    assert estimate.kv_cache_bytes is None and not estimate.complete
    ev = evaluate(model, hw(ram_gb=256, vram_gb=(80,)), LLAMA_CPP, 100_000, 10)
    assert ev.status == "not_recommended"
    assert "KV" in ev.reasons[0]


def test_quantization_changes_memory_q8_is_larger_than_q4() -> None:
    q8 = estimate_memory(spec(14, "Q8_0"), 8192, LLAMA_CPP)
    q4 = estimate_memory(spec(14, "Q4_K_M"), 8192, LLAMA_CPP)
    assert q8.weights_bytes and q4.weights_bytes and q8.weights_bytes > 1.6 * q4.weights_bytes
    file_based = estimate_memory(replace(spec(14), file_size_bytes=9 * GIB), 8192, LLAMA_CPP)
    assert file_based.weights_bytes == 9 * GIB and file_based.weights_source == "file"


def test_unknown_quantization_produces_no_false_recommendation() -> None:
    ev = evaluate(spec(8, None), hw(vram_gb=(24,)), LLAMA_CPP, 8192, 10)
    assert ev.status == "not_recommended"
    ranked = rank([ev], "balanced")
    assert ranked[0].status == "not_recommended" and not ranked[0].recommended_for_sentra


# --- Clasificación ---------------------------------------------------------------------------


def test_32b_is_not_rejected_for_its_parameter_count() -> None:
    # 32B Q4_K_M a 16K en una GPU de 24 GB: no cabe entero, pero sí con offload a RAM.
    ev = evaluate(spec(32), hw(ram_gb=64, vram_gb=(24,)), LLAMA_CPP, 16384, 10)
    assert ev.status in ("compatible_with_offload", "slow")
    assert ev.fit.placement == "partial_offload"
    # Con 48 GB de VRAM cabe entero y es "compatible", sin ninguna regla de tamaño.
    big = evaluate(spec(32), hw(ram_gb=64, vram_gb=(24, 24)), LLAMA_CPP, 16384, 10)
    assert big.status == "compatible" and big.fit.placement == "full_gpu"
    assert "~" in big.reasons[0]


def test_27b_and_32b_can_be_recommended_when_the_hardware_allows() -> None:
    hardware = hw(ram_gb=128, vram_gb=(48,))
    evaluations = [
        evaluate(spec(b, key=f"m{b}"), hardware, LLAMA_CPP, 16384, 10) for b in (8, 14, 27, 32)
    ]
    ranked = rank(evaluations, "quality")
    assert ranked[0].spec.key == "m32" and ranked[0].status == "recommended"
    sentra = next(ev for ev in ranked if ev.recommended_for_sentra)
    assert sentra.spec.key == "m32"


def test_sentra_profile_does_not_always_pick_the_biggest_model() -> None:
    # 24 GB de VRAM: 14B cabe entero (rápido); 32B necesita offload (moderado o lento).
    hardware = hw(ram_gb=64, vram_gb=(24,))
    evaluations = [
        evaluate(spec(b, key=f"m{b}", layers=48 if b == 14 else 64), hardware, LLAMA_CPP, 16384, 10)
        for b in (14, 32)
    ]
    rank(evaluations, "sentra")
    picked = next(ev for ev in evaluations if ev.recommended_for_sentra)
    assert picked.spec.key == "m14"


def test_profiles_change_the_recommendation() -> None:
    hardware = hw(ram_gb=64, vram_gb=(24,))
    picks = {}
    for profile in ("low_resource", "balanced", "quality", "max_speed"):
        evaluations = [
            evaluate(spec(b, key=f"m{b}", layers=40), hardware, LLAMA_CPP, 8192, 10)
            for b in (3.5, 8, 14, 24)
        ]
        ranked = rank(evaluations, profile)
        picks[profile] = next(ev.spec.key for ev in ranked if ev.status == "recommended")
    assert picks["low_resource"] == "m3.5"
    assert picks["quality"] == "m24"
    assert picks["max_speed"] != picks["quality"]


def test_insufficient_ram_and_vram_is_not_recommended() -> None:
    ev = evaluate(spec(70), hw(ram_gb=16, vram_gb=(8,)), LLAMA_CPP, 8192, 10)
    assert ev.status == "not_recommended" and ev.fit.placement == "does_not_fit"
    assert "Necesita" in ev.reasons[0]


def test_insufficient_disk_only_matters_for_models_not_yet_downloaded() -> None:
    hardware = hw(ram_gb=64, vram_gb=(24,), disk_gb=2)
    missing = evaluate(spec(8, on_disk=False), hardware, LLAMA_CPP, 8192, 10)
    present = evaluate(spec(8, on_disk=True), hardware, LLAMA_CPP, 8192, 10)
    assert missing.status == "not_recommended" and "disco" in missing.reasons[0]
    assert present.status == "compatible"


def test_context_beyond_the_declared_native_context_is_never_claimed() -> None:
    ev = evaluate(spec(8, context=32768), hw(ram_gb=256, vram_gb=(80,)), LLAMA_CPP, 131072, 10)
    assert ev.status == "not_recommended" and "declara 32,768" in ev.reasons[0]


def test_100k_context_warns_about_kv_cost_and_slows_cpu_offload() -> None:
    hardware = hw(ram_gb=128, vram_gb=(24,))
    short = evaluate(spec(8, layers=32), hardware, LLAMA_CPP, 8192, 10)
    long = evaluate(spec(8, layers=32), hardware, LLAMA_CPP, 131072, 10)
    assert short.fit.placement == "full_gpu"
    assert long.fit.placement == "partial_offload"
    assert any("Soportado no significa eficiente" in w for w in long.warnings)
    assert long.estimate.kv_cache_bytes and long.estimate.kv_cache_bytes > 10 * GIB


def test_runtime_without_offload_cannot_use_ram_for_gpu_models() -> None:
    hardware = hw(ram_gb=16, vram_gb=(24,))
    llama = evaluate(spec(32), hardware, LLAMA_CPP, 16384, 10)
    vllm = evaluate(spec(32), hardware, VLLM, 16384, 10)
    assert llama.fit.placement == "partial_offload"
    assert vllm.status == "not_recommended" and vllm.fit.placement == "does_not_fit"
    caps: RuntimeCapabilities = CAPABILITIES["vllm"]
    assert caps.gpu_offload is False and caps.load_model is False


def test_cpu_only_large_model_is_slow_until_measured() -> None:
    hardware = hw(ram_gb=128)
    estimated = evaluate(spec(14), hardware, LLAMA_CPP, 8192, 10)
    assert estimated.fit.placement == "cpu_only" and estimated.status == "slow"
    measured = evaluate(
        spec(14), hardware, LLAMA_CPP, 8192, 10, Observed(20.0, performance_class(20, (30, 15, 7)))
    )
    # La medición real pesa más que la estimación previa.
    assert measured.status == "compatible" and measured.speed_source == "benchmark"
    slow = evaluate(
        spec(8),
        hw(vram_gb=(24,)),
        LLAMA_CPP,
        8192,
        10,
        Observed(3.0, performance_class(3, (30, 15, 7))),
    )
    assert slow.status == "slow"


def test_performance_classes_are_configurable() -> None:
    assert [performance_class(v, (30, 15, 7)) for v in (45, 20, 8, 2)] == [
        "excellent",
        "good",
        "usable",
        "slow",
    ]
    assert performance_class(20, (60, 40, 20)) == "usable"


def test_ranking_is_deterministic() -> None:
    hardware = hw(ram_gb=64, vram_gb=(24,))

    def run() -> list[tuple[str, str]]:
        evaluations = [
            evaluate(spec(b, q, key=f"{b}-{q}", layers=40), hardware, LLAMA_CPP, 16384, 10)
            for b in (8, 14, 24)
            for q in ("Q4_K_M", "Q6_K", "Q8_0")
        ]
        return [(ev.spec.key, ev.status) for ev in rank(evaluations, "balanced")]

    assert run() == run()


# --- Benchmark -------------------------------------------------------------------------------


class _Runtime:
    kind = "ollama"

    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.calls: list[str] = []

    def load_model(self, model_id: str) -> int:
        self.calls.append("load")
        return 1500

    def benchmark(
        self, model_id: str, prompt: str, max_tokens: int, timeout: float
    ) -> BenchmarkSample:
        self.calls.append(f"run:{max_tokens}")
        if self.delay:
            threading.Event().wait(self.delay)
        return BenchmarkSample(2000, "runtime_timings", None, 90, 40, max_tokens, 400.0, 30.0)


def test_benchmark_uses_fixed_prompt_limits_and_measures_memory() -> None:
    runtime = _Runtime()
    outcome = run_benchmark(
        runtime,  # type: ignore[arg-type]
        "m",
        max_tokens=64,
        timeout_seconds=30,
        cancel=threading.Event(),
        sampler=lambda: (10 * GIB, 6 * GIB),
        load_first=True,
    )
    assert runtime.calls == ["load", "run:64", "run:64"]
    assert (outcome.load_ms, outcome.generation_tps, outcome.ttft_ms) == (1500, 30.0, 90)
    assert (outcome.peak_ram_bytes, outcome.peak_vram_bytes) == (10 * GIB, 6 * GIB)


def test_benchmark_cancellation_and_concurrency_limit() -> None:
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(BenchmarkCancelledError):
        run_benchmark(
            _Runtime(),  # type: ignore[arg-type]
            "m",
            max_tokens=16,
            timeout_seconds=30,
            cancel=cancel,
            sampler=lambda: (None, None),
            load_first=True,
        )
    manager = BenchmarkManager()
    started = threading.Event()
    release = threading.Event()

    def job(event: threading.Event) -> None:
        started.set()
        release.wait(5)

    manager.start(1, job)
    started.wait(5)
    from app.ai.local.benchmark import AIBenchmarkBusyError

    with pytest.raises(AIBenchmarkBusyError):
        manager.start(2, job)
    assert manager.running() == 1 and manager.cancel(1)
    release.set()
    manager.wait()
    assert manager.running() is None
