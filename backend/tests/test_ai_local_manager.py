"""Fase 4J.2: API del gestor de modelos locales de punta a punta, sin GPU ni Internet.

El runtime es un servidor HTTP falso en 127.0.0.1 (llama-server u Ollama) y las llamadas
pasan por el proveedor real de 4J/4J.1, así que también se prueba que el gestor no debilita
ninguna garantía: un solo destino, sin DNS, sin fallback y sin conexiones si la IA está
desactivada o el destino es externo.
"""

import socket
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.ai.config import AIConfig
from app.core.config import get_settings
from app.models.ai_local import AILocalModel, AIModelBenchmark
from app.models.audit import AuditEvent
from app.services.ai_service import AIRuntime
from tests.ai_local_fakes import FakeRuntimeServer, FakeSource, nvidia, write_gguf
from tests.conftest import authenticate

API = "/api/v1"
LOCAL = f"{API}/ai/local"


@dataclass
class Env:
    client: TestClient
    root: Path
    server: FakeRuntimeServer
    source: FakeSource


def _configure(client: TestClient, engine: Engine, **overrides: Any) -> None:
    values: dict[str, Any] = {
        "ai_enabled": True,
        "ai_model": "modelo-env",
        "ai_runtime": "llama_cpp",
        "ai_benchmark_max_tokens": 32,
        **overrides,
    }
    settings = get_settings().model_copy(update=values)
    app: Any = client.app
    app.dependency_overrides[get_settings] = lambda: settings
    app.state.ai_runtime = AIRuntime(AIConfig.from_settings(settings))
    state = app.state.ai_local
    state.session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    # SHA-256 síncrono en tests (en producción va a un hilo de fondo).
    state.run_background = lambda job: job()
    state.forget_runtime()


@pytest.fixture
def env(client: TestClient, engine: Engine, tmp_path: Path) -> Iterator[Env]:
    root = tmp_path / "models"
    root.mkdir()
    source = FakeSource(smi=nvidia(24))
    client.app.state.ai_local.source = source  # type: ignore[attr-defined]
    server = FakeRuntimeServer("llama_cpp")
    with server.running():
        _configure(client, engine, ai_base_url=server.base_url, ai_model_directories=str(root))
        yield Env(client, root, server, source)
    client.app.state.ai_local.benchmarks.wait()  # type: ignore[attr-defined]


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _audits(db: Session, action: str) -> list[AuditEvent]:
    db.expire_all()
    return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)).all())


def _register(env: Env, name: str = "model-Q4_K_M.gguf", **gguf: Any) -> dict[str, Any]:
    path = write_gguf(env.root / name, **gguf)
    response = env.client.post(f"{LOCAL}/models/register", json={"path": str(path)})
    assert response.status_code == 201, response.text
    return dict(response.json())


def _wait_benchmark(env: Env, benchmark_id: str) -> dict[str, Any]:
    env.client.app.state.ai_local.benchmarks.wait()  # type: ignore[attr-defined]
    return dict(env.client.get(f"{LOCAL}/benchmarks/{benchmark_id}").json())


# --- Hardware y lectura ---------------------------------------------------------------------


def test_hardware_is_detected_and_only_admin_refreshes(env: Env, engine: Engine) -> None:
    hardware = env.client.get(f"{LOCAL}/hardware").json()
    assert hardware["gpus"][0]["vendor"] == "nvidia"
    assert hardware["gpus"][0]["vram_total_bytes"] == 24 * 1024**3
    assert hardware["disk_scope"] == "model_directory"
    # Sin datos innecesarios del equipo: ni hostname ni rutas.
    assert (
        "hostname" not in hardware and str(env.root) not in env.client.get(f"{LOCAL}/hardware").text
    )
    assert env.client.post(f"{LOCAL}/hardware/refresh").status_code == 200
    with TestClient(env.client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        assert viewer.get(f"{LOCAL}/hardware").status_code == 200
        assert viewer.get(f"{LOCAL}/runtime").status_code == 200
        assert viewer.post(f"{LOCAL}/hardware/refresh").status_code == 403


def test_cpu_only_server_still_gets_recommendations(env: Env) -> None:
    env.source.smi = None
    env.client.post(f"{LOCAL}/hardware/refresh")
    data = env.client.get(f"{LOCAL}/recommendations", params={"profile": "sentra"}).json()
    assert data["items"] and all(i["estimate"]["placement"] != "full_gpu" for i in data["items"])
    assert all(i["estimate"]["usable_vram_bytes"] == 0 for i in data["items"])


# --- Registro --------------------------------------------------------------------------------


def test_register_gguf_reads_metadata_and_checksum(env: Env, db: Session) -> None:
    model = _register(env, name="engañoso-Q8_0.gguf")
    assert model["quantization"] == "Q4_K_M"  # metadata, no nombre del fichero
    assert model["parameter_count"] == 2 * 4096 * 976_563
    assert model["native_context"] == 32768 and model["metadata_source"] == "gguf"
    assert model["runtime"] == "llama_cpp" and model["local_path"].endswith("Q8_0.gguf")
    listed = env.client.get(f"{LOCAL}/models").json()
    item = listed["items"][0]
    assert item["checksum_status"] == "ok" and len(item["checksum_sha256"]) == 64
    assert listed["total"] == 1 and listed["discovered"] == []
    event = _audits(db, "ai_model_registered")[0]
    assert event.details is not None and event.details["file_name"] == "engañoso-Q8_0.gguf"
    assert "path" not in str(event.details)


def test_unregistered_files_are_discovered_for_admins_only(env: Env, engine: Engine) -> None:
    write_gguf(env.root / "pendiente.gguf")
    discovered = env.client.get(f"{LOCAL}/models").json()["discovered"]
    assert [d["file_name"] for d in discovered] == ["pendiente.gguf"]
    assert discovered[0]["state"] == "downloaded"
    _register(env)
    with TestClient(env.client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        data = viewer.get(f"{LOCAL}/models").json()
        assert data["discovered"] == []
        assert data["items"][0]["local_path"] is None  # rutas solo para ai:manage
        assert data["items"][0]["file_name"] == "model-Q4_K_M.gguf"


@pytest.mark.parametrize("attempt", ["outside", "traversal", "relative", "missing"])
def test_import_outside_allowed_directories_is_rejected(
    env: Env, tmp_path: Path, attempt: str
) -> None:
    secret = write_gguf(tmp_path / "secreto.gguf")
    path = {
        "outside": str(secret),
        "traversal": str(env.root / ".." / "secreto.gguf"),
        "relative": "models/secreto.gguf",
        "missing": str(env.root / "no-existe.gguf"),
    }[attempt]
    response = env.client.post(f"{LOCAL}/models/register", json={"path": path})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "local_model_path_rejected"
    # El mensaje no distingue "existe fuera" de "no existe fuera".
    if attempt in ("outside", "traversal"):
        assert "allowed model directory" in response.json()["error"]["message"]


def test_invalid_gguf_and_duplicates_are_rejected(env: Env) -> None:
    (env.root / "falso.gguf").write_bytes(b"MZ" + b"\0" * 4096)  # un ejecutable no es un GGUF
    response = env.client.post(
        f"{LOCAL}/models/register", json={"path": str(env.root / "falso.gguf")}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "local_model_invalid_file"
    model = _register(env)
    again = env.client.post(f"{LOCAL}/models/register", json={"path": model["local_path"]})
    assert again.status_code == 409
    both = env.client.post(
        f"{LOCAL}/models/register", json={"path": model["local_path"], "runtime_model": "x"}
    )
    assert both.status_code == 422


def test_unregister_keeps_the_file_and_clears_the_active_model(env: Env, db: Session) -> None:
    model = _register(env)
    env.client.post(f"{LOCAL}/models/{model['model_id']}/select")
    response = env.client.post(f"{LOCAL}/models/{model['model_id']}/unregister")
    assert response.status_code == 204
    assert Path(model["local_path"]).exists()
    runtime = env.client.get(f"{LOCAL}/runtime").json()
    assert runtime["active_model"] is None and runtime["effective_model"] == "modelo-env"
    event = _audits(db, "ai_model_unregistered")[0]
    assert event.details == {"name": "Test Model", "was_active": True, "file_deleted": False}


# --- Selección ------------------------------------------------------------------------------


def test_select_marks_active_only_when_the_runtime_serves_and_answers(
    env: Env, db: Session
) -> None:
    model = _register(env)
    response = env.client.post(f"{LOCAL}/models/{model['model_id']}/select")
    assert response.status_code == 200, response.text
    runtime = response.json()
    assert runtime["active_model"]["model_id"] == model["model_id"]
    assert runtime["effective_model"] == "model-Q4_K_M.gguf"
    # La comprobación previa no envía datos de Sentra: solo un "ping" fijo.
    chats = [p for m, path, p in env.server.requests if path == "/v1/chat/completions"]
    assert chats and chats[-1]["messages"][1]["content"] == "ping"
    # AI Insights usa ahora el modelo activo (el destino no cambia).
    assert env.client.get(f"{API}/ai/status").json()["model"] == "model-Q4_K_M.gguf"
    listed = env.client.get(f"{LOCAL}/models").json()["items"][0]
    assert (listed["state"], listed["active"], listed["loaded"]) == ("active", True, True)
    assert _audits(db, "ai_model_selected")


def test_failed_selection_keeps_the_previous_model(env: Env, db: Session) -> None:
    first = _register(env)
    assert env.client.post(f"{LOCAL}/models/{first['model_id']}/select").status_code == 200
    other = _register(env, name="otro-Q6_K.gguf", file_type=18)
    response = env.client.post(f"{LOCAL}/models/{other['model_id']}/select")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "local_model_not_loaded"
    assert "otro-Q6_K.gguf" in response.json()["error"]["message"]
    env.server.fail_chat = True
    response = env.client.post(f"{LOCAL}/models/{first['model_id']}/select")
    assert response.status_code == 502
    runtime = env.client.get(f"{LOCAL}/runtime").json()
    assert runtime["active_model"]["model_id"] == first["model_id"]
    codes = [e.details["error"] for e in _audits(db, "ai_model_load_failed") if e.details]
    assert sorted(codes) == ["ai_provider_unavailable", "local_model_not_loaded"]


def test_llama_cpp_match_uses_parameter_count_not_only_the_name(env: Env) -> None:
    model = _register(env, name="renombrado.gguf")
    env.server.loaded_file = "otro-nombre.gguf"
    env.server.n_params = model["parameter_count"]
    assert env.client.post(f"{LOCAL}/models/{model['model_id']}/select").status_code == 200
    env.server.n_params = model["parameter_count"] + 1
    env.server.loaded_file = "renombrado.gguf"
    assert env.client.post(f"{LOCAL}/models/{model['model_id']}/select").status_code == 409


def test_runtime_down_does_not_break_sentra(env: Env) -> None:
    model = _register(env)
    env.server.healthy = False
    runtime = env.client.get(f"{LOCAL}/runtime").json()
    assert runtime["reachable"] is False and runtime["available"] is True
    assert env.client.get(f"{LOCAL}/models").status_code == 200
    assert env.client.get(f"{LOCAL}/recommendations").status_code == 200
    response = env.client.post(f"{LOCAL}/models/{model['model_id']}/select")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "local_model_unavailable"
    assert env.client.post(f"{LOCAL}/models/{model['model_id']}/benchmark").status_code == 409
    assert env.client.get(f"{API}/ai/status").status_code == 200
    assert env.client.get(f"{API}/assets").status_code == 200


# --- Benchmark -------------------------------------------------------------------------------


def test_benchmark_runs_in_background_and_updates_the_recommendation(env: Env, db: Session) -> None:
    model = _register(env)
    response = env.client.post(f"{LOCAL}/models/{model['model_id']}/benchmark")
    assert response.status_code == 202 and response.json()["status"] == "running"
    result = _wait_benchmark(env, response.json()["benchmark_id"])
    assert result["status"] == "completed" and result["measurement"] == "runtime_timings"
    assert (result["generation_tps"], result["prompt_tps"], result["ttft_ms"]) == (42.5, 500.0, 80)
    assert result["performance_class"] == "excellent" and result["max_tokens"] == 32
    assert result["peak_vram_bytes"] == 1000 * 1024 * 1024
    # Prompt fijo, sin datos de Sentra, y con el límite de tokens.
    runs = [p for m, path, p in env.server.requests if path == "/completion"]
    assert len(runs) == 2 and all(p["n_predict"] == 32 for p in runs)
    assert all("mínimo privilegio" in p["prompt"] for p in runs)
    detail = env.client.get(f"{LOCAL}/models/{model['model_id']}").json()
    assert detail["evaluation"]["speed_source"] == "benchmark"
    assert detail["evaluation"]["observed_tps"] == 42.5
    assert detail["benchmarks"][0]["benchmark_id"] == result["benchmark_id"]
    assert _audits(db, "ai_model_benchmark_started")
    completed = _audits(db, "ai_model_benchmark_completed")[0]
    assert completed.details is not None and completed.details["generation_tps"] == 42.5


def test_benchmark_can_be_cancelled_and_only_one_runs_at_a_time(env: Env) -> None:
    model = _register(env)
    env.server.slow_seconds = 0.5
    started = env.client.post(f"{LOCAL}/models/{model['model_id']}/benchmark").json()
    busy = env.client.post(f"{LOCAL}/models/{model['model_id']}/benchmark")
    assert busy.status_code == 409 and busy.json()["error"]["code"] == "ai_benchmark_busy"
    cancel = env.client.post(f"{LOCAL}/benchmarks/{started['benchmark_id']}/cancel")
    assert cancel.status_code == 200
    assert _wait_benchmark(env, started["benchmark_id"])["status"] == "cancelled"


def test_benchmark_running_in_another_worker_blocks_a_new_one(env: Env, db: Session) -> None:
    # Fase 4M: con varios workers el estado en memoria no ve el benchmark del otro proceso;
    # la fila "running" vigente en la base sí lo bloquea.
    model = _register(env)
    stored = db.scalars(
        select(AILocalModel).where(AILocalModel.public_id == UUID(model["model_id"]))
    ).one()
    db.add(
        AIModelBenchmark(
            model_id=stored.id,
            status="running",
            runtime=stored.runtime,
            max_tokens=32,
            requested_by="otro-worker",
            started_at=datetime.now(UTC),
        )
    )
    db.commit()
    busy = env.client.post(f"{LOCAL}/models/{model['model_id']}/benchmark")
    assert busy.status_code == 409 and busy.json()["error"]["code"] == "ai_benchmark_busy"


def test_benchmark_failure_does_not_break_ai_insights(env: Env) -> None:
    model = _register(env)
    assert env.client.post(f"{LOCAL}/models/{model['model_id']}/select").status_code == 200
    env.server.fail_completion = True
    started = env.client.post(f"{LOCAL}/models/{model['model_id']}/benchmark")
    assert started.status_code == 202
    failed = _wait_benchmark(env, started.json()["benchmark_id"])
    assert (failed["status"], failed["error"]) == ("failed", "ai_provider_unavailable")
    status = env.client.get(f"{API}/ai/status").json()
    assert status["available"] is True and status["model"] == "model-Q4_K_M.gguf"


# --- Ollama -----------------------------------------------------------------------------------


def test_ollama_models_are_registered_loaded_and_benchmarked(
    client: TestClient, engine: Engine, tmp_path: Path
) -> None:
    client.app.state.ai_local.source = FakeSource(smi=nvidia(12))  # type: ignore[attr-defined]
    server = FakeRuntimeServer("ollama")
    with server.running():
        _configure(client, engine, ai_base_url=server.base_url, ai_runtime="ollama")
        runtime = client.get(f"{LOCAL}/runtime").json()
        assert runtime["kind"] == "ollama" and runtime["version"] == "0.9.0"
        assert runtime["detected_kind"] == "ollama" and runtime["capabilities"]["load_model"]
        discovered = client.get(f"{LOCAL}/models").json()["discovered"]
        assert discovered[0]["runtime_model_id"] == "qwen-test:8b"
        response = client.post(f"{LOCAL}/models/register", json={"runtime_model": "qwen-test:8b"})
        assert response.status_code == 201, response.text
        model = response.json()
        assert model["parameter_count"] == 8_190_000_000 and model["quantization"] == "Q4_K_M"
        assert model["metadata_source"] == "runtime" and model["native_context"] == 40960
        selected = client.post(f"{LOCAL}/models/{model['model_id']}/select")
        assert selected.status_code == 200, selected.text
        loads = [p for m, path, p in server.requests if path == "/api/generate" and not p["prompt"]]
        assert loads and loads[0]["model"] == "qwen-test:8b"
        assert client.get(f"{API}/ai/status").json()["model"] == "qwen-test:8b"
        server.ollama_loaded.clear()
        bench = client.post(f"{LOCAL}/models/{model['model_id']}/benchmark").json()
        client.app.state.ai_local.benchmarks.wait()  # type: ignore[attr-defined]
        result = client.get(f"{LOCAL}/benchmarks/{bench['benchmark_id']}").json()
        assert result["status"] == "completed" and result["load_ms"] is not None
        assert result["generation_tps"] == 8.0 and result["performance_class"] == "usable"
        missing = client.post(f"{LOCAL}/models/register", json={"runtime_model": "no-existe"})
        assert missing.status_code == 404


def test_changing_runtime_clears_the_active_model_and_is_audited(env: Env, db: Session) -> None:
    model = _register(env)
    env.client.post(f"{LOCAL}/models/{model['model_id']}/select")
    response = env.client.patch(f"{LOCAL}/settings", json={"runtime": "vllm"})
    assert response.status_code == 200
    data = response.json()
    assert data["kind"] == "vllm" and data["source"] == "settings" and data["active_model"] is None
    assert data["capabilities"]["gpu_offload"] is False
    event = _audits(db, "ai_runtime_changed")[0]
    assert event.details == {"previous": "llama_cpp", "runtime": "vllm", "active_cleared": True}
    mismatch = env.client.post(f"{LOCAL}/models/{model['model_id']}/select")
    assert mismatch.json()["error"]["code"] == "local_model_runtime_mismatch"
    assert env.client.patch(f"{LOCAL}/settings", json={"runtime": "rm -rf"}).status_code == 422


# --- RBAC -------------------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_only_admin_changes_models(env: Env, engine: Engine, db: Session, role: str) -> None:
    model = _register(env)
    with TestClient(env.client.app) as user:
        authenticate(user, engine, role)
        assert user.get(f"{LOCAL}/models").status_code == 200
        assert user.get(f"{LOCAL}/recommendations").status_code == 200
        assert user.get(f"{LOCAL}/models/{model['model_id']}").status_code == 200
        for method, path, body in (
            ("POST", f"{LOCAL}/models/register", {"path": model["local_path"]}),
            ("POST", f"{LOCAL}/models/{model['model_id']}/select", None),
            ("POST", f"{LOCAL}/models/{model['model_id']}/benchmark", None),
            ("POST", f"{LOCAL}/models/{model['model_id']}/unregister", None),
            ("PATCH", f"{LOCAL}/settings", {"runtime": "ollama"}),
        ):
            response = user.request(method, path, json=body)
            assert response.status_code == 403, (method, path)
    assert env.client.get(f"{LOCAL}/runtime").json()["active_model"] is None
    assert len(_audits(db, "permission_denied")) == 5


# --- Sin cloud ni fallback -------------------------------------------------------------------


@pytest.fixture
def connections(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    seen: list[tuple[str, int]] = []
    real = socket.create_connection

    def recording(address: tuple[str, int], *args: Any, **kwargs: Any) -> socket.socket:
        seen.append((address[0], address[1]))
        return real(address, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", recording)
    return seen


@pytest.mark.parametrize(
    "overrides",
    [
        {"ai_enabled": False},
        {"ai_base_url": "https://api.example.com/v1"},
        {"ai_base_url": "https://api.example.com/v1", "ai_allow_external": True},
    ],
)
def test_manager_never_talks_to_external_or_disabled_ai(
    client: TestClient,
    engine: Engine,
    tmp_path: Path,
    connections: list[tuple[str, int]],
    overrides: dict[str, Any],
) -> None:
    client.app.state.ai_local.source = FakeSource()  # type: ignore[attr-defined]
    _configure(
        client,
        engine,
        **{
            "ai_base_url": "http://127.0.0.1:9/v1",
            "ai_model_directories": str(tmp_path),
            **overrides,
        },
    )
    runtime = client.get(f"{LOCAL}/runtime").json()
    assert runtime["available"] is False and runtime["reachable"] is None
    assert runtime["external_ai"] == (
        "allowed" if overrides.get("ai_allow_external") else "blocked"
    )
    # Lo que no necesita runtime sigue funcionando offline.
    assert client.get(f"{LOCAL}/hardware").status_code == 200
    assert client.get(f"{LOCAL}/recommendations").status_code == 200
    path = write_gguf(tmp_path / "m.gguf")
    model = client.post(f"{LOCAL}/models/register", json={"path": str(path)}).json()
    response = client.post(f"{LOCAL}/models/{model['model_id']}/select")
    assert response.status_code == 409 and response.json()["error"]["code"] == "ai_not_configured"
    assert client.post(f"{LOCAL}/models/register", json={"runtime_model": "x"}).status_code == 409
    assert connections == []


def test_offline_without_dns_select_and_benchmark_work(
    env: Env, monkeypatch: pytest.MonkeyPatch, connections: list[tuple[str, int]]
) -> None:
    real = socket.getaddrinfo

    def offline(host: Any, *args: Any, **kwargs: Any) -> Any:
        if str(host) != "127.0.0.1":
            raise socket.gaierror("no DNS / no Internet in this test")
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", offline)
    model = _register(env)
    assert env.client.post(f"{LOCAL}/models/{model['model_id']}/select").status_code == 200
    bench = env.client.post(f"{LOCAL}/models/{model['model_id']}/benchmark").json()
    assert _wait_benchmark(env, bench["benchmark_id"])["status"] == "completed"
    # Un único destino: el runtime local configurado.
    assert {c for c in connections} == {("127.0.0.1", env.server.port)}


def test_recommendations_profiles_context_and_catalog(env: Env) -> None:
    _register(env)
    base = env.client.get(f"{LOCAL}/recommendations").json()
    assert base["context_tokens"] == 16384 and base["runtime"] == "llama_cpp"
    assert any(i["origin"] == "catalog" for i in base["items"])
    assert any(i["origin"] == "registered" for i in base["items"])
    assert base["sentra_pick"] is not None
    big = env.client.get(f"{LOCAL}/recommendations", params={"context": 131072}).json()
    by_key = {i["key"]: i for i in big["items"]}
    qwen = by_key["catalog:qwen2.5-7b-instruct:Q4_K_M"]
    assert qwen["status"] == "not_recommended" and "32,768" in qwen["reasons"][0]
    llama = by_key["catalog:llama-3.1-8b-instruct:Q4_K_M"]
    assert llama["estimate"]["kv_cache_bytes"] == 131072 * 2 * 32 * 8 * 128 * 2
    assert any("eficiente" in w for w in llama["warnings"])
    large_models = [i for i in base["items"] if (i["parameter_count"] or 0) > 30e9]
    assert large_models and any(i["status"] != "not_recommended" for i in large_models)
    profiles = {
        p: env.client.get(f"{LOCAL}/recommendations", params={"profile": p}).json()["profile_pick"]
        for p in ("low_resource", "quality")
    }
    assert profiles["low_resource"] != profiles["quality"]
    assert env.client.get(f"{LOCAL}/recommendations", params={"profile": "x"}).status_code == 422
    assert env.client.get(f"{LOCAL}/recommendations", params={"context": 10}).status_code == 422
