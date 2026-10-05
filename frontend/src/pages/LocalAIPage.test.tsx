// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  LocalBenchmark,
  LocalGPU,
  LocalHardware,
  LocalModel,
  LocalModelList,
  LocalRuntimeStatus,
  ModelEstimate,
  ModelRecommendation,
  RecommendationList,
  Role,
} from "../api/types";
import { compatTone, formatContext, formatParams, gpuSummary } from "../lib/localAi";
import { WithRole } from "../test/auth";
import { LocalAIPage } from "./LocalAIPage";

// Datos sintéticos de test: no proceden de ningún hardware ni modelo real.
const GIB = 1024 ** 3;
const MODEL_ID = "aaaaaaaa-0000-0000-0000-000000000001";
const BENCH_ID = "bbbbbbbb-0000-0000-0000-000000000001";

const GPU: LocalGPU = {
  index: 0,
  vendor: "nvidia",
  model: "GPU de prueba",
  vram_total_bytes: 12 * GIB,
  vram_free_bytes: 11 * GIB,
  memory_kind: "dedicated",
  source: "nvidia-smi",
  driver: "1.0",
};

const HARDWARE: LocalHardware = {
  os: "Windows",
  os_version: "11",
  architecture: "AMD64",
  cpu: { model: "CPU de prueba", physical_cores: 8, logical_cores: 16 },
  ram_total_bytes: 32 * GIB,
  ram_available_bytes: 20 * GIB,
  gpus: [GPU],
  disk_free_bytes: 500 * GIB,
  disk_total_bytes: 1000 * GIB,
  disk_scope: "model_directory",
  detected_at: new Date().toISOString(),
  duration_ms: 40,
  warnings: [],
};

const RUNTIME: LocalRuntimeStatus = {
  kind: "llama_cpp",
  label: "llama.cpp",
  source: "env",
  capabilities: {
    list_models: true,
    load_model: false,
    unload_model: false,
    benchmark: "runtime_timings",
    gpu_offload: true,
    multi_gpu_split: true,
    gguf_files: true,
    notes: ["llama-server carga el modelo al arrancar (-m)."],
  },
  available: true,
  reason: null,
  reachable: true,
  health_detail: null,
  health_latency_ms: 3,
  version: null,
  detected_kind: "llama_cpp",
  loaded_models: ["qwen-test.gguf"],
  configured_context: 16384,
  active_model: null,
  effective_model: "qwen-test.gguf",
  external_ai: "blocked",
  default_context_tokens: 16384,
  slots: ["default"],
};

const ESTIMATE: ModelEstimate = {
  weights_bytes: 4.5 * GIB,
  weights_source: "file",
  kv_cache_bytes: 2 * GIB,
  overhead_bytes: 0.7 * GIB,
  total_bytes: 7.2 * GIB,
  context_tokens: 16384,
  kv_type: "f16",
  complete: true,
  missing: [],
  placement: "full_gpu",
  vram_bytes: 7.2 * GIB,
  ram_bytes: 0,
  gpu_fraction: 1,
  usable_vram_bytes: 10.8 * GIB,
  usable_ram_bytes: 17 * GIB,
  safety_margin_percent: 10,
};

function bench(overrides: Partial<LocalBenchmark> = {}): LocalBenchmark {
  return {
    benchmark_id: BENCH_ID,
    model_id: MODEL_ID,
    status: "completed",
    runtime: "llama_cpp",
    measurement: "runtime_timings",
    max_tokens: 128,
    configured_context: 16384,
    load_ms: null,
    ttft_ms: 180,
    prompt_tokens: 60,
    output_tokens: 128,
    prompt_tps: 900,
    generation_tps: 42.5,
    peak_ram_bytes: 10 * GIB,
    peak_vram_bytes: 8 * GIB,
    performance_class: "excellent",
    error: null,
    requested_by: "admin",
    started_at: new Date().toISOString(),
    finished_at: new Date().toISOString(),
    ...overrides,
  };
}

function model(overrides: Partial<LocalModel> = {}): LocalModel {
  return {
    model_id: MODEL_ID,
    name: "Qwen test 8B",
    family: "qwen",
    architecture: "qwen3",
    parameter_count: 8_190_000_000,
    quantization: "Q4_K_M",
    file_size_bytes: 4.5 * GIB,
    native_context: 40960,
    runtime: "llama_cpp",
    runtime_model_id: "qwen-test.gguf",
    file_name: "qwen-test.gguf",
    local_path: "D:\\Models\\qwen-test.gguf",
    split_count: 1,
    metadata_source: "gguf",
    source: null,
    license: "apache-2.0",
    checksum_sha256: "ab".repeat(32),
    checksum_status: "ok",
    installed_at: new Date().toISOString(),
    last_selected_at: null,
    state: "loaded",
    active: false,
    loaded: true,
    compatibility: "recommended",
    recommended_for_sentra: true,
    latest_benchmark: null,
    ...overrides,
  };
}

function rec(overrides: Partial<ModelRecommendation> = {}): ModelRecommendation {
  return {
    key: `model:${MODEL_ID}`,
    origin: "registered",
    model_id: MODEL_ID,
    catalog_id: null,
    name: "Qwen test 8B",
    family: "qwen",
    parameter_count: 8_190_000_000,
    quantization: "Q4_K_M",
    native_context: 40960,
    license: "apache-2.0",
    source: null,
    status: "recommended",
    quality: "high",
    speed: "fast",
    speed_source: "estimate",
    estimate: ESTIMATE,
    reasons: ["Cabe entero en VRAM con el contexto elegido."],
    warnings: [],
    limitations: ["Cifras estimadas."],
    recommended_for_sentra: true,
    score: 3.2,
    observed_tps: null,
    performance_class: null,
    ...overrides,
  };
}

let runtime: LocalRuntimeStatus;
let hardware: LocalHardware;
let models: LocalModelList;
let recommendations: RecommendationList;
let selectFails: boolean;
let calls: { method: string; path: string; search: string; body: unknown }[];

function json(statusCode: number, body: unknown): Response {
  if (statusCode === 204) return new Response(null, { status: 204 });
  return new Response(JSON.stringify(body), { status: statusCode, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  runtime = RUNTIME;
  hardware = HARDWARE;
  models = { items: [model()], total: 1, discovered: [] };
  recommendations = {
    profile: "sentra",
    context_tokens: 16384,
    runtime: "llama_cpp",
    hardware_detected_at: HARDWARE.detected_at,
    items: [
      rec(),
      rec({
        key: "catalog:llama-3.3-70b:Q4_K_M",
        origin: "catalog",
        model_id: null,
        catalog_id: "llama-3.3-70b",
        name: "Llama 3.3 70B",
        status: "not_recommended",
        recommended_for_sentra: false,
        estimate: { ...ESTIMATE, placement: "does_not_fit" },
        reasons: ["No cabe en VRAM + RAM con el margen de seguridad."],
      }),
    ],
    total: 2,
    sentra_pick: `model:${MODEL_ID}`,
    profile_pick: `model:${MODEL_ID}`,
  };
  selectFails = false;
  calls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const url = new URL(input, "http://localhost");
      const path = url.pathname.replace("/api/v1", "");
      calls.push({ method, path, search: url.search, body: init.body ? JSON.parse(String(init.body)) : undefined });
      if (path === "/ai/local/runtime") return json(200, runtime);
      if (path === "/ai/local/hardware") return json(200, hardware);
      if (path === "/ai/local/hardware/refresh") return json(200, hardware);
      if (path === "/ai/local/models") return json(200, models);
      if (path === "/ai/local/recommendations") {
        return json(200, { ...recommendations, profile: url.searchParams.get("profile") ?? "sentra" });
      }
      if (path === `/ai/local/models/${MODEL_ID}`) {
        return json(200, { model: models.items[0], evaluation: rec(), benchmarks: [bench()], runtime_notes: [] });
      }
      if (path === `/ai/local/models/${MODEL_ID}/select`) {
        if (selectFails) {
          return json(409, { error: { code: "local_model_not_loaded", message: "El runtime tiene cargado otro modelo." } });
        }
        return json(200, runtime);
      }
      if (path === `/ai/local/models/${MODEL_ID}/benchmark`) return json(202, bench({ status: "running" }));
      if (path === `/ai/local/benchmarks/${BENCH_ID}`) return json(200, bench());
      if (path === `/ai/local/models/${MODEL_ID}/unregister`) return json(204, null);
      return json(404, { error: { code: "not_found", message: path } });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderPage(role: Role = "admin") {
  return render(
    <MemoryRouter>
      <WithRole role={role}>
        <LocalAIPage />
      </WithRole>
    </MemoryRouter>,
  );
}

const posts = () => calls.filter((c) => c.method !== "GET");

describe("LocalAIPage", () => {
  it("shows a loading state first", () => {
    renderPage();
    expect(screen.getByText("Cargando IA local…")).toBeInTheDocument();
  });

  it("shows the header with Local AI, runtime and external AI blocked", async () => {
    renderPage();
    const header = await screen.findByLabelText("Estado de la IA local");
    expect(header).toHaveTextContent("Disponible");
    expect(header).toHaveTextContent("qwen-test.gguf");
    expect(header).toHaveTextContent("llama.cpp");
    expect(header).toHaveTextContent("Blocked");
  });

  it("shows the detected hardware", async () => {
    renderPage();
    const card = await screen.findByRole("region", { name: "Hardware" });
    expect(within(card).getByText("CPU de prueba")).toBeInTheDocument();
    expect(card).toHaveTextContent("32.0 GB");
    expect(card).toHaveTextContent("GPU de prueba (12.0 GB VRAM)");
  });

  it("handles a CPU-only server", async () => {
    hardware = { ...HARDWARE, gpus: [] };
    renderPage();
    const card = await screen.findByRole("region", { name: "Hardware" });
    expect(card).toHaveTextContent("Sin GPU");
  });

  it("lists registered models with state and compatibility", async () => {
    renderPage();
    const card = await screen.findByRole("article", { name: "Qwen test 8B" });
    expect(card).toHaveTextContent("Cargado");
    expect(card).toHaveTextContent("Recomendado");
    expect(card).toHaveTextContent("8.2B");
    expect(card).toHaveTextContent("Q4_K_M");
    expect(card).toHaveTextContent("40K");
  });

  it("shows an empty state", async () => {
    models = { items: [], total: 0, discovered: [] };
    renderPage();
    expect(await screen.findByText(/No hay modelos registrados/)).toBeInTheDocument();
  });

  it("shows recommendations with the Sentra pick and reasons", async () => {
    renderPage();
    const panel = await screen.findByRole("region", { name: "Recomendaciones" });
    expect(await within(panel).findAllByText("Recommended for Sentra")).not.toHaveLength(0);
    expect(within(panel).getAllByText("Cabe entero en VRAM con el contexto elegido.").length).toBeGreaterThan(0);
    // Los no recomendados quedan ocultos hasta pedirlos.
    expect(within(panel).queryByText("Llama 3.3 70B")).not.toBeInTheDocument();
    fireEvent.click(within(panel).getByRole("button", { name: "Ver también los no recomendados" }));
    expect(within(panel).getByText("Llama 3.3 70B")).toBeInTheDocument();
    expect(within(panel).getByText("No cabe en VRAM + RAM con el margen de seguridad.")).toBeInTheDocument();
  });

  it("asks for recommendations with the chosen profile and context", async () => {
    renderPage();
    await screen.findByRole("region", { name: "Recomendaciones" });
    fireEvent.click(screen.getByRole("button", { name: "Mejor calidad" }));
    fireEvent.change(screen.getByLabelText("Contexto objetivo"), { target: { value: "131072" } });
    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.path === "/ai/local/recommendations" &&
            c.search.includes("profile=quality") &&
            c.search.includes("context=131072"),
        ),
      ).toBe(true),
    );
  });

  it("opens the details view with metadata and benchmark history", async () => {
    renderPage();
    const card = await screen.findByRole("article", { name: "Qwen test 8B" });
    fireEvent.click(within(card).getByRole("button", { name: "Detalles" }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText("ab".repeat(32))).toBeInTheDocument();
    expect(within(dialog).getByText(/Cabecera GGUF verificada/)).toBeInTheDocument();
    expect(within(dialog).getByText("42.5 tok/s")).toBeInTheDocument();
    expect(within(dialog).getByText("Excelente")).toBeInTheDocument();
  });

  it("starts a benchmark and shows the result", async () => {
    renderPage();
    const card = await screen.findByRole("article", { name: "Qwen test 8B" });
    fireEvent.click(within(card).getByRole("button", { name: "Benchmark" }));
    const running = await screen.findByRole("status", { name: "Benchmark en curso" });
    expect(await within(running).findByText("42.5 tok/s")).toBeInTheDocument();
    expect(posts().map((c) => c.path)).toEqual([`/ai/local/models/${MODEL_ID}/benchmark`]);
  });

  it("selects a model and keeps the previous one on failure", async () => {
    selectFails = true;
    renderPage();
    const card = await screen.findByRole("article", { name: "Qwen test 8B" });
    fireEvent.click(within(card).getByRole("button", { name: "Seleccionar" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "No se pudo activar Qwen test 8B: El runtime no tiene cargado este modelo: El runtime tiene cargado otro modelo. El modelo anterior sigue activo.",
    );
  });

  it("removes only the registration after confirming", async () => {
    renderPage();
    const card = await screen.findByRole("article", { name: "Qwen test 8B" });
    fireEvent.click(within(card).getByRole("button", { name: "Quitar registro" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("El fichero del modelo no se borra.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Quitar registro" }));
    await waitFor(() => expect(posts().map((c) => c.path)).toEqual([`/ai/local/models/${MODEL_ID}/unregister`]));
  });

  it("warns when the runtime is down and never offers an external fallback", async () => {
    runtime = { ...RUNTIME, reachable: false, health_detail: "connection refused", loaded_models: [] };
    renderPage();
    expect(await screen.findByText(/El runtime local no responde \(connection refused\)/)).toBeInTheDocument();
    expect(screen.getByText(/nunca usará un proveedor externo/)).toBeInTheDocument();
  });

  it("explains why the manager is unavailable when AI is disabled", async () => {
    runtime = { ...RUNTIME, available: false, reachable: null, reason: "IA no configurada: AI_ENABLED=false." };
    renderPage();
    expect(await screen.findByText("IA no configurada: AI_ENABLED=false.")).toBeInTheDocument();
  });

  it("is read-only for viewers and analysts", async () => {
    for (const role of ["viewer", "analyst"] as const) {
      renderPage(role);
      const card = await screen.findByRole("article", { name: "Qwen test 8B" });
      expect(within(card).getByRole("button", { name: "Detalles" })).toBeInTheDocument();
      expect(within(card).queryByRole("button", { name: "Seleccionar" })).not.toBeInTheDocument();
      expect(within(card).queryByRole("button", { name: "Benchmark" })).not.toBeInTheDocument();
      expect(screen.queryByRole("region", { name: "Importar modelo" })).not.toBeInTheDocument();
      expect(screen.queryByRole("combobox", { name: "Runtime" })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Volver a detectar" })).not.toBeInTheDocument();
      cleanup();
    }
    expect(posts()).toHaveLength(0);
  });

  it("shows an API error with a retry", async () => {
    runtime = undefined as unknown as LocalRuntimeStatus;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => json(500, { error: { code: "internal_error", message: "boom" } })),
    );
    renderPage();
    expect(await screen.findByRole("button", { name: /Reintentar/ })).toBeInTheDocument();
  });

  it("registers a GGUF path for admins", async () => {
    renderPage();
    const form = await screen.findByRole("region", { name: "Importar modelo" });
    fireEvent.change(within(form).getByLabelText("Ruta del fichero GGUF"), {
      target: { value: "D:\\Models\\otro.gguf" },
    });
    fireEvent.click(within(form).getByRole("button", { name: "Registrar" }));
    await waitFor(() => expect(posts()[0]?.body).toEqual({ path: "D:\\Models\\otro.gguf" }));
  });
});

describe("lib/localAi", () => {
  it("formats params and context", () => {
    expect(formatParams(8_030_261_248)).toBe("8.0B");
    expect(formatParams(770_000_000)).toBe("770M");
    expect(formatParams(null)).toBe("—");
    expect(formatContext(131072)).toBe("128K");
    expect(formatContext(102400)).toBe("100K");
    expect(formatContext(40960)).toBe("40K");
  });

  it("maps compatibility to badge tones", () => {
    expect(compatTone("recommended")).toContain("badge--ok");
    expect(compatTone("compatible_with_offload")).toContain("badge--warn");
    expect(compatTone("not_recommended")).toContain("badge--crit");
  });

  it("summarizes GPUs", () => {
    const fmt = (n: number) => `${n / GIB} GB`;
    expect(gpuSummary({ ...HARDWARE, gpus: [] }, fmt)).toBe("Sin GPU");
    expect(gpuSummary(HARDWARE, fmt)).toBe("GPU de prueba (12 GB VRAM)");
    expect(
      gpuSummary({ ...HARDWARE, gpus: [{ ...GPU, memory_kind: "shared", vram_total_bytes: null }] }, fmt),
    ).toBe("Sin GPU dedicada conocida");
  });
});
