// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AIStatus, ConsoleContextPreview, Insight, InsightResult, ToolExecutionOut } from "../../api/types";
import { installFetch, type Call, type Handler } from "../../test/sites";
import { ConsoleAssistant, usableExecutions } from "./ConsoleAssistant";

// Datos sintéticos de test: no proceden de ningún host ni modelo real.
const ASSET = "a7c00000-0000-0000-0000-0000000000a1";
const NOW = new Date().toISOString();

const STATUS: AIStatus = {
  enabled: true,
  available: true,
  reason: null,
  state: "local_available",
  mode_label: "Local AI",
  reachable: true,
  health_detail: null,
  health_latency_ms: 3,
  checked_at: NOW,
  provider: "openai_compatible",
  model: "qwen-local",
  location: "local",
  external_allowed: false,
  redaction: [],
  max_context_items: 40,
  rate_limit_per_user_per_minute: 6,
  prompt_versions: {},
  model_source: "settings",
  system_prompt_mode: "system",
  console_assist_available: true,
  console_max_executions: 2,
  console_assist_reason: null,
};

const DIGEST = "c".repeat(64);

function preview(task: ConsoleContextPreview["task"], overrides: Partial<ConsoleContextPreview> = {}): ConsoleContextPreview {
  return {
    task,
    context_sha256: DIGEST,
    destination: "loopback",
    model: "qwen-local",
    items: [{ ref: "R1", type: "tool_execution", label: "tool-1 sobre pc-01" }],
    redacted_values: 2,
    pseudonymized: [],
    chars: 812,
    question: null,
    document: { tool_results: [{ ref: "R1", output: { password: "[REDACTED]" } }] },
    ...overrides,
  };
}

function execution(id: string, overrides: Partial<ToolExecutionOut> = {}): ToolExecutionOut {
  return {
    execution_id: id,
    correlation_id: id,
    tool_id: "asset.profile",
    tool_version: 1,
    tool_name: `tool-${id.slice(-1)}`,
    category: "read",
    risk_level: "none",
    status: "succeeded",
    invoker: "user",
    actor: "user:ana",
    input: {},
    input_sha256: "0".repeat(64),
    output: { ok: true },
    output_sha256: "1".repeat(64),
    output_bytes: 10,
    truncated: false,
    summary: null,
    evidence: [],
    provenance: null,
    error_code: null,
    error_message: null,
    target_type: "asset",
    target_id: ASSET,
    target_label: "pc-01",
    site_id: null,
    asset_id: ASSET,
    incident_id: null,
    response_execution: null,
    approved_by: null,
    approved_at: null,
    approval_note: null,
    cancelled_by: null,
    created_at: NOW,
    started_at: NOW,
    finished_at: NOW,
    deadline_at: null,
    duration_ms: 5,
    version: 1,
    content_withheld: false,
    withheld_permissions: [],
    ...overrides,
  };
}

const E1 = "e7c00000-0000-0000-0000-000000000001";
const E2 = "e7c00000-0000-0000-0000-000000000002";
const E3 = "e7c00000-0000-0000-0000-000000000003";
const EXECUTIONS = [
  execution(E1),
  execution(E2, { category: "investigation" }),
  execution(E3),
  execution("e7c00000-0000-0000-0000-000000000004", { category: "action" }),
  execution("e7c00000-0000-0000-0000-000000000005", { status: "failed", output: null, output_sha256: null }),
];

function insight(result: Partial<InsightResult>): Insight {
  return {
    insight_id: "i-1",
    kind: "console_hypotheses",
    scope: "console",
    asset_id: ASSET,
    asset_name: "pc-01",
    detection_id: null,
    incident_id: null,
    risk_snapshot_id: null,
    question: null,
    provider: "openai_compatible",
    model: "qwen-local",
    prompt_version: "console_v1",
    generated_at: NOW,
    expires_at: NOW,
    stale: false,
    stale_reason: null,
    cached: false,
    evidence_count: 1,
    context_items: 2,
    latency_ms: 50,
    requested_by: "ana",
    tool_execution_ids: [E1],
    result: {
      summary: "Resumen <b>sin HTML</b>",
      assessment: "",
      confidence_note: "",
      key_findings: [],
      recommended_actions: [],
      evidence_refs: [{ ref: "R1", type: "tool_execution", id: E1, label: "tool-1 sobre pc-01", asset_id: ASSET }],
      limitations: [],
      insufficient_data: false,
      warnings: [],
      dropped_refs: 0,
      hypotheses: [],
      draft: null,
      origin: "model",
      ...result,
    },
  };
}

let routes: Record<string, Handler>;
let calls: Call[];

beforeEach(() => {
  routes = {};
  calls = installFetch(routes);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderAssistant(props: Partial<Parameters<typeof ConsoleAssistant>[0]> = {}) {
  return render(
    <MemoryRouter>
      <ConsoleAssistant status={STATUS} canUse executions={EXECUTIONS} assetId={ASSET} {...props} />
    </MemoryRouter>,
  );
}

const contextBodies = () =>
  calls.filter((c) => c.method === "POST" && c.path === "/ai/console/context").map((c) => JSON.parse(String(c.init.body)) as Record<string, unknown>);

/** Revisión y envío: el flujo obligatorio de 7C-Security-Fix1. */
function pickFirst() {
  const picks = screen.getByRole("group", { name: /Marca los resultados que quieres compartir/ });
  const first = within(picks).getAllByRole("checkbox")[0]!;
  if (!(first as HTMLInputElement).checked) fireEvent.click(first);
}

async function reviewAndSend(task: string) {
  pickFirst();
  fireEvent.click(screen.getByRole("button", { name: task }));
  const review = await screen.findByRole("region", { name: "Revisión de los datos a enviar" });
  fireEvent.click(within(review).getByRole("button", { name: "Enviar al modelo local" }));
  return review;
}

const assistBodies = () =>
  calls.filter((c) => c.method === "POST" && c.path === "/ai/console/assist").map((c) => JSON.parse(String(c.init.body)) as Record<string, unknown>);

describe("ConsoleAssistant (Fase 7C.2)", () => {
  it("solo ofrece resultados terminados con salida que no son acciones", () => {
    expect(usableExecutions(EXECUTIONS).map((e) => e.execution_id)).toEqual([E1, E2, E3]);
  });

  it("sin permiso, sin IA o con el asistente apagado lo dice y no ofrece tareas", () => {
    renderAssistant({ canUse: false });
    expect(screen.getByText(/no puede compartir datos de la consola con la IA/)).toBeInTheDocument();
    cleanup();
    renderAssistant({ status: { ...STATUS, available: false, reason: "IA local no configurada." } });
    expect(screen.getByRole("note")).toHaveTextContent("IA local no configurada. La consola funciona igual sin IA.");
    cleanup();
    renderAssistant({ status: { ...STATUS, console_assist_available: false } });
    expect(screen.getByRole("note")).toHaveTextContent("desactivado en este servidor");
    expect(screen.queryByRole("group", { name: "Tareas del asistente" })).toBeNull();
  });

  it("respeta el máximo de resultados y envía solo los elegidos", async () => {
    routes["POST /ai/console/assist"] = () => ({
      body: insight({
        hypotheses: [{ text: "Uso legítimo de administración", certainty: "possible", evidence: ["R1"], validate_with: "Preguntar al responsable del equipo" }],
      }),
    });
    renderAssistant();
    const picks = screen.getByRole("group", { name: /Marca los resultados que quieres compartir/ });
    const boxes = within(picks).getAllByRole("checkbox");
    expect(boxes).toHaveLength(3);
    // 7C-Security-Fix1: nada marcado por defecto; sin elección no se puede pedir nada.
    expect(boxes.map((b) => (b as HTMLInputElement).checked)).toEqual([false, false, false]);
    expect(screen.getByRole("button", { name: "Hipótesis" })).toBeDisabled();
    fireEvent.click(boxes[0]!);
    fireEvent.click(boxes[1]!);
    // Con máximo 2, el tercero queda bloqueado; se desmarca uno para enviar solo E1.
    expect(boxes[2]).toBeDisabled();
    fireEvent.click(boxes[1]!);
    fireEvent.change(screen.getByLabelText("Pregunta concreta (opcional)"), { target: { value: "¿Es normal?" } });
    routes["POST /ai/console/context"] = () => ({ body: preview("hypotheses", { question: "¿Es normal?" }) });
    await reviewAndSend("Hipótesis");
    expect(await screen.findByText("Sugerencia del modelo")).toBeInTheDocument();
    expect(contextBodies()[0]).toEqual({
      task: "hypotheses",
      execution_ids: [E1],
      asset_id: ASSET,
      detection_id: null,
      question: "¿Es normal?",
    });
    expect(screen.getByLabelText("Modelo en uso")).toHaveTextContent("Local AI · qwen-local · Disponible");
    expect(screen.getByLabelText("Modelo en uso")).toHaveTextContent("configurado en el servidor");
    expect(assistBodies()[0]).toEqual({
      task: "hypotheses",
      execution_ids: [E1],
      asset_id: ASSET,
      detection_id: null,
      question: "¿Es normal?",
      context_sha256: DIGEST,
      confirm_send: true,
    });
    // Enviado: la revisión desaparece.
    expect(screen.queryByRole("region", { name: "Revisión de los datos a enviar" })).toBeNull();
    const hypotheses = screen.getByRole("region", { name: "Hipótesis del modelo" });
    expect(within(hypotheses).getByText("Posible")).toBeInTheDocument();
    expect(hypotheses).toHaveTextContent("Cómo validarla: Preguntar al responsable del equipo");
    expect(screen.getByText(/No es evidencia/)).toBeInTheDocument();
    // El texto del modelo se pinta como texto, nunca como HTML.
    expect(screen.getByText("Resumen <b>sin HTML</b>")).toBeInTheDocument();
    const data = screen.getByRole("region", { name: "Datos de Sentra citados" });
    expect(within(data).getByText("Resultado de herramienta: tool-1 sobre pc-01")).toBeInTheDocument();
  });

  it("el borrador es de solo lectura y una respuesta sin modelo no se marca como sugerencia", async () => {
    routes["POST /ai/console/assist"] = () => ({
      body: insight({ origin: "sentra", draft: "[Borrador generado por IA local: revisar antes de usar]\nTexto" }),
    });
    routes["POST /ai/console/context"] = () => ({ body: preview("draft_note") });
    renderAssistant();
    await reviewAndSend("Borrador de nota");
    expect(await screen.findByText("Respuesta de Sentra (sin modelo)")).toBeInTheDocument();
    expect(screen.queryByText("Sugerencia del modelo")).toBeNull();
    const draft = screen.getByRole("region", { name: "Borrador de nota" });
    expect(within(draft).getByRole("textbox")).toHaveAttribute("readonly");
  });

  it("traduce los errores del servidor sin caer a otro proveedor", async () => {
    routes["POST /ai/console/assist"] = () => ({
      status: 503,
      body: { error: { code: "ai_provider_unavailable", message: "down" } },
    });
    routes["POST /ai/console/context"] = () => ({ body: preview("summary") });
    renderAssistant();
    await reviewAndSend("Resumir");
    expect(await screen.findByRole("alert")).toHaveTextContent("No se usa ningún otro proveedor");
    await waitFor(() => expect(screen.getByRole("button", { name: "Resumir" })).toBeEnabled());
  });

  it("con un modelo que solo razona dice el motivo concreto (7C-Fix2)", async () => {
    routes["POST /ai/console/assist"] = () => ({
      status: 502,
      body: { error: { code: "ai_invalid_response", message: "x", details: [{ reason: "truncated_reasoning" }] } },
    });
    routes["POST /ai/console/context"] = () => ({ body: preview("summary") });
    renderAssistant();
    await reviewAndSend("Resumir");
    expect(await screen.findByRole("alert")).toHaveTextContent("agotó el límite de salida razonando");
  });
});

describe("ConsoleAssistant: privacidad estricta (7C-Security-Fix1)", () => {
  it("enseña lo que se enviará y no envía nada si se cancela", async () => {
    routes["POST /ai/console/context"] = () => ({ body: preview("summary") });
    renderAssistant();
    pickFirst();
    fireEvent.click(screen.getByRole("button", { name: "Resumir" }));
    const review = await screen.findByRole("region", { name: "Revisión de los datos a enviar" });
    expect(review).toHaveTextContent("Destino: este servidor (loopback)");
    expect(review).toHaveTextContent("2 valores con aspecto de secreto retirados");
    expect(within(review).getByRole("list", { name: "Elementos incluidos" })).toHaveTextContent("tool-1 sobre pc-01");
    expect(review.querySelector("pre")?.textContent).toContain("[REDACTED]");
    fireEvent.click(within(review).getByRole("button", { name: "Cancelar" }));
    expect(screen.queryByRole("region", { name: "Revisión de los datos a enviar" })).toBeNull();
    expect(assistBodies()).toHaveLength(0);
  });

  it("si los datos cambiaron desde la revisión lo dice y obliga a revisar otra vez", async () => {
    routes["POST /ai/console/context"] = () => ({ body: preview("summary") });
    routes["POST /ai/console/assist"] = () => ({
      status: 409,
      body: { error: { code: "console_context_changed", message: "changed" } },
    });
    renderAssistant();
    await reviewAndSend("Resumir");
    expect(await screen.findByRole("alert")).toHaveTextContent("no se ha enviado nada");
    expect(screen.queryByRole("region", { name: "Revisión de los datos a enviar" })).toBeNull();
  });

  it("con el modelo fuera de loopback explica por qué no está disponible", () => {
    renderAssistant({
      status: {
        ...STATUS,
        console_assist_available: false,
        console_assist_reason: "El asistente de la consola solo usa un modelo en este mismo servidor.",
      },
    });
    expect(screen.getByRole("note")).toHaveTextContent("solo usa un modelo en este mismo servidor");
    expect(screen.queryByRole("group", { name: "Tareas del asistente" })).toBeNull();
  });
});
