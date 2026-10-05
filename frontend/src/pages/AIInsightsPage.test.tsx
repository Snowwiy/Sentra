// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AIStatus, Insight } from "../api/types";
import { AIAnalyzePanel } from "../components/ai/AIAnalyzePanel";
import { aiApi } from "../api/sentra";
import { WithRole } from "../test/auth";
import { AIInsightsPage } from "./AIInsightsPage";

// Datos sintéticos de test: no proceden de ningún host ni modelo real.
const ASSET = "aaaaaaaa-0000-0000-0000-000000000001";
const DETECTION = "11111111-2222-3333-4444-555555555555";

const AVAILABLE: AIStatus = {
  enabled: true,
  available: true,
  reason: null,
  provider: "openai_compatible",
  model: "llama-local",
  location: "local",
  external_allowed: false,
  redaction: [],
  max_context_items: 40,
  rate_limit_per_user_per_minute: 6,
  prompt_versions: { ask: "ask_v1.p1" },
};

function insight(overrides: Partial<Insight> = {}): Insight {
  return {
    insight_id: "i-1",
    kind: "ask",
    scope: "asset",
    asset_id: ASSET,
    asset_name: "pc-demo",
    detection_id: null,
    risk_snapshot_id: null,
    question: "¿Por qué pc-demo tiene riesgo alto?",
    provider: "openai_compatible",
    model: "llama-local",
    prompt_version: "ask_v1.p1",
    generated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    stale: false,
    stale_reason: null,
    cached: false,
    evidence_count: 1,
    context_items: 5,
    latency_ms: 120,
    requested_by: "viewer",
    result: {
      summary: "Fuerza bruta detectada <script>alert(1)</script>",
      assessment: "Requiere validación del analista.",
      confidence_note: "Media.",
      key_findings: [{ text: "Fallos repetidos de inicio de sesión.", certainty: "detected", evidence: ["D1"] }],
      recommended_actions: [{ text: "Validar si el login fue autorizado.", evidence: ["D1"] }],
      evidence_refs: [{ ref: "D1", type: "detection", id: DETECTION, label: "AUTH-001: Fuerza bruta", asset_id: ASSET }],
      limitations: ["Solo datos de Sentra."],
      insufficient_data: false,
      warnings: [],
      dropped_refs: 0,
    },
    ...overrides,
  };
}

let status: AIStatus;
let calls: { method: string; path: string; body: unknown }[];

function json(statusCode: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status: statusCode, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  status = AVAILABLE;
  calls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const path = new URL(input, "http://localhost").pathname.replace("/api/v1", "");
      calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined });
      if (path === "/ai/status") return json(200, status);
      if (path === "/ai/insights") return json(200, { items: [insight({ insight_id: "old", stale: true, stale_reason: "data_changed" })], total: 1 });
      if (path === "/ai/ask") return json(200, insight());
      if (path === `/ai/detections/${DETECTION}/analyze`) {
        return json(502, { error: { code: "ai_ungrounded_response", message: "x" } });
      }
      return json(404, { error: { code: "not_found", message: path } });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderPage() {
  return render(
    <MemoryRouter>
      <WithRole role="viewer">
        <AIInsightsPage />
      </WithRole>
    </MemoryRouter>,
  );
}

describe("AIInsightsPage", () => {
  it("says AI is not configured and offers no ask form", async () => {
    status = { ...AVAILABLE, enabled: false, available: false, reason: "IA no configurada: AI_ENABLED=false." };
    renderPage();
    expect(await screen.findByText(/IA no configurada: AI_ENABLED=false/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Pregunta para Sentra AI")).not.toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("asks only on submit and shows model text as plain text, apart from Sentra data", async () => {
    const { container } = renderPage();
    const box = await screen.findByLabelText("Pregunta para Sentra AI");
    // Abrir la página no llama al modelo.
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);
    fireEvent.change(box, { target: { value: "¿Por qué pc-demo tiene riesgo alto?" } });
    fireEvent.click(screen.getByRole("button", { name: "Preguntar" }));
    const model = await screen.findByRole("region", { name: "Análisis de IA" });
    const post = calls.find((c) => c.method === "POST");
    // Solo la pregunta y el alcance: nunca proveedor, URL ni modelo.
    expect(post?.body).toEqual({ question: "¿Por qué pc-demo tiene riesgo alto?", asset_id: null, detection_id: null, refresh: false });
    expect(within(model).getByText(/Fuerza bruta detectada <script>alert\(1\)<\/script>/)).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
    expect(within(model).getByText("Detectado")).toBeInTheDocument();
    expect(within(model).getByText(/Verifique la evidencia antes de tomar acciones/)).toBeInTheDocument();
    const data = screen.getAllByRole("region", { name: "Datos de Sentra" })[0] as HTMLElement;
    expect(within(data).getByRole("link", { name: /AUTH-001: Fuerza bruta/ })).toHaveAttribute("href", `/detections/${DETECTION}`);
  });

  it("marks stale history entries", async () => {
    renderPage();
    expect(await screen.findByText(/Desactualizado \(los datos cambiaron\)/)).toBeInTheDocument();
  });
});

describe("AIAnalyzePanel", () => {
  it("shows a controlled error when the answer is not grounded", async () => {
    render(
      <MemoryRouter>
        <WithRole role="viewer">
          <AIAnalyzePanel
            title="Explicación asistida por IA"
            buttonLabel="Explicar con IA"
            kind="detection_analysis"
            detectionId={DETECTION}
            run={(refresh) => aiApi.analyzeDetection(DETECTION, refresh)}
          />
        </WithRole>
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Explicar con IA" }));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("no citaba evidencia válida de Sentra"),
    );
  });
});
