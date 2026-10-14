// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ResponseAction, ResponseExecution, ResponsePreview } from "../../api/types";
import { WithRole } from "../../test/auth";
import { InvestigateButton } from "./InvestigateButton";
import { RunActionDialog } from "./RunActionDialog";

// Identificadores sintéticos: nada real.
const ASSET = "aaaaaaaa-0000-0000-0000-000000000001";
const EXECUTION = "eeeeeeee-0000-0000-0000-000000000001";

function action(overrides: Partial<ResponseAction> = {}): ResponseAction {
  return {
    id: "recalculate_risk",
    name: "Recalcular riesgo",
    description: "Recalcula ya el riesgo del activo.",
    category: "analysis",
    scope: "server",
    target_type: "asset",
    risk_level: "low",
    destructive: false,
    requires_confirmation: false,
    requires_agent: false,
    supported_platforms: [],
    required_role: "analyst",
    required_permissions: ["response:execute"],
    timeout_seconds: 60,
    retry_policy: "none",
    availability: "available",
    expected_effect: "Se recalcula el riesgo.",
    parameters_schema: { properties: {}, type: "object" },
    permitted: true,
    blockers: [],
    ...overrides,
  };
}

const ARCHIVE = action({
  id: "archive_asset",
  name: "Archivar activo",
  risk_level: "medium",
  requires_confirmation: true,
  required_role: "admin",
  parameters_schema: {
    properties: { reason: { maxLength: 500, minLength: 3, title: "Reason", type: "string" } },
    required: ["reason"],
    type: "object",
  },
});

function preview(overrides: Partial<ResponsePreview> = {}): ResponsePreview {
  return {
    action: "recalculate_risk",
    action_name: "Recalcular riesgo",
    target_type: "asset",
    target_id: ASSET,
    target_label: "pc-demo",
    parameters: {},
    risk_level: "low",
    required_role: "analyst",
    requires_confirmation: false,
    requires_agent: false,
    expected_effect: "Se recalcula el riesgo.",
    preconditions: [],
    blockers: [],
    warnings: [],
    allowed: true,
    ...overrides,
  };
}

function execution(overrides: Partial<ResponseExecution> = {}): ResponseExecution {
  return {
    execution_id: EXECUTION,
    correlation_id: "cccccccc-0000-0000-0000-000000000001",
    action_id: "recalculate_risk",
    action_name: "Recalcular riesgo",
    status: "succeeded",
    risk_level: "low",
    requires_agent: false,
    target_type: "asset",
    target_id: ASSET,
    target_label: "pc-demo",
    asset_id: ASSET,
    incident_id: null,
    detection_id: null,
    parameters: {},
    result: null,
    result_summary: null,
    error_code: null,
    error_message: null,
    blockers: [],
    actor: "analyst",
    reason: null,
    playbook_run_id: null,
    step_index: null,
    created_at: new Date().toISOString(),
    queued_at: null,
    started_at: null,
    finished_at: null,
    deadline_at: null,
    duration_ms: 12,
    version: 2,
    deduplicated: false,
    ...overrides,
  };
}

type Handler = (body: Record<string, unknown>) => { status?: number; body: unknown };
let routes: Record<string, Handler>;
let calls: { method: string; path: string; body: Record<string, unknown> }[];

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  calls = [];
  routes = {};
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const path = new URL(input, "http://localhost").pathname.replace("/api/v1", "");
      const body = init.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
      calls.push({ method, path, body });
      const handler = routes[`${method} ${path}`];
      if (!handler) return json(404, { error: { code: "not_found", message: `no route ${path}` } });
      const { status = 200, body: out } = handler(body);
      return json(status, out);
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderDialog(a: ResponseAction, role: "admin" | "analyst" = "admin") {
  return render(
    <MemoryRouter>
      <WithRole role={role}>
        <RunActionDialog action={a} assetId={ASSET} onClose={() => undefined} />
      </WithRole>
    </MemoryRouter>,
  );
}

describe("RunActionDialog", () => {
  it("previews on open and disables Execute while the server reports blockers", async () => {
    routes["POST /response/preview"] = () => ({
      body: preview({
        allowed: false,
        blockers: [{ code: "agent_offline", message: "El agente del activo no está conectado" }],
      }),
    });
    renderDialog(action({ id: "collect_inventory", scope: "agent", requires_agent: true }));

    expect(await screen.findByText(/El agente del activo no está conectado/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ejecutar" })).toBeDisabled();
    expect(calls.filter((c) => c.method === "POST" && c.path === "/response/executions")).toHaveLength(0);
    expect(calls[0]?.body).toMatchObject({ action_id: "collect_inventory", target_id: ASSET, target_type: "asset" });
  });

  it("requires the explicit checkbox and sends confirm:true with one idempotency key", async () => {
    routes["POST /response/preview"] = (body) => ({
      body: preview({
        action: "archive_asset",
        action_name: "Archivar activo",
        risk_level: "medium",
        required_role: "admin",
        requires_confirmation: true,
        parameters: body.parameters as Record<string, unknown>,
      }),
    });
    routes["POST /response/executions"] = () => ({ body: execution({ action_id: "archive_asset", action_name: "Archivar activo" }) });
    renderDialog(ARCHIVE);

    const preview_ = screen.getByRole("button", { name: "Previsualizar" });
    expect(preview_).toBeDisabled(); // falta el motivo obligatorio
    fireEvent.change(screen.getByLabelText("Motivo del archivado"), {
      target: { value: "retirado" },
    });
    fireEvent.click(preview_);

    const execute = await screen.findByRole("button", { name: "Ejecutar" });
    await screen.findByText(/Confirmo que quiero ejecutar/);
    expect(execute).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox"));
    expect(execute).toBeEnabled();
    fireEvent.click(execute);

    await screen.findByText("Completada");
    const previewCall = calls.find((c) => c.path === "/response/preview");
    const executeCall = calls.find((c) => c.method === "POST" && c.path === "/response/executions");
    expect(executeCall?.body).toMatchObject({
      action_id: "archive_asset",
      parameters: { reason: "retirado" },
      confirm: true,
    });
    const key = String(executeCall?.body.idempotency_key);
    expect(key).toMatch(/^[A-Za-z0-9_-]{8,64}$/);
    expect(previewCall?.body.idempotency_key).toBe(key);
  });

  it("renders the server result as literal text, never as HTML", async () => {
    routes["POST /response/preview"] = () => ({ body: preview() });
    routes["POST /response/executions"] = () => ({
      body: execution({
        result_summary: "<script>alert(1)</script>",
        result: { note: "<img src=x onerror=alert(1)>" },
      }),
    });
    const { container } = renderDialog(action());

    const execute = await screen.findByRole("button", { name: "Ejecutar" });
    await waitFor(() => expect(execute).toBeEnabled());
    fireEvent.click(execute);

    expect(await screen.findByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument();
    expect(container.ownerDocument.querySelector("script")).toBeNull();
    expect(container.ownerDocument.querySelector("img")).toBeNull();
  });

  it("shows the blockers of a 409 response_blocked and links the recorded attempt", async () => {
    routes["POST /response/preview"] = () => ({ body: preview() });
    routes["POST /response/executions"] = () => ({
      status: 409,
      body: {
        error: {
          code: "response_blocked",
          message: "The response policy blocks this action",
          details: [{ execution_id: EXECUTION }, { code: "asset_archived", message: "El activo está archivado" }],
        },
      },
    });
    renderDialog(action());

    const execute = await screen.findByRole("button", { name: "Ejecutar" });
    await waitFor(() => expect(execute).toBeEnabled());
    fireEvent.click(execute);

    expect(await screen.findByText(/El activo está archivado/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "ver ejecución bloqueada" })).toHaveAttribute(
      "href",
      `/response?tab=executions&execution=${EXECUTION}`,
    );
  });
});

describe("InvestigateButton", () => {
  it("is hidden without response:execute", () => {
    render(
      <MemoryRouter>
        <WithRole role="viewer">
          <InvestigateButton targets={[{ assetId: ASSET, label: "pc-demo" }]} />
        </WithRole>
      </MemoryRouter>,
    );
    expect(screen.queryByRole("button", { name: "Investigar" })).toBeNull();
  });

  it("is shown to analysts", () => {
    render(
      <MemoryRouter>
        <WithRole role="analyst">
          <InvestigateButton targets={[{ assetId: ASSET, label: "pc-demo" }]} />
        </WithRole>
      </MemoryRouter>,
    );
    expect(screen.getByRole("button", { name: "Investigar" })).toBeEnabled();
  });
});
