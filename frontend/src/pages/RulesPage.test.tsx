// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DetectionRule, Role, RuleCatalog, RuleDetail, SigmaPreview } from "../api/types";
import { WithRole } from "../test/auth";
import { RuleDetailPage } from "./RuleDetailPage";
import { RuleEditorPage } from "./RuleEditorPage";
import { RulesPage } from "./RulesPage";

// Datos sintéticos de test: no proceden de ningún host real.
const NOW = new Date().toISOString();
const XSS = "<img src=x onerror=alert(1)>";

function rule(overrides: Partial<DetectionRule> = {}): DetectionRule {
  return {
    rule_id: "SENTRA-CUSTOM-000001",
    source: "custom",
    version: 2,
    status: "draft",
    enabled: false,
    compile_status: "valid",
    read_only: false,
    kind: "single",
    category: "account",
    title: "Cuenta svc creada",
    description: "Alta de cuentas svc_*",
    why: "Suelen tener privilegios.",
    severity: "high",
    confidence: "low",
    logsource: "windows_security",
    triggers: ["event"],
    required_data: [],
    recommendations: ["Confirmar quién la creó."],
    mitre_tactic: "TA0003",
    mitre_technique: "T1136",
    mitre_subtechnique: null,
    cooldown_minutes: 0,
    sigma_id: null,
    revision: 3,
    updated_at: NOW,
    updated_by: "admin",
    detections_24h: 1,
    last_triggered_at: NOW,
    errors: 0,
    consecutive_errors: 0,
    ...overrides,
  };
}

function detail(overrides: Partial<RuleDetail> = {}): RuleDetail {
  return {
    ...rule(),
    tags: ["svc"],
    definition: {
      format: "sentra-rule/1",
      logsource: "windows_security",
      condition: {
        all: [
          { field: "event.code", op: "equals", value: 4720 },
          { field: "event.data.TargetUserName", op: "starts_with", value: "svc_" },
        ],
      },
      threshold: null,
      group_by: [],
      cooldown_minutes: 0,
    },
    compiled: {},
    compile_issues: [],
    complexity: "low",
    stats: {
      evaluations: 10,
      matches: 1,
      errors: 0,
      consecutive_errors: 0,
      slow_evaluations: 0,
      avg_eval_ms: 0.01,
      last_evaluated_at: NOW,
      last_matched_at: NOW,
      last_error_at: null,
      last_error: null,
    },
    detections_total: 1,
    sigma_metadata: null,
    has_sigma_source: false,
    created_at: NOW,
    created_by: "admin",
    retired_at: null,
    logsource_title: "Windows Security",
    ...overrides,
  };
}

const CATALOG: RuleCatalog = {
  logsources: [
    {
      name: "windows_security",
      title: "Windows Security",
      support: "supported",
      platforms: ["windows"],
      notes: "",
      event_codes: [4720],
      sigma_hint: "",
      default_category: "account",
      fields: [
        { name: "event.code", type: "integer", description: "", values: [], operators: ["equals", "in"] },
        {
          name: "event.data.TargetUserName",
          type: "string",
          description: "",
          values: [],
          operators: ["equals", "starts_with", "regex"],
        },
      ],
    },
  ],
  asset_fields: [],
  categories: ["account", "authentication"],
  limits: { threshold_min: 2, threshold_max: 10000, window_min_minutes: 1, window_max_minutes: 1440, cooldown_max_minutes: 1440 },
  compatibility: [],
  sigma_default_confidence: "low",
};

function preview(overrides: Partial<SigmaPreview> = {}): SigmaPreview {
  return {
    outcome: "supported",
    title: XSS,
    sigma_id: "7a7a2a39-7a52-4d39-9d7e-2f1f0d5b8a33",
    level: "high",
    severity: "high",
    confidence: "low",
    logsource: { product: "windows", service: "security" },
    sentra_logsource: "windows_security",
    mitre_tactic: null,
    mitre_technique: "T1136",
    mitre_subtechnique: null,
    tags: [],
    metadata: {},
    errors: [],
    unsupported: [],
    warnings: [],
    definition: null,
    compiled: null,
    duplicate: { state: "none", rule_id: null, current_version: null, revision: null },
    ...overrides,
  };
}

type Handler = (init: RequestInit, url: URL) => { status?: number; body: unknown };
let routes: Record<string, Handler>;
let calls: { method: string; path: string; url: URL; body: unknown }[];

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  calls = [];
  routes = {
    "GET /detection-rules": () => ({
      body: {
        items: [rule(), rule({ rule_id: "AUTH-001", source: "builtin", read_only: true, title: "Ráfaga", status: "active" })],
        total: 2,
        windows: {},
        alert_min_severity: "high",
      },
    }),
    "GET /detection-rules/catalog": () => ({ body: CATALOG }),
    "GET /detection-rules/SENTRA-CUSTOM-000001": () => ({ body: detail() }),
    "GET /detection-rules/AUTH-001": () => ({
      body: detail({ rule_id: "AUTH-001", source: "builtin", read_only: true, definition: null, status: "active" }),
    }),
    "POST /sigma/preview": () => ({ body: preview() }),
    "POST /sigma/import": () => ({ body: { result: "imported", rule: detail({ source: "sigma" }), preview: preview() } }),
    "POST /detection-rules/SENTRA-CUSTOM-000001/enable": () => ({ body: detail({ status: "active", enabled: true }) }),
    "POST /detection-rules/validate": () => ({
      body: {
        valid: false,
        compile_status: "invalid",
        errors: [{ code: "unsafe_regex", message: XSS, path: "condition" }],
        warnings: [],
        definition: null,
        compiled: null,
        complexity: null,
      },
    }),
    "POST /detection-rules": () => ({ status: 201, body: detail({ rule_id: "SENTRA-CUSTOM-000002" }) }),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const url = new URL(input, "http://localhost");
      const path = url.pathname.replace("/api/v1", "");
      calls.push({ method, path, url, body: init.body ? JSON.parse(String(init.body)) : undefined });
      const handler = routes[`${method} ${path}`];
      if (!handler) return json(404, { error: { code: "not_found", message: `no route ${path}` } });
      const { status = 200, body } = handler(init, url);
      return json(status, body);
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderAt(path: string, role: Role = "admin") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <WithRole role={role}>
        <Routes>
          <Route path="/detections/rules" element={<RulesPage />} />
          <Route path="/detections/rules/new" element={<RuleEditorPage />} />
          <Route path="/detections/rules/:ruleId" element={<RuleDetailPage />} />
          <Route path="/detections/rules/:ruleId/edit" element={<RuleEditorPage />} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

describe("RulesPage", () => {
  it("lists builtin and custom rules with server-side filters", async () => {
    renderAt("/detections/rules");
    expect(await screen.findByText("Cuenta svc creada")).toBeInTheDocument();
    expect(screen.getByText("AUTH-001")).toBeInTheDocument();
    expect(within(screen.getByRole("table")).getByText("Built-in")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Origen"), { target: { value: "sigma" } });
    await waitFor(() => expect(calls.some((c) => c.url.searchParams.get("source") === "sigma")).toBe(true));
    expect(screen.getByRole("link", { name: "Nueva regla" })).toBeInTheDocument();
  });

  it("viewer only reads: no create or import", async () => {
    renderAt("/detections/rules", "viewer");
    await screen.findByText("Cuenta svc creada");
    expect(screen.queryByText("Nueva regla")).not.toBeInTheDocument();
    expect(screen.queryByText("Importar Sigma")).not.toBeInTheDocument();
  });

  it("analyst previews Sigma but cannot import", async () => {
    renderAt("/detections/rules", "analyst");
    fireEvent.click(await screen.findByText("Importar Sigma"));
    fireEvent.change(screen.getByLabelText("YAML Sigma"), { target: { value: "title: x" } });
    fireEvent.click(screen.getByText("Vista previa"));
    expect(await screen.findByText("Soportada")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Importar" })).not.toBeInTheDocument();
  });

  it("imports Sigma after preview and renders untrusted text as text", async () => {
    renderAt("/detections/rules");
    fireEvent.click(await screen.findByText("Importar Sigma"));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("YAML Sigma"), { target: { value: `title: '${XSS}'` } });
    fireEvent.click(within(dialog).getByText("Vista previa"));
    expect(await within(dialog).findByText(XSS)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "Importar" }));
    expect(await within(dialog).findByText("Importada")).toBeInTheDocument();
    const imported = calls.find((c) => c.path === "/sigma/import");
    expect(imported?.body).toEqual({ yaml: `title: '${XSS}'`, on_duplicate: "reject", revision: null });
  });
});

describe("RuleDetailPage", () => {
  it("shows tabs and enables with the current revision", async () => {
    renderAt("/detections/rules/SENTRA-CUSTOM-000001");
    expect(await screen.findByRole("heading", { name: "Cuenta svc creada" })).toBeInTheDocument();
    for (const name of ["Resumen", "Lógica", "Versiones", "Detecciones", "Pruebas", "Auditoría"]) {
      expect(screen.getByRole("tab", { name })).toBeInTheDocument();
    }
    fireEvent.click(screen.getByRole("button", { name: "Activar" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Activar" }));
    await waitFor(() => expect(calls.some((c) => c.path.endsWith("/enable"))).toBe(true));
    const enable = calls.find((c) => c.path.endsWith("/enable"));
    expect(enable?.body).toEqual({ revision: 3, acknowledge_partial: false });
  });

  it("builtin rules are read-only", async () => {
    renderAt("/detections/rules/AUTH-001");
    expect(await screen.findByText(/solo lectura/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Activar" })).not.toBeInTheDocument();
    expect(screen.queryByText("Editar")).not.toBeInTheDocument();
  });

  it("analyst sees no management actions nor audit tab", async () => {
    renderAt("/detections/rules/SENTRA-CUSTOM-000001", "analyst");
    await screen.findByRole("heading", { name: "Cuenta svc creada" });
    expect(screen.queryByRole("button", { name: "Activar" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Auditoría" })).not.toBeInTheDocument();
  });
});

describe("RuleEditorPage", () => {
  it("builds a declarative definition and shows validation errors as text", async () => {
    renderAt("/detections/rules/new");
    fireEvent.change(await screen.findByLabelText("Título"), { target: { value: "Regla nueva" } });
    fireEvent.change(screen.getByLabelText("Campo 1"), { target: { value: "event.code" } });
    fireEvent.change(screen.getByLabelText("Valor 1"), { target: { value: "4720" } });
    fireEvent.click(screen.getByText("Validar"));
    expect(await screen.findByText(new RegExp("onerror"))).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Crear borrador" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/detection-rules")).toBe(true));
    const created = calls.find((c) => c.method === "POST" && c.path === "/detection-rules");
    expect(created?.body).toMatchObject({
      title: "Regla nueva",
      confidence: "low",
      definition: { logsource: "windows_security", condition: { field: "event.code", op: "equals", value: 4720 } },
    });
  });

  it("is not available without rules:manage", async () => {
    renderAt("/detections/rules/new", "analyst");
    expect(await screen.findByText("Sin permiso")).toBeInTheDocument();
  });
});
