// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AssetContext, AssetContextOptions, Role } from "../../api/types";
import { WithRole } from "../../test/auth";
import { ContextTab } from "./ContextTab";

// Datos sintéticos de test: no proceden de ningún host real.
const ASSET = "aaaaaaaa-0000-0000-0000-000000000001";
const NOW = new Date().toISOString();

function ctx(overrides: Partial<AssetContext> = {}): AssetContext {
  return {
    asset_id: ASSET,
    version: 0,
    criticality: "medium",
    criticality_confirmed: false,
    criticality_rationale: null,
    criticality_updated_at: null,
    criticality_updated_by: null,
    role: "unknown",
    role_suggestion: { value: "workstation", source: "agent", kind: "inferred", confidence: "high", reason: null },
    environment: "unknown",
    owner: null,
    department: null,
    data_sensitivity: "unknown",
    network_zone: "unknown",
    internet_exposed: null,
    tags: [],
    managed_state: "MANAGED",
    visibility_sources: ["agent"],
    provenance: {},
    completeness: { percent: 13, complete: false, known: ["criticality"], missing: ["role"] },
    updated_at: null,
    updated_by: null,
    ...overrides,
  };
}

const CONFIGURED = ctx({
  version: 2,
  criticality: "high",
  criticality_confirmed: true,
  role: "server",
  role_suggestion: null,
  environment: "production",
  owner: "<b>IT</b>",
  department: "Infra",
  network_zone: "server",
  internet_exposed: false,
  tags: ["pci"],
  provenance: {
    role: { source: "manual", kind: "configured", confidence: null, updated_at: NOW, updated_by: "admin" },
  },
  completeness: { percent: 100, complete: true, known: [], missing: [] },
  updated_at: NOW,
  updated_by: "admin",
});

const OPTIONS: AssetContextOptions = {
  criticality: ["low", "medium", "high", "critical"],
  role: ["server", "unknown"],
  environment: ["production", "unknown"],
  data_sensitivity: ["unknown"],
  network_zone: ["server", "unknown"],
  departments: ["Infra"],
  tags: ["pci"],
  limits: { owner_max: 128, department_max: 64, rationale_max: 200, max_tags: 20, tag_max: 32, tag_pattern: "" },
};

type Handler = (init: RequestInit) => { status?: number; body: unknown };
let routes: Record<string, Handler>;
let calls: { method: string; path: string; init: RequestInit }[];

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

beforeEach(() => {
  calls = [];
  routes = {
    [`GET /assets/${ASSET}/context`]: () => ({ body: ctx() }),
    "GET /assets/context/options": () => ({ body: OPTIONS }),
    [`GET /assets/${ASSET}/context/history`]: () => ({ body: { items: [], total: 0 } }),
    [`GET /assets/${ASSET}/threat-summary`]: () => ({
      body: {
        asset_id: ASSET,
        window_days: 7,
        active_detection_count: 2,
        high_critical_detection_count: 1,
        open_incident_count: 1,
        highest_incident_severity: "high",
        current_risk: null,
        recent_exposure_changes: 0,
        recent_context_changes: 3,
        last_security_activity: null,
        criticality: "medium",
        environment: "unknown",
        managed_state: "MANAGED",
      },
    }),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const path = new URL(input, "http://localhost").pathname.replace("/api/v1", "");
      calls.push({ method, path, init });
      const handler = routes[`${method} ${path}`];
      if (!handler) return json(404, { error: { code: "not_found", message: `no route ${path}` } });
      const { status = 200, body } = handler(init);
      return json(status, body);
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderTab(role: Role) {
  return render(
    <MemoryRouter>
      <WithRole role={role}>
        <ContextTab assetId={ASSET} />
      </WithRole>
    </MemoryRouter>,
  );
}

const patches = () => calls.filter((c) => c.method === "PATCH");

describe("ContextTab", () => {
  it("estado vacío: desconocido como dato que falta y el rol sugerido sin confirmar", async () => {
    renderTab("viewer");
    expect(await screen.findByText("Contexto incompleto · 13 %")).toBeInTheDocument();
    expect(screen.getByText(/Sugerido: Estación de trabajo/)).toHaveTextContent("no confirmado");
    expect(screen.getByText("(valor por defecto)")).toBeInTheDocument();
    expect(screen.getByText("Sin tags")).toBeInTheDocument();
    expect(screen.getByText("Nunca configurado")).toBeInTheDocument();
    const threat = screen.getByRole("region", { name: "Contexto de amenaza" });
    expect(await within(threat).findByText("Sin evaluar")).toBeInTheDocument();
    expect(within(threat).getByText(/máx\. high/)).toBeInTheDocument();
  });

  it.each<Role>(["viewer", "analyst"])("%s solo lee: sin botón de editar", async (role) => {
    routes[`GET /assets/${ASSET}/context`] = () => ({ body: CONFIGURED });
    renderTab(role);
    expect(await screen.findByText("Contexto completo")).toBeInTheDocument();
    expect(screen.getByText("Producción")).toBeInTheDocument();
    // Texto administrativo no confiable: se muestra literal, nunca como HTML.
    expect(screen.getByText("<b>IT</b>")).toBeInTheDocument();
    expect(screen.getByText(/manual · admin/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Editar" })).toBeNull();
    expect(screen.getByText("Solo lectura: el contexto lo edita un administrador.")).toBeInTheDocument();
  });

  it("admin edita y guarda solo los cambios con la versión leída", async () => {
    routes[`PATCH /assets/${ASSET}/context`] = (init) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      return { body: ctx({ ...CONFIGURED, version: 1, owner: String(body.owner) }) };
    };
    renderTab("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Editar" }));
    const form = screen.getByRole("form", { name: "Editar contexto" });
    fireEvent.change(within(form).getByLabelText("Rol"), { target: { value: "server" } });
    fireEvent.change(within(form).getByLabelText("Entorno"), { target: { value: "production" } });
    fireEvent.change(within(form).getByLabelText("Criticidad"), { target: { value: "high" } });
    fireEvent.change(within(form).getByLabelText("Zona de red"), { target: { value: "server" } });
    fireEvent.change(within(form).getByRole("textbox", { name: "Owner" }), { target: { value: " IT " } });
    fireEvent.change(within(form).getByRole("textbox", { name: /Tags/ }), { target: { value: "PCI" } });
    fireEvent.click(within(form).getByRole("button", { name: "Guardar" }));
    await waitFor(() => expect(patches()).toHaveLength(1));
    expect(JSON.parse(String(patches()[0]!.init.body))).toEqual({
      version: 0,
      criticality: "high",
      role: "server",
      environment: "production",
      owner: "IT",
      network_zone: "server",
      tags: ["pci"],
    });
    expect(await screen.findByText("Contexto completo")).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Editar contexto" })).toBeNull();
  });

  it("validación local: no envía nada con datos inválidos", async () => {
    renderTab("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Editar" }));
    const form = screen.getByRole("form", { name: "Editar contexto" });
    fireEvent.change(within(form).getByRole("textbox", { name: "Owner" }), { target: { value: "<script>" } });
    fireEvent.change(within(form).getByRole("textbox", { name: /Tags/ }), { target: { value: "-mal" } });
    fireEvent.click(within(form).getByRole("button", { name: "Guardar" }));
    const alert = await within(form).findByRole("alert");
    expect(alert).toHaveTextContent("Owner: solo texto plano");
    expect(alert).toHaveTextContent("Tags no válidos: -mal");
    expect(patches()).toHaveLength(0);
  });

  it("409: recarga, avisa y no reintenta", async () => {
    routes[`PATCH /assets/${ASSET}/context`] = () => ({
      status: 409,
      body: { error: { code: "asset_context_conflict", message: "stale" } },
    });
    renderTab("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Editar" }));
    routes[`GET /assets/${ASSET}/context`] = () => ({ body: CONFIGURED });
    const form = screen.getByRole("form", { name: "Editar contexto" });
    fireEvent.change(within(form).getByLabelText("Rol"), { target: { value: "server" } });
    fireEvent.click(within(form).getByRole("button", { name: "Guardar" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Otro administrador ha modificado el contexto");
    expect(await screen.findByText("Contexto completo")).toBeInTheDocument();
    expect(patches()).toHaveLength(1);
  });

  it("estado de carga y error", async () => {
    routes[`GET /assets/${ASSET}/context`] = () => ({
      status: 500,
      body: { error: { code: "internal_error", message: "boom" } },
    });
    renderTab("viewer");
    expect(screen.getByText("Cargando contexto…")).toBeInTheDocument();
    expect(await screen.findByText("No se pudieron cargar los datos")).toBeInTheDocument();
  });
});
