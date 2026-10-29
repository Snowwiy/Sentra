// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Role, ToolExecutionOut, ToolOut } from "../api/types";
import { WithRole } from "../test/auth";
import { installFetch, type Call, type Handler } from "../test/sites";
import { buildInput, fieldsOf, initialValues } from "../lib/toolSchema";
import { ConsolePage } from "./ConsolePage";

const ASSET = "a7000000-0000-0000-0000-000000000001";
const INCIDENT = "17000000-0000-0000-0000-000000000001";
const NOW = new Date().toISOString();

function tool(id: string, overrides: Partial<ToolOut> = {}): ToolOut {
  return {
    id,
    version: 1,
    name: id,
    description: `Descripción de ${id}`,
    category: "read",
    scope: "asset",
    risk_level: "none",
    policy: "direct",
    required_permissions: ["tools:execute"],
    required_role: "analyst",
    timeout_seconds: 10,
    max_rows: 100,
    required_capabilities: [],
    sources: ["assets"],
    availability: "available",
    unavailable_reason: null,
    permitted: true,
    input_schema: {
      type: "object",
      properties: { asset_id: { type: "string", format: "uuid" } },
      required: ["asset_id"],
    },
    output_schema: {},
    ...overrides,
  };
}

const CATALOG = [
  tool("asset.profile", { name: "Perfil del activo" }),
  tool("timeline.build", {
    name: "Línea temporal",
    category: "investigation",
    input_schema: {
      type: "object",
      properties: {
        asset_id: { type: "string" },
        hours: { type: "integer", minimum: 1, maximum: 168, default: 24 },
      },
      required: ["asset_id"],
    },
  }),
  tool("case.link_evidence", {
    name: "Añadir evidencia al caso",
    category: "action",
    policy: "preview_confirm",
    input_schema: {
      type: "object",
      properties: {
        incident_id: { type: "string" },
        kind: { enum: ["detection", "alert", "asset", "tool_execution"], type: "string" },
        evidence_id: { type: "string" },
      },
      required: ["incident_id", "kind", "evidence_id"],
    },
  }),
];

function execution(overrides: Partial<ToolExecutionOut> = {}): ToolExecutionOut {
  return {
    execution_id: "e7000000-0000-0000-0000-000000000001",
    correlation_id: "c7000000-0000-0000-0000-000000000001",
    tool_id: "asset.profile",
    tool_version: 1,
    tool_name: "Perfil del activo",
    category: "read",
    risk_level: "none",
    status: "succeeded",
    invoker: "user",
    actor: "user:ana",
    input: { asset_id: ASSET },
    input_sha256: "0".repeat(64),
    output: { hostname: "ravenslg", ports: [{ port: 8000, process: "<script>alert(1)</script>" }] },
    output_sha256: "1".repeat(64),
    output_bytes: 120,
    truncated: false,
    summary: "Perfil de ravenslg",
    evidence: [],
    provenance: null,
    error_code: null,
    error_message: null,
    target_type: "asset",
    target_id: ASSET,
    target_label: "ravenslg",
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
    duration_ms: 12,
    version: 1,
    ...overrides,
  };
}

let routes: Record<string, Handler>;
let calls: Call[];

beforeEach(() => {
  routes = {
    "GET /tools": () => ({ body: { items: CATALOG, enabled: true } }),
    "GET /tools/executions": () => ({ body: { items: [], total: 0 } }),
    [`GET /assets/${ASSET}`]: () => ({ body: { asset_id: ASSET, display_name: "ravenslg", primary_ip: "192.168.50.10" } }),
    "GET /search": (_init, url) => ({
      body: {
        query: url.searchParams.get("q"),
        kind: "ip",
        assets: [{ asset_id: ASSET, display_name: "ravenslg", primary_ip: "192.168.50.10", mac_address: null, archived: false }],
        detections: [],
        incidents: [],
        operations: [],
        users: [],
        users_visible: true,
      },
    }),
  };
  calls = installFetch(routes);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderConsole(role: Role, path = "/console") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <WithRole role={role}>
        <ConsolePage />
      </WithRole>
    </MemoryRouter>,
  );
}

const posts = (path: string) =>
  calls.filter((c) => c.method === "POST" && c.path === path).map((c) => JSON.parse(String(c.init.body)) as Record<string, unknown>);

describe("toolSchema", () => {
  it("convierte el JSON Schema en campos y valida la entrada sin inventar campos", () => {
    const fields = fieldsOf(CATALOG[1]!.input_schema);
    expect(fields.map((f) => [f.name, f.kind, f.required])).toEqual([
      ["asset_id", "text", true],
      ["hours", "number", false],
    ]);
    const values = initialValues(fields, { asset_id: ASSET });
    expect(values).toEqual({ asset_id: ASSET, hours: "24" });
    expect(buildInput(fields, values)).toEqual({ input: { asset_id: ASSET, hours: 24 } });
    expect(buildInput(fields, { asset_id: "", hours: "" })).toEqual({ error: "Falta «Activo (id)»." });
    expect(buildInput(fields, { asset_id: ASSET, hours: "1.5" })).toEqual({ error: "«Horas hacia atrás» debe ser un número entero." });
    // Un opcional vacío no se envía: el servidor aplica su valor por defecto.
    expect(buildInput(fields, { asset_id: ASSET, hours: "" })).toEqual({ input: { asset_id: ASSET } });
    const anyOf = fieldsOf({
      properties: { status: { anyOf: [{ enum: ["open", "closed"] }, { type: "null" }] } },
    });
    expect(anyOf[0]).toMatchObject({ kind: "enum", options: ["open", "closed"], required: false });
  });
});

describe("ConsolePage (Fase 7B.4)", () => {
  it("busca desde la URL, abre el workspace y ejecuta un atajo de lectura", async () => {
    routes["POST /tools/asset.profile/execute"] = () => ({ body: execution() });
    renderConsole("analyst", "/console?q=192.168.50.10");
    expect(await screen.findByText(/Búsqueda interpretada como dirección IP/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "ravenslg" }));
    const workspace = await screen.findByRole("region", { name: "Workspace" });
    expect(await within(workspace).findByText("ravenslg (192.168.50.10)")).toBeInTheDocument();
    const shortcuts = within(workspace).getByRole("group", { name: "Herramientas para esta entidad" });
    // Las acciones nunca son atajos: necesitan vista previa y confirmación.
    expect(within(shortcuts).queryByRole("button", { name: "Añadir evidencia al caso" })).toBeNull();
    fireEvent.click(within(shortcuts).getByRole("button", { name: "Perfil del activo" }));
    const result = await screen.findByRole("article", { name: "Resultado de Perfil del activo" });
    expect(posts("/tools/asset.profile/execute")[0]).toMatchObject({ input: { asset_id: ASSET } });
    // La salida se pinta como texto: nada del host se interpreta como HTML.
    expect(within(result).getByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(result.querySelector("script")).toBeNull();
  });

  it("acción del catálogo: vista previa, después confirmación explícita con versión", async () => {
    routes["POST /tools/case.link_evidence/preview"] = () => ({
      body: execution({
        tool_id: "case.link_evidence",
        tool_name: "Añadir evidencia al caso",
        category: "action",
        status: "previewed",
        version: 3,
        output: { preview: { allowed: true, effects: ["Se vincula la evidencia al caso INC-000001"], blockers: [], warnings: [] } },
      }),
    });
    routes["POST /tools/executions/e7000000-0000-0000-0000-000000000001/confirm"] = () => ({
      body: execution({ tool_name: "Añadir evidencia al caso", category: "action", status: "succeeded", output: { linked: true } }),
    });
    renderConsole("analyst");
    const catalog = await screen.findByRole("region", { name: "Catálogo de herramientas" });
    fireEvent.change(await within(catalog).findByLabelText("Herramienta"), { target: { value: "case.link_evidence" } });
    fireEvent.change(within(catalog).getByLabelText("Caso (id) *"), { target: { value: INCIDENT } });
    fireEvent.change(within(catalog).getByLabelText("Tipo *"), { target: { value: "asset" } });
    fireEvent.change(within(catalog).getByLabelText("Evidencia (id) *"), { target: { value: ASSET } });
    fireEvent.click(within(catalog).getByRole("button", { name: "Vista previa" }));
    const card = await screen.findByRole("article", { name: "Resultado de Añadir evidencia al caso" });
    expect(within(card).getByText("Se vincula la evidencia al caso INC-000001")).toBeInTheDocument();
    expect(posts("/tools/case.link_evidence/preview")[0]).toMatchObject({
      input: { incident_id: INCIDENT, kind: "asset", evidence_id: ASSET },
    });
    // Nada se ejecuta sin pulsar Confirmar.
    expect(posts("/tools/executions/e7000000-0000-0000-0000-000000000001/confirm")).toHaveLength(0);
    fireEvent.click(within(card).getByRole("button", { name: "Confirmar y ejecutar" }));
    await waitFor(() =>
      expect(posts("/tools/executions/e7000000-0000-0000-0000-000000000001/confirm")[0]).toEqual({
        version: 3,
        confirm: true,
        note: null,
      }),
    );
  });

  it("muestra usuarios de Sentra con su carga de casos, sin enlaces de acción", async () => {
    routes["GET /search"] = (_init, url) => ({
      body: {
        query: url.searchParams.get("q"),
        kind: "text",
        assets: [],
        detections: [],
        incidents: [],
        operations: [],
        users: [
          { user_id: "u1", username: "ana", role: "analyst", active: true, open_cases: 2 },
          { user_id: "u2", username: "antiguo", role: "admin", active: false, open_cases: 0 },
        ],
        users_visible: true,
      },
    });
    renderConsole("analyst", "/console?q=an");
    const section = await screen.findByRole("region", { name: "Usuarios encontrados" });
    expect(within(section).getByText("ana")).toBeInTheDocument();
    expect(within(section).getByText(/Analista · 2 casos activos/)).toBeInTheDocument();
    expect(within(section).getByText("Desactivado")).toBeInTheDocument();
  });

  it("viewer: busca y consulta el catálogo, pero no ejecuta", async () => {
    routes["GET /tools"] = () => ({
      body: { items: CATALOG.map((t) => ({ ...t, permitted: false })), enabled: true },
    });
    renderConsole("viewer", `/console?asset=${ASSET}`);
    const workspace = await screen.findByRole("region", { name: "Workspace" });
    expect(within(workspace).getByText("Tu rol puede consultar pero no ejecutar herramientas.")).toBeInTheDocument();
    const catalog = screen.getByRole("region", { name: "Catálogo de herramientas" });
    fireEvent.change(await within(catalog).findByLabelText("Herramienta"), { target: { value: "asset.profile" } });
    expect(within(catalog).getByRole("button", { name: "Ejecutar" })).toBeDisabled();
    expect(within(catalog).getByText("Tu rol no tiene permiso para esta herramienta.")).toBeInTheDocument();
  });
});
