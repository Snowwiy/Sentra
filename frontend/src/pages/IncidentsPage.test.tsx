// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WithRole } from "../test/auth";
import type { IncidentDetail, IncidentSummary, RelatedIncidentList, Role } from "../api/types";
import { DetectionDetailPage } from "./DetectionDetailPage";
import { IncidentDetailPage } from "./IncidentDetailPage";
import { IncidentsPage } from "./IncidentsPage";

// Datos sintéticos de test: no proceden de ningún host real.
const NOW = Date.now();
const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();
const ID = "11111111-2222-3333-4444-555555555555";
const OTHER = "11111111-2222-3333-4444-666666666666";
const ASSET = "aaaaaaaa-0000-0000-0000-000000000001";
const DETECTION = "dddddddd-0000-0000-0000-000000000001";

function summary(overrides: Partial<IncidentSummary> = {}): IncidentSummary {
  return {
    incident_id: ID,
    number: 7,
    key: "INC-000007",
    title: "Fuerza bruta en pc-demo",
    severity: "high",
    priority: "critical",
    status: "open",
    confidence: "medium",
    owner: null,
    assets: ["pc-demo"],
    asset_count: 1,
    last_activity_at: iso(-60_000),
    created_at: iso(-3_600_000),
    updated_at: iso(-60_000),
    version: 3,
    ...overrides,
  };
}

function detail(overrides: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    ...summary(),
    description: "Fallos repetidos y un inicio correcto.",
    first_seen_at: iso(-3_600_000),
    last_seen_at: iso(-60_000),
    triaged_at: null,
    resolved_at: null,
    closed_at: null,
    resolution_category: null,
    resolution_summary: null,
    duplicate_of: null,
    merged_into: null,
    merged_at: null,
    merged_from: [],
    created_by: { user_id: "u1", username: "ana", role: "analyst", active: true },
    assigned_by: null,
    assigned_at: null,
    updated_by: { user_id: "u1", username: "ana", role: "analyst", active: true },
    resolved_by: null,
    risk: {
      snapshot: { score: 72, level: "high", confidence: "medium", taken_at: iso(-3_600_000) },
      assets: [
        {
          asset_id: ASSET,
          name: "pc-demo",
          evaluated: true,
          score: 80,
          level: "critical",
          confidence: "high",
          calculated_at: iso(-120_000),
          changed_at: iso(-120_000),
          top_contributors: [
            {
              factor: "detection",
              category: "authentication",
              label: "Fuerza bruta",
              points: 30,
              nominal_points: 30,
              detection_id: DETECTION,
              rule_id: "AUTH-001",
              port: null,
              details: {},
            },
          ],
        },
      ],
    },
    asset_refs: [
      { asset_id: ASSET, name: "pc-demo", exists: true, primary_ip: "10.0.0.5", source: "detection", added_at: iso(-3_600_000),
        context: null, context_snapshot: null, resolved_context_snapshot: null },
    ],
    detections: [],
    detections_total: 0,
    alerts: [],
    alerts_total: 0,
    notes_total: 1,
    metrics: { age_seconds: 3600, time_to_triage_seconds: null, time_to_resolve_seconds: null },
    allowed_transitions: ["triage", "investigating"],
    ...overrides,
  };
}

const OVERVIEW = {
  open: 4,
  triage: 2,
  investigating: 1,
  contained: 0,
  critical: 3,
  unassigned: 5,
  assigned_to_me: 1,
  mean_age_seconds: 7200,
  recent_activity: [],
};

type Handler = (init: RequestInit, url: URL) => { status?: number; body: unknown };

let routes: Record<string, Handler>;
let calls: { method: string; path: string; url: URL; init: RequestInit }[];

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  calls = [];
  routes = {
    "GET /incidents": () => ({
      body: {
        items: [
          summary(),
          summary({
            incident_id: OTHER,
            number: 8,
            key: "INC-000008",
            title: "Puerto RDP expuesto",
            owner: { user_id: "u9", username: "luis", role: "analyst", active: false },
          }),
        ],
        total: 2,
      },
    }),
    "GET /incidents/overview": () => ({ body: OVERVIEW }),
    [`GET /incidents/${ID}`]: () => ({ body: detail() }),
    [`GET /incidents/${ID}/timeline`]: () => ({
      body: {
        items: [
          {
            item_id: "n1",
            occurred_at: iso(-120_000),
            source_type: "note",
            action: null,
            entity_type: "note",
            entity_id: "x",
            actor: "ana",
            summary: "<img src=x onerror=alert(1)>",
            incident_key: "INC-000007",
          },
          {
            item_id: "a1",
            occurred_at: iso(-3_600_000),
            source_type: "incident",
            action: "created",
            entity_type: "incident",
            entity_id: ID,
            actor: "ana",
            summary: "Incidente creado",
            incident_key: "INC-000007",
          },
        ],
        next_cursor: null,
      },
    }),
    [`GET /incidents/${ID}/notes`]: () => ({
      body: {
        items: [{ note_id: "n1", author: "ana", body: "<b>no es html</b>", created_at: iso(-120_000), incident_key: "INC-000007" }],
        total: 1,
      },
    }),
    "GET /ai/status": () => ({ body: { enabled: false, available: false, reason: "IA desactivada.", state: "disabled" } }),
    "GET /ai/insights": () => ({ body: { items: [], total: 0 } }),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const url = new URL(input, "http://localhost");
      const path = url.pathname.replace("/api/v1", "");
      calls.push({ method, path, url, init });
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
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/:incidentId" element={<IncidentDetailPage />} />
          <Route path="/detections/:detectionId" element={<DetectionDetailPage />} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

const listCalls = () => calls.filter((c) => c.method === "GET" && c.path === "/incidents");
const body = (path: string, method = "POST") =>
  JSON.parse(String(calls.filter((c) => c.method === method && c.path === path).at(-1)!.init.body)) as Record<
    string,
    unknown
  >;

describe("IncidentsPage", () => {
  it("muestra tarjetas, severidad y prioridad por separado y el owner histórico", async () => {
    renderAt("/incidents");
    const row = (await screen.findByText("Fuerza bruta en pc-demo")).closest("tr")!;
    expect(within(row).getByText("INC-000007")).toBeInTheDocument();
    expect(within(row).getByTitle("Severidad (impacto)")).toHaveTextContent("Alta");
    expect(within(row).getByTitle("Prioridad (urgencia)")).toHaveTextContent("Crítica");
    expect(within(row).getByText("Sin asignar")).toBeInTheDocument();
    const other = screen.getByText("Puerto RDP expuesto").closest("tr")!;
    expect(within(other).getByText(/luis \(desactivado\)/)).toBeInTheDocument();
    const cards = screen.getByRole("region", { name: "Resumen de incidentes" });
    expect(within(cards).getByRole("button", { name: /Sin asignar\s*5/ })).toBeInTheDocument();
    expect(screen.getByText(/2 h 0 min/)).toBeInTheDocument();
    expect(listCalls()[0]!.url.searchParams.get("active")).toBe("true");
    expect(listCalls()[0]!.url.searchParams.get("sort")).toBe("last_activity");
  });

  it("tarjetas, filtros, búsqueda y orden se resuelven en el servidor", async () => {
    renderAt("/incidents");
    await screen.findByText("Fuerza bruta en pc-demo");
    fireEvent.click(screen.getByRole("button", { name: /Asignados a mí/ }));
    await waitFor(() => expect(listCalls().at(-1)!.url.searchParams.get("owner")).toBe("me"));
    fireEvent.change(screen.getByLabelText("Prioridad"), { target: { value: "high" } });
    fireEvent.change(screen.getByLabelText("Buscar incidentes"), { target: { value: "INC-000007" } });
    fireEvent.click(await screen.findByRole("button", { name: /^Severidad/ }));
    await waitFor(() => {
      const params = listCalls().at(-1)!.url.searchParams;
      expect(params.get("priority")).toBe("high");
      expect(params.get("q")).toBe("INC-000007");
      expect(params.get("sort")).toBe("severity");
      expect(params.get("order")).toBe("desc");
    });
  });

  it("un viewer no puede crear; un analyst crea y abre el incidente", async () => {
    renderAt("/incidents", "viewer");
    await screen.findByText("Fuerza bruta en pc-demo");
    expect(screen.queryByRole("button", { name: "Nuevo incidente" })).not.toBeInTheDocument();
    cleanup();

    // Fase 4M: el selector busca en el servidor (q + limit), nunca descarga el inventario.
    const assetQueries: URLSearchParams[] = [];
    routes["GET /assets"] = (_init, url) => {
      assetQueries.push(url.searchParams);
      return { body: { items: [{ asset_id: ASSET, display_name: "pc-demo", primary_ip: "10.0.0.5" }], total: 1 } };
    };
    routes["POST /incidents"] = () => ({ status: 201, body: detail() });
    renderAt("/incidents", "analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Nuevo incidente" }));
    const dialog = screen.getByRole("dialog", { name: "Nuevo incidente" });
    fireEvent.change(within(dialog).getByLabelText("Título"), { target: { value: "Caso manual" } });
    fireEvent.change(within(dialog).getByLabelText("Severidad"), { target: { value: "critical" } });
    await within(dialog).findByRole("option", { name: /pc-demo/ });
    expect(assetQueries[0]?.get("limit")).toBe("50");
    fireEvent.change(within(dialog).getByLabelText("Buscar activo"), { target: { value: "pc-de" } });
    await waitFor(() => expect(assetQueries.some((q) => q.get("q") === "pc-de")).toBe(true));
    fireEvent.change(within(dialog).getByLabelText("Activo afectado"), { target: { value: ASSET } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Crear incidente" }));
    expect(await screen.findByRole("heading", { name: /INC-000007/ })).toBeInTheDocument();
    expect(body("/incidents")).toEqual({
      title: "Caso manual",
      description: null,
      severity: "critical",
      priority: "medium",
      asset_ids: [ASSET],
    });
  });
});

describe("IncidentDetailPage", () => {
  it("muestra resumen, riesgo de 4I y pestañas; el texto del timeline es plano", async () => {
    renderAt(`/incidents/${ID}`);
    expect(await screen.findByRole("heading", { name: /INC-000007 · Fuerza bruta en pc-demo/ })).toBeInTheDocument();
    expect(screen.getByText("Fallos repetidos y un inicio correcto.")).toBeInTheDocument();
    expect(screen.getByText(/Snapshot del caso: 72/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Fuerza bruta" })).toHaveAttribute("href", `/detections/${DETECTION}`);
    fireEvent.click(screen.getByRole("tab", { name: "Timeline" }));
    const timeline = await screen.findByRole("list", { name: "Timeline del incidente" });
    expect(within(timeline).getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(timeline.querySelector("img")).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: /Notas/ }));
    expect(await screen.findByText("<b>no es html</b>")).toBeInTheDocument();
  });

  it("muestra el contexto actual del activo y los snapshots al vincular y resolver", async () => {
    const ref = detail().asset_refs[0]!;
    routes[`GET /incidents/${ID}`] = () => ({
      body: detail({
        asset_refs: [
          {
            ...ref,
            context: {
              criticality: "high",
              role: "server",
              environment: "production",
              owner: "IT",
              department: "Infra",
              data_sensitivity: "unknown",
              network_zone: "server",
              internet_exposed: null,
              context_complete: false,
            },
            context_snapshot: {
              criticality: "medium",
              role: "unknown",
              environment: "unknown",
              data_sensitivity: "unknown",
              network_zone: "unknown",
              internet_exposed: null,
              captured_at: iso(-3_600_000),
            },
            resolved_context_snapshot: null,
          },
        ],
      }),
    });
    renderAt(`/incidents/${ID}`);
    const section = await screen.findByRole("region", { name: "Contexto de los activos" });
    expect(within(section).getByRole("link", { name: "pc-demo" })).toHaveAttribute("href", `/assets/${ASSET}?tab=context`);
    expect(section).toHaveTextContent("Servidor");
    expect(section).toHaveTextContent("Producción");
    expect(section).toHaveTextContent("Owner: IT");
    expect(section).toHaveTextContent("Internet: Desconocida");
    fireEvent.click(screen.getByRole("tab", { name: /Activos/ }));
    expect(await screen.findByText(/Al vincular:/)).toBeInTheDocument();
  });

  it("las acciones envían la versión leída y un 409 muestra el conflicto sin sobrescribir", async () => {
    routes[`PATCH /incidents/${ID}`] = () => ({
      status: 409,
      body: {
        error: {
          code: "incident_conflict",
          message: "The incident was changed by someone else; reload it and try again",
          details: [{ incident_id: ID, current_version: 4, status: "investigating", updated_by: "luis" }],
        },
      },
    });
    renderAt(`/incidents/${ID}`, "analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Pasar a triage" }));
    expect(await screen.findByText(/Otro operador \(luis\) modificó este incidente/)).toBeInTheDocument();
    expect(screen.getByText(/ahora Investigando/)).toBeInTheDocument();
    expect(body(`/incidents/${ID}`, "PATCH")).toEqual({ version: 3, status: "triage" });
    const before = calls.filter((c) => c.path === `/incidents/${ID}` && c.method === "GET").length;
    fireEvent.click(screen.getByRole("button", { name: "Recargar" }));
    await waitFor(() =>
      expect(calls.filter((c) => c.path === `/incidents/${ID}` && c.method === "GET").length).toBeGreaterThan(before),
    );
    expect(screen.queryByText(/Otro operador/)).not.toBeInTheDocument();
  });

  it("acciones según rol: viewer nada, analyst sin cerrar/fusionar, admin todo", async () => {
    renderAt(`/incidents/${ID}`, "viewer");
    await screen.findByRole("heading", { name: /INC-000007/ });
    expect(screen.queryByRole("region", { name: "Acciones del incidente" })).not.toBeInTheDocument();
    cleanup();

    renderAt(`/incidents/${ID}`, "analyst");
    expect(await screen.findByRole("button", { name: "Asignarme" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Fusionar…" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Asignar a…" })).not.toBeInTheDocument();
    cleanup();

    routes[`GET /incidents/${ID}`] = () => ({ body: detail({ status: "resolved", allowed_transitions: ["investigating"] }) });
    renderAt(`/incidents/${ID}`, "admin");
    expect(await screen.findByRole("button", { name: "Cerrar" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Fusionar…" })).not.toBeInTheDocument();
  });

  it("resolver exige categoría y duplicado exige el incidente principal", async () => {
    routes[`GET /incidents/${ID}`] = () => ({
      body: detail({ status: "investigating", allowed_transitions: ["contained", "resolved"] }),
    });
    routes[`POST /incidents/${ID}/resolve`] = () => ({ body: detail({ status: "resolved" }) });
    routes["GET /incidents"] = () => ({ body: { items: [summary({ incident_id: OTHER, key: "INC-000008", title: "Principal" })], total: 1 } });
    renderAt(`/incidents/${ID}`, "analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Resolver" }));
    const dialog = screen.getByRole("dialog", { name: "Resolver INC-000007" });
    const submit = within(dialog).getByRole("button", { name: "Resolver" });
    expect(submit).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Categoría de resolución"), { target: { value: "duplicate" } });
    expect(submit).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Buscar incidente"), { target: { value: "INC-000008" } });
    fireEvent.click(await within(dialog).findByRole("button", { name: "Elegir" }));
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    await waitFor(() =>
      expect(body(`/incidents/${ID}/resolve`)).toEqual({
        version: 3,
        category: "duplicate",
        summary: null,
        duplicate_of: OTHER,
      }),
    );
  });

  it("un analyst añade una nota de solo texto", async () => {
    routes[`POST /incidents/${ID}/notes`] = () => ({
      status: 201,
      body: { note_id: "n2", author: "analyst", body: "Revisado", created_at: iso(0), incident_key: "INC-000007" },
    });
    renderAt(`/incidents/${ID}?tab=notes`, "analyst");
    fireEvent.change(await screen.findByLabelText("Nueva nota"), { target: { value: "  Revisado  " } });
    fireEvent.click(screen.getByRole("button", { name: "Añadir nota" }));
    await waitFor(() => expect(body(`/incidents/${ID}/notes`)).toEqual({ body: "Revisado" }));
  });

  it("la IA es opcional: sin IA el caso funciona y se explica por qué", async () => {
    renderAt(`/incidents/${ID}?tab=ai`, "viewer");
    expect(await screen.findByText(/IA desactivada/)).toBeInTheDocument();
    expect(screen.getByText(/no cambia estado, responsable/)).toBeInTheDocument();
    expect(calls.some((c) => c.path.startsWith("/ai/incidents"))).toBe(false);
  });

  it("con IA disponible, el análisis pide la tarea elegida", async () => {
    routes["GET /ai/status"] = () => ({ body: { enabled: true, available: true, reason: null, state: "local_available", reachable: true } });
    routes[`POST /ai/incidents/${ID}/analyze`] = () => ({ status: 502, body: { error: { code: "ai_timeout", message: "x" } } });
    renderAt(`/incidents/${ID}?tab=ai`, "analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Siguientes pasos" }));
    fireEvent.click(await screen.findByRole("button", { name: "Analizar con IA" }));
    expect(await screen.findByText("El modelo de IA no respondió a tiempo.")).toBeInTheDocument();
    expect(body(`/ai/incidents/${ID}/analyze`)).toEqual({ task: "next_steps", refresh: false });
  });
});

describe("Incidentes desde una detección", () => {
  const related = (overrides: Partial<RelatedIncidentList> = {}): RelatedIncidentList => ({
    items: [{ incident: summary(), reasons: ["same_asset", "time_window"], score: 40 }],
    suggested_priority: "high",
    suggested_severity: "high",
    ...overrides,
  });

  beforeEach(() => {
    routes[`GET /detections/${DETECTION}`] = () => ({
      body: {
        detection_id: DETECTION,
        asset_id: ASSET,
        hostname: "pc-demo",
        rule_id: "AUTH-001",
        rule_version: 1,
        kind: "single",
        category: "authentication",
        severity: "high",
        confidence: "high",
        status: "open",
        title: "Ráfaga de fallos",
        summary: "s",
        why: "w",
        recommendations: [],
        required_data: [],
        evidence: [],
        evidence_total: 0,
        first_seen_at: iso(-60_000),
        last_seen_at: iso(-60_000),
        occurrence_count: 1,
      },
    });
    routes[`GET /detections/${DETECTION}/related-incidents`] = () => ({ body: related() });
  });

  it("sugiere incidentes relacionados y adjunta sin crear otro", async () => {
    routes[`POST /incidents/${ID}/detections/${DETECTION}`] = () => ({ body: detail() });
    renderAt(`/detections/${DETECTION}`, "analyst");
    expect(await screen.findByText(/mismo activo, misma ventana temporal/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Adjuntar" }));
    expect(await screen.findByRole("heading", { name: /INC-000007/ })).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST" && c.path === `/detections/${DETECTION}/incident`)).toBe(false);
  });

  it("crear incidente; si ya está vinculada se enlaza al existente", async () => {
    routes[`GET /detections/${DETECTION}/related-incidents`] = () => ({ body: related({ items: [] }) });
    routes[`POST /detections/${DETECTION}/incident`] = () => ({
      status: 409,
      body: {
        error: {
          code: "incident_already_linked",
          message: "Detection is already linked",
          details: [{ incident_id: ID, key: "INC-000007" }],
        },
      },
    });
    renderAt(`/detections/${DETECTION}`, "analyst");
    expect(await screen.findByText(/Prioridad sugerida: Alta/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Crear incidente" }));
    expect(await screen.findByRole("link", { name: "INC-000007" })).toHaveAttribute("href", `/incidents/${ID}`);
  });

  it("un viewer ve sugerencias pero no puede crear ni adjuntar", async () => {
    renderAt(`/detections/${DETECTION}`, "viewer");
    expect(await screen.findByText(/mismo activo/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Adjuntar" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Crear incidente" })).not.toBeInTheDocument();
  });
});
