// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WithRole } from "../test/auth";
import type { RiskAssetDetail, RiskAssetSummary, RiskLevelRange, RiskOverview, Role } from "../api/types";
import { RiskPanel } from "../components/risk/RiskPanel";
import { RiskPage } from "./RiskPage";

// Datos sintéticos de test: no proceden de ningún host real.
const NOW = Date.now();
const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();
const ASSET = "aaaaaaaa-0000-0000-0000-000000000001";
const OTHER = "aaaaaaaa-0000-0000-0000-000000000002";
const DETECTION = "11111111-2222-3333-4444-555555555555";

const THRESHOLDS: RiskLevelRange[] = [
  { level: "informational", min: 0, max: 19 },
  { level: "low", min: 20, max: 39 },
  { level: "medium", min: 40, max: 59 },
  { level: "high", min: 60, max: 79 },
  { level: "critical", min: 80, max: 100 },
];

function summary(overrides: Partial<RiskAssetSummary> = {}): RiskAssetSummary {
  return {
    asset_id: ASSET,
    display_name: "pc-demo",
    device_name: null,
    primary_ip: "192.168.50.10",
    device_type: "pc",
    monitoring_method: "agent",
    status: "online",
    criticality: "medium",
    last_seen_at: iso(-60_000),
    evaluated: true,
    score: 84,
    level: "critical",
    confidence: "high",
    top_factor: "CORR-001 · Inicio de sesión tras fallos repetidos",
    calculated_at: iso(-30_000),
    changed_at: iso(-120_000),
    ...overrides,
  };
}

function overview(overrides: Partial<RiskOverview> = {}): RiskOverview {
  return {
    total_assets: 3,
    evaluated: 2,
    pending: 1,
    by_level: { critical: 1, high: 0, medium: 1, low: 0, informational: 0 },
    by_confidence: { high: 1, medium: 1, low: 0 },
    top_factors: [{ category: "authentication", label: "CORR-001 · Inicio de sesión tras fallos repetidos", assets: 1, points: 62.5 }],
    top_assets: [summary()],
    recent_transitions: [
      {
        ...summary(),
        snapshot_id: "s1",
        calculated_at: iso(-120_000),
        score: 84,
        level: "critical",
        confidence: "high",
        previous_score: 45,
        previous_level: "medium",
        transition: "up",
        reason: "level_change",
        top_factor: null,
      },
    ],
    thresholds: THRESHOLDS,
    last_calculated_at: iso(-30_000),
    ...overrides,
  };
}

function detail(overrides: Partial<RiskAssetDetail> = {}): RiskAssetDetail {
  return {
    ...summary(),
    formula_version: 1,
    pending_recalculation: false,
    explanation: {
      headline: "84 / Crítico — confianza alta",
      reasons: ["Una correlación de alta severidad sigue abierta."],
      increased: [{ label: "CORR-001 · Inicio de sesión tras fallos repetidos", points: 62.5 }],
      reduced: [{ label: "AUTH-001 · Ráfaga de fallos (resuelta)", points: -4 }],
      confidence_factors: [{ effect: "+", label: "Evidencia de varias categorías independientes" }],
    },
    contributions: [
      {
        factor: "detection",
        category: "authentication",
        label: "CORR-001 · Inicio de sesión tras fallos repetidos",
        points: 62.5,
        nominal_points: 80.5,
        detection_id: DETECTION,
        rule_id: "CORR-001",
        port: null,
        details: { severity: "high", status: "open" },
      },
      {
        factor: "detection",
        category: "authentication",
        label: "AUTH-001 · Ráfaga de fallos",
        points: 0,
        nominal_points: 70,
        detection_id: "x2",
        rule_id: "AUTH-001",
        port: null,
        details: { absorbed_by: { rule_id: "CORR-001" } },
      },
      {
        factor: "exposure",
        category: "exposure",
        label: "Puerto 3389 (RDP) abierto",
        points: 7.5,
        nominal_points: 10,
        detection_id: null,
        rule_id: null,
        port: 3389,
        details: {},
      },
    ],
    active_detections: [
      {
        detection_id: DETECTION,
        rule_id: "CORR-001",
        title: "Inicio de sesión tras fallos repetidos",
        category: "authentication",
        severity: "high",
        confidence: "high",
        status: "open",
        occurrence_count: 1,
        last_seen_at: iso(-60_000),
      },
    ],
    active_detections_total: 1,
    recent_changes: [
      {
        snapshot_id: "s1",
        calculated_at: iso(-120_000),
        score: 84,
        level: "critical",
        confidence: "high",
        previous_score: 45,
        previous_level: "medium",
        transition: "up",
        reason: "level_change",
        top_factor: null,
      },
    ],
    trend_24h: 39,
    breakdown: null,
    thresholds: THRESHOLDS,
    ...overrides,
  };
}

type Handler = (init: RequestInit, url: URL) => { status?: number; body: unknown };

let routes: Record<string, Handler>;
let calls: { method: string; path: string; url: URL; init: RequestInit }[];

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  calls = [];
  routes = {
    "GET /risk/overview": () => ({ body: overview() }),
    "GET /risk/assets": () => ({
      body: {
        items: [
          summary(),
          summary({
            asset_id: OTHER,
            display_name: "nas-salon",
            device_type: "nas",
            monitoring_method: "discovered",
            score: 45,
            level: "medium",
            confidence: "low",
            criticality: "high",
            top_factor: null,
          }),
        ],
        total: 2,
      },
    }),
    [`GET /risk/assets/${ASSET}`]: () => ({ body: detail() }),
    [`GET /risk/assets/${ASSET}/history`]: (_init, url) => ({
      body: {
        asset_id: ASSET,
        range: url.searchParams.get("range") ?? "24h",
        since: iso(-24 * 3_600_000),
        bucket_minutes: url.searchParams.get("range") === "7d" ? 60 : null,
        start_score: 45,
        points: detail().recent_changes,
        current_score: 84,
        current_level: "critical",
        calculated_at: iso(-30_000),
      },
    }),
    [`PATCH /assets/${ASSET}/criticality`]: (init) => {
      const body = JSON.parse(String(init.body)) as { criticality: "critical" };
      return {
        body: detail({ criticality: body.criticality, score: 100, calculated_at: iso(0) }),
      };
    },
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

function renderPage(role: Role = "viewer") {
  return render(
    <MemoryRouter initialEntries={["/risk"]}>
      <WithRole role={role}>
        <Routes>
          <Route path="/risk" element={<RiskPage />} />
          <Route path="/assets/:assetId" element={<p>detalle del activo</p>} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

function renderPanel(role: Role = "viewer") {
  return render(
    <MemoryRouter>
      <WithRole role={role}>
        <RiskPanel assetId={ASSET} />
      </WithRole>
    </MemoryRouter>,
  );
}

const listCalls = () => calls.filter((c) => c.method === "GET" && c.path === "/risk/assets");

describe("RiskPage", () => {
  it("resumen por nivel, factores principales y transiciones", async () => {
    renderPage();
    const cards = await screen.findByRole("region", { name: "Activos por nivel de riesgo" });
    expect(within(cards).getByRole("button", { name: /Crítico\s*1/ })).toBeInTheDocument();
    expect(within(cards).getByRole("button", { name: /Alto\s*0/ })).toBeInTheDocument();
    expect(within(cards).getByRole("button", { name: /Medio\s*1/ })).toBeInTheDocument();
    expect(within(cards).getByRole("button", { name: /Bajo\s*0/ })).toBeInTheDocument();
    expect(within(cards).getByRole("button", { name: /Total evaluados\s*2/ })).toHaveTextContent("1 pendientes");
    const factors = screen.getByRole("region", { name: "Principales factores de riesgo" });
    expect(factors).toHaveTextContent("CORR-001 · Inicio de sesión tras fallos repetidos");
    expect(factors).toHaveTextContent("+62,5");
    const transitions = screen.getByRole("region", { name: "Transiciones recientes" });
    expect(within(transitions).getByRole("link", { name: "pc-demo" })).toHaveAttribute("href", `/assets/${ASSET}?tab=risk`);
    expect(transitions).toHaveTextContent("Medio → Crítico (84)");
  });

  it("tabla ordenada por riesgo descendente con score, nivel y confianza por separado", async () => {
    renderPage();
    const body = (await screen.findByText("nas-salon")).closest("tbody")!;
    const rows = within(body).getAllByRole("row");
    expect(rows).toHaveLength(2);
    const first = within(rows[0]!);
    expect(first.getByText("84")).toBeInTheDocument();
    expect(first.getByText("Crítico")).toHaveClass("risk-level--critical");
    expect(first.getByText("alta")).toBeInTheDocument();
    expect(first.getByText("CORR-001 · Inicio de sesión tras fallos repetidos")).toBeInTheDocument();
    const second = within(rows[1]!);
    expect(second.getByText("Medio")).toHaveClass("risk-level--medium");
    expect(second.getByText("baja")).toBeInTheDocument();
    expect(second.getByText("Alta")).toHaveClass("criticality--high");
    const params = listCalls()[0]!.url.searchParams;
    expect(params.get("sort")).toBe("score");
    expect(params.get("order")).toBe("desc");
    expect(screen.getByRole("columnheader", { name: /Risk score/ })).toHaveAttribute("aria-sort", "descending");
  });

  it("filtros, tarjetas y ordenación se envían al backend", async () => {
    renderPage();
    await screen.findByText("nas-salon");
    fireEvent.click(screen.getByRole("button", { name: /Último cambio/ }));
    fireEvent.change(screen.getByLabelText("Confianza"), { target: { value: "low" } });
    fireEvent.change(screen.getByLabelText("Tipo"), { target: { value: "nas" } });
    fireEvent.change(screen.getByLabelText("Estado"), { target: { value: "offline" } });
    fireEvent.change(screen.getByLabelText("Criticidad"), { target: { value: "critical" } });
    fireEvent.click(screen.getByRole("button", { name: /Crítico\s*1/ }));
    await waitFor(() => {
      const params = listCalls().at(-1)!.url.searchParams;
      expect(params.get("level")).toBe("critical");
      expect(params.get("confidence")).toBe("low");
      expect(params.get("device_type")).toBe("nas");
      expect(params.get("status")).toBe("offline");
      expect(params.get("criticality")).toBe("critical");
      expect(params.get("sort")).toBe("changed_at");
      expect(params.get("order")).toBe("desc");
    });
    // Pulsar de nuevo la tarjeta activa quita el filtro de nivel.
    fireEvent.click(screen.getByRole("button", { name: /Crítico\s*1/ }));
    await waitFor(() => expect(listCalls().at(-1)!.url.searchParams.get("level")).toBeNull());
  });

  it("activo sin evaluar aparece como pendiente", async () => {
    routes["GET /risk/assets"] = () => ({
      body: {
        items: [summary({ evaluated: false, score: null, level: null, confidence: null, top_factor: null })],
        total: 1,
      },
    });
    renderPage();
    const row = (await screen.findByText("Pendiente")).closest("tr")!;
    expect(within(row).getAllByText("—").length).toBeGreaterThanOrEqual(2);
  });

  it("estado de carga, vacío y error", async () => {
    let resolveList: (r: Response) => void = () => undefined;
    const pending = new Promise<Response>((r) => (resolveList = r));
    const fetchMock = vi.mocked(fetch);
    const original = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation(async (input, init) =>
      String(input).includes("/risk/assets?") ? pending : original(input, init),
    );
    renderPage();
    expect(screen.getByText("Cargando riesgo…")).toBeInTheDocument();
    resolveList(json(200, { items: [], total: 0 }));
    expect(await screen.findByText("Ningún activo para este filtro")).toBeInTheDocument();
    cleanup();

    fetchMock.mockImplementation(original);
    routes["GET /risk/assets"] = () => ({ status: 500, body: { error: { code: "internal_error", message: "boom" } } });
    routes["GET /risk/overview"] = () => ({ status: 500, body: { error: { code: "internal_error", message: "boom" } } });
    renderPage();
    expect(await screen.findAllByText("No se pudieron cargar los datos")).toHaveLength(2);
  });

  it("al pulsar una fila abre el riesgo del activo", async () => {
    renderPage();
    const row = (await screen.findByText("nas-salon")).closest("tr")!;
    fireEvent.click(row);
    expect(await screen.findByText("detalle del activo")).toBeInTheDocument();
  });
});

describe("RiskPanel", () => {
  it("muestra el porqué, contribuciones navegables, detecciones y cambios", async () => {
    renderPanel();
    expect(await screen.findByRole("heading", { name: "84 / Crítico — confianza alta" })).toBeInTheDocument();
    expect(screen.getByText("Una correlación de alta severidad sigue abierta.")).toBeInTheDocument();
    expect(screen.getByText("24 h: +39")).toBeInTheDocument();
    const contributions = screen.getByRole("region", { name: "Contribuciones" });
    expect(within(contributions).getByRole("link", { name: "CORR-001 · Inicio de sesión tras fallos repetidos" })).toHaveAttribute(
      "href",
      `/detections/${DETECTION}`,
    );
    expect(within(contributions).getByRole("link", { name: "Puerto 3389 (RDP) abierto" })).toHaveAttribute(
      "href",
      `/assets/${ASSET}?tab=exposure`,
    );
    // La detección absorbida por la correlación no suma dos veces.
    expect(within(contributions).getByText("Incluida en CORR-001 (sin doble conteo)")).toBeInTheDocument();
    const reduced = screen.getByText("AUTH-001 · Ráfaga de fallos (resuelta)").closest("li")!;
    expect(reduced).toHaveTextContent("−4");
    const active = screen.getByRole("region", { name: "Detecciones activas" });
    expect(within(active).getByRole("link", { name: /CORR-001/ })).toHaveAttribute("href", `/detections/${DETECTION}`);
    const changes = screen.getByRole("region", { name: "Cambios recientes de riesgo" });
    expect(changes).toHaveTextContent("45 → 84 Crítico");
    expect(changes).toHaveTextContent("Cambio de nivel");
  });

  it("tendencia: pide solo el rango elegido", async () => {
    renderPanel();
    expect(await screen.findByRole("img", { name: /Tendencia del riesgo \(24h\)/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "7 d" }));
    expect(await screen.findByText(/un punto cada 1 h/)).toBeInTheDocument();
    const ranges = calls.filter((c) => c.path.endsWith("/history")).map((c) => c.url.searchParams.get("range"));
    expect(ranges).toEqual(expect.arrayContaining(["24h", "7d"]));
    expect(ranges).not.toContain("30d");
  });

  it.each<Role>(["viewer", "analyst"])("%s ve la criticidad pero no puede cambiarla", async (role) => {
    renderPanel(role);
    await screen.findByRole("heading", { name: "84 / Crítico — confianza alta" });
    expect(screen.queryByLabelText("Criticidad del activo")).toBeNull();
    expect(screen.getByTitle("Criticidad del activo")).toHaveTextContent("Media");
  });

  it("admin cambia la criticidad y ve el riesgo recalculado", async () => {
    renderPanel("admin");
    const select = await screen.findByLabelText("Criticidad del activo");
    fireEvent.change(select, { target: { value: "critical" } });
    await waitFor(() => expect(screen.getByLabelText("Criticidad del activo")).toHaveValue("critical"));
    const patch = calls.find((c) => c.method === "PATCH")!;
    expect(patch.path).toBe(`/assets/${ASSET}/criticality`);
    expect(JSON.parse(String(patch.init.body))).toEqual({ criticality: "critical" });
  });

  it("muestra el error del backend al cambiar la criticidad", async () => {
    routes[`PATCH /assets/${ASSET}/criticality`] = () => ({
      status: 403,
      body: { error: { code: "forbidden", message: "Permiso insuficiente" } },
    });
    renderPanel("admin");
    fireEvent.change(await screen.findByLabelText("Criticidad del activo"), { target: { value: "low" } });
    expect(await screen.findByRole("alert")).toHaveTextContent("Permiso insuficiente");
  });

  it("activo pendiente de evaluar", async () => {
    routes[`GET /risk/assets/${ASSET}`] = () => ({
      body: detail({
        evaluated: false,
        score: null,
        level: null,
        confidence: null,
        calculated_at: null,
        pending_recalculation: true,
        contributions: [],
        active_detections: [],
        active_detections_total: 0,
        recent_changes: [],
        explanation: { headline: "Pendiente de evaluar", reasons: [], increased: [], reduced: [], confidence_factors: [] },
      }),
    });
    renderPanel();
    expect(await screen.findByText("Pendiente de evaluar", { selector: "span" })).toBeInTheDocument();
    expect(screen.getByText(/Sin calcular todavía/)).toHaveTextContent("recálculo pendiente");
    expect(screen.getByText("Ninguna: sin detecciones ni exposición sensible.")).toBeInTheDocument();
  });

  it("error al cargar", async () => {
    routes[`GET /risk/assets/${ASSET}`] = () => ({ status: 500, body: { error: { code: "internal_error", message: "boom" } } });
    renderPanel();
    expect(await screen.findByText("No se pudieron cargar los datos")).toBeInTheDocument();
  });
});
