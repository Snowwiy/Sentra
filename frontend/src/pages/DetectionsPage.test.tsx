// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WithRole } from "../test/auth";
import type { Detection, DetectionDetail, Role } from "../api/types";
import { DetectionDetailPage } from "./DetectionDetailPage";
import { DetectionsPage } from "./DetectionsPage";

// Datos sintéticos de test: no proceden de ningún host real.
const NOW = Date.now();
const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();
const ID = "11111111-2222-3333-4444-555555555555";
const ASSET = "aaaaaaaa-0000-0000-0000-000000000001";

function detection(overrides: Partial<Detection> = {}): Detection {
  return {
    detection_id: ID,
    asset_id: ASSET,
    hostname: "pc-demo",
    rule_id: "CORR-001",
    rule_version: 1,
    rule_source: "builtin",
    kind: "correlation",
    category: "authentication",
    severity: "high",
    confidence: "medium",
    status: "open",
    title: "Inicio de sesión tras fallos repetidos",
    summary: "6 fallos de inicio de sesión de 'ana' seguidos de un inicio correcto.",
    mitre_tactic: "TA0006",
    mitre_technique: "T1110",
    mitre_subtechnique: null,
    occurrence_count: 2,
    first_seen_at: iso(-3_600_000),
    last_seen_at: iso(-60_000),
    created_at: iso(-3_600_000),
    updated_at: iso(-60_000),
    acknowledged_at: null,
    acknowledged_by: null,
    resolved_at: null,
    resolved_by: null,
    resolution_note: null,
    alert_id: null,
    ...overrides,
  };
}

function detail(overrides: Partial<DetectionDetail> = {}): DetectionDetail {
  return {
    ...detection(),
    details: null,
    description: "d",
    why: "Puede indicar que se ha adivinado la contraseña.",
    recommendations: ["Confirmar con el usuario si fue él.", "Cambiar la contraseña."],
    required_data: ["Security 4625", "Security 4624"],
    evidence: [
      {
        signal_kind: "auth_failure",
        role: "failure",
        source_type: "event",
        source_id: null,
        occurred_at: iso(-3_600_000),
        summary: "Fallo de inicio de sesión de ana",
        data: { source_ip: "10.0.0.9", account: "<img src=x onerror=alert(1)>" },
      },
      {
        signal_kind: "auth_success",
        role: "success",
        source_type: "event",
        source_id: null,
        occurred_at: iso(-3_000_000),
        summary: "Inicio de sesión correcto de ana",
        data: null,
      },
    ],
    asset_context: null,
    evidence_total: 2,
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
    "GET /detections": () => ({ body: { items: [detection(), detection({ detection_id: "x2", rule_id: "AUTH-001", severity: "critical", confidence: "high", title: "Ráfaga de fallos", status: "acknowledged" })], total: 2 } }),
    "GET /detection-rules": () => ({
      body: {
        items: [{ rule_id: "AUTH-001", title: "Ráfaga de fallos" }, { rule_id: "CORR-001", title: "Fallos y éxito" }],
        windows: {},
        alert_min_severity: "high",
      },
    }),
    "GET /assets": () => ({ body: { items: [{ asset_id: ASSET, display_name: "pc-demo" }], total: 1 } }),
    [`GET /detections/${ID}`]: () => ({ body: detail() }),
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

function renderList(role: Role = "admin") {
  return render(
    <MemoryRouter initialEntries={["/detections"]}>
      <WithRole role={role}>
        <Routes>
          <Route path="/detections" element={<DetectionsPage />} />
          <Route path="/detections/:detectionId" element={<DetectionDetailPage />} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

function renderDetail(role: Role = "admin") {
  return render(
    <MemoryRouter initialEntries={[`/detections/${ID}`]}>
      <WithRole role={role}>
        <Routes>
          <Route path="/detections" element={<p>lista</p>} />
          <Route path="/detections/:detectionId" element={<DetectionDetailPage />} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

const listCalls = () => calls.filter((c) => c.method === "GET" && c.path === "/detections");

describe("DetectionsPage", () => {
  it("lista las detecciones con severidad y confianza por separado", async () => {
    renderList();
    const row = (await screen.findByText("Inicio de sesión tras fallos repetidos")).closest("tr")!;
    const cells = within(row);
    expect(cells.getByTitle("Severidad (impacto)")).toHaveTextContent("Alta");
    expect(cells.getByTitle("Severidad (impacto)")).toHaveClass("dseverity--high");
    expect(cells.getByTitle("Confianza (evidencia)")).toHaveTextContent("Media");
    expect(cells.getByText("CORR-001")).toBeInTheDocument();
    expect(cells.getByText("pc-demo")).toHaveAttribute("href", `/assets/${ASSET}`);
    expect(cells.getByText("Abierta")).toBeInTheDocument();
    expect(cells.getByText("2")).toBeInTheDocument();
    const other = screen.getByText("Ráfaga de fallos", { selector: "a" }).closest("tr")!;
    expect(within(other).getByTitle("Severidad (impacto)")).toHaveClass("dseverity--critical");
    expect(within(other).getByText("Reconocida")).toBeInTheDocument();
    expect(screen.getByText(/2 detecciones/)).toBeInTheDocument();
    // Por defecto: solo activas.
    expect(listCalls()[0]!.url.searchParams.get("active")).toBe("true");
  });

  it("los filtros se envían al backend", async () => {
    renderList();
    await screen.findByText("Inicio de sesión tras fallos repetidos");
    await screen.findByRole("option", { name: "AUTH-001 · Ráfaga de fallos" });
    fireEvent.change(screen.getByLabelText("Severidad"), { target: { value: "critical" } });
    fireEvent.change(screen.getByLabelText("Confianza"), { target: { value: "high" } });
    fireEvent.change(screen.getByLabelText("Regla"), { target: { value: "AUTH-001" } });
    fireEvent.change(screen.getByLabelText("Activo"), { target: { value: ASSET } });
    fireEvent.change(screen.getByLabelText("Periodo"), { target: { value: "24" } });
    fireEvent.click(screen.getByRole("button", { name: "Resueltas" }));
    await waitFor(() => {
      const params = listCalls().at(-1)!.url.searchParams;
      expect(params.get("severity")).toBe("critical");
      expect(params.get("confidence")).toBe("high");
      expect(params.get("rule_id")).toBe("AUTH-001");
      expect(params.get("asset_id")).toBe(ASSET);
      expect(params.get("status")).toBe("resolved");
      expect(params.get("active")).toBeNull();
      expect(Date.parse(params.get("since")!)).toBeLessThan(NOW - 23 * 3_600_000);
    });
  });

  it("estado de carga, vacío y error", async () => {
    let resolveList: (r: Response) => void = () => undefined;
    const pending = new Promise<Response>((r) => (resolveList = r));
    const fetchMock = vi.mocked(fetch);
    const original = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation(async (input, init) =>
      String(input).includes("/detections?") ? pending : original(input, init),
    );
    renderList();
    expect(screen.getByText("Cargando detecciones…")).toBeInTheDocument();
    resolveList(json(200, { items: [], total: 0 }));
    expect(await screen.findByText("Sin detecciones para este filtro")).toBeInTheDocument();
    cleanup();

    fetchMock.mockImplementation(original);
    routes["GET /detections"] = () => ({ status: 500, body: { error: { code: "internal_error", message: "boom" } } });
    renderList();
    expect(await screen.findByText("No se pudieron cargar los datos")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reintentar" })).toBeInTheDocument();
  });

  it("al pulsar una fila abre el detalle", async () => {
    renderList();
    const row = (await screen.findByText("Inicio de sesión tras fallos repetidos")).closest("tr")!;
    fireEvent.click(row);
    expect(await screen.findByRole("heading", { name: "Qué pasó" })).toBeInTheDocument();
  });
});

describe("DetectionDetailPage", () => {
  it("muestra qué pasó, por qué, MITRE, recomendaciones y el timeline como texto", async () => {
    renderDetail();
    expect(await screen.findByRole("heading", { name: "Inicio de sesión tras fallos repetidos" })).toBeInTheDocument();
    expect(screen.getByText(/6 fallos de inicio de sesión/)).toBeInTheDocument();
    expect(screen.getByText("Puede indicar que se ha adivinado la contraseña.")).toBeInTheDocument();
    expect(screen.getByText("TA0006 · T1110")).toBeInTheDocument();
    expect(screen.getByText("Cambiar la contraseña.")).toBeInTheDocument();
    const timeline = screen.getByRole("list", { name: "Timeline de evidencias" });
    const items = within(timeline).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("Fallo de inicio de sesión de ana");
    expect(items[1]).toHaveTextContent("Inicio de sesión correcto de ana");
    // Dato del host hostil: se muestra literal, nunca como HTML.
    expect(within(items[0]!).getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(timeline.querySelector("img")).toBeNull();
  });

  it("un analyst reconoce y resuelve con nota", async () => {
    let current = detail();
    routes[`GET /detections/${ID}`] = () => ({ body: current });
    routes[`POST /detections/${ID}/acknowledge`] = () => {
      current = detail({ status: "acknowledged", acknowledged_at: iso(0), acknowledged_by: "analyst" });
      return { body: current };
    };
    routes[`POST /detections/${ID}/resolve`] = () => {
      current = detail({ status: "resolved", resolved_at: iso(0), resolved_by: "analyst", resolution_note: "Era el usuario" });
      return { body: current };
    };
    renderDetail("analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Reconocer" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Reconocer" })).not.toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Nota de resolución"), { target: { value: "Era el usuario" } });
    fireEvent.click(screen.getByRole("button", { name: "Resolver" }));
    await screen.findByText("Era el usuario");
    const resolve = calls.find((c) => c.path === `/detections/${ID}/resolve`)!;
    expect(JSON.parse(String(resolve.init.body))).toEqual({ note: "Era el usuario" });
    expect(screen.queryByRole("button", { name: "Resolver" })).not.toBeInTheDocument();
  });

  it("un viewer no ve acciones", async () => {
    renderDetail("viewer");
    await screen.findByRole("heading", { name: "Qué pasó" });
    expect(screen.queryByRole("button", { name: "Reconocer" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resolver" })).not.toBeInTheDocument();
  });

  it("muestra el error del backend si la acción falla", async () => {
    routes[`POST /detections/${ID}/resolve`] = () => ({
      status: 409,
      body: { error: { code: "conflict", message: "Detection is already resolved" } },
    });
    renderDetail("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Resolver" }));
    expect(await screen.findByText(/already resolved/)).toBeInTheDocument();
  });

  it("detección inexistente muestra error", async () => {
    routes[`GET /detections/${ID}`] = () => ({ status: 404, body: { error: { code: "not_found", message: "Detection not found" } } });
    renderDetail();
    expect(await screen.findByText("Detection not found")).toBeInTheDocument();
  });
});
