// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthContext } from "../auth/AuthContext";
import { authValue, WithRole } from "../test/auth";
import type {
  Asset,
  DashboardSummary,
  DiscoveryJobDetail,
  DiscoverySchedule,
  DiscoveryScope,
  Permission,
  Role,
} from "../api/types";
import { NetworkPage } from "./NetworkPage";
import { networkTabRoutes } from "./network/NetworkRoutes";
import { NETWORK_TABS, visibleNetworkTabs } from "./network/tabs";
import { resetPreferencesForTests } from "../ui/preferences";

const NET = "192.168.50.0/24";
const NOW = Date.now();
const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();
// El modal consulta cada 1,5 s: las esperas de transición necesitan algo más de margen.
const POLL = { timeout: 5000 };

const SCOPE: DiscoveryScope = {
  enabled: true,
  allowed_networks: [NET],
  networks: [{ network: NET, hosts: 254 }],
  max_hosts_per_network: 1024,
  excluded: [],
  ports: [22, 80, 443],
  interval_minutes: null,
  icmp: true,
  reverse_dns: true,
  timeout_ms: 800,
  concurrency: 64,
  max_probes_per_second: 200,
};

const SCHEDULE: DiscoverySchedule = {
  enabled: false,
  disabled_reason: "no_interval",
  interval_minutes: null,
  last_run_at: null,
  last_run_status: null,
  next_run_at: null,
  running: false,
};

function job(overrides: Partial<DiscoveryJobDetail> = {}): DiscoveryJobDetail {
  return {
    job_id: "11111111-1111-1111-1111-111111111111",
    target: NET,
    trigger: "manual",
    status: "running",
    baseline: false,
    started_at: iso(-18_000),
    completed_at: null,
    duration_seconds: null,
    hosts_scanned: 73,
    hosts_alive: 8,
    hosts_new: 0,
    open_ports: 0,
    probes: 300,
    error_count: 0,
    errors: [],
    requested_via: "dashboard",
    hosts_total: 254,
    hosts_updated: null,
    ports_opened: 0,
    ports_closed: 0,
    cancel_requested: false,
    stop_reason: null,
    progress: { phase: "liveness", details_total: 0, details_done: 0 },
    parameters: { ports: [22, 80, 443], icmp: true, reverse_dns: true },
    site_id: "00000000-0000-0000-0000-00000000d5f1",
    site_name: "Principal",
    execution_target: "local",
    sensor_id: null,
    sensor_name: null,
    new_assets: [],
    changes: [],
    ...overrides,
  };
}

const COMPLETED = job({
  status: "completed",
  completed_at: iso(0),
  duration_seconds: 42,
  hosts_scanned: 254,
  hosts_alive: 8,
  hosts_new: 2,
  hosts_updated: 6,
  ports_opened: 3,
  ports_closed: 1,
  progress: null,
  new_assets: [
    {
      asset_id: "22222222-2222-2222-2222-222222222222",
      display_name: "192.168.50.77",
      primary_ip: "192.168.50.77",
      mac_address: "02:00:00:00:00:77",
      device_type: null,
      monitoring_method: "discovered",
    },
  ],
});

function asset(ip: string, network: string | null = NET): Asset {
  return {
    asset_id: crypto.randomUUID(),
    display_name: ip,
    monitoring_method: "discovered",
    hostname: null,
    os_name: null,
    os_version: null,
    architecture: null,
    primary_ip: ip,
    agent_version: null,
    status: "online",
    agent_status: null,
    network_status: "online",
    first_seen_at: iso(0),
    last_seen_at: null,
    created_at: iso(0),
    updated_at: iso(0),
    latest_telemetry: null,
    mac_address: null,
    reverse_dns: null,
    vendor: null,
    network_adapter_vendor: null,
    device_type: null,
    device_type_reason: null,
    device_name: null,
    name_source: null,
    device_vendor: null,
    device_model: null,
    probable_os: null,
    classification_confidence: null,
    classification_evidence: [],
    discovery_sources: ["tcp"],
    discovery_network: network,
    discovered_at: iso(0),
    last_network_seen_at: iso(0),
    open_ports: [],
    criticality: "medium",
    role: "unknown",
    risk_score: null,
    risk_level: null,
    risk_confidence: null,
    archived_at: null,
    archived_by: null,
    archive_reason: null,
    lifecycle_version: 0,
    custom_label: null,
    custom_label_version: 0,
    custom_label_updated_at: null,
    custom_label_updated_by: null,
    manual_device_type: null,
    observed_names: [],
    managed_history: false,
    event_coverage: null,
    event_coverage_at: null,
    lifecycle_state: "active",
    lifecycle_source: "discovered",
    missed_discovery_scans: 0,
    last_activity_at: null,
    site_id: "00000000-0000-0000-0000-00000000d5f1",
    site_name: "Principal",
  };
}

const SUMMARY: DashboardSummary = {
  generated_at: "2026-10-06T00:00:00Z",
  assets: {
    total: 0,
    online: 0,
    offline: 0,
    unknown: 0,
    by_method: { discovered: 0, agentless: 0, agent: 0 },
    by_device_type: {},
  },
  risk: { by_level: {}, unscored: 0 },
  incidents: null,
  detections: { active: 0, by_severity: {} },
  active_alerts: 0,
  site_id: null,
};

type Handler = (init: RequestInit, url: URL) => { status?: number; body: unknown };

let routes: Record<string, Handler>;
let calls: { method: string; path: string; init: RequestInit }[];

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function refused(code: string) {
  return () => ({ status: 403, body: { error: { code, message: "refused" } } });
}

beforeEach(() => {
  // Fase 7B.3: columnas, densidad y últimos filtros viven en localStorage; cada test empieza limpio.
  window.localStorage.clear();
  resetPreferencesForTests();
  calls = [];
  routes = {
    "GET /assets": () => ({ body: { items: [], total: 0, limit: 50, offset: 0, status_counts: {} } }),
    "GET /dashboard/summary": () => ({ body: SUMMARY }),
    "GET /discovery/scope": () => ({ body: SCOPE }),
    "GET /discovery/schedule": () => ({ body: SCHEDULE }),
    "GET /discovery/jobs": () => ({ body: { items: [] } }),
    "GET /discovery/observations": () => ({ body: { items: [], total: 0, limit: 50, offset: 0 } }),
    "GET /topology/changes": () => ({ body: { items: [], total: 0 } }),
    "GET /console": () => ({
      body: { enrollment_token_ttl_minutes: 15, suggested_server_urls: [], server_url_configured: false },
    }),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const url = new URL(input, "http://localhost");
      const path = url.pathname.replace("/api/v1", "");
      calls.push({ method, path, init });
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

/** Ruta y query actuales, para comprobar a dónde lleva cada pestaña o filtro. */
function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
}

const currentPath = () => screen.getByTestId("location").textContent ?? "";
const currentQuery = () => new URLSearchParams(currentPath().split("?")[1] ?? "");

/** El hub Red con sus rutas hijas reales (las de App), abierto en `path`. */
function renderHub(path: string, auth: ReactNode = null, role: Role = "admin") {
  const routes = (
    <>
      <Routes>
        <Route path="/network" element={<NetworkPage />}>
          {networkTabRoutes()}
        </Route>
        <Route path="/assets/:assetId" element={<p>Ficha del activo</p>} />
      </Routes>
      <LocationProbe />
    </>
  );
  return render(
    <MemoryRouter initialEntries={[path]}>
      {auth ?? <WithRole role={role}>{routes}</WithRole>}
    </MemoryRouter>,
  );
}

// La mayoría de pruebas de descubrimiento usan su pestaña (historial, scheduler y alcance).
function renderPage(role: Role = "admin", path = "/network/discovery") {
  return renderHub(path, null, role);
}

async function startButton() {
  const button = await screen.findByRole("button", { name: "Iniciar descubrimiento" });
  return button;
}

async function openModal() {
  renderPage();
  const button = await startButton();
  await waitFor(() => expect(button).toBeEnabled());
  fireEvent.click(button);
  return screen.findByRole("dialog", { name: "Iniciar descubrimiento" });
}

describe("NetworkPage: descubrimiento desde el dashboard", () => {
  it("muestra el estado de carga antes de la primera respuesta", () => {
    renderPage("admin", "/network/devices");
    expect(screen.getAllByText(/^Cargando/).length).toBeGreaterThan(0);
  });

  it("habilita Iniciar descubrimiento con redes autorizadas y consola local", async () => {
    renderPage();
    const button = await startButton();
    await waitFor(() => expect(button).toBeEnabled());
    const scope = await screen.findByRole("region", { name: "Redes autorizadas" });
    expect(within(scope).getByText(NET)).toBeInTheDocument();
    expect(within(scope).getByText("(254 direcciones)")).toBeInTheDocument();
    const auto = screen.getByRole("region", { name: "Descubrimiento automático" });
    expect(within(auto).getByText("OFF")).toBeInTheDocument();
    expect(within(auto).getByText(/DISCOVERY_INTERVAL_MINUTES/)).toBeInTheDocument();
  });

  it("muestra el scheduler activo con su próxima ejecución", async () => {
    routes["GET /discovery/schedule"] = () => ({
      body: {
        ...SCHEDULE,
        enabled: true,
        disabled_reason: null,
        interval_minutes: 60,
        last_run_at: iso(-600_000),
        last_run_status: "completed",
        next_run_at: iso(3_000_000),
      },
    });
    renderPage();
    const auto = await screen.findByRole("region", { name: "Descubrimiento automático" });
    await waitFor(() => expect(within(auto).getByText("ON")).toBeInTheDocument());
    expect(within(auto).getByText("60 minutos")).toBeInTheDocument();
    expect(within(auto).getByText(/Completado/)).toBeInTheDocument();
  });

  it("sin redes configuradas: avisa y deshabilita el botón", async () => {
    routes["GET /discovery/scope"] = () => ({
      body: { ...SCOPE, enabled: false, allowed_networks: [], networks: [] },
    });
    renderPage();
    const button = await startButton();
    await waitFor(() =>
      expect(
        screen.getByText(
          "El descubrimiento de red está desactivado. Configure DISCOVERY_ALLOWED_NETWORKS en el servidor.",
        ),
      ).toBeInTheDocument(),
    );
    expect(button).toBeDisabled();
  });

  it("viewer: lectura disponible, sin botón de iniciar ni de cancelar", async () => {
    routes["GET /discovery/jobs"] = () => ({ body: { items: [COMPLETED] } });
    renderPage("viewer");
    const history = await screen.findByRole("region", { name: "Ejecuciones recientes" });
    await waitFor(() => expect(within(history).getByText("Completado")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "Iniciar descubrimiento" })).not.toBeInTheDocument();
    expect(calls.some((c) => c.method !== "GET")).toBe(false);
  });

  it("analyst: puede iniciar descubrimientos", async () => {
    renderPage("analyst");
    expect(await startButton()).toBeInTheDocument();
  });

  it("el modal solo ofrece redes autorizadas y advierte del alcance", async () => {
    const dialog = await openModal();
    expect(within(dialog).getByText(/Solo se analizan las redes autorizadas/)).toBeInTheDocument();
    const select = within(dialog).getByRole("combobox");
    const options = within(select).getAllByRole("option").map((o) => o.textContent);
    expect(options).toEqual([NET]);
    expect(within(dialog).getByText("254")).toBeInTheDocument();
    expect(within(dialog).getByText(/sin descubrimientos activos/)).toBeInTheDocument();
    // Sin campo de texto libre: no se puede escribir un target fuera de la allowlist.
    expect(within(dialog).queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("inicia un job y muestra progreso real con barra", async () => {
    let body: unknown;
    routes["POST /console/discovery/jobs"] = (init) => {
      body = JSON.parse(String(init.body));
      return { status: 202, body: job({ status: "queued", hosts_scanned: 0, progress: { phase: "queued", details_total: 0, details_done: 0 } }) };
    };
    routes["GET /discovery/jobs/11111111-1111-1111-1111-111111111111"] = () => ({ body: job() });
    const dialog = await openModal();
    fireEvent.click(within(dialog).getByRole("button", { name: "Iniciar" }));

    await waitFor(() => expect(screen.getByText("Descubrimiento en curso")).toBeInTheDocument(), POLL);
    expect(body).toEqual({ target: NET });
    const post = calls.find((c) => c.method === "POST");
    expect(new Headers(post?.init.headers).get("X-Sentra-Console")).toBeNull();
    expect(post?.init.credentials).toBe("include");
    expect(screen.getByText("73 / 254")).toBeInTheDocument();
    expect(screen.getByText("8")).toBeInTheDocument();
    const bar = screen.getByRole("progressbar");
    expect(bar).toHaveAttribute("aria-valuenow", "73");
    expect(bar).toHaveAttribute("aria-valuemax", "254");
    expect(screen.getByRole("button", { name: "Cancelar" })).toBeEnabled();
  });

  it("sin total exacto no inventa porcentaje: spinner y contadores", async () => {
    routes["GET /discovery/jobs"] = () => ({
      body: { items: [job({ progress: { phase: "pending", details_total: 0, details_done: 0 } })] },
    });
    routes["GET /discovery/jobs/11111111-1111-1111-1111-111111111111"] = () => ({
      body: job({ progress: { phase: "pending", details_total: 0, details_done: 0 } }),
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Ver progreso" }));
    await screen.findByText("Descubrimiento en curso");
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    expect(screen.getByText(/Preparando/)).toBeInTheDocument();
    expect(screen.getByText("73 / 254")).toBeInTheDocument();
  });

  it("muestra un job en cola", async () => {
    routes["GET /discovery/jobs"] = () => ({ body: { items: [job({ status: "queued" })] } });
    routes["GET /discovery/jobs/11111111-1111-1111-1111-111111111111"] = () => ({
      body: job({ status: "queued", progress: { phase: "queued", details_total: 0, details_done: 0 } }),
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Ver progreso" }));
    expect(await screen.findByText("Descubrimiento en cola")).toBeInTheDocument();
  });

  it("completed: resultado, cambios y ver dispositivos", async () => {
    routes["GET /discovery/jobs"] = () => ({ body: { items: [COMPLETED] } });
    routes["GET /discovery/jobs/11111111-1111-1111-1111-111111111111"] = () => ({ body: COMPLETED });
    // Fase 4M: el filtro por red lo aplica el servidor; el mock lo imita con el parámetro.
    let lastQuery: URLSearchParams | undefined;
    routes["GET /assets"] = (_init, url) => {
      lastQuery = url.searchParams;
      const all = [asset("192.168.50.77"), asset("10.9.9.9", null)];
      const items = url.searchParams.get("subnet") ? all.slice(0, 1) : all;
      return { body: { items, total: items.length } };
    };
    renderPage();
    const history = await screen.findByRole("region", { name: "Ejecuciones recientes" });
    fireEvent.click(await within(history).findByRole("button", { name: /\d/ }));

    const dialog = await screen.findByRole("dialog", { name: "Descubrimiento de red" });
    await within(dialog).findByText("Descubrimiento completado");
    const result = within(dialog).getByRole("region", { name: "Resultado del descubrimiento" });
    const expected: [string, string][] = [
      ["Hosts evaluados", "254 / 254"],
      ["Nuevos dispositivos", "2"],
      ["Actualizados", "6"],
      ["Nuevos puertos", "3"],
      ["Puertos cerrados", "1"],
      ["Duración", "00:42"],
    ];
    for (const [label, value] of expected) {
      expect(within(result).getByText(label).nextElementSibling).toHaveTextContent(value);
    }
    fireEvent.click(within(dialog).getByRole("button", { name: "Ver cambios" }));
    expect(within(dialog).getByText("Dispositivos nuevos")).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "192.168.50.77" })).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Ejecutar nuevamente" })).toBeEnabled();

    fireEvent.click(within(dialog).getByRole("button", { name: "Ver dispositivos" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    // Fase 7A.5: lleva a Red › Dispositivos con la subred y los más recientes primero en la URL.
    expect(currentPath().startsWith("/network/devices?")).toBe(true);
    expect(currentQuery().get("subnet")).toBe(COMPLETED.target);
    expect(currentQuery().get("sort")).toBe("first");
    expect(currentQuery().get("dir")).toBe("desc");
    const table = await screen.findByRole("region", { name: "Dispositivos" });
    await waitFor(() => expect(within(table).getByText("192.168.50.77")).toBeInTheDocument());
    expect(within(table).queryByText("10.9.9.9")).not.toBeInTheDocument();
    expect(lastQuery?.get("subnet")).toBe(COMPLETED.target);
    expect(lastQuery?.get("sort")).toBe("first_seen");
    expect(lastQuery?.get("order")).toBe("desc");
  });

  it("failed: muestra el motivo y que el resultado es parcial", async () => {
    const failed = job({ status: "failed", stop_reason: "error", completed_at: iso(0), duration_seconds: 1, errors: ["RuntimeError('boom')"], error_count: 1, progress: null });
    routes["GET /discovery/jobs"] = () => ({ body: { items: [failed] } });
    routes["GET /discovery/jobs/11111111-1111-1111-1111-111111111111"] = () => ({ body: failed });
    renderPage();
    const history = await screen.findByRole("region", { name: "Ejecuciones recientes" });
    fireEvent.click(await within(history).findByRole("button", { name: /\d/ }));
    expect(await screen.findByText("Descubrimiento fallido")).toBeInTheDocument();
    expect(screen.getByText(/no se infiere que ningún\s+dispositivo haya desaparecido/)).toBeInTheDocument();
    expect(screen.getByText(/error durante el scan/)).toBeInTheDocument();
  });

  it("cancelar: pide la cancelación y muestra el resultado parcial", async () => {
    let state = job();
    routes["GET /discovery/jobs"] = () => ({ body: { items: [state] } });
    routes["GET /discovery/jobs/11111111-1111-1111-1111-111111111111"] = () => ({ body: state });
    routes["POST /console/discovery/jobs/11111111-1111-1111-1111-111111111111/cancel"] = () => {
      state = { ...state, cancel_requested: true };
      return { body: state };
    };
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Ver progreso" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancelar" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Cancelando…" })).toBeDisabled());
    expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/cancel"))).toBe(true);
    expect(screen.getByText(/Cancelación solicitada/)).toBeInTheDocument();

    state = { ...state, status: "cancelled", stop_reason: "operator", completed_at: iso(0), duration_seconds: 20, hosts_new: 0, hosts_updated: 8, progress: null };
    expect(await screen.findByText("Descubrimiento cancelado", undefined, POLL)).toBeInTheDocument();
    expect(screen.getByText(/cancelado por un operador/)).toBeInTheDocument();
  }, 10_000);

  it("al terminar, la tabla Red se actualiza sola con los activos nuevos", async () => {
    let state = job();
    let found: Asset[] = [];
    routes["GET /assets"] = () => ({ body: { items: found, total: found.length } });
    routes["GET /discovery/jobs"] = () => ({ body: { items: [state] } });
    routes["GET /discovery/jobs/11111111-1111-1111-1111-111111111111"] = () => ({ body: state });
    renderPage("admin", "/network/devices");
    fireEvent.click(await screen.findByRole("button", { name: "Ver progreso" }));
    await screen.findByText("Descubrimiento en curso");

    found = [asset("192.168.50.77")];
    state = COMPLETED;
    await screen.findByText("Descubrimiento completado", undefined, POLL);
    fireEvent.click(screen.getByRole("button", { name: "Cerrar" }));
    const table = await screen.findByRole("region", { name: "Dispositivos" });
    await waitFor(() => expect(within(table).getByText("192.168.50.77")).toBeInTheDocument());
  }, 10_000);

  it("error 403 al iniciar: muestra el motivo en el modal", async () => {
    // El rol cambió en el servidor mientras la página estaba abierta: el backend manda.
    routes["POST /console/discovery/jobs"] = refused("permission_denied");
    const dialog = await openModal();
    fireEvent.click(within(dialog).getByRole("button", { name: "Iniciar" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      /Tu rol no permite iniciar ni cancelar descubrimientos/,
    );
  });

  it("red ocupada: lo explica en lugar de duplicar el scan", async () => {
    routes["POST /console/discovery/jobs"] = () => ({
      status: 409,
      body: { error: { code: "discovery_busy", message: "busy" } },
    });
    const dialog = await openModal();
    fireEvent.click(within(dialog).getByRole("button", { name: "Iniciar" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(/Ya hay un descubrimiento/);
  });

  it("historial con columnas, estados y origen", async () => {
    routes["GET /discovery/jobs"] = () => ({
      body: {
        items: [
          COMPLETED,
          job({ job_id: "a", status: "cancelled", requested_via: "cli", progress: null, hosts_updated: 1, duration_seconds: 5, completed_at: iso(0) }),
          job({ job_id: "b", status: "failed", trigger: "scheduled", requested_via: "scheduler", progress: null, duration_seconds: 1, completed_at: iso(0) }),
        ],
      },
    });
    renderPage();
    const history = await screen.findByRole("region", { name: "Ejecuciones recientes" });
    await within(history).findByText("Completado");
    const headers = within(history).getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual([
      "Fecha/hora", "Red", "Ejecución", "Estado", "Encontrados", "Nuevos", "Actualizados", "Duración", "Perfil", "Origen",
    ]);
    expect(within(history).getByText("Cancelado")).toBeInTheDocument();
    expect(within(history).getByText("Fallido")).toBeInTheDocument();
    expect(within(history).getByText("Consola")).toBeInTheDocument();
    expect(within(history).getByText("CLI")).toBeInTheDocument();
    expect(within(history).getByText("Programado")).toBeInTheDocument();
    expect(within(history).getAllByText("3 puertos TCP · ICMP · DNS")).toHaveLength(3);
  });

  it("no guarda nada en el almacenamiento del navegador", async () => {
    const dialog = await openModal();
    routes["POST /console/discovery/jobs"] = () => ({ status: 202, body: job({ status: "queued" }) });
    routes["GET /discovery/jobs/11111111-1111-1111-1111-111111111111"] = () => ({ body: job() });
    fireEvent.click(within(dialog).getByRole("button", { name: "Iniciar" }));
    await screen.findByText("Descubrimiento en curso", undefined, POLL);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });
});

describe("NetworkPage: identificación de dispositivos", () => {
  it("presenta nombre, IP, tipo en español, NIC y Gestionado frente a Descubierto", async () => {
    const phone = {
      ...asset("192.168.50.141"),
      device_name: "MNA-LX9",
      display_name: "MNA-LX9",
      device_type: "mobile",
      device_vendor: "Huawei",
      network_adapter_vendor: "Huawei",
      classification_confidence: "high" as const,
    };
    const console_ = {
      ...asset("192.168.50.108"),
      mac_address: "a4:00:03:00:00:08",
      device_type: "console",
      network_adapter_vendor: "Realtek",
      classification_confidence: "medium" as const,
    };
    const managed = {
      ...asset("192.168.50.66"),
      monitoring_method: "agent" as const,
      hostname: "Ravenslg",
      device_name: "Ravenslg",
      display_name: "Ravenslg",
      os_name: "Linux",
      device_type: "pc",
      classification_confidence: "high" as const,
    };
    const unknown = asset("192.168.50.12");
    routes["GET /assets"] = () => ({ body: { items: [phone, console_, managed, unknown], total: 4 } });
    renderPage("admin", "/network/devices");

    const table = await screen.findByRole("region", { name: "Dispositivos" });
    const row = (ip: string) => within(table).getByText(ip, { selector: "td" }).closest("tr") as HTMLElement;
    expect(within(row("192.168.50.141")).getByRole("link", { name: "MNA-LX9" })).toBeInTheDocument();
    expect(within(row("192.168.50.141")).getByText("Móvil")).toBeInTheDocument();
    expect(within(row("192.168.50.141")).getByText("Huawei")).toBeInTheDocument();
    expect(within(row("192.168.50.108")).getByRole("link", { name: "Consola probable" })).toBeInTheDocument();
    expect(within(row("192.168.50.108")).getByText("NIC Realtek")).toBeInTheDocument();
    expect(within(row("192.168.50.66")).getByText("Gestionado")).toBeInTheDocument();
    expect(within(row("192.168.50.66")).getByText("PC")).toBeInTheDocument();
    expect(within(row("192.168.50.12")).getByRole("link", { name: "Dispositivo desconocido" })).toBeInTheDocument();
    expect(within(row("192.168.50.12")).getByText("Desconocido")).toBeInTheDocument();
  });
});

describe("NetworkPage: observaciones de red (Fase 6A)", () => {
  it("Descubrimiento muestra las observaciones paginadas en el servidor y el viewer puede leerlas", async () => {
    let query: URLSearchParams | undefined;
    routes["GET /discovery/observations"] = (_init, url) => {
      query = url.searchParams;
      return { body: { items: [], total: 0, limit: 50, offset: 0 } };
    };
    renderPage("viewer", "/network");
    const tabs = await screen.findByRole("tablist", { name: "Secciones de red" });
    expect(within(tabs).getByRole("tab", { name: "Resumen" })).toHaveAttribute("aria-selected", "true");
    // Hasta abrir la pestaña no se consulta nada de observaciones.
    expect(await screen.findByText("Todavía no hay dispositivos")).toBeInTheDocument();
    expect(calls.some((c) => c.path === "/discovery/observations")).toBe(false);

    fireEvent.click(within(tabs).getByRole("tab", { name: "Descubrimiento" }));
    const panel = await screen.findByRole("region", { name: "Observaciones de red" });
    expect(await within(panel).findByText("Sin observaciones")).toBeInTheDocument();
    expect(query?.get("latest")).toBe("true");
    expect(query?.get("limit")).toBe("50");
    expect(calls.some((c) => c.method !== "GET")).toBe(false);

    fireEvent.click(within(tabs).getByRole("tab", { name: "Dispositivos" }));
    expect(await screen.findByRole("region", { name: "Dispositivos" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Observaciones de red" })).not.toBeInTheDocument();
  });

  it("el historial muestra el perfil de cada ejecución", async () => {
    routes["GET /discovery/jobs"] = () => ({
      body: { items: [{ ...COMPLETED, profile: "quick", job_type: "discovery_advanced" }] },
    });
    renderPage();
    const history = await screen.findByRole("region", { name: "Ejecuciones recientes" });
    expect(await within(history).findByText("Quick")).toBeInTheDocument();
  });
});

// --- Fase 7A.5: hub Red con pestañas por ruta ------------------------------------------------

function device(name: string, ip: string, overrides: Partial<Asset> = {}): Asset {
  return { ...asset(ip), display_name: name, device_name: name, ...overrides };
}

/** GET /assets que imita al servidor: guarda cada consulta y devuelve `items` y `total`. */
function serveAssets(items: () => Asset[], total?: () => number) {
  const queries: URLSearchParams[] = [];
  routes["GET /assets"] = (_init, url) => {
    queries.push(url.searchParams);
    return {
      body: {
        items: items(),
        total: total ? total() : items().length,
        limit: 50,
        offset: Number(url.searchParams.get("offset") ?? 0),
        status_counts: { online: 7000, offline: 2900, unknown: 100 },
      },
    };
  };
  return queries;
}

describe("Red: pestañas del hub (Fase 7A.5)", () => {
  it("muestra todas las pestañas con su ARIA y cambia de pestaña por ruta", async () => {
    renderHub("/network");
    const tabs = await screen.findByRole("tablist", { name: "Secciones de red" });
    const names = within(tabs).getAllByRole("tab").map((t) => t.textContent);
    expect(names).toEqual([
      "Resumen",
      "Dispositivos",
      "Descubrimiento",
      "Topología",
      "Puertos y servicios",
      "Historial de cambios",
      "Identidad y evidencias",
      "Telemetría",
    ]);
    const resumen = within(tabs).getByRole("tab", { name: "Resumen" });
    expect(resumen).toHaveAttribute("aria-selected", "true");
    expect(resumen).toHaveAttribute("aria-controls", "network-tabpanel");
    expect(resumen).toHaveAttribute("tabindex", "0");
    expect(within(tabs).getByRole("tab", { name: "Dispositivos" })).toHaveAttribute("tabindex", "-1");
    const panel = screen.getByRole("tabpanel");
    expect(panel).toHaveAttribute("id", "network-tabpanel");
    expect(panel).toHaveAttribute("aria-labelledby", resumen.id);

    fireEvent.click(within(tabs).getByRole("tab", { name: "Dispositivos" }));
    expect(currentPath()).toBe("/network/devices");
    await waitFor(() =>
      expect(within(tabs).getByRole("tab", { name: "Dispositivos" })).toHaveAttribute("aria-selected", "true"),
    );
    expect(resumen).toHaveAttribute("aria-selected", "false");
    expect(await screen.findByRole("region", { name: "Dispositivos" })).toBeInTheDocument();
  });

  it("cada pestaña es una ruta: abrir la URL marca su pestaña", async () => {
    for (const tab of NETWORK_TABS) {
      const path = tab.path ? `/network/${tab.path}` : "/network";
      renderHub(path);
      const tabs = await screen.findByRole("tablist", { name: "Secciones de red" });
      expect(within(tabs).getByRole("tab", { name: tab.label })).toHaveAttribute("aria-selected", "true");
      expect(within(tabs).getByRole("tab", { name: tab.label })).toHaveAttribute("href", path);
      cleanup();
    }
  });

  it("teclado: flechas, Inicio y Fin mueven el foco; Espacio abre la pestaña", async () => {
    renderHub("/network");
    const tabs = await screen.findByRole("tablist", { name: "Secciones de red" });
    const tab = (name: string) => within(tabs).getByRole("tab", { name });
    tab("Resumen").focus();
    fireEvent.keyDown(tab("Resumen"), { key: "ArrowRight" });
    expect(tab("Dispositivos")).toHaveFocus();
    // Mover el foco no navega (activación manual): cada pestaña carga sus propios datos.
    expect(currentPath()).toBe("/network");
    fireEvent.keyDown(tab("Dispositivos"), { key: "End" });
    expect(tab("Telemetría")).toHaveFocus();
    fireEvent.keyDown(tab("Telemetría"), { key: "ArrowRight" });
    expect(tab("Resumen")).toHaveFocus();
    fireEvent.keyDown(tab("Resumen"), { key: "ArrowLeft" });
    expect(tab("Telemetría")).toHaveFocus();
    fireEvent.keyDown(tab("Telemetría"), { key: "Home" });
    expect(tab("Resumen")).toHaveFocus();
    fireEvent.keyDown(tab("Resumen"), { key: "ArrowRight" });
    fireEvent.keyDown(tab("Dispositivos"), { key: " " });
    expect(currentPath()).toBe("/network/devices");
  });

  it("sin el permiso de una pestaña: no se muestra y su URL responde acceso restringido", async () => {
    const limited = authValue("viewer");
    const denied = new Set<Permission>(["vulnerabilities:read", "monitoring:read"]);
    const can = (permission: Permission) => !denied.has(permission) && limited.can(permission);
    expect(visibleNetworkTabs(can).map((t) => t.key)).toEqual(["overview", "devices", "discovery", "telemetry"]);

    const routesFor = (
      <AuthContext.Provider value={{ ...limited, can }}>
        <Routes>
          <Route path="/network" element={<NetworkPage />}>
            {networkTabRoutes()}
          </Route>
        </Routes>
        <LocationProbe />
      </AuthContext.Provider>
    );
    renderHub("/network/services", routesFor);
    expect(await screen.findByRole("heading", { name: "Acceso restringido" })).toBeInTheDocument();
    const tabs = screen.getByRole("tablist", { name: "Secciones de red" });
    expect(within(tabs).queryByRole("tab", { name: "Puertos y servicios" })).toBeNull();
    expect(within(tabs).queryByRole("tab", { name: "Topología" })).toBeNull();
    expect(within(tabs).queryByRole("tab", { name: "Identidad y evidencias" })).toBeNull();
    expect(calls.some((c) => c.path.startsWith("/vulnerabilities"))).toBe(false);
  });

  it("una ruta desconocida dentro del hub muestra página no encontrada", async () => {
    renderHub("/network/no-existe");
    expect(await screen.findByText("Página no encontrada")).toBeInTheDocument();
    const tabs = screen.getByRole("tablist", { name: "Secciones de red" });
    // Sin pestaña activa, la primera sigue siendo alcanzable con Tab.
    expect(within(tabs).getByRole("tab", { name: "Resumen" })).toHaveAttribute("tabindex", "0");
  });

  it("Resumen: los recuentos llevan a Dispositivos ya filtrado", async () => {
    routes["GET /dashboard/summary"] = () => ({
      body: {
        ...SUMMARY,
        assets: {
          total: 12,
          online: 9,
          offline: 2,
          unknown: 1,
          by_method: { discovered: 8, agentless: 0, agent: 4 },
          by_device_type: { printer: 3, ip_camera: 2, unknown: 7 },
        },
      },
    });
    renderHub("/network");
    const byMethod = await screen.findByRole("region", { name: "Dispositivos por método" });
    expect(within(byMethod).getByRole("link", { name: /Gestionado\s*4/ })).toHaveAttribute(
      "href",
      "/network/devices?method=agent",
    );
    const byStatus = screen.getByRole("region", { name: "Dispositivos por estado" });
    expect(within(byStatus).getByRole("link", { name: /Sin conexión\s*2/ })).toHaveAttribute(
      "href",
      "/network/devices?status=offline",
    );
    const byType = screen.getByRole("list", { name: "Recuento por tipo" });
    expect(within(byType).getByRole("link", { name: "Cámara IP: 2" })).toHaveAttribute(
      "href",
      "/network/devices?type=ip_camera",
    );
  });
});

describe("Red › Dispositivos: la tabla única (Fase 7A.5)", () => {
  it("busca por IP, MAC y nombre en el servidor y guarda la búsqueda en la URL", async () => {
    const queries = serveAssets(() => [device("srv-db", "10.0.0.5", { mac_address: "02:00:00:00:00:05" })]);
    renderHub("/network/devices");
    const search = await screen.findByLabelText("Buscar dispositivos");
    for (const term of ["10.0.0.5", "02:00:00:00:00:05", "srv-db"]) {
      fireEvent.change(search, { target: { value: term } });
      await waitFor(() => expect(queries.at(-1)?.get("q")).toBe(term));
      expect(currentQuery().get("q")).toBe(term);
      expect(queries.at(-1)?.get("offset")).toBeNull();
    }
    const table = screen.getByRole("region", { name: "Dispositivos" });
    expect(within(table).getByText("10.0.0.5")).toBeInTheDocument();
    expect(within(table).getByText("02:00:00:00:00:05")).toBeInTheDocument();
  });

  it("los filtros de la URL se aplican al abrir (enlaces desde el panel y el resumen)", async () => {
    const queries = serveAssets(() => []);
    renderHub("/network/devices?status=offline&q=srv&type=ip_camera&archived=include");
    expect(await screen.findByText("Ningún dispositivo coincide con el filtro")).toBeInTheDocument();
    const first = queries[0]!;
    expect(first.get("status")).toBe("offline");
    expect(first.get("q")).toBe("srv");
    expect(first.get("device_type")).toBe("ip_camera");
    expect(first.get("archived")).toBe("include");
    expect(screen.getByLabelText("Buscar dispositivos")).toHaveValue("srv");
    expect(screen.getByLabelText("Mostrar archivados")).toBeChecked();
  });

  it("los contadores vienen del servidor; estado y página se filtran en el servidor", async () => {
    const queries = serveAssets(
      () => [device("b-db", "10.0.0.6"), device("a-pc", "10.0.0.7")],
      () => 120,
    );
    renderHub("/network/devices");
    const stats = await screen.findByRole("region", { name: "Dispositivos por estado" });
    expect(within(stats).getByText("10000")).toBeInTheDocument();
    expect(within(stats).getByText("2900")).toBeInTheDocument();
    for (const query of queries) expect(query.get("limit")).toBe("50");

    fireEvent.click(screen.getByRole("button", { name: "Siguiente" }));
    await waitFor(() => expect(queries.at(-1)?.get("offset")).toBe("50"));
    fireEvent.click(within(stats).getByRole("button", { name: /Sin conexión/ }));
    await waitFor(() => {
      expect(queries.at(-1)?.get("status")).toBe("offline");
      expect(queries.at(-1)?.get("offset")).toBeNull();
    });
    expect(currentQuery().get("status")).toBe("offline");
    expect(screen.getByText(/página 1 de 3/)).toBeInTheDocument();
  });

  it("filtros de contexto: se envían al servidor, ordenan por criticidad y se limpian", async () => {
    const queries = serveAssets(() => [
      device("b-db", "10.0.0.6", { criticality: "critical", role: "database" }),
      device("a-pc", "10.0.0.7"),
    ]);
    renderHub("/network/devices");
    const row = (await screen.findByText("b-db", { selector: "a" })).closest("tr")!;
    expect(within(row).getByText("Base de datos")).toBeInTheDocument();
    expect(within(row).getByText(/Crítica/)).toBeInTheDocument();
    expect(within(screen.getByText("a-pc", { selector: "a" }).closest("tr")!).queryByText(/Media/)).toBeNull();

    fireEvent.change(screen.getByLabelText("Criticidad"), { target: { value: "critical" } });
    fireEvent.change(screen.getByLabelText("Rol"), { target: { value: "database" } });
    fireEvent.change(screen.getByLabelText("Internet"), { target: { value: "unknown" } });
    fireEvent.change(screen.getByLabelText("Tag"), { target: { value: "pci" } });
    fireEvent.change(screen.getByLabelText("Ciclo de vida"), { target: { value: "cleanup_candidate" } });
    fireEvent.change(screen.getByLabelText("Orden"), { target: { value: "criticality" } });
    await waitFor(() => {
      const params = queries.at(-1)!;
      expect(params.get("criticality")).toBe("critical");
      expect(params.get("role")).toBe("database");
      expect(params.get("internet_exposed")).toBe("unknown");
      expect(params.get("tag")).toBe("pci");
      expect(params.get("lifecycle")).toBe("cleanup_candidate");
      expect(params.get("sort")).toBe("criticality");
    });
    fireEvent.click(screen.getByRole("button", { name: "Limpiar" }));
    await waitFor(() => expect(queries.at(-1)?.get("role")).toBeNull());
    expect(queries.at(-1)?.get("sort")).toBe("criticality");
  });

  it("filtros de contexto sin resultados muestran un vacío específico", async () => {
    let items = [device("b-db", "10.0.0.6")];
    serveAssets(() => items);
    renderHub("/network/devices");
    await screen.findByText("b-db", { selector: "a" });
    items = [];
    fireEvent.change(screen.getByLabelText("Entorno"), { target: { value: "production" } });
    expect(await screen.findByText("Ningún dispositivo coincide con los filtros de contexto")).toBeInTheDocument();
  });

  it("muestra Inactivo, Candidato a limpieza y Archivado; la fila abre el panel y el panel la ficha", async () => {
    serveAssets(() => [
      device("viejo", "10.0.0.1", { status: "offline", lifecycle_state: "stale" }),
      device("purgable", "10.0.0.2", { status: "offline", lifecycle_state: "cleanup_candidate" }),
      device("retirado", "10.0.0.3", { lifecycle_state: "archived", archived_at: iso(0), archive_reason: "Retirado" }),
      device("vivo", "10.0.0.4", { asset_id: "33333333-3333-3333-3333-333333333333" }),
    ]);
    renderHub("/network/devices");
    const rowOf = async (name: string) => (await screen.findByText(name, { selector: "a" })).closest("tr") as HTMLElement;
    expect(within(await rowOf("viejo")).getByText("Inactivo")).toBeInTheDocument();
    expect(within(await rowOf("purgable")).getByText("Candidato a limpieza")).toBeInTheDocument();
    expect(within(await rowOf("retirado")).getByText("Archivado")).toHaveAttribute("title", "Retirado");
    const vivo = await rowOf("vivo");
    expect(within(vivo).getByText("En línea")).toBeInTheDocument();
    fireEvent.click(within(vivo).getByText("10.0.0.4"));
    const panel = await screen.findByRole("dialog", { name: "Detalle de vivo" });
    expect(currentPath()).toBe("/network/devices");
    fireEvent.click(within(panel).getByRole("link", { name: "Abrir ficha" }));
    expect(currentPath()).toBe("/assets/33333333-3333-3333-3333-333333333333");
  });

  it("CPU, RAM, disco y puertos se añaden con el selector de columnas y se recuerdan", async () => {
    serveAssets(() => [
      device("pc-1", "10.0.0.8", {
        monitoring_method: "agent",
        latest_telemetry: { recorded_at: iso(0), cpu_percent: 42, ram_percent: 61, disk_percent: 77, uptime_seconds: 60 },
        open_ports: [22, 443],
      }),
    ]);
    renderHub("/network/devices");
    const row = () => screen.getByText("pc-1", { selector: "a" }).closest("tr") as HTMLElement;
    await screen.findByText("pc-1", { selector: "a" });
    expect(within(row()).queryByRole("meter", { name: "CPU" })).toBeNull();
    fireEvent.click(screen.getByLabelText("CPU / RAM / Disco"));
    fireEvent.click(screen.getByLabelText("Puertos"));
    expect(within(row()).getByRole("meter", { name: "CPU" })).toHaveAttribute("aria-valuenow", "42");
    expect(within(row()).getByRole("meter", { name: "RAM" })).toHaveAttribute("aria-valuenow", "61");
    expect(within(row()).getByRole("meter", { name: "Disco" })).toHaveAttribute("aria-valuenow", "77");
    expect(row()).toHaveTextContent("443");
    expect(JSON.parse(window.localStorage.getItem("sentra.ui.table.devices.columns") ?? "[]")).toEqual([
      "resources",
      "ports",
    ]);
  });
});

describe("Red › Dispositivos: consola SOC (Fase 7B.3)", () => {
  const ID = "55555555-5555-5555-5555-555555555555";
  const LAPTOP = "66666666-6666-6666-6666-666666666666";

  it("columnas básicas en orden, identidad sin resolver y MAC privada", async () => {
    serveAssets(() => [
      device("movil", "192.168.50.66", {
        asset_id: ID,
        mac_address: "da:a1:19:00:00:66",
        identity_state: "identity_unresolved",
        mac_randomized: true,
      }),
      device("srv", "10.0.0.9", { identity_state: "confirmed", monitoring_method: "agent" }),
    ]);
    renderHub("/network/devices");
    const table = await screen.findByRole("table");
    await within(table).findByText("movil", { selector: "a" });
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent?.replace(/[▲▼]/g, ""))).toEqual([
      "Dispositivo",
      "Identidad",
      "IP",
      "Estado",
      "Riesgo",
      "Última actividad",
      "Acciones",
    ]);
    const movil = within(table).getByText("movil", { selector: "a" }).closest("tr") as HTMLElement;
    expect(within(movil).getByText("Sin resolver")).toBeInTheDocument();
    expect(within(movil).getByText("MAC privada")).toBeInTheDocument();
    const srv = within(table).getByText("srv", { selector: "a" }).closest("tr") as HTMLElement;
    expect(within(srv).getByText("Confirmada")).toBeInTheDocument();
  });

  it("ordena por riesgo en el servidor y la vista compacta se recuerda", async () => {
    const queries = serveAssets(() => [device("a", "10.0.0.1")]);
    renderHub("/network/devices");
    await screen.findByText("a", { selector: "a" });
    fireEvent.click(screen.getByRole("button", { name: /^Riesgo/ }));
    await waitFor(() => {
      expect(queries.at(-1)?.get("sort")).toBe("risk");
      expect(queries.at(-1)?.get("order")).toBe("desc");
    });
    fireEvent.click(screen.getByRole("button", { name: "Compacta" }));
    expect(screen.getByRole("table")).toHaveClass("table--compact");
    expect(window.localStorage.getItem("sentra.ui.table.devices.density")).toBe("compact");
  });

  it("los filtros se restauran al volver sin parámetros y se pueden quitar", async () => {
    const queries = serveAssets(() => []);
    renderHub("/network/devices?status=offline&q=srv");
    await screen.findByText("Ningún dispositivo coincide con el filtro");
    cleanup();
    renderHub("/network/devices");
    await waitFor(() => expect(currentQuery().get("status")).toBe("offline"));
    await waitFor(() => expect(queries.at(-1)?.get("q")).toBe("srv"));
    fireEvent.click(await screen.findByRole("button", { name: "Quitar filtros" }));
    await waitFor(() => expect(currentPath()).toBe("/network/devices"));
    await waitFor(() => expect(window.localStorage.getItem("sentra.ui.table.devices.filters")).toBeNull());
  });

  it("teclado: flechas recorren filas, Enter abre el panel y Escape lo cierra devolviendo el foco", async () => {
    serveAssets(() => [device("uno", "10.0.0.1"), device("dos", "10.0.0.2", { asset_id: ID })]);
    routes[`GET /assets/${ID}/identity/profile`] = () => ({ body: profile() });
    routes[`GET /assets/${ID}/identity/candidates`] = () => ({ body: { items: [] } });
    renderHub("/network/devices");
    const first = (await screen.findByText("uno", { selector: "a" })).closest("tr") as HTMLElement;
    const second = screen.getByText("dos", { selector: "a" }).closest("tr") as HTMLElement;
    first.focus();
    fireEvent.keyDown(first, { key: "ArrowDown" });
    expect(second).toHaveFocus();
    fireEvent.keyDown(second, { key: "Enter" });
    const panel = await screen.findByRole("dialog", { name: "Detalle de dos" });
    expect(await within(panel).findByText("No hay otros registros con evidencias de ser el mismo dispositivo.")).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(second).toHaveFocus();
  });

  function profile(overrides: Record<string, unknown> = {}) {
    const tier = (value: string | null, source: string | null) => ({
      value,
      source,
      state: value ? "probable" : "unresolved",
      reasons: [],
      alternatives: [],
    });
    return {
      asset_id: ID,
      display_name: "dos",
      custom_label: null,
      managed: false,
      archived: false,
      state: "identity_unresolved",
      reasons: ["random_mac"],
      mac: { mac: "da:a1:19:00:00:66", kind: "local", randomized: true, slap_quadrant: "aai", nic_vendor: null },
      name: tier("dos", "mdns"),
      vendor: tier(null, null),
      device_type: tier("mobile", "classification"),
      os: tier(null, null),
      sources: [],
      addresses: [],
      links: [],
      ...overrides,
    };
  }

  it("panel: identidad por niveles y asociación manual con vista previa y motivo (admin)", async () => {
    serveAssets(() => [device("dos", "192.168.50.66", { asset_id: ID, identity_state: "identity_unresolved" })]);
    routes[`GET /assets/${ID}/identity/profile`] = () => ({ body: profile() });
    routes[`GET /assets/${ID}/identity/candidates`] = () => ({
      body: {
        items: [
          {
            asset: {
              asset_id: LAPTOP,
              display_name: "portatil",
              primary_ip: "192.168.50.20",
              mac_address: "00:11:22:33:44:55",
              managed: true,
              archived: false,
              last_seen_at: iso(0),
            },
            strength: "strong",
            evidence: [{ code: "agent_reported_mac", strength: "strong", detail: "da:a1:19:00:00:66" }],
          },
        ],
      },
    });
    const bodies: Record<string, unknown>[] = [];
    routes["POST /identity/links/preview"] = (init) => {
      bodies.push(JSON.parse(String(init.body)));
      return {
        body: {
          kind: "asset_alias",
          target: { asset_id: LAPTOP, display_name: "portatil", primary_ip: "192.168.50.20", mac_address: null, managed: true, archived: false, last_seen_at: null },
          alias: { asset_id: ID, display_name: "dos", primary_ip: "192.168.50.66", mac_address: null, managed: false, archived: false, last_seen_at: null },
          wlan_client_id: null,
          mac: "da:a1:19:00:00:66",
          allowed: true,
          blockers: [],
          evidence: [{ code: "agent_reported_mac", strength: "strong", detail: null }],
          effects: ["map_mac_to_target", "archive_alias", "keep_alias_history"],
        },
      };
    };
    routes["POST /identity/links"] = (init) => {
      bodies.push(JSON.parse(String(init.body)));
      return { status: 201, body: {} };
    };
    renderHub("/network/devices");
    fireEvent.click(await screen.findByRole("button", { name: "Ver detalle de dos" }));
    const panel = await screen.findByRole("dialog", { name: "Detalle de dos" });
    const tiers = await within(panel).findByRole("table");
    expect(within(tiers).getByText("mDNS")).toBeInTheDocument();
    expect(within(panel).getByText(/MAC privada \(aleatoria\)/)).toBeInTheDocument();
    expect(within(panel).getByText("El agente informa esta MAC: da:a1:19:00:00:66")).toBeInTheDocument();

    fireEvent.click(within(panel).getByRole("button", { name: "Asociar como el mismo dispositivo…" }));
    const dialog = await screen.findByRole("dialog", { name: "Asociar registros del mismo dispositivo" });
    expect(await within(dialog).findByText(/El registro alias se archiva/)).toBeInTheDocument();
    // La vista previa no lleva motivo: el motivo solo se envía al confirmar.
    expect(bodies[0]).toEqual({ kind: "asset_alias", target_asset_id: LAPTOP, alias_asset_id: ID });
    const confirm = within(dialog).getByRole("button", { name: "Confirmar asociación" });
    expect(confirm).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Motivo (queda en la auditoría)"), {
      target: { value: "El agente declara esa MAC privada" },
    });
    fireEvent.click(confirm);
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toMatchObject({ confirm: true, reason: "El agente declara esa MAC privada", alias_asset_id: ID });
  });

  it("panel: un analista ve los candidatos pero no puede asociar", async () => {
    serveAssets(() => [device("dos", "192.168.50.66", { asset_id: ID })]);
    routes[`GET /assets/${ID}/identity/profile`] = () => ({ body: profile() });
    routes[`GET /assets/${ID}/identity/candidates`] = () => ({
      body: {
        items: [
          {
            asset: { asset_id: LAPTOP, display_name: "portatil", primary_ip: "10.0.0.1", mac_address: null, managed: true, archived: false, last_seen_at: null },
            strength: "medium",
            evidence: [{ code: "same_device_name", strength: "weak", detail: null }],
          },
        ],
      },
    });
    renderHub("/network/devices", null, "analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Ver detalle de dos" }));
    const panel = await screen.findByRole("dialog", { name: "Detalle de dos" });
    expect(await within(panel).findByText("portatil")).toBeInTheDocument();
    expect(within(panel).queryByRole("button", { name: /Asociar/ })).toBeNull();
  });
});

describe("Red › Identidad y evidencias (Fase 7A.5)", () => {
  const ID = "44444444-4444-4444-4444-444444444444";
  const camera = device("cam-patio", "192.168.50.30", {
    asset_id: ID,
    device_type: "ip_camera",
    classification_confidence: "medium",
    classification_evidence: [
      { source: "mdns_service", value: "_rtsp._tcp, _http._tcp" },
      { source: "web", value: "Hikvision-Webs | Login" },
    ],
  });

  function identityRoutes() {
    routes["GET /dhcp/sources"] = () => ({ body: { items: [] } });
    routes["GET /dhcp/leases"] = () => ({ body: { items: [], total: 0, limit: 100, offset: 0 } });
    routes[`GET /assets/${ID}`] = () => ({ body: camera });
    routes[`GET /assets/${ID}/identity`] = () => ({
      body: {
        asset_id: ID,
        display_name: "cam-patio",
        custom_label: null,
        automatic_name: "cam-patio",
        name_source: "mdns",
        names: [],
        ip: "192.168.50.30",
        mac: "02:00:00:00:00:30",
        mac_randomized: false,
        vendor: null,
        device_type: "ip_camera",
        classification_confidence: "medium",
        leases: [],
        wifi: null,
        unidentified_reasons: [],
      },
    });
    routes[`GET /assets/${ID}/identity/history`] = () => ({ body: { asset_id: ID, next_before_id: null, items: [] } });
  }

  it("con ?asset= muestra la identificación del equipo, sus huellas y la asignación manual (admin)", async () => {
    identityRoutes();
    renderHub(`/network/identity?asset=${ID}`);
    const panel = await screen.findByRole("region", { name: "Identificación de un equipo" });
    expect(await within(panel).findByText("Cámara IP")).toBeInTheDocument();
    expect(within(panel).getByRole("list", { name: "Huellas de servicio" })).toHaveTextContent("_rtsp._tcp");
    expect(within(panel).getByRole("button", { name: "Asignar tipo" })).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: "Abrir la ficha de cam-patio" })).toHaveAttribute(
      "href",
      `/assets/${ID}`,
    );
    // Las fuentes DHCP de la antigua página /dhcp están en la misma pestaña.
    expect(await screen.findByRole("region", { name: "Fuentes DHCP" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Nueva fuente" })).toBeInTheDocument();
  });

  it("viewer: sin asignación manual ni gestión de fuentes", async () => {
    identityRoutes();
    renderHub(`/network/identity?asset=${ID}`, null, "viewer");
    const panel = await screen.findByRole("region", { name: "Identificación de un equipo" });
    expect(await within(panel).findByText("Cámara IP")).toBeInTheDocument();
    expect(within(panel).queryByRole("button", { name: /tipo/ })).toBeNull();
    await screen.findByRole("region", { name: "Fuentes DHCP" });
    expect(screen.queryByRole("button", { name: "Nueva fuente" })).toBeNull();
  });

  it("elegir un equipo lo guarda en la URL", async () => {
    identityRoutes();
    serveAssets(() => [camera]);
    renderHub("/network/identity");
    const select = await screen.findByRole("combobox", { name: "Equipo" });
    await within(select).findByRole("option", { name: /cam-patio/ });
    fireEvent.change(select, { target: { value: ID } });
    expect(currentQuery().get("asset")).toBe(ID);
    expect(await screen.findByRole("link", { name: "Abrir la ficha de cam-patio" })).toBeInTheDocument();
  });

  it("los cambios de identidad mezclan los tipos de identidad por fecha", async () => {
    identityRoutes();
    const asked: string[] = [];
    routes["GET /topology/changes"] = (_init, url) => {
      const type = url.searchParams.get("change_type") ?? "";
      asked.push(type);
      const base = {
        site_id: "00000000-0000-0000-0000-00000000d5f1",
        subject_type: "node",
        asset_id: ID,
        evidence: [],
        source: "discovery",
        confidence: "high",
        status: "detected",
        review_note: null,
        reviewed_by: null,
        reviewed_at: null,
        preserved: false,
        version: 1,
      };
      const items =
        type === "ip_changed"
          ? [{ ...base, id: "c1", change_type: type, subject_key: "k", subject_label: "cam-patio", before: "192.168.50.29", after: "192.168.50.30", detected_at: iso(-60_000) }]
          : type === "name_changed"
            ? [{ ...base, id: "c2", change_type: type, subject_key: "k", subject_label: "cam-patio", before: null, after: "cam-patio", detected_at: iso(-1_000) }]
            : [];
      return { body: { items, total: items.length } };
    };
    renderHub("/network/identity");
    const changes = await screen.findByRole("region", { name: "Cambios de identidad" });
    await within(changes).findByText("Cambio de IP");
    expect(asked.sort()).toEqual(["classification_changed", "ip_changed", "mac_changed", "name_changed", "vendor_changed"]);
    const rows = within(changes).getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("Cambio de nombre");
    expect(rows[1]).toHaveTextContent("192.168.50.29");
  });
});

describe("Red › Telemetría (Fase 7A.5)", () => {
  it("lista los equipos con agente y su último envío", async () => {
    const queries = serveAssets(() => [
      device("pc-1", "10.0.0.8", {
        monitoring_method: "agent",
        latest_telemetry: { recorded_at: iso(0), cpu_percent: 12, ram_percent: 34, disk_percent: 56, uptime_seconds: 7200 },
      }),
      device("pc-2", "10.0.0.9", { monitoring_method: "agent" }),
    ]);
    routes["GET /endpoint/metrics"] = () => ({
      body: {
        window_hours: 24,
        events_last_hour: 120,
        assets_reporting_last_hour: 2,
        ingest_lag_p50_seconds: 1,
        ingest_lag_p95_seconds: 3,
        ingest_lag_max_seconds: 9,
        behavior_detections_24h: 0,
        detection_latency_p50_seconds: null,
        detection_latency_p95_seconds: null,
      },
    });
    renderHub("/network/telemetry");
    const panel = await screen.findByRole("region", { name: "Telemetría de equipos" });
    const row = (await within(panel).findByText("pc-1")).closest("tr") as HTMLElement;
    expect(within(row).getByRole("meter", { name: "CPU" })).toHaveAttribute("aria-valuenow", "12");
    expect(within(within(panel).getByText("pc-2").closest("tr") as HTMLElement).getByText(/Sin telemetría/)).toBeInTheDocument();
    expect(queries[0]?.get("method")).toBe("agent");
    expect(await screen.findByRole("region", { name: "Ingesta de telemetría" })).toHaveTextContent("120 eventos");
  });

  it("sin equipos con agente lo explica y enlaza a Dispositivos", async () => {
    serveAssets(() => []);
    renderHub("/network/telemetry", null, "viewer");
    expect(await screen.findByText("Ningún equipo envía telemetría")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Dispositivos" })).toHaveAttribute("href", "/network/devices");
    // El viewer no tiene telemetry:read: no se pide la métrica de ingesta.
    expect(calls.some((c) => c.path === "/endpoint/metrics")).toBe(false);
  });
});
