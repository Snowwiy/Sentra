// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WithRole } from "../test/auth";
import type {
  Asset,
  DiscoveryJobDetail,
  DiscoverySchedule,
  DiscoveryScope,
  Role,
} from "../api/types";
import { NetworkPage } from "./NetworkPage";

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
  };
}

type Handler = (init: RequestInit) => { status?: number; body: unknown };

let routes: Record<string, Handler>;
let calls: { method: string; path: string; init: RequestInit }[];

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function refused(code: string) {
  return () => ({ status: 403, body: { error: { code, message: "refused" } } });
}

beforeEach(() => {
  calls = [];
  routes = {
    "GET /assets": () => ({ body: { items: [], total: 0 } }),
    "GET /discovery/scope": () => ({ body: SCOPE }),
    "GET /discovery/schedule": () => ({ body: SCHEDULE }),
    "GET /discovery/jobs": () => ({ body: { items: [] } }),
    "GET /console": () => ({
      body: { enrollment_token_ttl_minutes: 15, suggested_server_urls: [], server_url_configured: false },
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

function renderPage(role: Role = "admin") {
  return render(
    <MemoryRouter>
      <WithRole role={role}>
        <NetworkPage />
      </WithRole>
    </MemoryRouter>,
  );
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
    renderPage();
    expect(screen.getByText("Cargando red…")).toBeInTheDocument();
  });

  it("habilita Iniciar descubrimiento con redes autorizadas y consola local", async () => {
    renderPage();
    const button = await startButton();
    await waitFor(() => expect(button).toBeEnabled());
    const scope = screen.getByRole("region", { name: "Redes autorizadas" });
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
    expect(within(auto).getByText(/Completed/)).toBeInTheDocument();
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
    await waitFor(() => expect(within(history).getByText("Completed")).toBeInTheDocument());
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
    routes["GET /assets"] = () => ({ body: { items: [asset("192.168.50.77"), asset("10.9.9.9", null)], total: 2 } });
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
    const table = screen.getByRole("region", { name: "Activos de red" });
    expect(within(table).getByText("192.168.50.77")).toBeInTheDocument();
    expect(within(table).queryByText("10.9.9.9")).not.toBeInTheDocument();
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
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Ver progreso" }));
    await screen.findByText("Descubrimiento en curso");

    found = [asset("192.168.50.77")];
    state = COMPLETED;
    await screen.findByText("Descubrimiento completado", undefined, POLL);
    fireEvent.click(screen.getByRole("button", { name: "Cerrar" }));
    const table = await screen.findByRole("region", { name: "Activos de red" });
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
    await within(history).findByText("Completed");
    const headers = within(history).getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual([
      "Fecha/hora", "Red", "Estado", "Encontrados", "Nuevos", "Actualizados", "Duración", "Perfil", "Origen",
    ]);
    expect(within(history).getByText("Cancelled")).toBeInTheDocument();
    expect(within(history).getByText("Failed")).toBeInTheDocument();
    expect(within(history).getByText("Dashboard")).toBeInTheDocument();
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
  it("presenta nombre, IP, tipo en español, NIC y Managed frente a Discovered", async () => {
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
    renderPage();

    const table = await screen.findByRole("region", { name: "Activos de red" });
    const row = (ip: string) => within(table).getByText(ip, { selector: "td" }).closest("tr") as HTMLElement;
    expect(within(row("192.168.50.141")).getByRole("link", { name: "MNA-LX9" })).toBeInTheDocument();
    expect(within(row("192.168.50.141")).getByText("Móvil")).toBeInTheDocument();
    expect(within(row("192.168.50.141")).getByText("Huawei")).toBeInTheDocument();
    expect(within(row("192.168.50.108")).getByRole("link", { name: "Consola probable" })).toBeInTheDocument();
    expect(within(row("192.168.50.108")).getByText("NIC Realtek")).toBeInTheDocument();
    expect(within(row("192.168.50.66")).getByText("Managed")).toBeInTheDocument();
    expect(within(row("192.168.50.66")).getByText("PC")).toBeInTheDocument();
    expect(within(row("192.168.50.12")).getByRole("link", { name: "Dispositivo desconocido" })).toBeInTheDocument();
    expect(within(row("192.168.50.12")).getByText("Desconocido")).toBeInTheDocument();
  });
});
