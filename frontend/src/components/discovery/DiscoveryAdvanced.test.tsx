// @vitest-environment jsdom
// Fase 6A: perfiles avanzados, límites (discovery:tune), capacidad del sensor, observaciones
// del job y vista de observaciones de red.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  DiscoveryJob,
  DiscoveryJobDetail,
  DiscoveryLimits,
  DiscoveryProfileCatalog,
  DiscoveryScope,
  Observation,
} from "../../api/types";
import { SiteProvider } from "../../site/SiteContext";
import { BRANCH_SITE_ID, SITES, installFetch, sensor, type Call, type Handler } from "../../test/sites";
import { DiscoveryModal } from "./DiscoveryModal";
import { JobsPanel } from "./DiscoveryPanels";
import { NetworkObservations } from "./NetworkObservations";

const NET = "192.168.50.0/24";
const JOB_ID = "11111111-1111-1111-1111-111111111111";
const POLL = { timeout: 5000 };

const SCOPE: DiscoveryScope = {
  enabled: true,
  allowed_networks: [NET],
  networks: [{ network: NET, hosts: 254 }],
  max_hosts_per_network: 1024,
  excluded: [],
  ports: [22, 80],
  interval_minutes: null,
  icmp: true,
  reverse_dns: true,
  timeout_ms: 500,
  concurrency: 32,
  max_probes_per_second: 100,
};

const CAPS: DiscoveryLimits = {
  timeout_ms: 800,
  dns_timeout_ms: 5000,
  concurrency: 64,
  max_probes_per_second: 200,
  tcp_retries: 2,
  max_hosts: 1024,
  max_ports: 256,
  deadline_minutes: 30,
  max_dns_queries: 4096,
};

function limits(overrides: Partial<DiscoveryLimits> = {}): DiscoveryLimits {
  return {
    timeout_ms: 500,
    dns_timeout_ms: 1000,
    concurrency: 32,
    max_probes_per_second: 100,
    tcp_retries: 0,
    max_hosts: 1024,
    max_ports: 16,
    deadline_minutes: 10,
    max_dns_queries: 0,
    ...overrides,
  };
}

function catalog(overrides: Partial<DiscoveryProfileCatalog> = {}): DiscoveryProfileCatalog {
  return {
    default_profile: "standard",
    can_tune: false,
    caps: CAPS,
    profiles: [
      {
        name: "quick",
        label: "Quick",
        description: "Pocos puertos, sin DNS.",
        ports: [22, 80, 443, 445, 3389],
        icmp: true,
        tcp: true,
        arp: true,
        reverse_dns: false,
        forward_dns: false,
        limits: limits(),
      },
      {
        name: "standard",
        label: "Standard",
        description: "Puertos comunes y DNS inverso.",
        ports: [22, 80, 443],
        icmp: true,
        tcp: true,
        arp: true,
        reverse_dns: true,
        forward_dns: false,
        limits: limits({ concurrency: 48, deadline_minutes: 20 }),
      },
      {
        name: "deep",
        label: "Deep",
        description: "Más puertos y DNS directo.",
        ports: [21, 22, 80, 443, 8080],
        icmp: true,
        tcp: true,
        arp: true,
        reverse_dns: true,
        forward_dns: true,
        limits: limits({ max_hosts: 128 }),
      },
    ],
    ...overrides,
  };
}

function job(overrides: Partial<DiscoveryJobDetail> = {}): DiscoveryJobDetail {
  return {
    job_id: JOB_ID,
    target: NET,
    trigger: "manual",
    status: "running",
    baseline: false,
    started_at: new Date(Date.now() - 10_000).toISOString(),
    completed_at: null,
    duration_seconds: null,
    hosts_scanned: 40,
    hosts_alive: 5,
    hosts_new: 0,
    open_ports: 0,
    probes: 100,
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
    parameters: { profile: "standard", ports: [22, 80, 443], icmp: true, reverse_dns: true },
    site_id: "00000000-0000-0000-0000-00000000d5f1",
    site_name: "Principal",
    execution_target: "local",
    sensor_id: null,
    sensor_name: null,
    profile: "standard",
    job_type: "discovery_advanced",
    observations_total: 0,
    hosts_unresponsive: 0,
    new_assets: [],
    changes: [],
    ...overrides,
  };
}

function observation(overrides: Partial<Observation> = {}): Observation {
  return {
    observation_id: crypto.randomUUID(),
    job_id: JOB_ID,
    site_id: "00000000-0000-0000-0000-00000000d5f1",
    site_name: "Principal",
    executor: "sensor",
    sensor_id: "5e000000-0000-0000-0000-00000000000a",
    sensor_name: "sensor-norte",
    asset_id: null,
    address: "192.168.50.20",
    mac: "aa:bb:cc:00:00:20",
    hostname: "printer.local",
    reverse_dns: "printer.local",
    forward_dns_match: true,
    open_ports: [22, 80],
    port_hints: [{ port: 22, hint: "ssh", state: "inferred" }],
    methods: ["icmp", "tcp"],
    reachability: "responded",
    rtt_ms: 3,
    confidence: "high",
    evidence: [
      { field: "reachability", value: "responded", method: "icmp", state: "observed" },
      { field: "service", value: "ssh", method: "tcp", state: "inferred" },
    ],
    changes: [{ kind: "port_new", previous: null, current: "443", state: "inferred" }],
    profile: "standard",
    observed_at: new Date().toISOString(),
    ...overrides,
  };
}

let routes: Record<string, Handler>;
let calls: Call[];
let posted: unknown;

beforeEach(() => {
  posted = undefined;
  window.localStorage.clear();
  routes = {
    "GET /discovery/profiles": () => ({ body: catalog() }),
    "POST /console/discovery/jobs": (init) => {
      posted = JSON.parse(String(init.body));
      return { status: 202, body: job({ status: "queued" }) };
    },
    [`GET /discovery/jobs/${JOB_ID}`]: () => ({ body: job() }),
    "GET /discovery/observations": () => ({ body: { items: [], total: 0, limit: 50, offset: 0 } }),
  };
  calls = installFetch(routes);
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderModal(props: { canAdminister?: boolean; initialJobId?: string; sites?: boolean } = {}) {
  const modal = (
    <DiscoveryModal
      scope={SCOPE}
      activeJobs={[]}
      initialJobId={props.initialJobId}
      canAdminister={props.canAdminister ?? true}
      adminReason={props.canAdminister === false ? "Sin permiso" : undefined}
      onClose={() => undefined}
      onShowDevices={() => undefined}
      onChanged={() => undefined}
    />
  );
  return render(<MemoryRouter>{props.sites ? <SiteProvider>{modal}</SiteProvider> : modal}</MemoryRouter>);
}

async function openForm() {
  renderModal();
  const dialog = screen.getByRole("dialog", { name: "Iniciar descubrimiento" });
  // El perfil por defecto del servidor queda elegido en cuanto llega el catálogo.
  await waitFor(() => expect(within(dialog).getByLabelText(/^Standard/)).toBeChecked());
  return dialog;
}

const start = (dialog: HTMLElement) => within(dialog).getByRole("button", { name: "Iniciar" });

describe("DiscoveryModal: perfiles", () => {
  it("elige el perfil por defecto con su descripción, puertos y límites efectivos en solo lectura", async () => {
    const dialog = await openForm();
    expect(within(dialog).getByLabelText(/^Básico/)).not.toBeChecked();
    expect(within(dialog).getByText(/Puertos comunes y DNS inverso/)).toBeInTheDocument();
    const group = within(dialog).getByRole("group", { name: "Parámetros del perfil Standard" });
    for (const port of ["22", "80", "443"]) expect(within(group).getByLabelText(port)).toBeChecked();
    // Sin discovery:tune: límites visibles pero no editables.
    expect(within(group).getByText("Concurrencia").nextElementSibling).toHaveTextContent("48 sondas");
    expect(within(dialog).queryByRole("group", { name: "Límites" })).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("spinbutton")).not.toBeInTheDocument();
    expect(within(dialog).queryByLabelText(/Puertos adicionales/)).not.toBeInTheDocument();

    fireEvent.click(start(dialog));
    await waitFor(() => expect(posted).toEqual({ target: NET, profile: "standard" }));
  });

  it("Básico mantiene la petición de siempre; Quick con un subconjunto de puertos los envía", async () => {
    const dialog = await openForm();
    fireEvent.click(within(dialog).getByLabelText(/^Básico/));
    expect(within(dialog).queryByRole("group", { name: /Parámetros del perfil/ })).not.toBeInTheDocument();
    fireEvent.click(start(dialog));
    await waitFor(() => expect(posted).toEqual({ target: NET }));
  });

  it("Quick con un subconjunto de puertos solo envía esos puertos", async () => {
    const dialog = await openForm();
    fireEvent.click(within(dialog).getByLabelText(/^Quick/));
    const group = within(dialog).getByRole("group", { name: "Parámetros del perfil Quick" });
    fireEvent.click(within(group).getByLabelText("445"));
    fireEvent.click(within(group).getByLabelText("3389"));
    fireEvent.click(start(dialog));
    await waitFor(() => expect(posted).toEqual({ target: NET, profile: "quick", ports: [22, 80, 443] }));
  });

  it("sin ningún puerto elegido no deja iniciar", async () => {
    const dialog = await openForm();
    const group = within(dialog).getByRole("group", { name: "Parámetros del perfil Standard" });
    for (const port of ["22", "80", "443"]) fireEvent.click(within(group).getByLabelText(port));
    expect(within(dialog).getByText("Elige al menos un puerto.")).toBeInTheDocument();
    expect(start(dialog)).toBeDisabled();
  });

  it("avisa y bloquea si la red supera el máximo de hosts del perfil", async () => {
    const dialog = await openForm();
    fireEvent.click(within(dialog).getByLabelText(/^Deep/));
    expect(within(dialog).getByText(/254 direcciones y el perfil admite como máximo 128 hosts/)).toBeInTheDocument();
    expect(start(dialog)).toBeDisabled();
  });

  it("sin catálogo de perfiles (servidor anterior) solo ofrece Básico", async () => {
    routes["GET /discovery/profiles"] = () => ({ status: 404, body: { error: { code: "not_found", message: "no" } } });
    renderModal();
    const dialog = screen.getByRole("dialog", { name: "Iniciar descubrimiento" });
    expect(await within(dialog).findByText(/no ofrece perfiles avanzados/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Básico/)).toBeChecked();
    expect(within(dialog).queryByLabelText(/^Quick/)).not.toBeInTheDocument();
    fireEvent.click(start(dialog));
    await waitFor(() => expect(posted).toEqual({ target: NET }));
  });

  it("sin permiso para lanzar el botón Iniciar queda deshabilitado", async () => {
    renderModal({ canAdminister: false });
    const dialog = screen.getByRole("dialog", { name: "Iniciar descubrimiento" });
    await waitFor(() => expect(within(dialog).getByLabelText(/^Standard/)).toBeChecked());
    expect(start(dialog)).toBeDisabled();
    expect(within(dialog).getByText("Sin permiso")).toBeInTheDocument();
  });
});

describe("DiscoveryModal: límites con discovery:tune", () => {
  beforeEach(() => {
    routes["GET /discovery/profiles"] = () => ({ body: catalog({ can_tune: true }) });
  });

  it("muestra los límites editables con sus topes y envía solo lo cambiado", async () => {
    const dialog = await openForm();
    const group = within(dialog).getByRole("group", { name: "Límites" });
    const concurrency = within(group).getByLabelText(/Concurrencia/);
    expect(concurrency).toHaveValue(48);
    expect(within(group).getAllByText(/Tope del servidor/)).toHaveLength(7);
    fireEvent.change(concurrency, { target: { value: "16" } });
    fireEvent.change(within(dialog).getByLabelText(/Puertos adicionales/), { target: { value: "8080, 22" } });
    fireEvent.click(start(dialog));
    await waitFor(() =>
      expect(posted).toEqual({ target: NET, profile: "standard", ports: [22, 80, 443, 8080], limits: { concurrency: 16 } }),
    );
  });

  it("valida en cliente contra los topes y no deja iniciar", async () => {
    const dialog = await openForm();
    const group = within(dialog).getByRole("group", { name: "Límites" });
    const concurrency = within(group).getByLabelText(/Concurrencia/);
    fireEvent.change(concurrency, { target: { value: "65" } });
    expect(within(group).getByText("Máximo 64 (tope del servidor).")).toBeInTheDocument();
    expect(concurrency).toHaveAttribute("aria-invalid", "true");
    expect(start(dialog)).toBeDisabled();

    fireEvent.change(concurrency, { target: { value: "16" } });
    fireEvent.change(within(dialog).getByLabelText(/Puertos adicionales/), { target: { value: "99999" } });
    expect(within(dialog).getByText("99999 está fuera de 1–65535.")).toBeInTheDocument();
    expect(start(dialog)).toBeDisabled();
  });
});

describe("DiscoveryModal: errores del servidor por código", () => {
  it.each([
    ["discovery_tune_forbidden", 403, undefined, /requiere discovery:tune/],
    ["discovery_limit_exceeded", 422, [{ field: "concurrency", max: 64 }], /Concurrencia \(máx\. 64\)/],
    ["discovery_scope_too_large", 422, undefined, /más direcciones que el máximo de hosts/],
    ["discovery_options_require_profile", 422, undefined, /solo se pueden fijar con un perfil avanzado/],
    ["sensor_not_available", 409, undefined, /sin soporte para el perfil avanzado/],
  ])("%s", async (code, status, details, message) => {
    routes["POST /console/discovery/jobs"] = () => ({ status, body: { error: { code, message: "x", details } } });
    const dialog = await openForm();
    fireEvent.click(start(dialog));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(message);
  });
});

describe("DiscoveryModal: sensor y capacidad avanzada", () => {
  const BASIC = sensor({ sensor_id: "5e000000-0000-0000-0000-00000000000a", name: "sensor-viejo" });
  const ADVANCED = sensor({
    sensor_id: "5e000000-0000-0000-0000-00000000000b",
    name: "sensor-nuevo",
    capabilities: ["discovery_basic", "network.discovery.advanced"],
  });

  beforeEach(() => {
    routes["GET /sites"] = () => ({ body: { items: SITES } });
    routes["GET /sensors"] = () => ({
      body: { items: [BASIC, ADVANCED], summary: { total: 2, pending: 0, online: 2, offline: 0, stale: 0, disabled: 0, revoked: 0 } },
    });
    routes[`GET /sites/${BRANCH_SITE_ID}/networks`] = () => ({
      body: {
        items: [{ network_id: "n1", site_id: BRANCH_SITE_ID, cidr: "10.20.0.0/24", name: null, enabled: true, host_count: 254, created_at: "", updated_at: "" }],
      },
    });
  });

  it("un sensor sin network.discovery.advanced solo admite Básico; uno con ella, perfiles", async () => {
    renderModal({ sites: true });
    const dialog = screen.getByRole("dialog", { name: "Iniciar descubrimiento" });
    fireEvent.change(await within(dialog).findByLabelText("Site"), { target: { value: BRANCH_SITE_ID } });
    const sensorSelect = await within(dialog).findByLabelText("Sensor");
    expect(sensorSelect).toHaveValue(BASIC.sensor_id);

    expect(await within(dialog).findByText(/sensor-viejo no declara la capacidad network\.discovery\.advanced/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Quick/)).toBeDisabled();
    expect(within(dialog).getByLabelText(/^Standard/)).toBeDisabled();
    expect(within(dialog).getByLabelText(/^Básico/)).toBeChecked();

    fireEvent.change(sensorSelect, { target: { value: ADVANCED.sensor_id } });
    await waitFor(() => expect(within(dialog).getByLabelText(/^Standard/)).toBeChecked());
    expect(within(dialog).queryByText(/no declara la capacidad/)).not.toBeInTheDocument();
    fireEvent.click(await within(dialog).findByRole("button", { name: "Iniciar" }));
    await waitFor(() =>
      expect(posted).toEqual({
        target: "10.20.0.0/24",
        site_id: BRANCH_SITE_ID,
        execution_target: "sensor",
        sensor_id: ADVANCED.sensor_id,
        profile: "standard",
      }),
    );
  });
});

describe("DiscoveryJobView: jobs avanzados", () => {
  it("en curso: perfil, progreso real y observaciones vacías mientras avanza", async () => {
    renderModal({ initialJobId: JOB_ID });
    const dialog = screen.getByRole("dialog", { name: "Descubrimiento de red" });
    await within(dialog).findByText("Descubrimiento en curso");
    expect(within(dialog).getByText("Standard")).toBeInTheDocument();
    expect(within(dialog).getByText("(Avanzado)")).toBeInTheDocument();
    expect(within(dialog).getByRole("progressbar")).toHaveAttribute("aria-valuenow", "40");
    expect(await within(dialog).findByText(/aparecen a medida que el scan avanza/)).toBeInTheDocument();
    const obs = calls.find((c) => c.path === "/discovery/observations");
    expect(obs?.url.searchParams.get("job_id")).toBe(JOB_ID);
    expect(obs?.url.searchParams.get("limit")).toBe("50");
  });

  it("terminado: tabla con evidencia, pistas, RTT, cambios, fuente y paginación en el servidor", async () => {
    routes[`GET /discovery/jobs/${JOB_ID}`] = () => ({
      body: job({
        status: "completed",
        progress: null,
        completed_at: new Date().toISOString(),
        duration_seconds: 65,
        hosts_scanned: 254,
        observations_total: 120,
        hosts_unresponsive: 3,
        execution_target: "sensor",
        sensor_name: "sensor-norte",
      }),
    });
    routes["GET /discovery/observations"] = (_init, url) => {
      const offset = Number(url.searchParams.get("offset") ?? 0);
      const items =
        offset === 0
          ? [observation(), observation({ address: "192.168.50.30", rtt_ms: null, reachability: "no_response", hostname: null, reverse_dns: null, mac: null, port_hints: [], changes: [], evidence: [] })]
          : [observation({ address: "192.168.50.99" })];
      return { body: { items, total: 120, limit: 50, offset } };
    };
    renderModal({ initialJobId: JOB_ID });
    const dialog = screen.getByRole("dialog", { name: "Descubrimiento de red" });
    const result = await within(dialog).findByRole("region", { name: "Resultado del descubrimiento" });
    expect(within(result).getByText("Observaciones").nextElementSibling).toHaveTextContent("120");
    expect(within(result).getByText("Sin respuesta").nextElementSibling).toHaveTextContent("3");
    expect(within(result).getByText("Duración").nextElementSibling).toHaveTextContent("01:05");

    const section = within(dialog).getByRole("region", { name: "Observaciones del descubrimiento" });
    const row = (await within(section).findByText("192.168.50.20")).closest("tr") as HTMLElement;
    expect(within(row).getByText("printer.local")).toBeInTheDocument();
    expect(within(row).getByText("aa:bb:cc:00:00:20")).toBeInTheDocument();
    expect(within(row).getByText("ICMP, TCP")).toBeInTheDocument();
    expect(within(row).getByText("Respondió")).toBeInTheDocument();
    expect(within(row).getByText("3 ms")).toBeInTheDocument();
    expect(within(row).getByText("Alta")).toBeInTheDocument();
    expect(within(row).getByText("Sensor sensor-norte")).toBeInTheDocument();
    // Una pista de puerto nunca es un servicio confirmado.
    expect(within(row).getByText("22: ssh? (pista)")).toHaveAttribute("title", expect.stringMatching(/no es un servicio confirmado/));
    expect(within(row).getByText(/puerto nuevo/)).toHaveTextContent("(inferido)");

    const second = within(section).getByText("192.168.50.30").closest("tr") as HTMLElement;
    // RTT no medido: nunca un 0 inventado.
    expect(within(second).getByTitle("No medido")).toHaveTextContent("—");
    expect(within(second).getByText("Sin respuesta")).toBeInTheDocument();

    const toggle = within(row).getByRole("button", { name: "2 evidencias" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const evidence = within(section).getByRole("list", { name: "Evidencia de 192.168.50.20" });
    expect(within(evidence).getByText("observado")).toBeInTheDocument();
    expect(within(evidence).getByText("inferido")).toBeInTheDocument();

    expect(within(section).getByText(/120 observaciones · página 1 de 3/)).toBeInTheDocument();
    fireEvent.click(within(section).getByRole("button", { name: "Siguiente" }));
    expect(await within(section).findByText("192.168.50.99")).toBeInTheDocument();
    expect(calls.filter((c) => c.path === "/discovery/observations").at(-1)?.url.searchParams.get("offset")).toBe("50");
  });

  it("resultado parcial: errores parciales en un completado y aviso en un cancelado", async () => {
    let state = job({
      status: "completed",
      progress: null,
      completed_at: new Date().toISOString(),
      duration_seconds: 5,
      error_count: 2,
      errors: ["timeout 10.0.0.1", "timeout 10.0.0.2"],
    });
    routes[`GET /discovery/jobs/${JOB_ID}`] = () => ({ body: state });
    renderModal({ initialJobId: JOB_ID });
    const dialog = screen.getByRole("dialog", { name: "Descubrimiento de red" });
    expect(await within(dialog).findByText(/Completado con 2 errores parciales/)).toBeInTheDocument();
    expect(within(dialog).getByText("Errores (2)")).toBeInTheDocument();
    expect(await within(dialog).findByText("Este descubrimiento no registró observaciones.")).toBeInTheDocument();
    cleanup();

    state = job({ status: "cancelled", stop_reason: "operator", progress: null, completed_at: new Date().toISOString(), duration_seconds: 5, hosts_unresponsive: 7 });
    renderModal({ initialJobId: JOB_ID });
    const again = screen.getByRole("dialog", { name: "Descubrimiento de red" });
    expect(await within(again).findByText(/Resultado parcial/)).toBeInTheDocument();
    // Un scan incompleto no afirma que nadie dejara de responder.
    const result = within(again).getByRole("region", { name: "Resultado del descubrimiento" });
    expect(within(result).getByText("Sin respuesta").nextElementSibling).toHaveTextContent("—");
  });

  it("cancelar un job avanzado en curso", async () => {
    let state = job();
    routes[`GET /discovery/jobs/${JOB_ID}`] = () => ({ body: state });
    routes[`POST /console/discovery/jobs/${JOB_ID}/cancel`] = () => {
      state = { ...state, cancel_requested: true };
      return { body: state };
    };
    renderModal({ initialJobId: JOB_ID });
    fireEvent.click(await screen.findByRole("button", { name: "Cancelar" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Cancelando…" })).toBeDisabled());
    expect(screen.getByText(/Cancelación solicitada/)).toBeInTheDocument();
    state = { ...state, status: "cancelled", stop_reason: "operator", progress: null, completed_at: new Date().toISOString(), duration_seconds: 9 };
    expect(await screen.findByText("Descubrimiento cancelado", undefined, POLL)).toBeInTheDocument();
  }, 10_000);

  it("los jobs básicos no consultan observaciones", async () => {
    routes[`GET /discovery/jobs/${JOB_ID}`] = () => ({
      body: job({ profile: null, job_type: "discovery_basic", status: "completed", progress: null, completed_at: new Date().toISOString(), duration_seconds: 3 }),
    });
    renderModal({ initialJobId: JOB_ID });
    await screen.findByText("Descubrimiento completado");
    expect(screen.getByText("Básico")).toBeInTheDocument();
    expect(calls.some((c) => c.path === "/discovery/observations")).toBe(false);
  });
});

describe("Historial: columna de perfil", () => {
  it("muestra el perfil de cada ejecución (los anteriores, Básico)", () => {
    const older: DiscoveryJob = { ...job({ job_id: "a", status: "completed" }), profile: undefined, job_type: undefined };
    render(
      <JobsPanel
        jobs={[job({ status: "completed", profile: "deep" }), older]}
        loading={false}
        error={undefined}
        onOpen={() => undefined}
      />,
    );
    const history = screen.getByRole("region", { name: "Ejecuciones recientes" });
    expect(within(history).getByText("Deep")).toBeInTheDocument();
    expect(within(history).getByText("Básico")).toBeInTheDocument();
  });
});

describe("NetworkObservations: vista de red", () => {
  function renderView(scopeId?: string) {
    return render(
      <MemoryRouter>
        <SiteProvider>
          <NetworkObservations scopeId={scopeId} allowedNetworks={[NET]} />
        </SiteProvider>
      </MemoryRouter>,
    );
  }

  const lastQuery = () => calls.filter((c) => c.path === "/discovery/observations").at(-1)?.url.searchParams;

  beforeEach(() => {
    routes["GET /sites"] = () => ({ body: { items: SITES } });
    routes["GET /sensors"] = () => ({
      body: {
        items: [sensor({ sensor_id: "5e000000-0000-0000-0000-00000000000a", name: "sensor-norte" })],
        summary: { total: 1, pending: 0, online: 1, offline: 0, stale: 0, disabled: 0, revoked: 0 },
      },
    });
    routes[`GET /sites/${BRANCH_SITE_ID}/networks`] = () => ({
      body: {
        items: [{ network_id: "n1", site_id: BRANCH_SITE_ID, cidr: "10.20.0.0/24", name: null, enabled: true, host_count: 254, created_at: "", updated_at: "" }],
      },
    });
  });

  it("empty state sin observaciones y consulta latest=true paginada", async () => {
    renderView();
    expect(await screen.findByText("Sin observaciones")).toBeInTheDocument();
    expect(lastQuery()?.get("latest")).toBe("true");
    expect(lastQuery()?.get("limit")).toBe("50");
  });

  it("columnas de la última observación por IP", async () => {
    routes["GET /discovery/observations"] = () => ({ body: { items: [observation({ asset_id: "22222222-2222-2222-2222-222222222222" })], total: 1, limit: 50, offset: 0 } });
    renderView();
    const panel = await screen.findByRole("region", { name: "Observaciones de red" });
    const link = await within(panel).findByRole("link", { name: "192.168.50.20" });
    expect(within(panel).getAllByRole("columnheader").map((h) => h.textContent)).toEqual([
      "IP", "Hostname", "MAC", "Site", "Fuente", "Alcance", "Puertos", "Última vez", "Confianza",
    ]);
    const row = link.closest("tr") as HTMLElement;
    expect(within(row).getByText("Principal")).toBeInTheDocument();
    expect(within(row).getByText("Sensor sensor-norte")).toBeInTheDocument();
    expect(within(row).getByText("22: ssh? (pista)")).toBeInTheDocument();
  });

  it("filtros de Site, Red, Sensor, método, alcance y búsqueda van al servidor", async () => {
    routes["GET /discovery/observations"] = () => ({ body: { items: [observation()], total: 1, limit: 50, offset: 0 } });
    renderView();
    const panel = await screen.findByRole("region", { name: "Observaciones de red" });
    await within(panel).findByText("192.168.50.20");

    fireEvent.change(await within(panel).findByLabelText("Site"), { target: { value: BRANCH_SITE_ID } });
    await waitFor(() => expect(lastQuery()?.get("site_id")).toBe(BRANCH_SITE_ID));
    // La red del site se suma a las autorizadas del servidor local.
    const network = (await within(panel).findByLabelText("Red")) as HTMLSelectElement;
    await waitFor(() => expect(Array.from(network.options).map((o) => o.value)).toEqual(["", NET, "10.20.0.0/24"]));
    fireEvent.change(network, { target: { value: "10.20.0.0/24" } });
    await waitFor(() => expect(lastQuery()?.get("network")).toBe("10.20.0.0/24"));

    const sensorFilter = within(panel).getByLabelText("Sensor");
    await waitFor(() => expect(within(sensorFilter).getByText("sensor-norte")).toBeInTheDocument());
    fireEvent.change(sensorFilter, { target: { value: "5e000000-0000-0000-0000-00000000000a" } });
    await waitFor(() => expect(lastQuery()?.get("sensor_id")).toBe("5e000000-0000-0000-0000-00000000000a"));
    fireEvent.change(sensorFilter, { target: { value: "local" } });
    await waitFor(() => expect(lastQuery()?.get("executor")).toBe("local"));
    expect(lastQuery()?.get("sensor_id")).toBeNull();

    fireEvent.change(within(panel).getByLabelText("Método"), { target: { value: "arp" } });
    await waitFor(() => expect(lastQuery()?.get("method")).toBe("arp"));
    fireEvent.change(within(panel).getByLabelText("Alcance"), { target: { value: "no_response" } });
    await waitFor(() => expect(lastQuery()?.get("reachability")).toBe("no_response"));
    fireEvent.change(within(panel).getByLabelText("Buscar observaciones"), { target: { value: "printer" } });
    await waitFor(() => expect(lastQuery()?.get("q")).toBe("printer"));
    expect(lastQuery()?.get("latest")).toBe("true");
  });

  it("con un site como alcance global no ofrece el filtro Site y lo fija en la consulta", async () => {
    renderView(BRANCH_SITE_ID);
    await screen.findByText("Sin observaciones");
    expect(screen.queryByLabelText("Site")).not.toBeInTheDocument();
    expect(lastQuery()?.get("site_id")).toBe(BRANCH_SITE_ID);
  });

  it("sin coincidencias y filtro rechazado por el servidor", async () => {
    let invalid = false;
    routes["GET /discovery/observations"] = (_init, url) =>
      invalid
        ? { status: 422, body: { error: { code: "discovery_filter_invalid", message: "network no válido" } } }
        : url.searchParams.get("method")
          ? { body: { items: [], total: 0, limit: 50, offset: 0 } }
          : { body: { items: [observation()], total: 1, limit: 50, offset: 0 } };
    renderView();
    const panel = await screen.findByRole("region", { name: "Observaciones de red" });
    await within(panel).findByText("192.168.50.20");
    fireEvent.change(within(panel).getByLabelText("Método"), { target: { value: "dns" } });
    expect(await within(panel).findByText("Ninguna observación coincide con el filtro")).toBeInTheDocument();
    invalid = true;
    fireEvent.change(within(panel).getByLabelText("Alcance"), { target: { value: "unknown" } });
    expect(await within(panel).findByText(/El servidor rechazó el filtro: network no válido/)).toBeInTheDocument();
  });
});
