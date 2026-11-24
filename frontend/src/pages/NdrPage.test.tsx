// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  NdrAnomalyRead,
  NdrOverview,
  NdrResponsePlan,
  NdrRuleRead,
  NdrSensorRead,
  Role,
} from "../api/types";
import { SiteProvider } from "../site/SiteContext";
import { WithRole } from "../test/auth";
import { DEFAULT_SITE_ID, SITES, installFetch, type Call, type Handler } from "../test/sites";
import { NdrPage } from "./NdrPage";

const ISO = "2026-11-24T08:00:00Z";
const SENSOR_ID = "5e000000-0000-0000-0000-0000000000a1";
const ANOMALY_ID = "a0000000-0000-0000-0000-000000000001";
const ASSET_ID = "a5000000-0000-0000-0000-000000000001";

const OVERVIEW: NdrOverview = {
  window_hours: 24,
  sensors_capable: 1,
  sensors_enabled: 0,
  sensors_capturing: 0,
  sensors_degraded: 0,
  flows: 0,
  bytes: 0,
  packets_seen: 0,
  packets_dropped: 0,
  observations: {},
  transports: [],
  services: [],
  top_talkers: [],
  last_batch_at: null,
};

function ndrSensor(overrides: Partial<NdrSensorRead> = {}): NdrSensorRead {
  return {
    sensor_id: SENSOR_ID,
    name: "sensor-core",
    site_id: DEFAULT_SITE_ID,
    site_name: "Principal",
    status: "online",
    sensor_version: "0.8.0",
    last_seen_at: ISO,
    capable: true,
    capture_state: "not_configured",
    reported_revision: null,
    interfaces: [],
    spool_items: null,
    spool_dropped: null,
    config: null,
    last_batch_at: null,
    packets_24h: 0,
    dropped_24h: 0,
    ...overrides,
  };
}

function anomaly(overrides: Partial<NdrAnomalyRead> = {}): NdrAnomalyRead {
  return {
    anomaly_id: ANOMALY_ID,
    site_id: DEFAULT_SITE_ID,
    site_name: "Principal",
    sensor_id: SENSOR_ID,
    sensor_name: "sensor-core",
    rule_id: "NDR-MITM-001",
    rule_version: 1,
    category: "mitm",
    title: "Suplantación de la puerta de enlace",
    verdict: "probable",
    severity: "high",
    status: "open",
    subject_ip: "10.70.0.1",
    subject_mac: "02:00:00:00:00:66",
    summary: "Otra MAC anuncia la IP de la puerta de enlace.",
    evidence: { previous_macs: ["02:00:00:00:00:01"] },
    occurrences: 3,
    first_seen: ISO,
    last_seen: ISO,
    status_by: null,
    status_at: null,
    status_note: null,
    asset_id: ASSET_ID,
    asset_name: "pc-intruso",
    context: null,
    mitre: { tactic: "TA0006", technique: "T1557", subtechnique: "T1557.002" },
    ...overrides,
  };
}

const RULE: NdrRuleRead = {
  id: "NDR-MITM-001",
  version: 1,
  category: "mitm",
  title: "Suplantación de la puerta de enlace",
  description: "Otra MAC anuncia la IP del router.",
  why: "Es la base de un ataque de intermediario.",
  recommendations: [],
  verdicts: { probable: "La MAC nueva anuncia la puerta de enlace.", confirmed: "Además disputa la IP." },
  mitre: { tactic: "TA0006", technique: "T1557", subtechnique: "T1557.002" },
};

const INCIDENT_ID = "1c000000-0000-0000-0000-000000000001";

const PLAN: NdrResponsePlan = {
  anomaly_id: ANOMALY_ID,
  applied_by_sentra: false,
  note: "Sentra no aplica cambios en la red.",
  incidents: [{ incident_id: INCIDENT_ID, number: 7, title: "Intruso en la VLAN 20", status: "open" }],
  suggestions: [
    {
      suggestion_id: "block_address:203.0.113.66/32",
      kind: "network_control",
      title: "Bloquear el tráfico saliente hacia 203.0.113.66",
      rationale: "IOC malicioso.",
      instructions: ["En el cortafuegos perimetral, denegar la salida."],
      control_type: "block_address",
      target: { cidr: "203.0.113.66/32" },
      direction: "outbound",
      playbook_key: null,
    },
    {
      suggestion_id: "isolate_switch_port",
      kind: "manual",
      title: "Localizar y aislar el puerto del switch",
      rationale: "Sentra no gestiona switches.",
      instructions: ["Buscar la MAC en la tabla del switch."],
      control_type: null,
      target: null,
      direction: null,
      playbook_key: null,
    },
  ],
};

let calls: Call[];
let routes: Record<string, Handler>;

beforeEach(() => {
  window.localStorage.clear();
  routes = {
    "GET /sites": () => ({ body: { items: SITES } }),
    "GET /ndr/overview": () => ({ body: OVERVIEW }),
    "GET /ndr/sensors": () => ({ body: { items: [ndrSensor()] } }),
    "GET /ndr/rules": () => ({ body: { items: [RULE] } }),
    "GET /ndr/anomalies": () => ({ body: { items: [anomaly()], total: 1 } }),
    [`GET /ndr/anomalies/${ANOMALY_ID}`]: () => ({
      body: anomaly({
        context: {
          asset: { asset_id: ASSET_ID, name: "pc-intruso", primary_ip: "10.70.0.66", mac_address: null },
          switch_locations: [
            {
              device_id: "d0000000-0000-0000-0000-000000000001",
              device_name: "core-sw",
              interface: "Gi1/0/7",
              vlan: 20,
              location: "access",
              last_seen: ISO,
            },
          ],
          detections: [
            {
              detection_id: "de000000-0000-0000-0000-000000000001",
              rule_id: "NET-NDR-001",
              severity: "high",
              confidence: "medium",
              status: "open",
            },
          ],
          incidents: [],
        },
      }),
    }),
    [`GET /ndr/anomalies/${ANOMALY_ID}/response-plan`]: () => ({ body: PLAN }),
    "GET /ndr/flows": () => ({ body: { items: [], total: 0 } }),
    "GET /ndr/observations": () => ({ body: { items: [], total: 0 } }),
  };
  calls = installFetch(routes);
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderPage(role: Role, path = "/ndr") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <WithRole role={role}>
        <SiteProvider>
          <NdrPage />
        </SiteProvider>
      </WithRole>
    </MemoryRouter>,
  );
}

describe("NdrPage", () => {
  it("viewer: ve sensores y anomalías, pero ni aprobar captura ni flujos", async () => {
    renderPage("viewer");
    const table = await screen.findByRole("region", { name: "Sensores NDR" });
    expect(within(table).getByText("sensor-core")).toBeInTheDocument();
    expect(within(table).getByText("Sin configurar")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Aprobar captura" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Flujos y metadatos" })).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Anomalías" })).toBeInTheDocument();
  });

  it("admin: aprobar exige punto de observación y confirmación expresa", async () => {
    routes["PUT /ndr/sensors/" + SENSOR_ID + "/config"] = (init) => ({
      body: { ...JSON.parse(String(init.body)), revision: 1, updated_by: "admin", updated_at: ISO },
    });
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Aprobar captura" }));
    const dialog = await screen.findByRole("dialog");
    const save = within(dialog).getByRole("button", { name: "Guardar configuración" });
    fireEvent.change(within(dialog).getByLabelText(/Interfaces/), { target: { value: "lan" } });
    fireEvent.change(within(dialog).getByLabelText(/Punto de observación/), {
      target: { value: "SPAN del switch core" },
    });
    expect(save).toBeDisabled();
    fireEvent.click(within(dialog).getByLabelText(/Confirmo que la captura es pasiva/));
    expect(save).toBeEnabled();
    fireEvent.click(save);
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const put = calls.find((c) => c.method === "PUT")!;
    expect(JSON.parse(String(put.init.body))).toMatchObject({
      enabled: true,
      interfaces: ["lan"],
      observation_point: "SPAN del switch core",
      confirm_passive_authorized: true,
      dns_metadata: false,
      tls_metadata: false,
      expected_revision: 0,
    });
  });

  it("analyst: abre la anomalía con su correlación y cerrar exige nota", async () => {
    routes[`POST /ndr/anomalies/${ANOMALY_ID}/status`] = (init) => ({
      body: anomaly({ status: JSON.parse(String(init.body)).status }),
    });
    renderPage("analyst", "/ndr?tab=anomalies");
    fireEvent.click(await screen.findByRole("button", { name: "NDR-MITM-001" }));
    const panel = await screen.findByRole("region", { name: "Detalle de la anomalía" });
    expect(await within(panel).findByText(/Switch core-sw, puerto Gi1\/0\/7, VLAN 20/)).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: "NET-NDR-001" })).toHaveAttribute(
      "href",
      "/detections/de000000-0000-0000-0000-000000000001",
    );
    expect(within(panel).getByText("TA0006 · T1557.002")).toBeInTheDocument();
    const resolve = within(panel).getByRole("button", { name: "Resolver" });
    expect(resolve).toBeDisabled();
    fireEvent.change(within(panel).getByLabelText(/Nota/), { target: { value: "Router sustituido por IT" } });
    fireEvent.click(within(panel).getByRole("button", { name: "Falso positivo" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    const post = calls.find((c) => c.method === "POST")!;
    expect(JSON.parse(String(post.init.body))).toEqual({
      status: "false_positive",
      note: "Router sustituido por IT",
    });
  });

  it("muestra el catálogo de reglas con su técnica MITRE", async () => {
    renderPage("viewer", "/ndr?tab=rules");
    const rule = await screen.findByRole("article", { name: "NDR-MITM-001" });
    expect(within(rule).getByText(/La MAC nueva anuncia la puerta de enlace/)).toBeInTheDocument();
    expect(within(rule).getByText("TA0006 · T1557.002")).toBeInTheDocument();
  });

  it("analyst: la evidencia consulta flujos y metadatos con el filtro de IP", async () => {
    renderPage("analyst", "/ndr?tab=evidence");
    expect(await screen.findByText("Sin flujos en la retención")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Filtrar evidencia por IP"), { target: { value: "10.70.0.20" } });
    await waitFor(() =>
      expect(calls.some((c) => c.path === "/ndr/flows" && c.url.searchParams.get("ip") === "10.70.0.20")).toBe(true),
    );
    expect(calls.some((c) => c.path === "/ndr/observations" && c.url.searchParams.get("kind") === "dns")).toBe(true);
  });

  it("analyst: el plan de respuesta registra la solicitud en el incidente, sin aplicarla", async () => {
    routes[`POST /ndr/anomalies/${ANOMALY_ID}/network-controls`] = () => ({ status: 201, body: {} });
    renderPage("analyst", `/ndr?tab=anomalies&anomaly=${ANOMALY_ID}`);
    const plan = await screen.findByRole("article", { name: "Bloquear el tráfico saliente hacia 203.0.113.66" });
    expect(screen.getByText("Sentra no aplica cambios en la red.")).toBeInTheDocument();
    // Los pasos manuales se muestran, pero no tienen formulario de solicitud.
    const manual = screen.getByRole("article", { name: "Localizar y aislar el puerto del switch" });
    expect(within(manual).queryByRole("button", { name: "Registrar solicitud" })).not.toBeInTheDocument();
    const submit = within(plan).getByRole("button", { name: "Registrar solicitud" });
    expect(submit).toBeDisabled();
    fireEvent.change(within(plan).getByLabelText(/Justificación/), {
      target: { value: "IOC contactado desde la VLAN 20" },
    });
    fireEvent.click(submit);
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.path).toBe(`/ndr/anomalies/${ANOMALY_ID}/network-controls`);
    expect(JSON.parse(String(post.init.body))).toEqual({
      incident_id: INCIDENT_ID,
      suggestion_id: "block_address:203.0.113.66/32",
      justification: "IOC contactado desde la VLAN 20",
    });
    expect(await within(plan).findByRole("status")).toHaveTextContent(/pendiente de aprobación/);
  });

  it("viewer: ve el plan pero no puede registrar solicitudes", async () => {
    renderPage("viewer", `/ndr?tab=anomalies&anomaly=${ANOMALY_ID}`);
    const plan = await screen.findByRole("article", { name: "Bloquear el tráfico saliente hacia 203.0.113.66" });
    expect(within(plan).queryByRole("button", { name: "Registrar solicitud" })).not.toBeInTheDocument();
  });
});
