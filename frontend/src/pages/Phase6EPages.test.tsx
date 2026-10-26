// @vitest-environment jsdom
// Fase 6E: fuentes DHCP (desde la Fase 7A.5 dentro de Red), excepciones de reglas, aislamiento en vivo e investigaciones, y
// las pestañas nuevas del activo, con el control de permisos de cada rol. Datos sintéticos.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DetectionExclusion, DhcpSource, Role } from "../api/types";
import { DhcpPanels } from "../components/dhcp/DhcpPanels";
import { WithRole } from "../test/auth";
import { asset, ASSET_ID, isolationOverview, isolationSession } from "../test/phase6e";
import { installFetch, type Call, type Handler } from "../test/sites";
import { AssetDetailPage } from "./AssetDetailPage";
import { ContainmentPage } from "./ContainmentPage";
import { DetectionExclusionsPage } from "./DetectionExclusionsPage";
import { InvestigationsPage } from "./InvestigationsPage";

const ISO = "2026-10-22T10:00:00Z";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderAt(path: string, route: string, element: ReactNode, role: Role) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <WithRole role={role}>
        <Routes>
          <Route path={route} element={element} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

function dhcpSource(overrides: Partial<DhcpSource> = {}): DhcpSource {
  return {
    id: "d1000000-0000-4000-8000-000000000001",
    site: { id: "00000000-0000-0000-0000-00000000d5f1", name: "Principal" },
    name: "router-casa",
    kind: "lease_import",
    format: "dnsmasq",
    sensor_id: null,
    sensor_name: null,
    sensor_source_name: null,
    poll_interval_minutes: 0,
    status: "ok",
    last_requested_at: null,
    last_import_at: ISO,
    last_error_code: null,
    last_stats: null,
    lease_count: 12,
    created_by: "admin",
    created_at: ISO,
    updated_at: ISO,
    version: 4,
    ...overrides,
  };
}

// Fase 7A.5: las fuentes y concesiones DHCP viven en Red › Identidad y evidencias.
describe("DHCP (Red › Identidad y evidencias)", () => {
  function setup(): Call[] {
    return installFetch({
      "GET /dhcp/sources": () => ({ body: { items: [dhcpSource()] } }),
      "GET /dhcp/leases": () => ({
        body: {
          total: 1,
          limit: 100,
          offset: 0,
          items: [
            {
              source_id: "d1000000-0000-4000-8000-000000000001",
              source_name: "router-casa",
              ip: "192.168.50.23",
              mac: "aa:bb:cc:dd:ee:ff",
              mac_randomized: false,
              hostname: "pixel-7",
              hostname_usable: true,
              state: "active",
              starts_at: null,
              ends_at: ISO,
              match: "mac_ip",
              asset_id: ASSET_ID,
              asset_name: "pixel-7",
              first_seen_at: ISO,
              last_seen_at: ISO,
            },
          ],
        },
      }),
      "POST /dhcp/sources/d1000000-0000-4000-8000-000000000001/import": (init) => ({
        body: {
          source: dhcpSource(),
          lines: 3,
          parsed: 2,
          skipped: 1,
          truncated: false,
          matched: 2,
          named: 1,
          ambiguous: 0,
          echo: JSON.parse(String(init.body)),
        },
      }),
    });
  }

  it("viewer: ve fuentes y concesiones, sin acciones de gestión", async () => {
    setup();
    renderAt("/network/identity", "/network/identity", <DhcpPanels />, "viewer");
    expect(await screen.findByText("router-casa", { selector: "td" })).toBeInTheDocument();
    expect(await screen.findByText("pixel-7", { selector: "td" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Nueva fuente" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Importar fichero" })).toBeNull();
  });

  it("admin: importa el texto de un fichero con la versión de la fuente", async () => {
    const calls = setup();
    renderAt("/network/identity", "/network/identity", <DhcpPanels />, "admin");
    expect(await screen.findByRole("button", { name: "Nueva fuente" })).toBeInTheDocument();
    await screen.findByRole("button", { name: "Importar fichero" });
    const input = screen.getByLabelText("Fichero de concesiones") as HTMLInputElement;
    fireEvent.click(screen.getByRole("button", { name: "Importar fichero" }));
    const file = new File(["1700000000 aa:bb:cc:dd:ee:ff 192.168.50.23 pixel-7 *\n"], "dnsmasq.leases", { type: "text/plain" });
    fireEvent.change(input, { target: { files: [file] } });
    expect(await screen.findByText(/Importadas 2 concesiones de 3 registros/)).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST");
    expect(JSON.parse(String(post?.init.body))).toEqual({
      content: "1700000000 aa:bb:cc:dd:ee:ff 192.168.50.23 pixel-7 *\n",
      version: 4,
    });
  });
});

function exclusion(overrides: Partial<DetectionExclusion> = {}): DetectionExclusion {
  return {
    id: "e1000000-0000-4000-8000-000000000001",
    rule_id: "BEH-001",
    asset_id: null,
    asset_name: null,
    field: "exe",
    value: "C:\\Tools\\backup.exe",
    reason: "Herramienta de copia legítima",
    created_by: "admin",
    created_at: ISO,
    expires_at: null,
    revoked_at: null,
    revoked_by: null,
    active: true,
    hits: 3,
    last_hit_at: ISO,
    require_sha256: null,
    port: null,
    ...overrides,
  };
}

describe("DetectionExclusionsPage", () => {
  const routes = (): Record<string, Handler> => ({
    "GET /detection-exclusions": () => ({ body: { items: [exclusion()] } }),
    "POST /detection-exclusions/e1000000-0000-4000-8000-000000000001/revoke": () => ({
      body: exclusion({ active: false, revoked_at: ISO, revoked_by: "admin" }),
    }),
    "GET /endpoint/metrics": () => ({
      body: {
        window_hours: 24,
        events_last_hour: 120,
        assets_reporting_last_hour: 3,
        ingest_lag_p50_seconds: 1.2,
        ingest_lag_p95_seconds: 4.5,
        ingest_lag_max_seconds: 9,
        behavior_detections_24h: 2,
        detection_latency_p50_seconds: 30,
        detection_latency_p95_seconds: null,
      },
    }),
  });

  it("viewer (rules:read): ve las excepciones, sin crear ni revocar ni métricas de telemetría", async () => {
    const calls = installFetch(routes());
    renderAt("/detections/exclusions", "/detections/exclusions", <DetectionExclusionsPage />, "viewer");
    expect(await screen.findByText("BEH-001")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Nueva excepción" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Revocar" })).toBeNull();
    expect(calls.some((c) => c.path === "/endpoint/metrics")).toBe(false);
  });

  it("admin: revoca con confirmación y ve la latencia medida (sin medida no es 0)", async () => {
    const calls = installFetch(routes());
    renderAt("/detections/exclusions", "/detections/exclusions", <DetectionExclusionsPage />, "admin");
    const metrics = await screen.findByRole("region", { name: "Detección conductual" });
    expect(within(metrics).getByText("30.0 s / sin medida")).toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Revocar" }));
    const dialog = screen.getByRole("dialog", { name: "Revocar excepción" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Revocar" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/revoke"))).toBe(true));
  });
});

describe("ContainmentPage", () => {
  it("lista las sesiones vivas con enlace a la pestaña Aislamiento del equipo", async () => {
    installFetch({ "GET /isolation/sessions": () => ({ body: { items: [isolationSession()], total: 1 } }) });
    renderAt("/containment", "/containment", <ContainmentPage />, "analyst");
    const link = await screen.findByRole("link", { name: "pc-ana" });
    expect(link).toHaveAttribute("href", `/assets/${ASSET_ID}?tab=isolation`);
    expect(screen.getByText("Aislado")).toBeInTheDocument();
  });
});

describe("InvestigationsPage", () => {
  it("lista investigaciones abiertas y marca las que tienen evidencias sin verificar", async () => {
    const calls = installFetch({
      "GET /investigations": () => ({
        body: {
          total: 1,
          items: [
            {
              id: "1a000000-0000-4000-8000-000000000001",
              asset_id: ASSET_ID,
              asset_label: "pc-ana",
              asset_exists: true,
              incident_id: null,
              title: "Conexiones sospechosas",
              status: "open",
              legal_hold: true,
              created_by: "ana",
              created_at: ISO,
              updated_at: ISO,
              closed_at: null,
              closed_by: null,
              version: 1,
              artifact_count: 4,
              mismatch_count: 1,
            },
          ],
        },
      }),
    });
    renderAt("/investigations", "/investigations", <InvestigationsPage />, "analyst");
    expect(await screen.findByRole("link", { name: "Conexiones sospechosas" })).toBeInTheDocument();
    expect(screen.getByText("1 sin verificar")).toBeInTheDocument();
    expect(screen.getByText("retención legal")).toBeInTheDocument();
    expect(calls[0]?.url.searchParams.get("status")).toBe("open");
  });
});

describe("AssetDetailPage: pestañas de la Fase 6E", () => {
  function setup() {
    return installFetch({
      [`GET /assets/${ASSET_ID}`]: () => ({ body: asset() }),
      [`GET /assets/${ASSET_ID}/isolation`]: () => ({
        body: isolationOverview({
          available: false,
          unavailable_message: "Aislamiento no disponible para este dispositivo",
          reasons: [{ code: "no_agent", message: "El dispositivo no tiene agente de Sentra." }],
          manual_recommendations: ["Desconecta el puerto del switch."],
        }),
      }),
      [`GET /assets/${ASSET_ID}/isolation/sessions`]: () => ({ body: { items: [], total: 0 } }),
    });
  }

  const tabs = () => screen.getAllByRole("tab").map((t) => t.textContent);

  it("viewer: Identidad sí; Investigaciones y Aislamiento no", async () => {
    setup();
    renderAt(`/assets/${ASSET_ID}`, "/assets/:assetId", <AssetDetailPage />, "viewer");
    await screen.findByRole("tablist", { name: "Secciones del activo" });
    expect(tabs()).toContain("Identidad");
    expect(tabs()).not.toContain("Investigaciones");
    expect(tabs()).not.toContain("Aislamiento");
  });

  it("analyst en un equipo sin agente: Aislamiento muestra el texto fijo y las recomendaciones", async () => {
    setup();
    renderAt(`/assets/${ASSET_ID}?tab=isolation`, "/assets/:assetId", <AssetDetailPage />, "analyst");
    await screen.findByRole("tablist", { name: "Secciones del activo" });
    expect(tabs()).toEqual(expect.arrayContaining(["Identidad", "Investigaciones", "Aislamiento"]));
    expect(await screen.findByRole("heading", { name: "Aislamiento no disponible para este dispositivo" })).toBeInTheDocument();
    expect(screen.getByText("Desconecta el puerto del switch.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Aislar/ })).toBeNull();
  });
});
