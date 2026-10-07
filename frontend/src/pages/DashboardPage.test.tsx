// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Asset } from "../api/types";
import { WithRole } from "../test/auth";
import { DashboardPage } from "./DashboardPage";

// Datos sintéticos de test: no proceden de ningún host real.
const iso = () => new Date().toISOString();

function asset(name: string, overrides: Partial<Asset> = {}): Asset {
  return {
    asset_id: crypto.randomUUID(),
    display_name: name,
    monitoring_method: "agent",
    hostname: name,
    os_name: null,
    os_version: null,
    architecture: null,
    primary_ip: "10.0.0.5",
    agent_version: null,
    status: "online",
    agent_status: null,
    network_status: null,
    first_seen_at: iso(),
    last_seen_at: iso(),
    created_at: iso(),
    updated_at: iso(),
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
    discovery_sources: [],
    discovery_network: null,
    discovered_at: null,
    last_network_seen_at: null,
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
    managed_history: false,
    event_coverage: null,
    event_coverage_at: null,
    ...overrides,
  };
}

let items: Asset[];
let assetCalls: URL[];
let summaryCalls: number;
// Total del servidor (todas las páginas); por defecto, los items de la página.
let serverTotal: number | undefined;

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

beforeEach(() => {
  items = [asset("b-db", { criticality: "critical", role: "database" }), asset("a-pc")];
  assetCalls = [];
  summaryCalls = 0;
  serverTotal = undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string) => {
      const url = new URL(input, "http://localhost");
      const path = url.pathname.replace("/api/v1", "");
      if (path === "/assets") {
        assetCalls.push(url);
        return json(200, {
          items,
          total: serverTotal ?? items.length,
          limit: Number(url.searchParams.get("limit")),
          offset: Number(url.searchParams.get("offset") ?? 0),
          status_counts: { online: 7000, offline: 2900, unknown: 100 },
        });
      }
      if (path === "/dashboard/summary") {
        summaryCalls += 1;
        return json(200, {
          generated_at: iso(),
          assets: {
            total: 10000,
            online: 7000,
            offline: 2900,
            unknown: 100,
            by_method: { discovered: 6000, agentless: 0, agent: 4000 },
            by_device_type: { unknown: 10000 },
          },
          risk: { by_level: { critical: 12, high: 30 }, unscored: 0 },
          incidents: { active: 3, critical: 1, unassigned: 2 },
          detections: { active: 5, by_severity: { high: 5 } },
          active_alerts: 4,
        });
      }
      if (path === "/alerts" || path === "/events") return json(200, { items: [], total: 0 });
      return json(404, { error: { code: "not_found", message: path } });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderPage() {
  return render(
    <MemoryRouter>
      <WithRole role="viewer">
        <DashboardPage />
      </WithRole>
    </MemoryRouter>,
  );
}

describe("DashboardPage · contexto", () => {
  it("lista compacta: criticidad no por defecto y rol conocido", async () => {
    renderPage();
    const row = (await screen.findByText("b-db")).closest("tr")!;
    expect(within(row).getByText("Base de datos")).toBeInTheDocument();
    expect(within(row).getByText(/Crítica/)).toBeInTheDocument();
    // Criticidad por defecto (media) y rol desconocido no añaden ruido a la fila.
    const other = screen.getByText("a-pc").closest("tr")!;
    expect(within(other).queryByText(/Media/)).toBeNull();
  });

  it("los filtros de contexto se envían al backend y se pueden limpiar", async () => {
    renderPage();
    await screen.findByText("b-db");
    fireEvent.change(screen.getByLabelText("Criticidad"), { target: { value: "critical" } });
    fireEvent.change(screen.getByLabelText("Rol"), { target: { value: "database" } });
    fireEvent.change(screen.getByLabelText("Internet"), { target: { value: "unknown" } });
    fireEvent.change(screen.getByLabelText("Tag"), { target: { value: "pci" } });
    fireEvent.change(screen.getByLabelText("Orden"), { target: { value: "criticality" } });
    await waitFor(() => {
      const params = assetCalls.at(-1)!.searchParams;
      expect(params.get("criticality")).toBe("critical");
      expect(params.get("role")).toBe("database");
      expect(params.get("internet_exposed")).toBe("unknown");
      expect(params.get("tag")).toBe("pci");
      expect(params.get("sort")).toBe("criticality");
    });
    // Con orden por criticidad se respeta el orden del servidor (no se reordena por nombre).
    const names = screen.getAllByRole("row").map((r) => r.textContent ?? "");
    expect(names.findIndex((t) => t.includes("b-db"))).toBeLessThan(names.findIndex((t) => t.includes("a-pc")));
    fireEvent.click(screen.getByRole("button", { name: "Limpiar" }));
    await waitFor(() => expect(assetCalls.at(-1)!.searchParams.get("role")).toBeNull());
  });

  it("filtros sin resultados muestran un vacío específico", async () => {
    renderPage();
    await screen.findByText("b-db");
    items = [];
    fireEvent.change(screen.getByLabelText("Entorno"), { target: { value: "production" } });
    expect(await screen.findByText("Ningún activo coincide con los filtros de contexto")).toBeInTheDocument();
  });
});

describe("DashboardPage · paginación en servidor (Fase 4M)", () => {
  it("nunca descarga todos los activos: siempre pide una página con limit", async () => {
    renderPage();
    await screen.findByText("b-db");
    for (const call of assetCalls) {
      expect(call.searchParams.get("limit")).toBe("50");
      // offset 0 no se envía (es el valor por defecto del servidor).
      expect(call.searchParams.get("offset")).toBeNull();
    }
  });

  it("los contadores vienen del servidor, no de la página descargada", async () => {
    renderPage();
    await screen.findByText("b-db");
    const stats = screen.getByLabelText("Resumen de estado");
    expect(within(stats).getByText("10000")).toBeInTheDocument();
    expect(within(stats).getByText("2900")).toBeInTheDocument();
    expect(await screen.findByText(/4000 gestionados con agente/)).toBeInTheDocument();
    expect(screen.getByText(/riesgo crítico 12/)).toBeInTheDocument();
    expect(summaryCalls).toBeGreaterThan(0);
  });

  it("estado y búsqueda se filtran en el servidor y vuelven a la página 1", async () => {
    serverTotal = 120;
    renderPage();
    await screen.findByText("b-db");
    fireEvent.click(screen.getByRole("button", { name: "Siguiente" }));
    await waitFor(() => expect(assetCalls.at(-1)!.searchParams.get("offset")).toBe("50"));
    fireEvent.click(screen.getByRole("button", { name: /Offline/ }));
    await waitFor(() => {
      const params = assetCalls.at(-1)!.searchParams;
      expect(params.get("status")).toBe("offline");
      expect(params.get("offset")).toBeNull();
    });
    fireEvent.change(screen.getByLabelText("Buscar activos"), { target: { value: "srv" } });
    await waitFor(() => expect(assetCalls.at(-1)!.searchParams.get("q")).toBe("srv"));
    expect(screen.getByText(/página 1 de 3/)).toBeInTheDocument();
  });
});
