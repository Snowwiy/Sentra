// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Asset, DashboardVulnerabilities, SecurityOverview } from "../api/types";
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
    ...overrides,
  };
}

let items: Asset[];
let assetCalls: URL[];
let summaryCalls: number;
// Total del servidor (todas las páginas); por defecto, los items de la página.
let serverTotal: number | undefined;
// Bloque vulnerabilities del resumen (Fase 6C.4); undefined = el rol no lo recibe.
let vulnSummary: DashboardVulnerabilities | undefined;
// Fase 7A.7: respuesta de /dashboard/security-overview; null = el endpoint falla (500).
let overview: SecurityOverview | null;
let overviewCalls: URL[];

function day(offset: number): string {
  const date = new Date(Date.UTC(2026, 9, 1 + offset));
  return date.toISOString();
}

function makeOverview(overrides: Partial<SecurityOverview> = {}): SecurityOverview {
  return {
    generated_at: iso(),
    site_id: null,
    window_days: 30,
    posture: {
      formula_version: 1,
      state: "ok",
      score: 47,
      level: "medium",
      peak_score: 91,
      high_or_critical: 42,
      assets_current: 10000,
      assets_scored: 9000,
      coverage: 0.9,
      method: {
        formula: "Media de AssetRisk.score ponderada por la criticidad del activo",
        population: "Activos actuales con riesgo calculado",
        weights: { low: 1, medium: 2, high: 3, critical: 4 },
        missing_data: "Los activos sin riesgo calculado no cuentan como cero",
        thresholds: { low: 20, medium: 40, high: 60, critical: 80 },
        reference: "docs/security-dashboard.md",
      },
    },
    incidents_by_status: { open: 2, investigating: 1, closed: 4 },
    detections_recent: [
      {
        detection_id: "d1",
        rule_id: "SCR-001",
        title: "Script de PowerShell sospechoso",
        severity: "high",
        status: "open",
        asset_id: "a1",
        asset_name: "pc-01",
        last_seen_at: iso(),
      },
    ],
    risk_history: [0, 1, 2].map((offset) => ({
      day: day(offset),
      assets_scored: 9000,
      average_score: 40 + offset,
      high: 30,
      critical: 12,
    })),
    new_devices: { window_days: 7, count: 0, items: [] },
    exposed_ports: { open_ports: 12, assets_with_open_ports: 4, top: [{ port: 445, protocol: "tcp", assets: 3 }] },
    ...overrides,
  };
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

beforeEach(() => {
  items = [asset("b-db", { criticality: "critical", role: "database" }), asset("a-pc")];
  assetCalls = [];
  summaryCalls = 0;
  serverTotal = undefined;
  vulnSummary = undefined;
  overview = makeOverview();
  overviewCalls = [];
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
          ...(vulnSummary ? { vulnerabilities: vulnSummary } : {}),
        });
      }
      if (path === "/dashboard/security-overview") {
        overviewCalls.push(url);
        if (!overview) return json(500, { error: { code: "internal_error", message: "boom" } });
        return json(200, overview);
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

// Fase 7A.5: la tabla completa de activos se movió a Red › Dispositivos (sus pruebas de
// filtros, paginación y ciclo de vida están en NetworkPage.test.tsx). El Panel resume.
describe("Panel (Fase 7A.5)", () => {
  it("los contadores vienen del resumen del servidor y abren Dispositivos filtrado", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { level: 1, name: "Panel" })).toBeInTheDocument();
    const stats = screen.getByLabelText("Resumen de estado");
    expect(within(stats).getByRole("link", { name: /Total de dispositivos\s*10000/ })).toHaveAttribute(
      "href",
      "/network/devices",
    );
    expect(within(stats).getByRole("link", { name: /Sin conexión\s*2900/ })).toHaveAttribute(
      "href",
      "/network/devices?status=offline",
    );
    expect(within(stats).getByRole("link", { name: /En línea\s*7000/ })).toHaveAttribute(
      "href",
      "/network/devices?status=online",
    );
    expect(screen.getByText(/4000 gestionados con agente/)).toBeInTheDocument();
    expect(screen.getByText(/riesgo crítico 12/)).toBeInTheDocument();
    expect(summaryCalls).toBeGreaterThan(0);
  });

  it("solo pide los dispositivos más recientes y enlaza a la lista completa", async () => {
    renderPage();
    const recent = await screen.findByRole("region", { name: "Dispositivos recientes" });
    expect(await within(recent).findByText("b-db")).toBeInTheDocument();
    expect(within(recent).getByRole("link", { name: "Ver todos los dispositivos" })).toHaveAttribute(
      "href",
      "/network/devices",
    );
    for (const call of assetCalls) {
      expect(call.searchParams.get("limit")).toBe("5");
      expect(call.searchParams.get("sort")).toBe("first_seen");
      expect(call.searchParams.get("order")).toBe("desc");
    }
    // Sin la tabla completa: ni búsqueda ni filtros de contexto en el Panel.
    expect(screen.queryByRole("searchbox")).toBeNull();
    expect(screen.queryByLabelText("Criticidad")).toBeNull();
  });

  it("sin dispositivos lo explica en el bloque de recientes", async () => {
    items = [];
    renderPage();
    const recent = await screen.findByRole("region", { name: "Dispositivos recientes" });
    expect(await within(recent).findByText("No hay dispositivos registrados")).toBeInTheDocument();
  });

  it("si el resumen falla muestra el error con reintento", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => json(500, { error: { code: "internal_error", message: "boom" } })),
    );
    renderPage();
    expect(await screen.findByRole("button", { name: /Reintentar/ })).toBeInTheDocument();
  });
});

describe("DashboardPage: tarjeta de vulnerabilidades (Fase 6C.4)", () => {
  const base: DashboardVulnerabilities = {
    by_severity: {},
    potential: 0,
    assets_affected: 0,
    evaluation_state: "no_vulnerabilities",
    catalog_stale: false,
    assets_evaluated: 8,
    assets_covered: 6,
    assets_pending: 0,
  };

  function renderDashboard() {
    return render(
      <MemoryRouter>
        <WithRole role="viewer">
          <DashboardPage />
        </WithRole>
      </MemoryRouter>,
    );
  }

  it("sin vulnerabilidades solo cuando el catálogo cubre lo evaluado, con cobertura", async () => {
    vulnSummary = base;
    renderDashboard();
    const card = await screen.findByRole("region", { name: "Resumen de vulnerabilidades" });
    expect(within(card).getByText("Sin vulnerabilidades conocidas")).toHaveClass("badge--ok");
    expect(within(card).getByLabelText("Cobertura de la evaluación")).toHaveTextContent(
      "8 activos evaluados · 6 cubiertos por el catálogo · 0 pendientes",
    );
    expect(within(card).queryByText("Catálogo desactualizado")).not.toBeInTheDocument();
  });

  it.each([
    ["no_catalog", "Sin catálogo"],
    ["insufficient_catalog", "Catálogo insuficiente"],
    ["pending", "Evaluación pendiente"],
  ] as const)("%s no se presenta como «sin vulnerabilidades»", async (state, label) => {
    vulnSummary = { ...base, evaluation_state: state, assets_pending: state === "pending" ? 3 : 0 };
    renderDashboard();
    const card = await screen.findByRole("region", { name: "Resumen de vulnerabilidades" });
    expect(within(card).getByText(label)).not.toHaveClass("badge--ok");
    expect(within(card).queryByText("Sin vulnerabilidades conocidas")).not.toBeInTheDocument();
  });

  it("con vulnerabilidades muestra los recuentos y avisa del catálogo desactualizado", async () => {
    vulnSummary = {
      ...base,
      evaluation_state: "vulnerabilities_found",
      by_severity: { critical: 2, high: 5 },
      assets_affected: 3,
      potential: 4,
      catalog_stale: true,
    };
    renderDashboard();
    const card = await screen.findByRole("region", { name: "Resumen de vulnerabilidades" });
    expect(within(card).getByText("Vulnerabilidades encontradas")).toBeInTheDocument();
    expect(card).toHaveTextContent("Críticas 2 · altas 5 · medias 0 · bajas 0 · 3 activos afectados · 4 potenciales sin confirmar");
    expect(within(card).getByText("Catálogo desactualizado")).toBeInTheDocument();
    expect(within(card).getByRole("link", { name: "Ver el estado del catálogo" })).toHaveAttribute(
      "href",
      "/vulnerabilities/catalog",
    );
  });

  it("sin el bloque (rol sin vulnerabilities:read) no hay tarjeta", async () => {
    renderDashboard();
    await screen.findByLabelText("Resumen de la plataforma");
    expect(screen.queryByRole("region", { name: "Resumen de vulnerabilidades" })).not.toBeInTheDocument();
  });
});

describe("Panel: postura y gráficos (Fase 7A.7)", () => {
  it("muestra la postura con su cobertura y cómo se calcula", async () => {
    renderPage();
    const card = await screen.findByRole("region", { name: "Postura de seguridad" });
    expect(within(card).getByLabelText("Puntuación 47 de 100")).toBeInTheDocument();
    expect(within(card).getByText("Medio")).toBeInTheDocument();
    expect(within(card).getByText(/9000 de 10000 activos \(90 %\)/)).toBeInTheDocument();
    expect(within(card).queryByText("Cobertura parcial")).not.toBeInTheDocument();
    expect(within(card).getByText("Cómo se calcula")).toBeInTheDocument();
    expect(card).toHaveTextContent("Crítico 80");
    expect(card).toHaveTextContent("Media de AssetRisk.score ponderada");
  });

  it("sin datos no enseña ninguna puntuación", async () => {
    overview = makeOverview({
      posture: {
        ...makeOverview().posture,
        state: "no_data",
        score: null,
        level: null,
        peak_score: null,
        assets_scored: 0,
        coverage: 0,
      },
      risk_history: [{ day: day(0), assets_scored: 0, average_score: null, high: 0, critical: 0 }],
    });
    renderPage();
    const card = await screen.findByRole("region", { name: "Postura de seguridad" });
    expect(within(card).getByText("Sin datos.")).toBeInTheDocument();
    expect(within(card).queryByLabelText(/Puntuación/)).not.toBeInTheDocument();
    expect(screen.getByText(/Sin historial de riesgo en este periodo/)).toBeInTheDocument();
  });

  it("con cobertura parcial lo marca de forma visible", async () => {
    overview = makeOverview({
      posture: { ...makeOverview().posture, state: "partial", assets_scored: 1000, coverage: 0.1 },
    });
    renderPage();
    const card = await screen.findByRole("region", { name: "Postura de seguridad" });
    expect(within(card).getByText("Cobertura parcial")).toBeInTheDocument();
    expect(within(card).getByRole("note")).toHaveTextContent("Solo 1000 de 10000 activos");
  });

  it("los anillos tienen tabla con valores y porcentajes; el de incidentes depende del permiso", async () => {
    renderPage();
    const detections = await screen.findByRole("figure", { name: "Detecciones activas por severidad" });
    expect(within(detections).getByRole("img")).toHaveAccessibleName(/Alta 5 \(100 %\)/);
    const methods = screen.getByRole("figure", { name: "Gestionados y descubiertos" });
    expect(within(methods).getByRole("row", { name: /Descubierto 6000 60 %/ })).toBeInTheDocument();
    expect(within(methods).getByRole("link", { name: "Gestionado" })).toHaveAttribute(
      "href",
      "/network/devices?method=agent",
    );
    expect(await screen.findByRole("figure", { name: "Incidentes por estado" })).toBeInTheDocument();
    cleanup();
    overview = makeOverview({ incidents_by_status: null });
    renderPage();
    await screen.findByRole("region", { name: "Postura de seguridad" });
    expect(screen.queryByRole("figure", { name: "Incidentes por estado" })).not.toBeInTheDocument();
  });

  it("el selector de periodo vuelve a pedir el historial con days", async () => {
    renderPage();
    await screen.findByRole("figure", { name: "Evolución del riesgo medio" });
    expect(overviewCalls.at(-1)?.searchParams.get("days")).toBe("30");
    fireEvent.click(screen.getByRole("button", { name: "90 días" }));
    await screen.findByRole("button", { name: "90 días", pressed: true });
    await vi.waitFor(() => expect(overviewCalls.at(-1)?.searchParams.get("days")).toBe("90"));
  });

  it("si la vista de seguridad falla, el resto del Panel sigue funcionando", async () => {
    overview = null;
    renderPage();
    expect(await screen.findByText(/No se pudo cargar la postura de seguridad/)).toBeInTheDocument();
    expect(screen.getByLabelText("Resumen de estado")).toBeInTheDocument();
    expect(screen.getByRole("figure", { name: "Distribución del riesgo" })).toBeInTheDocument();
  });

  it("lista detecciones recientes y puertos expuestos", async () => {
    renderPage();
    const recent = await screen.findByRole("region", { name: "Detecciones recientes" });
    expect(within(recent).getByRole("link", { name: "Script de PowerShell sospechoso" })).toHaveAttribute(
      "href",
      "/detections/d1",
    );
    const ports = screen.getByRole("region", { name: "Puertos expuestos" });
    expect(ports).toHaveTextContent("12 puertos abiertos en 4 activos.");
    expect(within(ports).getByText("445/tcp")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Dispositivos nuevos" })).toHaveTextContent("Ningún dispositivo nuevo");
  });
});
