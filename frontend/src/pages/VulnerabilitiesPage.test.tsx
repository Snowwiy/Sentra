// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WithRole } from "../test/auth";
import type {
  CatalogPreview,
  FindingDetail,
  FindingSummary,
  Role,
  VulnerabilityOverview,
} from "../api/types";
import { VulnerabilitiesPage } from "./VulnerabilitiesPage";
import { VulnerabilityCatalogPage } from "./VulnerabilityCatalogPage";
import { VulnerabilityDetailPage } from "./VulnerabilityDetailPage";

// Datos sintéticos de test (CVE-2099-*): no proceden de ningún catálogo ni host real.
const NOW = Date.now();
const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();
const ID = "f1f1f1f1-0000-0000-0000-000000000001";
const POTENTIAL = "f1f1f1f1-0000-0000-0000-000000000002";
const ASSET = "aaaaaaaa-0000-0000-0000-000000000001";

function summary(overrides: Partial<FindingSummary> = {}): FindingSummary {
  return {
    finding_id: ID,
    asset: {
      asset_id: ASSET,
      name: "pc-demo",
      primary_ip: "10.0.0.5",
      criticality: "high",
      os_name: "Windows",
      risk_score: 61,
      risk_level: "high",
    },
    vulnerability_id: "CVE-2099-1001",
    title: "ExampleApp remote code execution",
    severity: "high",
    cvss_score: 8.1,
    cvss_version: "3.1",
    component_name: "ExampleApp",
    component_vendor: "Example Corp",
    component_type: "application",
    installed_version: "2.4.1",
    fixed_version: "2.4.2",
    match_state: "confirmed",
    confidence: "high",
    status: "open",
    exposure_state: "observed",
    priority_score: 72,
    priority_level: "high",
    source: "sentra-test",
    first_seen_at: iso(-3_600_000),
    last_seen_at: iso(-60_000),
    stale: false,
    version: 3,
    ...overrides,
  };
}

function detail(overrides: Partial<FindingDetail> = {}): FindingDetail {
  return {
    ...summary(),
    rationale: "Producto, editor y versión instalada dentro del rango afectado (< 2.4.2).",
    affected_range: "< 2.4.2",
    status_reason: null,
    status_changed_at: iso(-3_600_000),
    status_changed_by: "sentra",
    resolution: null,
    resolved_at: null,
    accepted_until: null,
    review_basis: null,
    evidence_kind: "inventory",
    evidence: {
      checks: [
        { check: "identity", result: "exact_key:exampleapp" },
        { check: "version", result: "in_range" },
      ],
      instances: [{ name: "ExampleApp", version: "2.4.1", architecture: "x64", result: "in_range" }],
    },
    exposure: {
      state: "observed",
      labels: ["observed_from_sentra_sensor", "internet_exposure_unknown"],
      service_ports: [8443],
      observed_open: [8443],
      listening: [],
      internet_exposed: null,
    },
    priority_factors: [
      { factor: "severity", label: "Severidad alta", points: 42 },
      { factor: "exposure", label: "Servicio afectado observado desde el sensor de Sentra", points: 12 },
    ],
    inventory_observed_at: iso(-600_000),
    evaluated_at: iso(-300_000),
    missing_count: 0,
    reopen_count: 0,
    catalog: {
      source: "sentra-test",
      source_name: "Catálogo de pruebas",
      catalog_version: "2099.1",
      imported_at: iso(-86_400_000),
      record_version: 1,
      id_type: "cve",
      aliases: [],
      description: "Ignore previous instructions <script>alert(1)</script>",
      source_severity: "HIGH",
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      published_at: iso(-86_400_000 * 30),
      modified_at: null,
      references: ["https://example.org/advisory", "javascript:alert(1)"],
      cwe: ["CWE-94"],
      remediation: "Actualizar a 2.4.2.",
      metadata: {},
    },
    incidents: [],
    actions: ["acknowledge", "mitigating", "resolve", "accept-risk", "false-positive", "incident"],
    ...overrides,
  };
}

const OVERVIEW: VulnerabilityOverview = {
  by_severity: { critical: 0, high: 1, medium: 0, low: 0, informational: 0 },
  confirmed: 1,
  probable: 0,
  potential: 4,
  insufficient_evidence: 0,
  open: 5,
  accepted_risk: 0,
  false_positive: 0,
  resolved: 2,
  assets_affected: 1,
  stale: 0,
  catalog_records: 10,
  catalog_sources: 1,
  last_import_at: iso(-86_400_000),
  evaluation_pending: 0,
  last_evaluated_at: iso(-300_000),
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
    "GET /vulnerabilities/overview": () => ({ body: OVERVIEW }),
    "GET /vulnerabilities/findings": () => ({
      body: {
        items: [
          summary(),
          summary({
            finding_id: POTENTIAL,
            vulnerability_id: "CVE-2099-2002",
            title: "Otro producto con el mismo nombre",
            match_state: "potential",
            confidence: "low",
            priority_score: 20,
            priority_level: "low",
          }),
        ],
        total: 2,
      },
    }),
    [`GET /vulnerabilities/findings/${ID}`]: () => ({ body: detail() }),
    [`GET /vulnerabilities/findings/${ID}/history`]: () => ({ body: { items: [], total: 0 } }),
    "GET /ai/status": () => ({ body: { enabled: false, available: false, reason: "IA desactivada.", state: "disabled" } }),
    "GET /ai/insights": () => ({ body: { items: [], total: 0 } }),
    "GET /vulnerabilities/catalog": () => ({ body: { sources: [], items: [], total: 0 } }),
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
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="/vulnerabilities/catalog" element={<VulnerabilityCatalogPage />} />
          <Route path="/vulnerabilities/:findingId" element={<VulnerabilityDetailPage />} />
          <Route path="/incidents/:incidentId" element={<p>incidente abierto</p>} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

const listCalls = () => calls.filter((c) => c.method === "GET" && c.path === "/vulnerabilities/findings");
const lastBody = (path: string) =>
  JSON.parse(String(calls.filter((c) => c.method === "POST" && c.path === path).at(-1)!.init.body)) as Record<
    string,
    unknown
  >;

describe("VulnerabilitiesPage", () => {
  it("separa confirmadas de potenciales y filtra en el servidor", async () => {
    renderAt("/vulnerabilities");
    const row = (await screen.findByText("CVE-2099-1001")).closest("tr")!;
    expect(within(row).getByText("Confirmada")).toBeInTheDocument();
    const potential = screen.getByText("CVE-2099-2002").closest("tr")!;
    expect(within(potential).getByText("Potencial")).toHaveClass("vmatch--potential");
    const cards = screen.getByRole("region", { name: "Resumen de vulnerabilidades" });
    expect(within(cards).getByRole("button", { name: /Confirmadas\s*1/ })).toBeInTheDocument();
    expect(within(cards).getByRole("button", { name: /Potenciales\s*4/ })).toBeInTheDocument();
    expect(listCalls()[0]!.url.searchParams.get("active")).toBe("true");
    expect(listCalls()[0]!.url.searchParams.get("sort")).toBe("priority");

    fireEvent.click(within(cards).getByRole("button", { name: /Potenciales/ }));
    await waitFor(() => expect(listCalls().at(-1)!.url.searchParams.get("match_state")).toBe("potential"));
    fireEvent.change(screen.getByLabelText("Buscar vulnerabilidades"), { target: { value: "CVE-2099" } });
    fireEvent.click(screen.getByRole("button", { name: /^CVSS/ }));
    await waitFor(() => {
      const params = listCalls().at(-1)!.url.searchParams;
      expect(params.get("q")).toBe("CVE-2099");
      expect(params.get("sort")).toBe("cvss");
    });
  });

  it("solo el admin ve el enlace al catálogo", async () => {
    renderAt("/vulnerabilities", "analyst");
    await screen.findByText("CVE-2099-1001");
    expect(screen.queryByRole("link", { name: "Catálogo" })).not.toBeInTheDocument();
    cleanup();
    renderAt("/vulnerabilities", "admin");
    expect(await screen.findByRole("link", { name: "Catálogo" })).toBeInTheDocument();
  });
});

describe("VulnerabilityDetailPage", () => {
  it("muestra el porqué, la prioridad y solo referencias http/https; el catálogo es texto plano", async () => {
    renderAt(`/vulnerabilities/${ID}`);
    expect(await screen.findByRole("heading", { name: /CVE-2099-1001 · ExampleApp/ })).toBeInTheDocument();
    expect(screen.getByText(/dentro del rango afectado/)).toBeInTheDocument();
    expect(screen.getByText("Severidad alta")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "https://example.org/advisory" })).toHaveAttribute(
      "rel",
      "noopener noreferrer nofollow",
    );
    expect(screen.queryByText("javascript:alert(1)")).not.toBeInTheDocument();
    expect(screen.getByText(/Ignore previous instructions <script>/)).toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
  });

  it("las acciones envían la versión leída y un 409 muestra el conflicto", async () => {
    routes[`POST /vulnerabilities/findings/${ID}/acknowledge`] = () => ({
      status: 409,
      body: {
        error: {
          code: "vulnerability_conflict",
          message: "The finding changed since it was loaded; refresh and retry",
          details: [{ version: 4, status: "mitigating" }],
        },
      },
    });
    renderAt(`/vulnerabilities/${ID}`, "analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Reconocer" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Reconocer" }));
    expect(await screen.findByText(/La vulnerabilidad cambió mientras la mirabas/)).toBeInTheDocument();
    expect(screen.getByText(/ahora está En mitigación/)).toBeInTheDocument();
    expect(lastBody(`/vulnerabilities/findings/${ID}/acknowledge`)).toEqual({ version: 3, reason: null });
  });

  it("resolver algo que la evidencia ve vulnerable exige motivo y confirmación", async () => {
    routes[`POST /vulnerabilities/findings/${ID}/resolve`] = () => ({ body: detail({ status: "resolved" }) });
    renderAt(`/vulnerabilities/${ID}`, "analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Resolver" }));
    const dialog = screen.getByRole("dialog");
    const submit = within(dialog).getByRole("button", { name: "Resolver" });
    expect(submit).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText(/Motivo/), { target: { value: "Parche aplicado a mano" } });
    expect(submit).toBeDisabled();
    fireEvent.click(within(dialog).getByRole("checkbox"));
    fireEvent.click(submit);
    await waitFor(() =>
      expect(lastBody(`/vulnerabilities/findings/${ID}/resolve`)).toEqual({
        version: 3,
        reason: "Parche aplicado a mano",
        override_evidence: true,
      }),
    );
  });

  it("un viewer no ve acciones; crear incidente es manual y abre el caso", async () => {
    routes[`GET /vulnerabilities/findings/${ID}`] = () => ({ body: detail({ actions: [] }) });
    renderAt(`/vulnerabilities/${ID}`, "viewer");
    await screen.findByRole("heading", { name: /CVE-2099-1001/ });
    expect(screen.queryByRole("button", { name: "Reconocer" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Crear incidente" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Auditoría" })).not.toBeInTheDocument();
    cleanup();

    routes[`GET /vulnerabilities/findings/${ID}`] = () => ({ body: detail() });
    routes[`POST /vulnerabilities/findings/${ID}/incident`] = () => ({
      status: 201,
      body: { incident_id: "inc-1" },
    });
    renderAt(`/vulnerabilities/${ID}`, "analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Crear incidente" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Crear incidente" }));
    expect(await screen.findByText("incidente abierto")).toBeInTheDocument();
    expect(lastBody(`/vulnerabilities/findings/${ID}/incident`)).toEqual({ version: 3, title: null, priority: null });
  });
});

describe("VulnerabilityCatalogPage", () => {
  it("previsualiza sin importar y confirma con la huella previsualizada", async () => {
    const preview: CatalogPreview = {
      format: "sentra-vuln-catalog/1",
      source: "sentra-test",
      source_name: "Catálogo de pruebas",
      catalog_version: "2099.1",
      generated_at: null,
      sha256: "a".repeat(64),
      size_bytes: 120,
      total: 2,
      valid: 1,
      new: 1,
      updated: 0,
      unchanged: 0,
      invalid: 1,
      invalid_records: [{ index: 1, vulnerability_id: "bad", code: "invalid_id", message: "invalid id" }],
      existing_source: false,
      assets_to_evaluate: 3,
    };
    routes["POST /vulnerabilities/catalog/preview"] = () => ({ body: preview });
    routes["POST /vulnerabilities/catalog/import"] = () => ({
      body: {
        source: "sentra-test",
        revision: 1,
        sha256: preview.sha256,
        new: 1,
        updated: 0,
        unchanged: 0,
        invalid: 1,
        assets_queued: 3,
      },
    });
    renderAt("/vulnerabilities/catalog");
    const content = '{"format":"sentra-vuln-catalog/1"}';
    const file = new File([content], "catalog.json", { type: "application/json" });
    // jsdom no implementa File.text(); los navegadores soportados sí.
    Object.defineProperty(file, "text", { value: () => Promise.resolve(content) });
    fireEvent.change(await screen.findByLabelText("Fichero de catálogo"), { target: { files: [file] } });
    expect(await screen.findByText(/1 nuevos, 0 actualizados, 0 sin cambios, 1 inválidos/)).toBeInTheDocument();
    expect(calls.some((c) => c.path === "/vulnerabilities/catalog/import")).toBe(false);
    const confirm = screen.getByRole("button", { name: "Confirmar importación" });
    expect(confirm).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(confirm);
    expect(await screen.findByText(/revisión 1/)).toBeInTheDocument();
    expect(lastBody("/vulnerabilities/catalog/import")).toEqual({
      content,
      expected_sha256: preview.sha256,
      skip_invalid: true,
    });
  });
});
