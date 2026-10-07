// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WithRole } from "../test/auth";
import type {
  FindingThreatIntel,
  Role,
  ThreatIntelOverview,
  ThreatMatchDetail,
  ThreatSource,
} from "../api/types";
import { FindingIntelPanel } from "../components/threatintel/FindingIntelPanel";
import { ThreatIntelPage } from "./ThreatIntelPage";
import { ThreatMatchDetailPage } from "./ThreatMatchDetailPage";

// Datos sintéticos (CVE-2099-*, IPs de documentación 203.0.113.0/24): nada real.
const NOW = Date.now();
const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();
const MATCH = "bbbbbbbb-0000-0000-0000-000000000001";
const INDICATOR = "cccccccc-0000-0000-0000-000000000001";
const ASSET = "aaaaaaaa-0000-0000-0000-000000000001";
const FINDING = "f1f1f1f1-0000-0000-0000-000000000001";

const EMPTY_OVERVIEW: ThreatIntelOverview = {
  status: "none_configured",
  sources_total: 3,
  sources_enabled: 1,
  sources_stale: 0,
  sources_failing: 0,
  sync_enabled: false,
  detection_policy: "high_confidence_malicious",
  last_success_at: null,
  kev_findings: 0,
  kev_assets: 0,
  high_epss_findings: 0,
  indicators_total: 0,
  indicators_active: 0,
  active_matches: 0,
  malicious_matches: 0,
  matched_assets: 0,
  recent_changes: [],
};

function source(overrides: Partial<ThreatSource> = {}): ThreatSource {
  return {
    id: 1,
    source_key: "cisa-kev",
    name: "CISA Known Exploited Vulnerabilities",
    description: null,
    provider: "cisa_kev",
    provider_title: "CISA KEV",
    category: "exploitation",
    trust: "official",
    enabled: false,
    archived: false,
    network_required: true,
    capabilities: ["vulnerability_intel"],
    sync_interval_hours: 24,
    stale_after_hours: 120,
    status: "never",
    state: "disabled",
    last_attempt_at: null,
    last_success_at: null,
    last_error: null,
    last_error_message: null,
    record_count: 0,
    next_sync_at: null,
    sync_requested_at: null,
    download_host: "www.cisa.gov",
    reference_url: null,
    revision: 0,
    created_at: iso(-86_400_000),
    updated_at: iso(-86_400_000),
    ...overrides,
  };
}

function match(overrides: Partial<ThreatMatchDetail> = {}): ThreatMatchDetail {
  return {
    match_id: MATCH,
    asset: { asset_id: ASSET, name: "pc-demo", primary_ip: "10.0.0.5" },
    indicator_id: INDICATOR,
    indicator_type: "ipv4",
    indicator_value: "203.0.113.66",
    source_name: "Indicadores locales",
    source_trust: "local",
    classification: "malicious",
    match_confidence: "high",
    observation_type: "auth_source_ip",
    observed_value: "203.0.113.66",
    first_observed_at: iso(-3_600_000),
    last_observed_at: iso(-60_000),
    observation_count: 3,
    status: "open",
    detection_id: null,
    version: 2,
    observed_field: "system_events.data.IpAddress",
    event_id: null,
    evidence: { event_code: 4625, target_user: "<script>alert(1)</script>" },
    indicator_confidence: "high",
    indicator_state: "active",
    status_reason: null,
    status_changed_at: iso(-3_600_000),
    status_changed_by: "threat-intel",
    matched_at: iso(-3_600_000),
    incidents: [],
    actions: ["acknowledge", "dismiss", "incident"],
    ...overrides,
  };
}

const INTEL: FindingThreatIntel = {
  finding_id: FINDING,
  cve: "CVE-2099-1001",
  status: "available",
  kev: [
    {
      source: { source_id: 1, name: "CISA KEV", trust: "official", state: "fresh", last_success_at: iso(-3_600_000) },
      date_added: "2099-01-01",
      due_date: "2099-01-22",
      required_action: "Apply updates per vendor instructions.",
      known_ransomware_use: "unknown",
      vendor_project: "Example Corp",
      product: "ExampleApp",
      vulnerability_name: "ExampleApp issue",
      notes: null,
      retrieved_at: iso(-3_600_000),
      active: true,
      removed_at: null,
    },
  ],
  epss: [
    {
      source: { source_id: 2, name: "FIRST EPSS", trust: "official", state: "stale", last_success_at: iso(-86_400_000 * 9) },
      score: 0.91234,
      percentile: 0.99876,
      band: "high",
      model_version: "v2099.01.01",
      score_date: "2099-01-02",
      retrieved_at: iso(-86_400_000 * 9),
      previous: { score: 0.4, score_date: "2099-01-01" },
    },
  ],
  conflicting: false,
  changes: [{ occurred_at: iso(-3_600_000), source_name: "CISA KEV", change: "kev_added", details: null }],
  priority_factors: [{ factor: "known_exploited", label: "Explotación conocida reportada (CISA KEV)", points: 10 }],
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
    "GET /threat-intel/overview": () => ({ body: EMPTY_OVERVIEW }),
    "GET /threat-intel/sources": () => ({
      body: {
        items: [
          source(),
          source({
            id: 3,
            source_key: "local-iocs",
            name: "Indicadores locales",
            provider: "local_import",
            provider_title: "Importación local",
            trust: "local",
            enabled: true,
            network_required: false,
            state: "fresh",
            download_host: null,
          }),
        ],
        sync_enabled: false,
        detection_policy: "high_confidence_malicious",
      },
    }),
    [`GET /threat-intel/matches/${MATCH}`]: () => ({ body: match() }),
    [`GET /vulnerabilities/findings/${FINDING}/threat-intel`]: () => ({ body: INTEL }),
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
          <Route path="/threat-intel" element={<ThreatIntelPage />} />
          <Route path="/threat-intel/matches/:matchId" element={<ThreatMatchDetailPage />} />
          <Route path="/finding" element={<FindingIntelPanel findingId={FINDING} />} />
          <Route path="/incidents/:incidentId" element={<p>incidente abierto</p>} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

describe("ThreatIntelPage", () => {
  it("sin fuentes muestra un estado neutro, no un error", async () => {
    renderAt("/threat-intel");
    expect(await screen.findByText(/No intelligence source configured/)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText(/Desactivada \(instalación offline\)/)).toBeInTheDocument();
  });

  it("solo el admin ve importar, activar fuentes y reevaluar", async () => {
    renderAt("/threat-intel?tab=sources", "viewer");
    expect(await screen.findByText("CISA Known Exploited Vulnerabilities")).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Importar" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Activar" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reevaluar coincidencias" })).not.toBeInTheDocument();
    cleanup();

    renderAt("/threat-intel?tab=sources", "admin");
    const row = (await screen.findByText("CISA Known Exploited Vulnerabilities")).closest("tr")!;
    // Solo el host: la URL completa nunca llega al navegador.
    expect(within(row).getByText("www.cisa.gov")).toBeInTheDocument();
    routes["POST /threat-intel/sources/1/enable"] = () => ({ body: source({ enabled: true, revision: 1 }) });
    fireEvent.click(within(row).getByRole("button", { name: "Activar" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/threat-intel/sources/1/enable")).toBe(true));
    const body = JSON.parse(String(calls.find((c) => c.path === "/threat-intel/sources/1/enable")!.init.body)) as {
      revision: number;
    };
    expect(body.revision).toBe(0);
    expect(screen.getByRole("tab", { name: "Importar" })).toBeInTheDocument();
  });

  it("importa en dos pasos con la misma huella", async () => {
    const preview = {
      source_key: "local-iocs",
      format: "sentra-ioc",
      sha256: "a".repeat(64),
      size_bytes: 120,
      source_version: null,
      total: 2,
      valid: 2,
      new: 2,
      updated: 0,
      unchanged: 0,
      invalid: 0,
      invalid_records: [],
      unsupported: {},
      by_type: { ipv4: 1, sha256: 1 },
      not_matchable: 1,
    };
    routes["POST /threat-intel/import/preview"] = () => ({ body: preview });
    routes["POST /threat-intel/import"] = () => ({
      body: { source_key: "local-iocs", sha256: preview.sha256, new: 2, updated: 0, unchanged: 0, invalid: 0, pending_match: 1 },
    });
    renderAt("/threat-intel?tab=import");
    const input = await screen.findByLabelText("Fichero de indicadores");
    const content = JSON.stringify({ format: "sentra-ioc/1", indicators: [] });
    const file = new File([content], "iocs.json", { type: "application/json" });
    // jsdom no implementa File.text(); los navegadores soportados sí.
    Object.defineProperty(file, "text", { value: () => Promise.resolve(content) });
    fireEvent.change(input, { target: { files: [file] } });
    expect(await screen.findByText(/hashes, URLs o emails/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Confirmar importación" }));
    expect(await screen.findByText(/Importado en local-iocs/)).toBeInTheDocument();
    const sent = JSON.parse(String(calls.find((c) => c.path === "/threat-intel/import")!.init.body)) as Record<
      string,
      unknown
    >;
    expect(sent.expected_sha256).toBe(preview.sha256);
    expect(sent.format).toBe("sentra-ioc");
    expect(sent.source_id).toBe(3);
  });
});

describe("ThreatMatchDetailPage", () => {
  it("no afirma compromiso, pinta la evidencia como texto y exige motivo para descartar", async () => {
    routes[`POST /threat-intel/matches/${MATCH}/dismiss`] = () => ({ body: match({ status: "dismissed", version: 3 }) });
    renderAt(`/threat-intel/matches/${MATCH}`, "analyst");
    expect(await screen.findByText(/No confirma un compromiso/)).toBeInTheDocument();
    expect(screen.getByText("<script>alert(1)</script>")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Descartar (falso positivo)" }));
    const confirm = screen.getByRole("button", { name: /Confirmar/ });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Motivo"), { target: { value: "IP del CDN corporativo" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(calls.some((c) => c.path === `/threat-intel/matches/${MATCH}/dismiss`)).toBe(true));
    const body = JSON.parse(
      String(calls.find((c) => c.path === `/threat-intel/matches/${MATCH}/dismiss`)!.init.body),
    ) as Record<string, unknown>;
    expect(body).toEqual({ version: 2, reason: "IP del CDN corporativo" });
  });

  it("un viewer no ve acciones", async () => {
    routes[`GET /threat-intel/matches/${MATCH}`] = () => ({ body: match({ actions: [] }) });
    renderAt(`/threat-intel/matches/${MATCH}`, "viewer");
    expect(await screen.findByText(/No confirma un compromiso/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reconocer" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Crear incidente" })).not.toBeInTheDocument();
  });
});

describe("FindingIntelPanel", () => {
  it("muestra KEV y EPSS con procedencia y sin lenguaje de compromiso", async () => {
    renderAt("/finding");
    expect(await screen.findByText("Explotación conocida reportada (CISA KEV)")).toBeInTheDocument();
    expect(screen.getByText(/Desconocido \(no significa que no\)/)).toBeInTheDocument();
    expect(screen.getByText(/91,2 %/)).toBeInTheDocument();
    expect(screen.getByText("Desactualizada")).toBeInTheDocument();
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/explotad[ao] en este|comprometid|% vulnerable/i);
  });

  it("sin fuentes lo dice sin error", async () => {
    routes[`GET /vulnerabilities/findings/${FINDING}/threat-intel`] = () => ({
      body: { ...INTEL, status: "none_configured", kev: [], epss: [], changes: [], priority_factors: [] },
    });
    renderAt("/finding");
    expect(await screen.findByText("No intelligence source configured")).toBeInTheDocument();
  });
});
