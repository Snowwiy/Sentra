// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Report, ReportCatalog, ReportTypeInfo, Role } from "../api/types";
import { WithRole } from "../test/auth";
import { GenerateReportLink } from "../components/reports/GenerateReportLink";
import { ReportsPage } from "./ReportsPage";

// Datos sintéticos de test: no proceden de ningún host real.
const INCIDENT_ID = "11111111-2222-3333-4444-555555555555";
const SHA = "ab".repeat(32);
const NOW = new Date().toISOString();

function type(overrides: Partial<ReportTypeInfo>): ReportTypeInfo {
  return {
    id: "incident",
    name: "Informe de incidente",
    description: "Caso completo",
    audience: "technical",
    template_version: 1,
    supported_formats: ["html", "pdf", "evidence"],
    filters: ["incident_ids"],
    required_filters: ["incident_ids"],
    status_values: [],
    uses_range: false,
    max_range_days: 365,
    can_generate: true,
    ...overrides,
  };
}

const CATALOG: ReportCatalog = {
  items: [
    type({ id: "executive_summary", name: "Resumen ejecutivo de seguridad", supported_formats: ["html", "pdf"], filters: [], required_filters: [], uses_range: true, can_generate: false }),
    type({}),
    type({
      id: "detection",
      name: "Informe de detecciones",
      supported_formats: ["html", "pdf", "csv", "evidence"],
      filters: ["detection_ids", "severities", "statuses"],
      required_filters: [],
      status_values: ["open", "resolved"],
      severity_values: ["critical", "high"],
      uses_range: true,
    }),
  ],
  classifications: ["internal", "confidential", "restricted"],
  limits: { max_range_days: 365, max_ids: 100, max_rows: 500 },
  enabled: true,
};

function report(overrides: Partial<Report> = {}): Report {
  return {
    id: "rrrrrrrr-0000-0000-0000-000000000001",
    report_type: "incident",
    name: "Informe de incidente",
    title: "Informe de incidente INC-000012",
    format: "pdf",
    classification: "internal",
    status: "succeeded",
    template_version: 1,
    requested_by: "ana",
    created_at: NOW,
    started_at: NOW,
    finished_at: NOW,
    cutoff_at: NOW,
    time_from: null,
    time_to: null,
    timezone: "UTC",
    filters: { incident_ids: [INCIDENT_ID] },
    scope: { assets: 3 },
    summary: [],
    artifact: { filename: "sentra-incident.pdf", content_type: "application/pdf", size_bytes: 2048, sha256: SHA, created_at: NOW },
    snapshot_sha256: null,
    error_code: null,
    error_message: null,
    cancel_requested: false,
    deduplicated: false,
    can_cancel: false,
    can_delete: false,
    version: 1,
    ...overrides,
  };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

let fetchMock: ReturnType<typeof vi.fn>;
const bodies = (path: string) =>
  fetchMock.mock.calls
    .filter(([input, init]) => (init as RequestInit | undefined)?.method === "POST" && String(input).includes(path))
    .map(([, init]) => JSON.parse(String((init as RequestInit).body)) as Record<string, unknown>);
const listQueries = () =>
  fetchMock.mock.calls
    .map(([input]) => new URL(String(input), "http://localhost"))
    .filter((url) => url.pathname === "/api/v1/reports")
    .map((url) => url.searchParams);

beforeEach(() => {
  fetchMock = vi.fn(async (input: string, init: RequestInit = {}) => {
    const method = init.method ?? "GET";
    const path = new URL(input, "http://localhost").pathname.replace("/api/v1", "");
    if (method === "GET" && path === "/reports/catalog") return json(200, CATALOG);
    if (method === "GET" && path === "/reports") return json(200, { items: [report()], total: 1 });
    if (method === "POST" && path === "/reports/preview") {
      return json(200, {
        report_type: "incident",
        name: "Informe de incidente",
        format: "pdf",
        classification: "internal",
        template_version: 1,
        time_from: null,
        time_to: null,
        timezone: "UTC",
        filters: { incident_ids: [INCIDENT_ID] },
        sections: ["Resumen", "Línea de tiempo"],
        scope: { assets: 3, detections: 12 },
        warnings: [{ code: "rows_truncated", message: "Se truncarán filas." }],
        can_generate: true,
      });
    }
    if (method === "POST" && path === "/reports") {
      return json(202, report({ id: "rrrrrrrr-0000-0000-0000-000000000002", status: "pending", artifact: null }));
    }
    return json(404, { error: { code: "not_found", message: path } });
  });
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderPage(role: Role, url = "/reports") {
  render(
    <MemoryRouter initialEntries={[url]}>
      <WithRole role={role}>
        <Routes>
          <Route path="/reports" element={<ReportsPage />} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

describe("ReportsPage", () => {
  it("renders the catalog types and the formats of the selected type", async () => {
    renderPage("analyst");
    const typeSelect = await screen.findByLabelText("Tipo de informe");
    const options = within(typeSelect).getAllByRole("option").map((o) => o.textContent);
    expect(options).toEqual([
      "Resumen ejecutivo de seguridad (sin permiso para generar)",
      "Informe de incidente",
      "Informe de detecciones",
    ]);
    // El resumen ejecutivo no se puede generar con este rol: solo vista previa.
    expect(screen.queryByRole("button", { name: "Generar" })).toBeNull();
    fireEvent.change(typeSelect, { target: { value: "detection" } });
    const formats = within(screen.getByLabelText("Formato")).getAllByRole("option").map((o) => o.getAttribute("value"));
    expect(formats).toEqual(["html", "pdf", "csv", "evidence"]);
    // Filtros del tipo: severidades y estados del catálogo.
    expect(screen.getByLabelText("Crítico")).toBeInTheDocument();
    expect(screen.queryByLabelText("Medio")).toBeNull();
    expect(screen.getByLabelText("Abierto")).toBeInTheDocument();
  });

  it("prefills the form from the query string and shows the preview", async () => {
    renderPage("analyst", `/reports?type=incident&incident_id=${INCIDENT_ID}`);
    expect(await screen.findByLabelText("Tipo de informe")).toHaveValue("incident");
    expect(screen.getByLabelText("Incidentes")).toHaveValue(INCIDENT_ID);
    expect(screen.queryByLabelText("Rango")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Vista previa" }));
    const preview = await screen.findByRole("region", { name: "Vista previa" });
    expect(within(preview).getByText("Línea de tiempo")).toBeInTheDocument();
    expect(within(preview).getByText("Se truncarán filas.")).toBeInTheDocument();
    expect(within(preview).getByText("12")).toBeInTheDocument();
    expect(bodies("/reports/preview")[0]).toEqual({
      report_type: "incident",
      format: "html",
      classification: "internal",
      filters: { incident_ids: [INCIDENT_ID] },
    });
  });

  it("sends an idempotency key when generating and reuses it on retry of the same request", async () => {
    renderPage("analyst", `/reports?type=incident&incident_id=${INCIDENT_ID}`);
    fireEvent.change(await screen.findByLabelText("Formato"), { target: { value: "evidence" } });
    fireEvent.change(screen.getByLabelText("Clasificación"), { target: { value: "confidential" } });
    fireEvent.click(screen.getByRole("button", { name: "Generar" }));
    expect(await screen.findByText(/Informe solicitado/)).toBeInTheDocument();
    const [body] = bodies("/reports").filter((b) => "idempotency_key" in b);
    expect(body).toMatchObject({
      report_type: "incident",
      format: "evidence",
      classification: "confidential",
      filters: { incident_ids: [INCIDENT_ID] },
    });
    expect(String(body?.idempotency_key)).toMatch(/^[0-9a-f-]{36}$/);
    // Tras crear el informe, el historial se recarga.
    await waitFor(() => expect(listQueries().length).toBeGreaterThanOrEqual(2));
  });

  it("disables actions while a required filter is missing", async () => {
    renderPage("analyst", "/reports?type=incident");
    expect(await screen.findByText(/Falta el filtro obligatorio/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generar" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Vista previa" })).toBeDisabled();
  });

  it("lists history with checksum, size and download for viewers without the form", async () => {
    renderPage("viewer");
    const history = await screen.findByRole("region", { name: "Historial de informes" });
    expect(await within(history).findByRole("link", { name: "Informe de incidente INC-000012" })).toHaveAttribute(
      "href",
      "/reports/rrrrrrrr-0000-0000-0000-000000000001",
    );
    expect(within(history).getByText(`${SHA.slice(0, 12)}…`)).toBeInTheDocument();
    expect(within(history).getByText("2.0 KB")).toBeInTheDocument();
    expect(within(history).getByRole("button", { name: "Descargar" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Generar informe" })).toBeNull();
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/reports/preview"))).toBe(false);
  });

  it("filters history by type, status, user and dates", async () => {
    renderPage("viewer");
    await screen.findByRole("region", { name: "Historial de informes" });
    fireEvent.change(screen.getByLabelText("Estado"), { target: { value: "failed" } });
    fireEvent.change(screen.getByLabelText("Creado desde"), { target: { value: "2026-10-01" } });
    fireEvent.change(screen.getByLabelText("Solicitado por"), { target: { value: "ana" } });
    await waitFor(() => {
      const last = listQueries().at(-1);
      expect(last?.get("status")).toBe("failed");
      expect(last?.get("created_from")).toBe("2026-10-01T00:00:00Z");
      expect(last?.get("requested_by")).toBe("ana");
      expect(last?.get("limit")).toBe("25");
    });
  });
});

describe("GenerateReportLink", () => {
  function renderLink(role: Role) {
    render(
      <MemoryRouter>
        <WithRole role={role}>
          <GenerateReportLink type="response_activity" ids={{ execution_id: "e1" }} label="Exportar actividad" />
        </WithRole>
      </MemoryRouter>,
    );
  }

  it("links to the prefilled form only with reports:generate", () => {
    renderLink("analyst");
    expect(screen.getByRole("link", { name: "Exportar actividad" })).toHaveAttribute(
      "href",
      "/reports?type=response_activity&execution_id=e1",
    );
    cleanup();
    renderLink("viewer");
    expect(screen.queryByRole("link")).toBeNull();
  });
});
