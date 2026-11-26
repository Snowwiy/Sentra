// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Role, SiemConnectorRead, SiemEventDetail, SiemOverview, SiemSourceRead } from "../api/types";
import { SiteProvider } from "../site/SiteContext";
import { WithRole } from "../test/auth";
import { DEFAULT_SITE_ID, SITES, installFetch, type Call, type Handler } from "../test/sites";
import * as format from "../lib/format";
import { readFileText, SiemPage } from "./SiemPage";

// 7F-Fix3: el botón que abre el detalle muestra la hora relativa ("hace 2 h", "anteayer",
// "2 days ago"...), que depende del reloj, la zona y el idioma. Las pruebas localizan el
// evento por su contenido y el botón dentro de su fila, nunca por ese texto.
// Se guarda la implementación real para restaurarla tras cada prueba que fija una etiqueta.
const realFormat = vi.hoisted(() => ({ formatRelative: null as null | typeof import("../lib/format").formatRelative }));
vi.mock("../lib/format", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/format")>();
  realFormat.formatRelative = actual.formatRelative;
  return { ...actual, formatRelative: vi.fn(actual.formatRelative) };
});

const HOSTILE = '<img src=x onerror="alert(1)"> https://evil.example/run';

const ISO = "2026-11-24T08:00:00Z";
const SOURCE_ID = "5f000000-0000-0000-0000-0000000000a1";
const EVENT_ID = "e7000000-0000-0000-0000-000000000001";

const OVERVIEW: SiemOverview = {
  window_hours: 24,
  sources_total: 1,
  sources_by_status: { healthy: 1 },
  events: 3,
  rejected: 1,
  duplicates: 0,
  by_source_type: [],
  by_severity: [],
  by_category: [],
  lagging_sources: 0,
  last_event_received_at: ISO,
};

const CONNECTOR: SiemConnectorRead = {
  source_type: "sentra_json",
  title: "Sentra JSON (contrato normalizado)",
  version: "1.0.0",
  transports: ["upload", "sensor"],
  sensor_input: "file",
  description: "Una línea JSON por evento.",
  severity_policy: {},
  severity_policy_doc: "La severidad viene ya en la escala de Sentra.",
  event_types: [],
  sensitive_fields: [],
  validation: "Contrato propio.",
  formats: ["json_lines"],
};

function source(overrides: Partial<SiemSourceRead> = {}): SiemSourceRead {
  return {
    source_id: SOURCE_ID,
    name: "Exportación firewall",
    source_type: "sentra_json",
    connector_title: CONNECTOR.title,
    connector_version: "1.0.0",
    transport: "upload",
    site_id: DEFAULT_SITE_ID,
    site_name: "Principal",
    sensor_id: null,
    sensor_name: null,
    input_name: null,
    enabled: true,
    revision: 2,
    status: "healthy",
    status_reasons: [],
    config: {},
    effective_severity_policy: {},
    retention_days: null,
    effective_retention_days: 30,
    max_events_per_minute: 6000,
    events_received: 4,
    events_accepted: 3,
    events_rejected: 1,
    events_duplicate: 0,
    events_dropped: 0,
    last_success_at: ISO,
    last_event_at: ISO,
    lag_seconds: null,
    last_error_code: null,
    last_error_at: null,
    reported_state: null,
    reported_at: null,
    created_by: "admin",
    updated_by: "admin",
    created_at: ISO,
    updated_at: ISO,
    ...overrides,
  };
}

const EVENT: SiemEventDetail = {
  event_id: EVENT_ID,
  schema_version: 1,
  normalization_version: "sentra_json/1.0.0",
  source_id: SOURCE_ID,
  source_name: "Exportación firewall",
  source_type: "sentra_json",
  site_id: DEFAULT_SITE_ID,
  event_type: "firewall.deny",
  category: "network",
  timestamp: ISO,
  collected_at: ISO,
  received_at: ISO,
  time_quality: "source",
  severity: "low",
  source_severity: "low",
  confidence: "unknown",
  hostname: null,
  source_ip: "10.0.0.5",
  destination_ip: "10.0.0.9",
  source_port: 51000,
  destination_port: 445,
  protocol: "tcp",
  username: null,
  process_name: null,
  action: "deny",
  outcome: "failure",
  signature_id: null,
  rule_id: null,
  message: HOSTILE,
  tags: [],
  mitre_techniques: [],
  external_id: "a-1",
  flow_ref: null,
  raw_reference: "upload:abc#1",
  evidence_hash: "a".repeat(64),
  asset: null,
  attribution: {
    verdict: "attributed",
    candidates: [
      { asset_id: "a5000000-0000-0000-0000-000000000001", asset_name: "srv-files", role: "destination", method: "ip_in_site", confidence: "medium", value: "10.0.0.9" },
    ],
    ambiguous: 0,
    origin: null,
  },
  links: [
    {
      kind: "ndr_flow",
      target_ref: "abc123",
      method: "five_tuple_time",
      confidence: "high",
      explanation: "Misma 5-tupla",
      created_at: ISO,
    },
  ],
  raw_excerpt: '{"message":"<script>alert(1)</script>"}',
  data: null,
};

const SECOND_ID = "e7000000-0000-0000-0000-000000000002";

let calls: Call[];
let routes: Record<string, Handler>;

/** Fila de la tabla de eventos que contiene el tipo indicado (dato inequívoco del evento). */
async function findEventRow(eventType: string): Promise<HTMLElement> {
  const cell = await screen.findByText(eventType, { selector: "td" });
  const row = cell.closest("tr");
  expect(row).not.toBeNull();
  return row as HTMLElement;
}

/** Nada del contenido hostil se ha convertido en elementos, manejadores o enlaces. */
function expectInert(root: HTMLElement) {
  expect(root.querySelector("img, script, iframe, object, embed")).toBeNull();
  expect(root.querySelector("[onerror], [onload], [onclick]")).toBeNull();
  expect(root.querySelector("a[href*='evil.example'], a[href^='javascript:']")).toBeNull();
}

beforeEach(() => {
  window.localStorage.clear();
  routes = {
    "GET /sites": () => ({ body: { items: SITES } }),
    "GET /siem/overview": () => ({ body: OVERVIEW }),
    "GET /siem/sources": () => ({ body: { items: [source()] } }),
    "GET /siem/connectors": () => ({ body: { items: [CONNECTOR] } }),
    "GET /siem/events": () => ({ body: { items: [EVENT], total: 1, limit: 50, offset: 0, total_capped: false } }),
    [`GET /siem/events/${EVENT_ID}`]: () => ({ body: EVENT }),
    [`PUT /siem/sources/${SOURCE_ID}`]: () => ({ body: source({ enabled: false, status: "disabled" }) }),
    [`POST /siem/sources/${SOURCE_ID}/import`]: () => ({
      body: {
        batch_id: "b",
        duplicate: false,
        records: 2,
        accepted: 1,
        duplicates: 0,
        rejected: 1,
        reject_reasons: { invalid_json: 1 },
      },
    }),
  };
  calls = installFetch(routes);
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  // restoreAllMocks no devuelve vi.fn() a su implementación: se restablece la original.
  vi.mocked(format.formatRelative).mockReset();
  vi.mocked(format.formatRelative).mockImplementation(realFormat.formatRelative!);
});

function renderPage(role: Role, path = "/siem") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <WithRole role={role}>
        <SiteProvider>
          <SiemPage />
        </SiteProvider>
      </WithRole>
    </MemoryRouter>,
  );
}

describe("SiemPage", () => {
  it("shows sources and their real status without management actions for viewers", async () => {
    renderPage("viewer");
    expect(await screen.findByText("Exportación firewall")).toBeInTheDocument();
    expect(screen.getByText("Operativa")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Registrar fuente" })).not.toBeInTheDocument();
    // Sin siem:evidence no hay pestaña de eventos.
    expect(screen.queryByRole("tab", { name: "Eventos" })).not.toBeInTheDocument();
  });

  it("lets admins disable a source with the expected revision", async () => {
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Deshabilitar" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const put = calls.find((c) => c.method === "PUT");
    expect(JSON.parse(String(put?.init.body))).toEqual({ expected_revision: 2, enabled: false });
  });

  it("imports a file and reports rejections by reason", async () => {
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Importar" }));
    const file = new File(['{"a":1}\nnot-json\n'], "export.jsonl", { type: "application/json" });
    const input = screen.getByLabelText("Fichero exportado");
    fireEvent.change(input, { target: { files: [file] } });
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Importar" }));
    expect(await screen.findByText(/1 aceptados, 0 duplicados, 1 rechazados de 2/)).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST" && c.path.endsWith("/import"));
    expect(JSON.parse(String(post?.init.body))).toMatchObject({ filename: "export.jsonl" });
  });

  it("renders hostile event content as inert text", async () => {
    const alertSpy = vi.spyOn(window, "alert").mockImplementation(() => undefined);
    renderPage("analyst", "/siem?tab=events");
    const row = await findEventRow("firewall.deny");
    // En la tabla: el mensaje es texto literal, sin elementos ni enlaces creados a partir de él.
    expect(within(row).getByText(HOSTILE)).toBeInTheDocument();
    expectInert(document.body);
    fireEvent.click(within(row).getByRole("button"));
    const dialog = await screen.findByRole("dialog", { name: "Evento SIEM" });
    expect(await within(dialog).findByText(/Extracto del registro original/)).toBeInTheDocument();
    // En el detalle: el mismo mensaje y el extracto del registro original, también como texto.
    expect(within(dialog).getByText(HOSTILE)).toBeInTheDocument();
    expect(within(dialog).getByText('{"message":"<script>alert(1)</script>"}')).toBeInTheDocument();
    expectInert(dialog);
    expectInert(document.body);
    expect(alertSpy).not.toHaveBeenCalled();
    // Atribución y correlaciones explicadas, sin afirmar causalidad.
    expect(within(dialog).getByText("Atribuido a un activo")).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "srv-files" })).toHaveAttribute(
      "href",
      "/assets/a5000000-0000-0000-0000-000000000001",
    );
    expect(within(dialog).getByText(/no implica causalidad/)).toBeInTheDocument();
  });

  it("opens the detail of the selected row and closes it with the button or Escape", async () => {
    const second: SiemEventDetail = {
      ...EVENT,
      event_id: SECOND_ID,
      event_type: "auth.failure",
      message: "Fallo de autenticación",
      raw_excerpt: null,
    };
    routes["GET /siem/events"] = () => ({
      body: { items: [EVENT, second], total: 2, limit: 50, offset: 0, total_capped: false },
    });
    routes[`GET /siem/events/${SECOND_ID}`] = () => ({ body: second });
    renderPage("analyst", "/siem?tab=events");
    const row = await findEventRow("auth.failure");
    const opener = within(row).getByRole("button");
    // fireEvent.click no mueve el foco como un clic real: se enfoca antes el botón.
    opener.focus();
    fireEvent.click(opener);
    const dialog = await screen.findByRole("dialog", { name: "Evento SIEM" });
    expect(await within(dialog).findByText("Fallo de autenticación")).toBeInTheDocument();
    expect(calls.some((c) => c.path === `/siem/events/${SECOND_ID}`)).toBe(true);
    expect(calls.some((c) => c.path === `/siem/events/${EVENT_ID}`)).toBe(false);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cerrar" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(opener).toHaveFocus();
    // Teclado: se reabre y Escape lo cierra.
    fireEvent.click(opener);
    expect(await screen.findByRole("dialog", { name: "Evento SIEM" })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it.each([
    ["hoy", () => new Date().toISOString(), null],
    ["ayer", () => new Date(Date.now() - 86_400_000).toISOString(), null],
    ["anteayer", () => new Date(Date.now() - 2 * 86_400_000).toISOString(), null],
    ["hace varios días", () => new Date(Date.now() - 9 * 86_400_000).toISOString(), null],
    ["fecha absoluta antigua", () => "2020-01-01T00:00:00Z", null],
    ["texto en inglés", () => ISO, "2 days ago"],
    ["texto en español", () => ISO, "anteayer"],
    ["fecha absoluta como texto", () => ISO, "24/11/2026 08:00"],
  ])("finds and opens the event whatever the time label says (%s)", async (_case, when, label) => {
    // Las horas se calculan dentro del test (no al recoger los casos): el reloj avanza.
    const timestamp = when();
    if (label) vi.mocked(format.formatRelative).mockReturnValue(label);
    const event = { ...EVENT, timestamp };
    routes["GET /siem/events"] = () => ({
      body: { items: [event], total: 1, limit: 50, offset: 0, total_capped: false },
    });
    routes[`GET /siem/events/${EVENT_ID}`] = () => ({ body: event });
    renderPage("analyst", "/siem?tab=events");
    const row = await findEventRow("firewall.deny");
    const opener = within(row).getByRole("button");
    if (label) expect(opener).toHaveTextContent(label);
    fireEvent.click(opener);
    expect(await screen.findByRole("dialog", { name: "Evento SIEM" })).toBeInTheDocument();
  });

  it("does not load or show events without siem:evidence", async () => {
    renderPage("viewer", "/siem?tab=events");
    expect(await screen.findByText("Exportación firewall")).toBeInTheDocument();
    expect(screen.queryByText("firewall.deny")).not.toBeInTheDocument();
    expect(screen.queryByText(HOSTILE)).not.toBeInTheDocument();
    expect(calls.some((c) => c.path.startsWith("/siem/events"))).toBe(false);
  });

  it("reads files with FileReader when Blob.text is missing", async () => {
    const blob = new Blob(["linea"]);
    Object.defineProperty(blob, "text", { value: undefined });
    await expect(readFileText(blob)).resolves.toBe("linea");
  });
});
