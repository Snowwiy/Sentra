// @vitest-environment jsdom
// Fase 5C.1: ciclo de vida del activo y eventos Linux en la UI.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Asset, AssetDeleteCheck, DuplicateCandidate, Role, SystemEvent } from "../../api/types";
import { WithRole } from "../../test/auth";
import { EventsTab } from "./EventsTab";
import { DELETE_CONFIRMATION, DELETE_REFUSED, LifecyclePanel, REENROLL_HINT } from "./LifecyclePanel";

function asset(overrides: Partial<Asset> = {}): Asset {
  const now = new Date().toISOString();
  return {
    asset_id: "6f1c2a8e-0000-4000-8000-000000000001",
    display_name: "192.168.50.108",
    monitoring_method: "discovered",
    hostname: null,
    os_name: null,
    os_version: null,
    architecture: null,
    primary_ip: "192.168.50.108",
    agent_version: null,
    status: "online",
    agent_status: null,
    network_status: "online",
    first_seen_at: now,
    last_seen_at: null,
    created_at: now,
    updated_at: now,
    latest_telemetry: null,
    mac_address: "a4:00:03:00:00:12",
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
    discovery_sources: ["arp"],
    discovery_network: "192.168.50.0/24",
    discovered_at: now,
    last_network_seen_at: now,
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

const ID = "6f1c2a8e-0000-4000-8000-000000000001";

function check(overrides: Partial<AssetDeleteCheck> = {}): AssetDeleteCheck {
  return {
    asset_id: ID,
    deletable: true,
    blocking_reasons: [],
    dependencies: {},
    removes: { ports: 2 },
    can_archive: true,
    version: 3,
    display_name: "192.168.50.108",
    hostname: "fantasma",
    primary_ip: "192.168.50.108",
    mac_address: "a4:00:03:00:00:12",
    monitoring_method: "discovered",
    last_seen_at: new Date().toISOString(),
    ...overrides,
  };
}

function candidate(overrides: Partial<DuplicateCandidate> = {}): DuplicateCandidate {
  return {
    asset: {
      asset_id: "11111111-0000-4000-8000-000000000009",
      display_name: "Ravenslg",
      hostname: "Ravenslg",
      primary_ip: "192.168.50.66",
      mac_address: null,
      os_name: "Windows",
      monitoring_method: "agent",
      agent_version: "0.1.0",
      credential_status: "revoked",
      archived: false,
      last_seen_at: new Date().toISOString(),
      first_seen_at: new Date().toISOString(),
      version: 4,
    },
    reasons: ["same_hostname", "same_ip"],
    confidence: "medium",
    reconcilable: true,
    reconcile_blockers: [],
    ...overrides,
  };
}

type Handler = (init: RequestInit, url: URL) => { status?: number; body?: unknown };
let routes: Record<string, Handler>;
let calls: { method: string; path: string; url: URL; init: RequestInit }[];

beforeEach(() => {
  calls = [];
  routes = {
    [`GET /assets/${ID}/duplicate-candidates`]: () => ({ body: { asset_id: ID, items: [] } }),
    [`GET /assets/${ID}/delete-check`]: () => ({ body: check() }),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const url = new URL(input, "http://localhost");
      const path = url.pathname.replace("/api/v1", "");
      calls.push({ method, path, url, init });
      const handler = routes[`${method} ${path}`];
      if (!handler) return new Response(JSON.stringify({ error: { code: "not_found", message: path } }), { status: 404 });
      const { status = 200, body } = handler(init, url);
      return status === 204 ? new Response(null, { status }) : new Response(JSON.stringify(body), { status });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderAs(role: Role, node: ReactNode) {
  return render(
    <MemoryRouter>
      <WithRole role={role}>{node}</WithRole>
    </MemoryRouter>,
  );
}

describe("LifecyclePanel", () => {
  it("deletes a discovered asset without history after the exact confirmation", async () => {
    routes[`DELETE /assets/${ID}`] = () => ({ status: 204 });
    renderAs("admin", <LifecyclePanel asset={asset()} onChanged={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "Eliminar" }));
    // El diálogo pasa de "comprobando" a la confirmación: se vuelve a buscar.
    await screen.findByText(DELETE_CONFIRMATION);
    const dialog = screen.getByRole("dialog", { name: "Eliminar activo" });
    expect(dialog).toHaveTextContent("fantasma");
    expect(dialog).toHaveTextContent("a4:00:03:00:00:12");
    fireEvent.click(within(dialog).getByRole("button", { name: "Eliminar permanentemente" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
    const call = calls.find((c) => c.method === "DELETE");
    expect(call?.url.searchParams.get("version")).toBe("3");
  });

  it("refuses to delete an asset with history and offers to archive it", async () => {
    routes[`GET /assets/${ID}/delete-check`] = () => ({
      body: check({ deletable: false, blocking_reasons: ["vulnerabilities"] }),
    });
    renderAs("admin", <LifecyclePanel asset={asset()} onChanged={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "Eliminar" }));
    const dialog = await screen.findByRole("dialog", { name: "Eliminar activo" });
    await within(dialog).findByText(DELETE_REFUSED);
    expect(within(dialog).queryByRole("button", { name: "Eliminar permanentemente" })).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "Archivar" }));
    await screen.findByRole("dialog", { name: "Archivar activo" });
  });

  it("never offers delete for a managed asset and archives with a reason", async () => {
    let body: unknown;
    routes[`POST /assets/${ID}/archive`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: asset({ archived_at: new Date().toISOString() }) };
    };
    const changed = vi.fn();
    renderAs("admin", <LifecyclePanel asset={asset({ monitoring_method: "agent", managed_history: true })} onChanged={changed} />);
    expect(screen.queryByRole("button", { name: "Eliminar" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Archivar" }));
    const dialog = await screen.findByRole("dialog", { name: "Archivar activo" });
    fireEvent.change(within(dialog).getByRole("textbox"), { target: { value: "Equipo retirado" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Archivar" }));
    await waitFor(() => expect(changed).toHaveBeenCalled());
    expect(body).toEqual({ reason: "Equipo retirado", version: 0 });
  });

  it("shows the archived state and restore without touching the credential", async () => {
    routes[`POST /assets/${ID}/restore`] = () => ({ body: asset() });
    renderAs(
      "admin",
      <LifecyclePanel asset={asset({ archived_at: new Date().toISOString(), archive_reason: "Retirado" })} onChanged={() => undefined} />,
    );
    expect(screen.getByRole("status")).toHaveTextContent("Archivado");
    expect(screen.getByRole("status")).toHaveTextContent("Retirado");
    fireEvent.click(screen.getByRole("button", { name: "Restaurar" }));
    const dialog = await screen.findByRole("dialog", { name: "Restaurar activo" });
    expect(dialog).toHaveTextContent("no reactiva la credencial");
  });

  it("suggests the re-enrollment duplicate and lets an admin reconcile", async () => {
    let body: unknown;
    routes[`GET /assets/${ID}/duplicate-candidates`] = () => ({ body: { asset_id: ID, items: [candidate()] } });
    routes[`POST /assets/${ID}/reconcile`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: { asset: asset(), archived_duplicate_id: ID, confidence: "medium", reasons: [] } };
    };
    renderAs("admin", <LifecyclePanel asset={asset({ monitoring_method: "agent", managed_history: true, lifecycle_version: 1 })} onChanged={() => undefined} />);
    await screen.findByText(REENROLL_HINT);
    expect(screen.getByText("mismo hostname, misma IP")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Reconciliar con activo existente" }));
    const dialog = await screen.findByRole("dialog", { name: "Reconciliar con activo existente" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Reconciliar" }));
    await waitFor(() =>
      expect(body).toEqual({ target_asset_id: candidate().asset.asset_id, version: 1, target_version: 4 }),
    );
  });

  it("gives analysts read-only duplicate suggestions and viewers nothing", async () => {
    routes[`GET /assets/${ID}/duplicate-candidates`] = () => ({ body: { asset_id: ID, items: [candidate()] } });
    renderAs("analyst", <LifecyclePanel asset={asset({ monitoring_method: "agent" })} onChanged={() => undefined} />);
    await screen.findByText(REENROLL_HINT);
    expect(screen.queryByRole("button", { name: "Reconciliar con activo existente" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Archivar" })).toBeNull();
    cleanup();
    renderAs("viewer", <LifecyclePanel asset={asset({ monitoring_method: "agent" })} onChanged={() => undefined} />);
    expect(screen.queryByRole("button", { name: "Eliminar" })).toBeNull();
    expect(calls.filter((c) => c.path.endsWith("duplicate-candidates"))).toHaveLength(1);
  });
});

function linuxEvent(overrides: Partial<SystemEvent> = {}): SystemEvent {
  return {
    event_id: "e1",
    asset_id: ID,
    hostname: "mint",
    source: "linux_journal",
    channel: "journal",
    event_code: null,
    event_type: "auth_failure",
    provider: "sshd",
    level: "warning",
    message: "Failed password for ana from 203.0.113.9 port 51234 ssh2",
    record_id: 1,
    computer: "mint",
    data: { user: "ana", source_ip: "203.0.113.9" },
    occurred_at: new Date().toISOString(),
    ...overrides,
  };
}

describe("EventsTab", () => {
  it("shows Linux columns, filters and coverage", async () => {
    routes["GET /events"] = () => ({ body: { items: [linuxEvent()], total: 1, has_more: false } });
    const linux = asset({
      monitoring_method: "agent",
      os_name: "Linux",
      event_coverage: { journal: "active", sshd: "active", sudo: "active", auditd: "unavailable" },
      event_coverage_at: new Date().toISOString(),
    });
    renderAs("viewer", <EventsTab asset={linux} />);
    expect(await screen.findByRole("columnheader", { name: "Usuario" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "Autenticación fallida" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Origen/IP" })).toBeInTheDocument();
    expect(screen.getByText("203.0.113.9")).toBeInTheDocument();
    expect(screen.queryByText(/Canal/)).toBeNull();
    expect(screen.getByLabelText("Cobertura de eventos")).toHaveTextContent("No disponible");
    fireEvent.change(screen.getByRole("combobox", { name: "Tipo" }), { target: { value: "sudo_command" } });
    await waitFor(() => expect(calls.at(-1)?.url.searchParams.get("event_type")).toBe("sudo_command"));
    expect(calls.at(-1)?.url.searchParams.get("channel")).toBeNull();
  });

  it("warns when the journal is not readable", async () => {
    routes["GET /events"] = () => ({ body: { items: [], total: 0, has_more: false } });
    const linux = asset({
      os_name: "Linux",
      event_coverage: { journal: "no_permission" },
      event_coverage_at: new Date().toISOString(),
    });
    renderAs("viewer", <EventsTab asset={linux} />);
    await screen.findByText(/journal de systemd/);
    expect(screen.getByText(/grupo systemd-journal/)).toBeInTheDocument();
  });

  it("keeps the Windows channel filter and Event ID", async () => {
    routes["GET /events"] = () => ({
      body: {
        items: [linuxEvent({ source: "windows_eventlog", channel: "Security", event_code: 4625, event_type: null, provider: "Microsoft-Windows-Security-Auditing" })],
        total: 1,
        has_more: false,
      },
    });
    renderAs("viewer", <EventsTab asset={asset({ os_name: "Windows" })} />);
    await screen.findByText(/ID 4625/);
    expect(screen.getByRole("combobox", { name: "Canal" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Cobertura de eventos")).toBeNull();
  });
});
