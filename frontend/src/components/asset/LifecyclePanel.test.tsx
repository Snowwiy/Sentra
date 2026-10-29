// @vitest-environment jsdom
// Fase 5C.1: ciclo de vida del activo y eventos Linux en la UI.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  Asset,
  AssetDeleteCheck,
  AssetReconcileResult,
  DuplicateAsset,
  DuplicateCandidate,
  ReconcilePreview,
  Role,
  SystemEvent,
} from "../../api/types";
import { WithRole } from "../../test/auth";
import { EventsTab } from "./EventsTab";
import { ACK_WEAK_EVIDENCE, IRREVERSIBLE_WARNING, NOT_YET_DELETABLE } from "../../lib/lifecycle";
import { AssetStateBadge } from "../StatusBadge";
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
    lifecycle_state: "cleanup_candidate",
    missed_discovery_scans: 6,
    last_activity_at: new Date(Date.now() - 40 * 86_400_000).toISOString(),
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
    evidence: [
      { code: "same_hostname", strength: "weak" },
      { code: "same_ip", strength: "weak" },
    ],
    conflicts: [],
    reconcile_warnings: [],
    hypothesis: "re_enrollment",
    requires_acknowledgement: false,
    ...overrides,
  };
}

function preview(overrides: Partial<ReconcilePreview> = {}): ReconcilePreview {
  const source: DuplicateAsset = { ...candidate().asset, asset_id: ID, display_name: "ravenslg-nuevo", credential_status: "active", version: 1 };
  return {
    source,
    target: candidate().asset,
    confidence: "medium",
    reasons: ["same_hostname", "same_ip"],
    evidence: candidate().evidence,
    conflicts: [],
    reconcilable: true,
    reconcile_blockers: [],
    reconcile_warnings: [],
    requires_acknowledgement: false,
    source_history: { telemetry: 3 },
    target_history: { detections: 12, incidents: 1 },
    target_has_previous_agent: true,
    source_disposition: "source_archived",
    source_disposition_reasons: [],
    ...overrides,
  };
}

function reconcileResult(overrides: Partial<AssetReconcileResult> = {}): AssetReconcileResult {
  return {
    asset: asset(),
    archived_duplicate_id: ID,
    confidence: "medium",
    reasons: [],
    source_asset_id: ID,
    target_asset_id: candidate().asset.asset_id,
    agent_id: "agent-1",
    previous_target_agent_id: "agent-0",
    source_disposition: "source_archived",
    source_disposition_reasons: [],
    evidence: [],
    acknowledged_warnings: [],
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

  it("suggests the re-enrollment duplicate and lets an admin reconcile through the wizard", async () => {
    let body: unknown;
    const target = candidate().asset;
    routes[`GET /assets/${ID}/duplicate-candidates`] = () => ({ body: { asset_id: ID, items: [candidate()] } });
    routes[`GET /assets/${ID}/reconcile-preview`] = (_init, url) => {
      expect(url.searchParams.get("target_asset_id")).toBe(target.asset_id);
      return { body: preview() };
    };
    routes[`POST /assets/${ID}/reconcile`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: reconcileResult() };
    };
    renderAs("admin", <LifecyclePanel asset={asset({ monitoring_method: "agent", managed_history: true, lifecycle_version: 1 })} onChanged={() => undefined} />);
    await screen.findByText(REENROLL_HINT);
    // Evidencia con su fuerza; nunca como duplicado confirmado.
    const panel = screen.getByRole("region", { name: "Posibles duplicados" });
    expect(within(panel).getByLabelText("Evidencia")).toHaveTextContent("mismo hostname");
    expect(within(panel).getAllByText("débil")).toHaveLength(2);
    expect(panel).toHaveTextContent("Sin confirmar");
    fireEvent.click(screen.getByRole("button", { name: "Reconciliar con activo existente" }));
    const dialog = await screen.findByRole("dialog", { name: "Reconciliar con activo existente" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Siguiente" }));
    // El candidato llega preseleccionado.
    await waitFor(() => expect(within(dialog).getByRole("radio")).toBeChecked());
    fireEvent.click(within(dialog).getByRole("button", { name: "Ver evidencia" }));
    await within(dialog).findByRole("region", { name: "Destino (activo existente)" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Ver impacto" }));
    const impact = within(dialog).getByRole("list", { name: "Impacto" });
    expect(impact).toHaveTextContent("12 detecciones");
    expect(impact).toHaveTextContent("agente anterior del destino queda como histórico");
    fireEvent.click(within(dialog).getByRole("button", { name: "Continuar" }));
    expect(within(dialog).queryByRole("checkbox")).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "Reconciliar" }));
    await within(dialog).findByText(/Reconciliado/);
    expect(dialog).toHaveTextContent("queda archivado");
    expect(body).toEqual({
      target_asset_id: target.asset_id,
      version: 1,
      target_version: 4,
      acknowledge_weak_evidence: false,
    });
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

describe("LifecyclePanel (Fase 5C.2)", () => {
  it("distinguishes online, offline, stale, cleanup candidate and Archived", () => {
    const states = [
      [{ status: "online", lifecycle_state: "active" }, "En línea", "status--online"],
      [{ status: "offline", lifecycle_state: "offline" }, "Sin conexión", "status--offline"],
      [{ status: "offline", lifecycle_state: "stale" }, "Inactivo", "status--stale"],
      [{ status: "offline", lifecycle_state: "cleanup_candidate" }, "Candidato a limpieza", "status--cleanup"],
      [{ status: "online", lifecycle_state: "archived" }, "Archivado", "status--archived"],
      // Servidor anterior a 5C.2: archived_at sigue marcando el archivado.
      [{ status: "online", archived_at: new Date().toISOString() }, "Archivado", "status--archived"],
    ] as const;
    for (const [value, label, className] of states) {
      const { unmount } = render(<AssetStateBadge asset={value} />);
      expect(screen.getByText(label)).toHaveClass(className);
      unmount();
    }
  });

  it("shows lifecycle state, missed scans and last activity", () => {
    renderAs(
      "viewer",
      <LifecyclePanel asset={asset({ lifecycle_state: "stale", missed_discovery_scans: 4, last_activity_at: new Date().toISOString() })} onChanged={() => undefined} />,
    );
    const summary = screen.getByLabelText("Ciclo de vida");
    expect(summary).toHaveTextContent("Inactivo");
    expect(summary).toHaveTextContent("4 escaneos completos sin verlo");
    expect(summary).toHaveTextContent("Descubierto");
    expect(summary).toHaveTextContent("última actividad");
  });

  it("hard delete confirmation shows name, IP, Asset ID, eligibility and the irreversible warning", async () => {
    renderAs("admin", <LifecyclePanel asset={asset()} onChanged={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "Eliminar" }));
    await screen.findByText(DELETE_CONFIRMATION);
    const dialog = screen.getByRole("dialog", { name: "Eliminar activo" });
    const identity = within(dialog).getByLabelText("Activo a eliminar");
    expect(identity).toHaveTextContent("fantasma");
    expect(identity).toHaveTextContent("192.168.50.108");
    expect(identity).toHaveTextContent(ID);
    expect(identity).toHaveTextContent("Candidato a limpieza");
    expect(identity).toHaveTextContent(/Elegible para eliminación definitivaSí/);
    expect(dialog).toHaveTextContent(IRREVERSIBLE_WARNING);
  });

  it("explains the new lifecycle blocking reasons without claiming history", async () => {
    routes[`GET /assets/${ID}/delete-check`] = () => ({
      body: check({ deletable: false, blocking_reasons: ["purge_window_not_reached"], lifecycle_state: "stale" }),
    });
    renderAs("admin", <LifecyclePanel asset={asset()} onChanged={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "Eliminar" }));
    const dialog = await screen.findByRole("dialog", { name: "Eliminar activo" });
    await within(dialog).findByText(NOT_YET_DELETABLE);
    expect(within(dialog).queryByText(DELETE_REFUSED)).toBeNull();
    expect(dialog).toHaveTextContent("todavía no ha pasado la ventana de purga");
    expect(within(dialog).getByLabelText("Activo a eliminar")).toHaveTextContent(/Elegible para eliminación definitivaNo/);
  });

  it("manual reconcile by Asset ID requires the explicit weak-evidence acknowledgement", async () => {
    const TARGET = "22222222-0000-4000-8000-000000000002";
    let body: Record<string, unknown> | undefined;
    routes[`GET /assets/${ID}/reconcile-preview`] = () => ({
      body: preview({
        target: { ...candidate().asset, asset_id: TARGET, display_name: "viejo", version: 9 },
        confidence: "low",
        conflicts: ["machine_id_mismatch"],
        reconcile_warnings: ["insufficient_evidence", "machine_id_mismatch"],
        requires_acknowledgement: true,
        source_disposition: "source_deleted",
        source_disposition_reasons: ["no_history"],
      }),
    });
    routes[`POST /assets/${ID}/reconcile`] = (init) => {
      body = JSON.parse(String(init.body)) as Record<string, unknown>;
      return {
        body: reconcileResult({
          target_asset_id: TARGET,
          source_disposition: "source_deleted",
          acknowledged_warnings: ["insufficient_evidence"],
        }),
      };
    };
    renderAs("admin", <LifecyclePanel asset={asset({ monitoring_method: "agent", lifecycle_version: 1 })} onChanged={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "Reconciliar manualmente…" }));
    const dialog = await screen.findByRole("dialog", { name: "Reconciliar con activo existente" });
    expect(dialog).toHaveTextContent(ID);
    fireEvent.click(within(dialog).getByRole("button", { name: "Siguiente" }));
    const input = within(dialog).getByLabelText("Asset ID del destino");
    // Origen y destino nunca pueden ser el mismo activo.
    fireEvent.change(input, { target: { value: ID } });
    expect(within(dialog).getByRole("button", { name: "Ver evidencia" })).toBeDisabled();
    expect(dialog).toHaveTextContent("no puede ser el mismo activo");
    fireEvent.change(input, { target: { value: TARGET } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Ver evidencia" }));
    await within(dialog).findByText(/Conflicto: identidades de máquina distintas/);
    expect(dialog).toHaveTextContent("Confianza baja");
    expect(dialog).toHaveTextContent("no confirmado");
    fireEvent.click(within(dialog).getByRole("button", { name: "Ver impacto" }));
    expect(within(dialog).getByRole("list", { name: "Impacto" })).toHaveTextContent("se elimina");
    fireEvent.click(within(dialog).getByRole("button", { name: "Continuar" }));
    const confirm = within(dialog).getByRole("button", { name: "Reconciliar" });
    expect(confirm).toBeDisabled();
    fireEvent.click(within(dialog).getByRole("checkbox", { name: ACK_WEAK_EVIDENCE }));
    fireEvent.click(confirm);
    await within(dialog).findByText(/Reconciliado/);
    expect(body).toEqual({ target_asset_id: TARGET, version: 1, target_version: 9, acknowledge_weak_evidence: true });
    expect(dialog).toHaveTextContent("se elimina");
    expect(dialog).toHaveTextContent("Avisos aceptados");
  });

  it("asks for the acknowledgement when the server refuses weak evidence", async () => {
    routes[`GET /assets/${ID}/reconcile-preview`] = () => ({ body: preview() });
    let attempts = 0;
    routes[`POST /assets/${ID}/reconcile`] = (init) => {
      attempts += 1;
      const sent = JSON.parse(String(init.body)) as { acknowledge_weak_evidence: boolean };
      if (!sent.acknowledge_weak_evidence) {
        return {
          status: 409,
          body: {
            error: {
              code: "asset_reconcile_refused",
              message: "refused",
              details: [{ blockers: [], reasons: ["insufficient_evidence"], requires_acknowledgement: true }],
            },
          },
        };
      }
      return { body: reconcileResult() };
    };
    renderAs("admin", <LifecyclePanel asset={asset({ monitoring_method: "agent" })} onChanged={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "Reconciliar manualmente…" }));
    const dialog = await screen.findByRole("dialog", { name: "Reconciliar con activo existente" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Siguiente" }));
    fireEvent.change(within(dialog).getByLabelText("Asset ID del destino"), { target: { value: candidate().asset.asset_id } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Ver evidencia" }));
    fireEvent.click(await within(dialog).findByRole("button", { name: "Ver impacto" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Continuar" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Reconciliar" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("confirmes explícitamente");
    fireEvent.click(within(dialog).getByRole("checkbox", { name: ACK_WEAK_EVIDENCE }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Reconciliar" }));
    await within(dialog).findByText(/Reconciliado/);
    expect(attempts).toBe(2);
  });

  it("only admins see manual reconciliation", () => {
    renderAs("analyst", <LifecyclePanel asset={asset({ monitoring_method: "agent" })} onChanged={() => undefined} />);
    expect(screen.queryByRole("button", { name: "Reconciliar manualmente…" })).toBeNull();
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
