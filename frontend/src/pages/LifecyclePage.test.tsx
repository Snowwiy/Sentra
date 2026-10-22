// @vitest-environment jsdom
// Fase 5C.2: página de administración del ciclo de vida (política, vista previa y limpieza).
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthState, CleanupCandidate, CleanupPreview, Role } from "../api/types";
import { AppRoutes } from "../App";
import { IRREVERSIBLE_WARNING } from "../lib/lifecycle";
import { ROLE_PERMISSIONS, WithRole } from "../test/auth";
import { LifecyclePage } from "./LifecyclePage";

// Datos sintéticos de test: no proceden de ningún host real.
function row(n: number, overrides: Partial<CleanupCandidate> = {}): CleanupCandidate {
  return {
    asset_id: `00000000-0000-4000-8000-00000000000${n}`,
    display_name: `fantasma-${n}`,
    hostname: null,
    primary_ip: `192.168.50.${n}`,
    mac_address: null,
    platform: null,
    monitoring_method: "discovered",
    lifecycle_source: "discovered",
    lifecycle_state: "cleanup_candidate",
    status: "offline",
    last_seen_at: null,
    last_network_seen_at: null,
    last_activity_at: new Date(Date.now() - 40 * 86_400_000).toISOString(),
    missed_successful_scans: 7,
    stale_for_hours: 900,
    action: "hard_delete_eligible",
    hard_delete_eligible: true,
    blocking_reasons: [],
    dependencies: {},
    version: n,
    ...overrides,
  };
}

function previewBody(items: CleanupCandidate[], batch = 2): CleanupPreview {
  return {
    generated_at: new Date().toISOString(),
    policy: {
      discovered_stale_after_hours: 72,
      discovered_stale_missed_scans: 3,
      discovered_purge_after_days: 30,
      managed_stale_after_days: 30,
      auto_cleanup: false,
      batch_size: batch,
    },
    total: items.length,
    limit: 50,
    offset: 0,
    counts: { keep: 0, mark_stale: 1, archive_candidate: 0, hard_delete_eligible: 3, blocked: 1 },
    items,
  };
}

type Handler = (init: RequestInit, url: URL) => { status?: number; body?: unknown };
let routes: Record<string, Handler>;
let calls: { method: string; path: string; url: URL; init: RequestInit }[];

const json = (status: number, body: unknown) =>
  status === 204 ? new Response(null, { status }) : new Response(JSON.stringify(body), { status });

beforeEach(() => {
  calls = [];
  routes = {
    "GET /assets/lifecycle/cleanup-preview": () => ({
      body: previewBody([
        row(1),
        row(2),
        row(3),
        row(4, {
          action: "blocked",
          hard_delete_eligible: false,
          lifecycle_state: "stale",
          blocking_reasons: ["purge_window_not_reached"],
          dependencies: { detections: 2 },
        }),
      ]),
    }),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const url = new URL(input, "http://localhost");
      const path = url.pathname.replace(/^\/api\/v1/, "");
      const method = init.method ?? "GET";
      calls.push({ method, path, url, init });
      const handler = routes[`${method} ${path}`];
      if (!handler) return json(404, { error: { code: "not_found", message: `${method} ${path}` } });
      const { status = 200, body } = handler(init, url);
      return json(status, body);
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderPage() {
  return render(
    <MemoryRouter>
      <WithRole role="admin">
        <LifecyclePage />
      </WithRole>
    </MemoryRouter>,
  );
}

describe("LifecyclePage", () => {
  it("shows the policy, counters, preview rows and blocking reasons; filters go to the server", async () => {
    renderPage();
    const policy = await screen.findByRole("region", { name: "Política de limpieza" });
    expect(policy).toHaveTextContent("72 h y 3 escaneos completos");
    expect(policy).toHaveTextContent("30 días");
    expect(policy).toHaveTextContent("Limpieza automática desactivada");
    const counters = screen.getByRole("region", { name: "Activos por acción" });
    expect(within(counters).getByRole("button", { name: /Eliminable\s*3/ })).toBeInTheDocument();
    expect(screen.getByText("fantasma-1")).toBeInTheDocument();
    expect(screen.getAllByText("Candidato a limpieza").length).toBeGreaterThan(0);
    expect(screen.getByText(/todavía no ha pasado la ventana de purga/)).toBeInTheDocument();
    expect(screen.getByText(/2 detecciones/)).toBeInTheDocument();

    fireEvent.change(screen.getByRole("combobox", { name: "Acción" }), { target: { value: "blocked" } });
    await waitFor(() => expect(calls.at(-1)?.url.searchParams.get("action")).toBe("blocked"));
    fireEvent.change(screen.getByRole("combobox", { name: "Origen" }), { target: { value: "monitored" } });
    await waitFor(() => expect(calls.at(-1)?.url.searchParams.get("source")).toBe("monitored"));
    expect(calls.at(-1)?.url.searchParams.get("limit")).toBe("50");
  });

  it("hard deletes only eligible rows, never more than the batch size, after listing them", async () => {
    let body: unknown;
    routes["POST /assets/lifecycle/cleanup"] = (init) => {
      body = JSON.parse(String(init.body));
      return {
        body: {
          action: "hard_delete",
          requested: 1,
          succeeded: 0,
          skipped: 1,
          results: [{ asset_id: row(1).asset_id, outcome: "skipped", reasons: ["version_conflict"], display_name: "fantasma-1" }],
        },
      };
    };
    renderPage();
    await screen.findByText("fantasma-1");
    // Lote de 2: la tercera casilla queda deshabilitada.
    fireEvent.click(screen.getByRole("checkbox", { name: "Seleccionar fantasma-1" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Seleccionar fantasma-4" }));
    expect(screen.getByRole("checkbox", { name: "Seleccionar fantasma-2" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Eliminar definitivamente" }));
    const dialog = screen.getByRole("dialog", { name: "Eliminar definitivamente" });
    expect(dialog).toHaveTextContent(IRREVERSIBLE_WARNING);
    const list = within(dialog).getByRole("list", { name: "Activos a eliminar" });
    expect(list).toHaveTextContent("fantasma-1");
    expect(list).toHaveTextContent("192.168.50.1");
    expect(list).toHaveTextContent(row(1).asset_id);
    expect(list).not.toHaveTextContent("fantasma-4");
    expect(dialog).toHaveTextContent("se ignoran 1 seleccionados que no son elegibles");
    fireEvent.click(within(dialog).getByRole("button", { name: "Eliminar definitivamente" }));
    const result = await screen.findByRole("region", { name: "Resultado de la limpieza" });
    expect(body).toEqual({ action: "hard_delete", items: [{ asset_id: row(1).asset_id, version: 1 }] });
    expect(result).toHaveTextContent("1 omitidos");
    expect(result).toHaveTextContent("cambió desde la vista previa");
  });

  it("archives the selection with a mandatory reason", async () => {
    let body: unknown;
    routes["POST /assets/lifecycle/cleanup"] = (init) => {
      body = JSON.parse(String(init.body));
      return {
        body: {
          action: "archive",
          requested: 1,
          succeeded: 1,
          skipped: 0,
          results: [{ asset_id: row(4).asset_id, outcome: "archived", reasons: [], display_name: "fantasma-4" }],
        },
      };
    };
    renderPage();
    await screen.findByText("fantasma-4");
    expect(screen.getByRole("button", { name: "Eliminar definitivamente" })).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: "Seleccionar fantasma-4" }));
    expect(screen.getByRole("button", { name: "Eliminar definitivamente" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Archivar seleccionados" }));
    const dialog = screen.getByRole("dialog", { name: "Archivar seleccionados" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Archivar" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Indica un motivo");
    fireEvent.change(within(dialog).getByRole("textbox"), { target: { value: "Retirados" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Archivar" }));
    const result = await screen.findByRole("region", { name: "Resultado de la limpieza" });
    expect(body).toEqual({ action: "archive", items: [{ asset_id: row(4).asset_id, version: 4 }], reason: "Retirados" });
    expect(result).toHaveTextContent("1 archivados");
  });
});

function session(role: Role): AuthState {
  return {
    user: { user_id: "u-1", username: `ana-${role}`, role, last_login_at: null },
    permissions: ROLE_PERMISSIONS[role],
    csrf_token: `csrf-${role}`,
    session_expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    server_version: "0.2.0",
  };
}

describe("Ciclo de vida: permisos", () => {
  beforeEach(() => {
    Object.assign(routes, {
      "GET /health/ready": () => ({ body: { status: "ready", checks: { database: "ok" } } }),
      "GET /dashboard/summary": () => ({
        body: {
          generated_at: new Date().toISOString(),
          assets: { total: 0, online: 0, offline: 0, unknown: 0, by_method: { discovered: 0, agentless: 0, agent: 0 }, by_device_type: {} },
          risk: { by_level: {}, unscored: 0 },
          incidents: { active: 0, critical: 0, unassigned: 0 },
          detections: { active: 0, by_severity: {} },
          active_alerts: 0,
        },
      }),
      "GET /assets": () => ({
        body: { items: [], total: 0, limit: 50, offset: 0, status_counts: { online: 0, offline: 0, unknown: 0 } },
      }),
      "GET /alerts": () => ({ body: { items: [], total: 0 } }),
      "GET /events": () => ({ body: { items: [], total: 0, has_more: false } }),
    });
  });

  it.each([
    ["viewer", false],
    ["analyst", false],
    ["admin", true],
  ] as const)("%s: enlace a Ciclo de vida = %s", async (role, visible) => {
    routes["GET /auth/me"] = () => ({ body: session(role) });
    render(
      <MemoryRouter initialEntries={["/"]}>
        <AppRoutes />
      </MemoryRouter>,
    );
    await screen.findByText(`ana-${role}`);
    const nav = screen.getByRole("navigation");
    if (visible) expect(within(nav).getByRole("link", { name: "Ciclo de vida" })).toBeInTheDocument();
    else expect(within(nav).queryByRole("link", { name: "Ciclo de vida" })).not.toBeInTheDocument();
  });

  it("an analyst typing the URL gets restricted access and no preview request", async () => {
    routes["GET /auth/me"] = () => ({ body: session("analyst") });
    render(
      <MemoryRouter initialEntries={["/admin/lifecycle"]}>
        <AppRoutes />
      </MemoryRouter>,
    );
    expect(await screen.findByRole("heading", { name: "Acceso restringido" })).toBeInTheDocument();
    expect(calls.some((c) => c.path.startsWith("/assets/lifecycle"))).toBe(false);
  });

  it("an admin opens the page from the route", async () => {
    routes["GET /auth/me"] = () => ({ body: session("admin") });
    render(
      <MemoryRouter initialEntries={["/admin/lifecycle"]}>
        <AppRoutes />
      </MemoryRouter>,
    );
    expect(await screen.findByRole("heading", { name: "Ciclo de vida" })).toBeInTheDocument();
  });
});
