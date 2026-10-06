// @vitest-environment jsdom
// Fase 4G: login, logout, restauración de sesión, caducidad, rutas protegidas y roles.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setCsrfToken } from "../api/client";
import type { AuthState, Role } from "../api/types";
import { AppRoutes } from "../App";
import { ROLE_PERMISSIONS } from "../test/auth";

const PASSWORD = "correct horse battery staple";

function session(role: Role, csrf = `csrf-${role}`): AuthState {
  return {
    user: { user_id: "u-1", username: `ana-${role}`, role, last_login_at: null },
    permissions: ROLE_PERMISSIONS[role],
    csrf_token: csrf,
    session_expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    server_version: "0.1.0",
  };
}

const SUMMARY = {
  generated_at: new Date().toISOString(),
  assets: { total: 0, online: 0, offline: 0, unknown: 0, by_method: { discovered: 0, agentless: 0, agent: 0 }, by_device_type: {} },
  risk: { by_level: {}, unscored: 0 },
  incidents: { active: 0, critical: 0, unassigned: 0 },
  detections: { active: 0, by_severity: {} },
  active_alerts: 0,
};

type Handler = (init: RequestInit) => { status?: number; body?: unknown };
let routes: Record<string, Handler>;
let calls: { method: string; path: string; init: RequestInit }[];

function json(status: number, body: unknown): Response {
  if (status === 204) return new Response(null, { status });
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const UNAUTHENTICATED = {
  status: 401,
  body: { error: { code: "not_authenticated", message: "Authentication required" } },
};

beforeEach(() => {
  calls = [];
  routes = {
    "GET /auth/me": () => UNAUTHENTICATED,
    "GET /health/ready": () => ({ body: { status: "ready", checks: { database: "ok" } } }),
    "GET /dashboard/summary": () => ({ body: SUMMARY }),
    "GET /assets": () => ({
      body: { items: [], total: 0, limit: 50, offset: 0, status_counts: { online: 0, offline: 0, unknown: 0 } },
    }),
    "GET /alerts": () => ({ body: { items: [], total: 0 } }),
    "GET /agents": () => ({ body: { summary: { total: 0, online: 0, offline: 0, pending: 0, revoked: 0 }, items: [] } }),
    "GET /users": () => ({ body: { items: [] } }),
    "GET /audit": () => ({ body: { items: [] } }),
    "GET /console": () => ({ body: { enrollment_token_ttl_minutes: 15, suggested_server_urls: [], server_url_configured: false } }),
    "GET /console/enrollment-tokens": () => ({ body: { items: [] } }),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const url = new URL(input, "http://localhost");
      const path = url.pathname.replace(/^\/api\/v1/, "");
      const method = init.method ?? "GET";
      calls.push({ method, path, init });
      const handler = routes[`${method} ${path}`];
      if (!handler) return json(404, { error: { code: "not_found", message: `${method} ${path}` } });
      const { status = 200, body } = handler(init);
      return json(status, body);
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  setCsrfToken(undefined);
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AppRoutes />
    </MemoryRouter>,
  );
}

async function signIn(username = "ana", password = PASSWORD) {
  fireEvent.change(await screen.findByLabelText("Usuario"), { target: { value: username } });
  fireEvent.change(screen.getByLabelText("Contraseña"), { target: { value: password } });
  fireEvent.click(screen.getByRole("button", { name: "Entrar" }));
}

describe("login", () => {
  it("sin sesión, cualquier ruta protegida lleva a /login", async () => {
    renderAt("/agents");
    expect(await screen.findByRole("heading", { name: "Iniciar sesión" })).toBeInTheDocument();
    expect(calls.some((c) => c.path === "/agents")).toBe(false);
  });

  it("inicia sesión y vuelve a la página pedida", async () => {
    routes["POST /auth/login"] = () => ({ body: session("viewer") });
    renderAt("/alerts");
    await signIn();
    expect(await screen.findByRole("heading", { name: "Alertas" })).toBeInTheDocument();
    const login = calls.find((c) => c.path === "/auth/login")!;
    expect(JSON.parse(login.init.body as string)).toEqual({ username: "ana", password: PASSWORD });
    expect(login.init.credentials).toBe("include");
    expect(screen.getByText("ana-viewer")).toBeInTheDocument();
    expect(screen.getByText("Solo lectura")).toBeInTheDocument();
  });

  it("error genérico ante credenciales incorrectas y el campo de contraseña se vacía", async () => {
    routes["POST /auth/login"] = () => ({
      status: 401,
      body: { error: { code: "invalid_credentials", message: "Invalid username or password" } },
    });
    renderAt("/");
    await signIn("ana", "equivocada-larga");
    expect(await screen.findByRole("alert")).toHaveTextContent("Usuario o contraseña incorrectos.");
    expect(screen.getByLabelText("Contraseña")).toHaveValue("");
    // Un 401 del login no es "sesión caducada": nada de bucles ni avisos globales.
    expect(calls.filter((c) => c.path === "/auth/me")).toHaveLength(1);
  });

  it("muestra el bloqueo por demasiados intentos", async () => {
    routes["POST /auth/login"] = () => ({
      status: 429,
      body: { error: { code: "rate_limited", message: "Too many login attempts" } },
    });
    renderAt("/");
    await signIn();
    expect(await screen.findByRole("alert")).toHaveTextContent(/Demasiados intentos/);
  });

  it("estado de carga mientras comprueba la sesión y error si la API no responde", async () => {
    routes["GET /auth/me"] = () => ({ status: 503, body: { error: { code: "database_unavailable", message: "down" } } });
    renderAt("/");
    expect(screen.getByRole("status")).toHaveTextContent("Comprobando sesión…");
    expect(await screen.findByText("No se pudo comprobar la sesión")).toBeInTheDocument();
    routes["GET /auth/me"] = () => ({ body: session("admin") });
    fireEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    expect(await screen.findByText("ana-admin")).toBeInTheDocument();
  });
});

describe("sesión", () => {
  it("se restaura con /auth/me sin pedir la contraseña", async () => {
    routes["GET /auth/me"] = () => ({ body: session("analyst") });
    renderAt("/alerts");
    expect(await screen.findByRole("heading", { name: "Alertas" })).toBeInTheDocument();
    expect(screen.getByText("Analista")).toBeInTheDocument();
    expect(calls.some((c) => c.path === "/auth/login")).toBe(false);
  });

  it("envía el token CSRF recibido (solo en memoria) en las mutaciones", async () => {
    routes["GET /auth/me"] = () => ({ body: session("admin", "csrf-abc") });
    routes["POST /auth/logout"] = () => ({ status: 204 });
    renderAt("/");
    fireEvent.click(await screen.findByRole("button", { name: "Cerrar sesión" }));
    await screen.findByRole("heading", { name: "Iniciar sesión" });
    const logout = calls.find((c) => c.path === "/auth/logout")!;
    expect(logout.init.headers).toMatchObject({ "X-CSRF-Token": "csrf-abc" });
  });

  it("logout vuelve al login y deja de consultar la API", async () => {
    routes["GET /auth/me"] = () => ({ body: session("viewer") });
    routes["POST /auth/logout"] = () => ({ status: 204 });
    renderAt("/");
    fireEvent.click(await screen.findByRole("button", { name: "Cerrar sesión" }));
    expect(await screen.findByRole("heading", { name: "Iniciar sesión" })).toBeInTheDocument();
    const before = calls.length;
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(calls.length).toBe(before);
  });

  it("sesión caducada (401 en un panel): limpia el estado y lleva al login una sola vez", async () => {
    // /auth/me aún era válida al cargar, pero la sesión caduca (o la revoca un admin) antes
    // de que los paneles consulten la API.
    routes["GET /auth/me"] = () => ({ body: session("viewer") });
    routes["GET /alerts"] = () => UNAUTHENTICATED;
    renderAt("/alerts");
    expect(await screen.findByRole("heading", { name: "Iniciar sesión" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/sesión ha caducado/);
    // Sin bucle: ni /auth/me ni /alerts se repiten por el 401.
    const before = calls.length;
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(calls.length).toBe(before);
    expect(calls.filter((c) => c.path === "/auth/me")).toHaveLength(1);
  });
});

describe("navegación por rol", () => {
  it.each([
    ["viewer", false],
    ["analyst", false],
    ["admin", true],
  ] as const)("%s: enlace a Usuarios = %s", async (role, visible) => {
    routes["GET /auth/me"] = () => ({ body: session(role) });
    renderAt("/");
    await screen.findByText(`ana-${role}`);
    const nav = screen.getByRole("navigation");
    if (visible) expect(within(nav).getByRole("link", { name: "Usuarios" })).toBeInTheDocument();
    else expect(within(nav).queryByRole("link", { name: "Usuarios" })).not.toBeInTheDocument();
  });

  it("una ruta de admin escrita a mano muestra acceso restringido y no consulta la API", async () => {
    routes["GET /auth/me"] = () => ({ body: session("analyst") });
    renderAt("/admin/users");
    expect(await screen.findByRole("heading", { name: "Acceso restringido" })).toBeInTheDocument();
    expect(calls.some((c) => c.path === "/users")).toBe(false);
  });

  it("admin: página de usuarios, crear usuario con confirmación de contraseña", async () => {
    routes["GET /auth/me"] = () => ({ body: session("admin") });
    let created: unknown;
    routes["POST /users"] = (init) => {
      created = JSON.parse(String(init.body));
      return { status: 201, body: {} };
    };
    renderAt("/admin/users");
    fireEvent.click(await screen.findByRole("button", { name: "+ Nuevo usuario" }));
    const dialog = screen.getByRole("dialog", { name: "Nuevo usuario" });
    fireEvent.change(within(dialog).getByLabelText(/^Usuario/), { target: { value: "pepe" } });
    fireEvent.change(within(dialog).getByLabelText(/^Contraseña/), { target: { value: PASSWORD } });
    fireEvent.change(within(dialog).getByLabelText("Repetir contraseña"), { target: { value: "otra cosa distinta" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Crear usuario" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Las contraseñas no coinciden.");
    fireEvent.change(within(dialog).getByLabelText("Repetir contraseña"), { target: { value: PASSWORD } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Crear usuario" }));
    await waitFor(() => expect(created).toEqual({ username: "pepe", password: PASSWORD, role: "viewer" }));
  });
});

describe("alertas por rol", () => {
  const ALERT = {
    alert_id: "a-1",
    asset_id: "as-1",
    hostname: "pc-1",
    rule: "high_cpu",
    severity: "warning",
    status: "open",
    message: "CPU alta",
    value: 95,
    details: null,
    occurrences: 1,
    last_triggered_at: null,
    opened_at: new Date().toISOString(),
    acknowledged_at: null,
    resolved_at: null,
  };

  async function openAlert(role: Role) {
    routes["GET /auth/me"] = () => ({ body: session(role) });
    routes["GET /alerts"] = () => ({ body: { items: [ALERT], total: 1 } });
    renderAt("/alerts");
    fireEvent.click(await screen.findByText("CPU alta"));
  }

  it("viewer: ve la alerta pero no puede reconocerla ni resolverla", async () => {
    await openAlert("viewer");
    expect(await screen.findByText("Ocurrencias")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reconocer" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resolver" })).not.toBeInTheDocument();
  });

  it("analyst: reconoce la alerta", async () => {
    routes["POST /alerts/a-1/acknowledge"] = () => ({ body: { ...ALERT, status: "acknowledged" } });
    await openAlert("analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Reconocer" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/alerts/a-1/acknowledge")).toBe(true));
  });

  it("un 403 del backend se explica aunque la UI mostrara el botón", async () => {
    routes["POST /alerts/a-1/resolve"] = () => ({
      status: 403,
      body: { error: { code: "permission_denied", message: "Your role does not allow" } },
    });
    await openAlert("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Resolver" }));
    expect(await screen.findByText("Tu rol no permite esta acción.")).toBeInTheDocument();
  });
});
