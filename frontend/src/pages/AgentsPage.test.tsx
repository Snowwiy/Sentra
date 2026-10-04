// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Agent, EnrollmentToken } from "../api/types";
import { AgentsPage } from "./AgentsPage";

// Test value only: the right shape, never issued by a server.
const TOKEN = "sentra_et_TEST-not-a-real-token_0123456789abcdef";
const NOW = Date.now();
const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();

function agent(overrides: Partial<Agent>): Agent {
  return {
    asset_id: crypto.randomUUID(),
    agent_id: crypto.randomUUID(),
    display_name: "pc",
    hostname: "pc",
    primary_ip: "192.168.50.10",
    os_name: "Linux",
    os_version: "Ubuntu 24.04",
    architecture: "x86_64",
    platform: "linux",
    agent_version: "0.1.0",
    monitoring_method: "agent",
    status: "online",
    credential_status: "active",
    enrolled_at: iso(-86_400_000),
    credential_issued_at: iso(-86_400_000),
    revoked_at: null,
    last_seen_at: iso(-10_000),
    ...overrides,
  };
}

const AGENTS = [
  agent({ hostname: "ravenslg", display_name: "ravenslg", os_name: "Windows", platform: "windows" }),
  agent({ hostname: "linux-off", status: "offline", last_seen_at: iso(-3_600_000) }),
  agent({ hostname: "linux-revoked", status: "offline", credential_status: "revoked", revoked_at: iso(-60_000) }),
  agent({ hostname: "linux-new", status: "unknown", last_seen_at: null }),
];
const [RAVENSLG, OFFLINE, REVOKED] = AGENTS as [Agent, Agent, Agent, Agent];
const SUMMARY = { total: 4, online: 1, offline: 1, pending: 1, revoked: 1 };

function tokenRow(overrides: Partial<EnrollmentToken> = {}): EnrollmentToken {
  return {
    token_id: "11111111-1111-1111-1111-111111111111",
    state: "active",
    created_at: iso(0),
    expires_at: iso(15 * 60_000),
    consumed_at: null,
    revoked_at: null,
    last_used_at: null,
    max_uses: 1,
    use_count: 0,
    expected_platform: "linux",
    expected_hostname: null,
    note: null,
    created_via: "dashboard",
    last_asset_id: null,
    ...overrides,
  };
}

type Handler = (init: RequestInit) => { status?: number; body: unknown };

let routes: Record<string, Handler>;
let calls: { method: string; path: string; init: RequestInit }[];

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  calls = [];
  routes = {
    "GET /agents": () => ({ body: { summary: SUMMARY, items: AGENTS } }),
    "GET /console": () => ({
      body: {
        enrollment_token_ttl_minutes: 15,
        suggested_server_urls: ["http://192.168.50.201:8000"],
        server_url_configured: false,
      },
    }),
    "GET /console/enrollment-tokens": () => ({ body: { items: [] } }),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const path = new URL(input, "http://localhost").pathname.replace("/api/v1", "");
      calls.push({ method, path, init });
      const handler = routes[`${method} ${path}`];
      if (!handler) return json(404, { error: { code: "not_found", message: `no route ${path}` } });
      const { status = 200, body } = handler(init);
      return json(status, body);
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
      <AgentsPage />
    </MemoryRouter>,
  );
}

async function openWizard() {
  renderPage();
  const add = await screen.findByRole("button", { name: "+ Añadir agente" });
  await waitFor(() => expect(add).toBeEnabled());
  fireEvent.click(add);
  return screen.getByRole("dialog", { name: "Añadir agente" });
}

async function generateToken() {
  routes["POST /console/enrollment-tokens"] = () => ({
    status: 201,
    body: { ...tokenRow(), token: TOKEN },
  });
  routes["GET /console/enrollment-tokens"] = () => ({ body: { items: [tokenRow()] } });
  const dialog = await openWizard();
  fireEvent.click(within(dialog).getByRole("button", { name: "Continuar" }));
  fireEvent.click(within(dialog).getByRole("button", { name: "Generar token de instalación" }));
  await within(dialog).findByLabelText("Token de instalación");
  return dialog;
}

describe("AgentsPage", () => {
  it("shows the loading state first", () => {
    renderPage();
    expect(screen.getByRole("status")).toHaveTextContent("Cargando agentes…");
  });

  it("renders summary cards and every agent state", async () => {
    renderPage();
    expect(await screen.findByText("ravenslg")).toBeInTheDocument();
    const stats = screen.getByRole("region", { name: "Agentes por estado" });
    for (const [label, value] of [["Total", 4], ["Online", 1], ["Offline", 1], ["Revoked", 1]] as const) {
      expect(within(stats).getByText(label).nextSibling).toHaveTextContent(String(value));
    }
    const rows = screen.getAllByRole("row").slice(1);
    const stateOf = (name: string) => rows.find((r) => r.textContent?.includes(name))!;
    expect(within(stateOf("ravenslg")).getByText("Online")).toBeInTheDocument();
    expect(within(stateOf("linux-off")).getByText("Offline")).toBeInTheDocument();
    expect(within(stateOf("linux-revoked")).getAllByText("Revoked").length).toBeGreaterThan(0);
    expect(within(stateOf("linux-new")).getByText("Pending")).toBeInTheDocument();
    expect(within(stateOf("linux-revoked")).getByRole("button", { name: "Reactivar…" })).toBeInTheDocument();
  });

  it("filters by state from the summary cards", async () => {
    renderPage();
    await screen.findByText("ravenslg");
    fireEvent.click(screen.getByRole("button", { name: /Revoked/ }));
    expect(screen.queryByText("ravenslg")).not.toBeInTheDocument();
    expect(screen.getByText("linux-revoked")).toBeInTheDocument();
  });

  it("shows an error state when the agent list cannot be loaded", async () => {
    routes["GET /agents"] = () => ({ status: 500, body: { error: { code: "internal_error", message: "boom" } } });
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent("boom");
  });

  it("explains why management is unavailable and disables the actions", async () => {
    routes["GET /console"] = () => ({
      status: 403,
      body: { error: { code: "console_disabled", message: "disabled" } },
    });
    renderPage();
    expect(await screen.findByText(/DASHBOARD_ADMIN_ENABLED=true/, { selector: ".banner" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "+ Añadir agente" })).toBeDisabled();
    expect(screen.getAllByRole("button", { name: "Revocar" })[0]).toBeDisabled();
    expect(calls.some((c) => c.path === "/console/enrollment-tokens")).toBe(false);
  });

  it("explains that only the server's own browser can manage agents", async () => {
    routes["GET /console"] = () => ({
      status: 403,
      body: { error: { code: "console_not_local", message: "not local" } },
    });
    renderPage();
    expect(await screen.findByText(/propio servidor Sentra/, { selector: ".banner" })).toBeInTheDocument();
  });
});

describe("Add agent wizard", () => {
  it("offers Linux and marks Windows as coming soon", async () => {
    const dialog = await openWizard();
    expect(within(dialog).getByRole("radio", { name: /Linux/ })).toHaveAttribute("aria-checked", "true");
    const windows = within(dialog).getByRole("radio", { name: /Windows/ });
    expect(windows).toBeDisabled();
    expect(windows).toHaveTextContent("Próximamente");
  });

  it("suggests the server URL, warns about HTTP and loopback and validates it", async () => {
    const dialog = await openWizard();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continuar" }));
    const url = within(dialog).getByPlaceholderText("http://192.168.1.10:8000");
    expect(url).toHaveValue("http://192.168.50.201:8000");
    expect(dialog).toHaveTextContent("HTTP no cifra las credenciales durante el transporte. Use HTTPS en producción.");
    fireEvent.change(url, { target: { value: "http://localhost:8000" } });
    expect(dialog).toHaveTextContent("localhost/127.0.0.1 es el propio equipo Linux");
    fireEvent.change(url, { target: { value: "https://sentra.lan" } });
    expect(dialog).not.toHaveTextContent("HTTP no cifra");
    fireEvent.change(url, { target: { value: "no es una url" } });
    expect(within(dialog).getByRole("button", { name: "Generar token de instalación" })).toBeDisabled();
  });

  it("generates a one-time Linux token, shows it once with the expiry warning", async () => {
    const dialog = await generateToken();

    const create = calls.find((c) => c.method === "POST" && c.path === "/console/enrollment-tokens")!;
    expect(JSON.parse(create.init.body as string)).toEqual({ expected_platform: "linux", max_uses: 1 });
    expect(create.init.headers).toMatchObject({ "X-Sentra-Console": "1" });
    expect(dialog).toHaveTextContent("Este token solo puede utilizarse una vez y expira en 15 minutos.");
    expect(within(dialog).getByLabelText("Token de instalación")).toHaveTextContent(TOKEN);
    expect(dialog).toHaveTextContent("Esperando a que el equipo se registre");
  });

  it("sends the expected hostname when given", async () => {
    routes["POST /console/enrollment-tokens"] = () => ({ status: 201, body: { ...tokenRow(), token: TOKEN } });
    const dialog = await openWizard();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continuar" }));
    fireEvent.change(within(dialog).getByPlaceholderText("p. ej. pc-ana"), { target: { value: " pc-ana " } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Generar token de instalación" }));
    await within(dialog).findByLabelText("Token de instalación");
    const create = calls.find((c) => c.method === "POST")!;
    expect(JSON.parse(create.init.body as string)).toMatchObject({ expected_hostname: "pc-ana" });
  });

  it("recommended command keeps the token out of the command line; quick one includes it", async () => {
    const dialog = await generateToken();
    const commands = () => within(dialog).getAllByText((_, el) => el?.tagName === "PRE").map((el) => el.textContent);

    expect(commands().join("\n")).not.toContain(TOKEN);
    expect(commands().join("\n")).toContain("--token-file ./enrollment.token");
    expect(commands().join("\n")).toContain("--server 'http://192.168.50.201:8000'");

    fireEvent.click(within(dialog).getByRole("tab", { name: "Método rápido (--token)" }));
    expect(commands().join("\n")).toContain(`--token '${TOKEN}'`);
    expect(dialog).toHaveTextContent("historial de la shell");
  });

  it("copies the installation command to the clipboard", async () => {
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    const dialog = await generateToken();

    const install = within(dialog).getByText(/install-sentra-agent\.sh/, { selector: "pre" });
    fireEvent.click(within(install.parentElement!).getByRole("button", { name: "Copiar" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith(install.textContent));
    expect(await within(install.parentElement!).findByRole("button", { name: "Copiado ✓" })).toBeInTheDocument();
  });

  it("never persists or logs the token, and forgets it when closed", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const logs = (["log", "info", "debug", "warn", "error"] as const).map((level) =>
      vi.spyOn(console, level).mockImplementation(() => undefined),
    );
    const dialog = await generateToken();
    fireEvent.click(within(dialog).getByRole("tab", { name: "Método rápido (--token)" }));

    expect(setItem).not.toHaveBeenCalled();
    for (const spy of logs) {
      expect(JSON.stringify(spy.mock.calls)).not.toContain(TOKEN);
    }
    expect(window.location.href).not.toContain(TOKEN);
    expect(document.cookie).not.toContain(TOKEN);

    fireEvent.click(within(dialog).getAllByRole("button", { name: "Cerrar" })[0]!); // the ✕
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(TOKEN);
  });

  it("shows when the new host has registered", async () => {
    routes["POST /console/enrollment-tokens"] = () => ({ status: 201, body: { ...tokenRow(), token: TOKEN } });
    routes["GET /console/enrollment-tokens"] = () => ({
      body: { items: [tokenRow({ state: "consumed", use_count: 1, last_asset_id: OFFLINE.asset_id })] },
    });
    const dialog = await openWizard();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continuar" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Generar token de instalación" }));

    expect(await within(dialog).findByText("Equipo registrado.")).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "Ver el activo" })).toHaveAttribute(
      "href",
      `/assets/${OFFLINE.asset_id}`,
    );
    expect(within(dialog).queryByLabelText("Token de instalación")).not.toBeInTheDocument();
  });

  it("shows the API error when the token cannot be created", async () => {
    routes["POST /console/enrollment-tokens"] = () => ({
      status: 403,
      body: { error: { code: "console_not_local", message: "Only from the server" } },
    });
    const dialog = await openWizard();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continuar" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Generar token de instalación" }));
    expect(await within(dialog).findByText(/No se pudo generar el token: Only from the server/)).toBeInTheDocument();
  });
});

describe("Revocation", () => {
  it("revokes an agent only after confirmation", async () => {
    routes[`POST /console/agents/${RAVENSLG.asset_id}/revoke`] = () => ({
      body: { ...RAVENSLG, credential_status: "revoked" },
    });
    renderPage();
    await screen.findByText("ravenslg");
    const row = screen.getAllByRole("row").find((r) => r.textContent?.includes("ravenslg"))!;
    await waitFor(() => expect(within(row).getByRole("button", { name: "Revocar" })).toBeEnabled());

    fireEvent.click(within(row).getByRole("button", { name: "Revocar" }));
    let dialog = screen.getByRole("dialog", { name: "Revocar agente" });
    expect(dialog).toHaveTextContent(
      "El agente ravenslg dejará de poder enviar telemetry, heartbeat, inventory y events.",
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancelar" }));
    expect(calls.some((c) => c.method === "POST")).toBe(false);

    fireEvent.click(within(row).getByRole("button", { name: "Revocar" }));
    dialog = screen.getByRole("dialog", { name: "Revocar agente" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Revocar agente" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    const revoke = calls.filter((c) => c.method === "POST");
    expect(revoke.map((c) => c.path)).toEqual([`/console/agents/${RAVENSLG.asset_id}/revoke`]);
    expect(revoke[0]!.init.headers).toMatchObject({ "X-Sentra-Console": "1" });
  });

  it("keeps the dialog open with the error when revocation fails", async () => {
    routes[`POST /console/agents/${RAVENSLG.asset_id}/revoke`] = () => ({
      status: 500,
      body: { error: { code: "internal_error", message: "database down" } },
    });
    renderPage();
    await screen.findByText("ravenslg");
    const row = screen.getAllByRole("row").find((r) => r.textContent?.includes("ravenslg"))!;
    await waitFor(() => expect(within(row).getByRole("button", { name: "Revocar" })).toBeEnabled());
    fireEvent.click(within(row).getByRole("button", { name: "Revocar" }));
    const dialog = screen.getByRole("dialog", { name: "Revocar agente" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Revocar agente" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent("database down");
  });

  it("reinstating a revoked agent requires a new token (re-enrollment)", async () => {
    const revoked = REVOKED;
    routes[`POST /console/agents/${revoked.asset_id}/reinstate`] = () => ({
      body: { ...revoked, credential_status: "re_enrollment_required" },
    });
    renderPage();
    await screen.findByText("linux-revoked");
    const row = screen.getAllByRole("row").find((r) => r.textContent?.includes("linux-revoked"))!;
    await waitFor(() => expect(within(row).getByRole("button", { name: "Reactivar…" })).toBeEnabled());
    fireEvent.click(within(row).getByRole("button", { name: "Reactivar…" }));
    const confirm = screen.getByRole("dialog", { name: "Reactivar agente" });
    expect(confirm).toHaveTextContent("Re-enrollment required");
    fireEvent.click(within(confirm).getByRole("button", { name: "Reactivar" }));

    const wizard = await screen.findByRole("dialog", { name: "Añadir agente" });
    expect(within(wizard).getByPlaceholderText("p. ej. pc-ana")).toHaveValue("linux-revoked");
    expect(wizard).toHaveTextContent("conservará su identidad");
  });

  it("lists installation tokens without their value and revokes an active one", async () => {
    routes["GET /console/enrollment-tokens"] = () => ({
      body: {
        items: [
          tokenRow({ expected_hostname: "pc-ana" }),
          tokenRow({ token_id: "2", state: "consumed", last_asset_id: RAVENSLG.asset_id }),
          tokenRow({ token_id: "3", state: "expired" }),
          tokenRow({ token_id: "4", state: "revoked" }),
        ],
      },
    });
    routes["POST /console/enrollment-tokens/11111111-1111-1111-1111-111111111111/revoke"] = () => ({
      body: tokenRow({ state: "revoked" }),
    });
    renderPage();
    const panel = await screen.findByRole("region", { name: "Tokens de instalación" });
    await within(panel).findByText("pc-ana");
    for (const state of ["Active", "Consumed", "Expired", "Revoked"]) {
      expect(within(panel).getByText(state)).toBeInTheDocument();
    }
    expect(within(panel).getAllByRole("button", { name: "Revocar" })).toHaveLength(1); // only active
    expect(panel.textContent).not.toContain("sentra_et_");

    fireEvent.click(within(panel).getByRole("button", { name: "Revocar" }));
    const dialog = screen.getByRole("dialog", { name: "Revocar token de instalación" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Revocar token" }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/revoke"))).toBe(true),
    );
  });
});
