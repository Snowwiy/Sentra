// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MaintenanceOperationRead, Role } from "../api/types";
import { WithRole } from "../test/auth";
import { installFetch, type Call, type Handler } from "../test/sites";
import { MaintenancePage } from "./MaintenancePage";

const ASSET = "a7000000-0000-0000-0000-000000000002";
const OP = "0b000000-0000-0000-0000-000000000001";
const SHA = "c".repeat(64);
const NOW = new Date().toISOString();

function operation(overrides: Partial<MaintenanceOperationRead> = {}): MaintenanceOperationRead {
  return {
    id: OP,
    operation_key: "0c000000-0000-0000-0000-000000000001",
    version: 1,
    supersedes: null,
    asset_id: ASSET,
    asset_name: "ravenslg",
    kind: "agent_install",
    title: "Instalación del agente 0.6.1",
    reason: "Instalación inicial del agente en el PC de desarrollo",
    status: "pending_review",
    active: false,
    window_start: NOW,
    window_end: NOW,
    expires_at: NOW,
    accounts: ["ravenslg\\jesus"],
    interpreters: [],
    parents: [],
    signer: null,
    artifacts: [
      {
        kind: "script",
        path: "c:\\sentra\\scripts\\install-sentra-agent.ps1",
        sha256: SHA,
        signer: null,
        reference_source: "server_distribution",
        service_name: null,
        service_display_name: null,
        image_path: null,
        service_account: null,
      },
    ],
    created_by: "user:admin",
    created_at: NOW,
    approved_by: null,
    approved_at: null,
    approval_note: null,
    revoked_by: null,
    revoked_at: null,
    revoke_reason: null,
    matches: 0,
    last_match_at: null,
    ...overrides,
  };
}

let routes: Record<string, Handler>;
let calls: Call[];

beforeEach(() => {
  routes = {
    "GET /maintenance-operations": () => ({ body: { items: [operation()], total: 1 } }),
    "GET /maintenance-operations/reference-artifacts": () => ({
      body: {
        root_available: true,
        items: [{ name: "install-sentra-agent.ps1", relative_path: "agent/packaging/windows/install-sentra-agent.ps1", sha256: SHA, size: 100 }],
      },
    }),
    "GET /assets": () => ({ body: { items: [{ asset_id: ASSET, display_name: "ravenslg", primary_ip: "192.168.50.10" }], total: 1 } }),
  };
  calls = installFetch(routes);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderPage(role: Role) {
  return render(
    <MemoryRouter>
      <WithRole role={role}>
        <MaintenancePage />
      </WithRole>
    </MemoryRouter>,
  );
}

const posts = (path: string) =>
  calls.filter((c) => c.method === "POST" && c.path === path).map((c) => JSON.parse(String(c.init.body)) as Record<string, unknown>);

describe("MaintenancePage (Fase 7B.1)", () => {
  it("analista: ve las operaciones pero no registra ni aprueba", async () => {
    renderPage("analyst");
    expect(await screen.findByText("Instalación del agente 0.6.1")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Registrar operación" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Aprobar" })).toBeNull();
  });

  it("admin: registra una operación con el hash de referencia del servidor; sin hash no se envía", async () => {
    routes["POST /maintenance-operations"] = () => ({ status: 201, body: operation() });
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Registrar operación" }));
    const dialog = await screen.findByRole("dialog", { name: "Registrar operación de mantenimiento" });
    await within(dialog).findByRole("option", { name: "ravenslg" });
    fireEvent.change(within(dialog).getByLabelText("Equipo"), { target: { value: ASSET } });
    fireEvent.change(within(dialog).getByLabelText("Título"), { target: { value: "Instalación del agente" } });
    fireEvent.change(within(dialog).getByLabelText("Motivo"), { target: { value: "Instalación inicial en el PC de desarrollo" } });
    fireEvent.change(within(dialog).getByLabelText("Ruta completa 1"), {
      target: { value: "C:\\Sentra\\scripts\\install-sentra-agent.ps1" },
    });
    const submit = within(dialog).getByRole("button", { name: "Registrar (pendiente de aprobar)" });
    fireEvent.click(submit);
    expect(within(dialog).getByRole("alert")).toHaveTextContent("Un script o binario necesita ruta completa y SHA-256.");
    expect(posts("/maintenance-operations")).toHaveLength(0);

    const refSelect = await within(dialog).findByLabelText("Hash de referencia del servidor 1");
    fireEvent.change(refSelect, { target: { value: "agent/packaging/windows/install-sentra-agent.ps1" } });
    expect(within(dialog).getByLabelText("SHA-256 1")).toHaveValue(SHA);
    fireEvent.change(within(dialog).getByLabelText("Cuentas que ejecutan (una por línea)"), {
      target: { value: "RAVENSLG\\jesus\n" },
    });
    fireEvent.click(submit);
    await waitFor(() => expect(posts("/maintenance-operations")).toHaveLength(1));
    expect(posts("/maintenance-operations")[0]).toMatchObject({
      asset_id: ASSET,
      accounts: ["RAVENSLG\\jesus"],
      artifacts: [
        {
          kind: "script",
          path: "C:\\Sentra\\scripts\\install-sentra-agent.ps1",
          sha256: SHA,
          reference_source: "server_distribution",
        },
      ],
    });
  });

  it("admin: aprueba, revisa la vista previa y aplica solo tras pulsar", async () => {
    let approved = false;
    routes["GET /maintenance-operations"] = () => ({
      body: { items: [operation(approved ? { status: "approved", approved_by: "user:admin" } : {})], total: 1 },
    });
    routes[`POST /maintenance-operations/${OP}/approve`] = () => {
      approved = true;
      return { body: operation({ status: "approved" }) };
    };
    routes[`POST /maintenance-operations/${OP}/preview`] = () => ({
      body: {
        operation_id: OP,
        verified: 1,
        not_verified: 0,
        items: [
          {
            detection_id: "d7000000-0000-0000-0000-000000000009",
            rule_id: "SCR-001",
            title: "PowerShell sospechoso",
            status: "open",
            current_verdict: "suspicious_unverified",
            verdict: "verified_benign",
            would_resolve: true,
            attribution: {},
          },
        ],
      },
    });
    routes[`POST /maintenance-operations/${OP}/apply`] = () => ({
      body: { operation_id: OP, evaluated: 1, verified: 1, resolved: 1 },
    });
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Aprobar" }));
    const dialog = await screen.findByRole("dialog", { name: "Aprobar operación" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Aprobar" }));
    await waitFor(() => expect(posts(`/maintenance-operations/${OP}/approve`)).toEqual([{ note: null }]));

    fireEvent.click(await screen.findByRole("button", { name: "Vista previa" }));
    const preview = await screen.findByRole("dialog", { name: "Vista previa: Instalación del agente 0.6.1" });
    expect(await within(preview).findByText("Verificada como legítima")).toBeInTheDocument();
    expect(posts(`/maintenance-operations/${OP}/apply`)).toHaveLength(0);
    fireEvent.click(within(preview).getByRole("button", { name: "Aplicar veredictos" }));
    expect(await within(preview).findByText("Evaluadas 1, verificadas 1, cerradas 1.")).toBeInTheDocument();
    expect(posts(`/maintenance-operations/${OP}/apply`)).toEqual([{ confirm: true }]);
  });
});
