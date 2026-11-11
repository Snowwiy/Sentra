// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { WithRole } from "../../test/auth";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Agent } from "../../api/types";
import { AgentPanel } from "./AgentPanel";

const AGENT: Agent = {
  asset_id: "6f1c2a8e-0000-4000-8000-000000000001",
  agent_id: "0b3d5c7e-0000-4000-8000-000000000002",
  display_name: "pc-linux",
  hostname: "pc-linux",
  primary_ip: "192.168.50.30",
  os_name: "Linux",
  os_version: "Ubuntu 24.04",
  architecture: "x86_64",
  platform: "linux",
  agent_version: "0.1.0",
  installation_method: null,
  monitoring_method: "agent",
  status: "online",
  credential_status: "active",
  enrolled_at: new Date().toISOString(),
  credential_issued_at: new Date().toISOString(),
  revoked_at: null,
  last_seen_at: new Date().toISOString(),
  asset_state: "active",
  archived_at: null,
  lifecycle_version: 0,
  site_id: "00000000-0000-0000-0000-00000000d5f1",
  site_name: "Principal",
  credential_source: "enrollment_token",
  rotation_pending: false,
  rotation_requested_at: null,
  rotation_reason: null,
  transport: "https",
  transport_at: null,
  insecure_transport_at: null,
  ingest_throttled_at: null,
  ingest_rejections: 0,
};

let agent: Agent;
const posts: string[] = [];

beforeEach(() => {
  agent = { ...AGENT };
  posts.length = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const path = new URL(input, "http://localhost").pathname.replace("/api/v1", "");
      const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
      if (init.method === "POST") {
        posts.push(path);
        if (path.endsWith("/rotate-credential")) {
          agent = { ...agent, rotation_requested_at: new Date().toISOString(), rotation_reason: "operator_request" };
          return ok(agent);
        }
        agent = { ...agent, credential_status: "revoked", revoked_at: new Date().toISOString() };
        return ok(agent);
      }
      if (path === `/assets/${AGENT.asset_id}/agent`) return ok(agent);
      if (path === "/console") {
        return ok({ enrollment_token_ttl_minutes: 15, suggested_server_urls: [], server_url_configured: false });
      }
      return new Response("{}", { status: 404 });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("AgentPanel (asset detail)", () => {
  it("shows the agent identity and credential state, without remote control", async () => {
    render(
      <MemoryRouter>
        <WithRole role="admin">
          <AgentPanel assetId={AGENT.asset_id} />
        </WithRole>
      </MemoryRouter>,
    );
    const panel = await screen.findByRole("region", { name: "Agent" });
    await within(panel).findByText(AGENT.agent_id);
    expect(panel).toHaveTextContent("0.1.0");
    expect(panel).toHaveTextContent("Linux");
    expect(panel).toHaveTextContent("Activa");
    expect(panel).toHaveTextContent("No reportado");
    expect(within(panel).getByRole("button", { name: "Reiniciar agente" })).toBeDisabled();
  });

  it("shows the ingest quota state of the agent (7D.2 H06)", async () => {
    agent = { ...AGENT, ingest_throttled_at: new Date().toISOString(), ingest_rejections: 2 };
    render(
      <MemoryRouter>
        <WithRole role="admin">
          <AgentPanel assetId={AGENT.asset_id} />
        </WithRole>
      </MemoryRouter>,
    );
    const panel = await screen.findByRole("region", { name: "Agent" });
    await within(panel).findByText(/Limitado/);
    expect(panel).toHaveTextContent("(2 rechazos)");
  });

  it("shows an agent that was never throttled as not limited", async () => {
    render(
      <MemoryRouter>
        <WithRole role="admin">
          <AgentPanel assetId={AGENT.asset_id} />
        </WithRole>
      </MemoryRouter>,
    );
    const panel = await screen.findByRole("region", { name: "Agent" });
    await within(panel).findByText("Sin limitar");
  });

  it("shows the installation method reported by the agent", async () => {
    agent = { ...AGENT, platform: "windows", os_name: "Windows", installation_method: "windows_service" };
    render(
      <MemoryRouter>
        <WithRole role="admin">
          <AgentPanel assetId={AGENT.asset_id} />
        </WithRole>
      </MemoryRouter>,
    );
    const panel = await screen.findByRole("region", { name: "Agent" });
    await within(panel).findByText("Servicio Windows");
    expect(panel).not.toHaveTextContent("No reportado");
    expect(within(panel).getByRole("button", { name: "Reiniciar agente" })).toHaveAttribute(
      "title",
      expect.stringContaining("Restart-Service SentraAgent"),
    );
  });

  it("revokes after confirmation and then shows the agent as revoked", async () => {
    render(
      <MemoryRouter>
        <WithRole role="admin">
          <AgentPanel assetId={AGENT.asset_id} />
        </WithRole>
      </MemoryRouter>,
    );
    const panel = await screen.findByRole("region", { name: "Agent" });
    const revoke = await within(panel).findByRole("button", { name: "Revocar agente" });
    await waitFor(() => expect(revoke).toBeEnabled());
    fireEvent.click(revoke);
    const dialog = screen.getByRole("dialog", { name: "Revocar agente" });
    expect(dialog).toHaveTextContent("pc-linux dejará de poder enviar telemetry, heartbeat, inventory y events");
    fireEvent.click(within(dialog).getByRole("button", { name: "Revocar agente" }));

    await waitFor(() => expect(posts).toEqual([`/console/agents/${AGENT.asset_id}/revoke`]));
    expect(await within(panel).findByRole("button", { name: "Reactivar…" })).toBeInTheDocument();
    expect(within(panel).getAllByText("Revocado").length).toBeGreaterThan(0);
  });

  it("requests a credential rotation and shows it as requested (7D.1 H01)", async () => {
    render(
      <MemoryRouter>
        <WithRole role="admin">
          <AgentPanel assetId={AGENT.asset_id} />
        </WithRole>
      </MemoryRouter>,
    );
    const panel = await screen.findByRole("region", { name: "Agent" });
    expect(await within(panel).findByText("Token de instalación")).toBeInTheDocument();
    expect(within(panel).getByText("HTTPS")).toHaveClass("badge--ok");
    const rotate = within(panel).getByRole("button", { name: "Rotar credencial…" });
    await waitFor(() => expect(rotate).toBeEnabled());
    fireEvent.click(rotate);
    const dialog = screen.getByRole("dialog", { name: "Rotar credencial" });
    expect(dialog).toHaveTextContent("no hay corte de monitorización");
    fireEvent.click(within(dialog).getByRole("button", { name: "Pedir rotación" }));
    await waitFor(() => expect(posts).toEqual([`/console/agents/${AGENT.asset_id}/rotate-credential`]));
    expect(await within(panel).findByText("(rotación pedida)")).toBeInTheDocument();
  });

  it("warns about cleartext HTTP without cutting the agent off (7D.1 H04)", async () => {
    agent = { ...AGENT, transport: "http_remote" };
    render(
      <MemoryRouter>
        <WithRole role="admin">
          <AgentPanel assetId={AGENT.asset_id} />
        </WithRole>
      </MemoryRouter>,
    );
    const panel = await screen.findByRole("region", { name: "Agent" });
    expect(await within(panel).findByText("HTTP en claro")).toHaveClass("badge--warn");
    expect(within(panel).getByRole("alert")).toHaveTextContent("Sigue monitorizado");
  });
});
