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
    expect(panel).toHaveTextContent("Active");
    expect(panel).toHaveTextContent("No reportado");
    expect(within(panel).getByRole("button", { name: "Reiniciar agente" })).toBeDisabled();
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
    expect(within(panel).getAllByText("Revoked").length).toBeGreaterThan(0);
  });
});
