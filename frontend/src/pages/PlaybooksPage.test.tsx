// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Playbook, ResponseAction, Role } from "../api/types";
import { WithRole } from "../test/auth";
import { PlaybooksPage } from "./PlaybooksPage";

const NOW = new Date().toISOString();

function action(id: string, risk: string, overrides: Partial<ResponseAction> = {}): ResponseAction {
  return {
    id,
    name: id,
    description: "",
    category: "analysis",
    scope: "server",
    target_type: "asset",
    risk_level: risk,
    destructive: false,
    requires_confirmation: risk !== "low",
    requires_agent: false,
    supported_platforms: [],
    required_role: risk === "low" ? "analyst" : "admin",
    required_permissions: [],
    timeout_seconds: 60,
    retry_policy: "none",
    availability: "available",
    expected_effect: "",
    parameters_schema: { properties: {}, type: "object" },
    permitted: true,
    blockers: [],
    ...overrides,
  };
}

const ACTIONS = [
  action("recalculate_risk", "low"),
  action("archive_asset", "medium", {
    parameters_schema: { properties: { reason: { minLength: 3, type: "string" } }, required: ["reason"] },
  }),
  action("add_incident_note", "medium", { target_type: "incident" }),
  action("isolate_host", "critical", { availability: "not_implemented" }),
];

const BUILTIN: Playbook = {
  playbook_id: "11111111-0000-0000-0000-000000000001",
  key: "investigate_endpoint",
  name: "Investigar endpoint",
  description: "Recolecta y reevalúa.",
  builtin: true,
  enabled: true,
  version: 1,
  risk_level: "low",
  required_role: "analyst",
  requires_confirmation: false,
  requires_agent: true,
  steps: [
    {
      order: 1,
      action_id: "recalculate_risk",
      action_name: "Recalcular riesgo",
      parameters: {},
      on_success: "continue",
      on_failure: "continue",
      timeout_seconds: 60,
      risk_level: "low",
    },
  ],
  created_by: "system",
  created_at: NOW,
  updated_at: NOW,
  revision: 1,
  permitted: true,
  blockers: [],
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const path = new URL(input, "http://localhost").pathname.replace("/api/v1", "");
      if (method === "GET" && path === "/response/playbooks") return json(200, { items: [BUILTIN] });
      if (method === "GET" && path === "/response/actions") {
        return json(200, { items: ACTIONS, response_enabled: true, playbooks_enabled: true });
      }
      return json(404, { error: { code: "not_found", message: path } });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderPage(role: Role) {
  render(
    <MemoryRouter>
      <WithRole role={role}>
        <PlaybooksPage />
      </WithRole>
    </MemoryRouter>,
  );
}

describe("PlaybooksPage", () => {
  it("shows builtin playbooks to viewers without execute or manage buttons", async () => {
    renderPage("viewer");
    const card = await screen.findByRole("region", { name: "Investigar endpoint" });
    expect(within(card).getByText("Integrado")).toBeInTheDocument();
    expect(within(card).queryByRole("button")).toBeNull();
    expect(screen.queryByRole("button", { name: "Nuevo playbook" })).toBeNull();
  });

  it("lets analysts run but not manage", async () => {
    renderPage("analyst");
    const card = await screen.findByRole("region", { name: "Investigar endpoint" });
    expect(within(card).getByRole("button", { name: "Ejecutar" })).toBeEnabled();
    expect(within(card).queryByRole("button", { name: "Desactivar" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Nuevo playbook" })).toBeNull();
  });

  it("offers only available asset actions and 'continue' only on low-risk steps", async () => {
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Nuevo playbook" }));
    fireEvent.click(await screen.findByRole("button", { name: "Añadir paso" }));

    const actionSelect = screen.getByLabelText("Acción del paso 1");
    const options = within(actionSelect).getAllByRole("option").map((o) => o.getAttribute("value"));
    expect(options).toEqual(["recalculate_risk", "archive_asset"]);

    const onFailure = () => within(screen.getByLabelText("Si falla el paso 1")).getAllByRole("option");
    expect(onFailure().map((o) => o.getAttribute("value"))).toEqual(["stop", "continue"]);

    fireEvent.change(actionSelect, { target: { value: "archive_asset" } });
    expect(onFailure().map((o) => o.getAttribute("value"))).toEqual(["stop"]);
  });
});
