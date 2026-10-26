// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Role } from "../api/types";
import { OwnerSelect } from "../components/incidents/OwnerSelect";
import { WithRole } from "../test/auth";
import { MyTasksPage } from "./MyTasksPage";

// Datos sintéticos de test: no proceden de ningún host real.
const iso = () => new Date().toISOString();
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

let urls: URL[];

beforeEach(() => {
  urls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string) => {
      const url = new URL(input, "http://localhost");
      urls.push(url);
      const path = url.pathname.replace("/api/v1", "");
      if (path === "/tasks") {
        return json(200, {
          items: [
            {
              task_id: "t1",
              incident_id: "i1",
              incident_key: "INC-000009",
              kind: "verify_service",
              title: "Verificar el servicio RDP",
              description: null,
              status: "in_progress",
              asset: null,
              assignee: { user_id: "00000000-0000-0000-0000-000000000001", username: "analyst", active: true },
              assignee_name: "analyst",
              assigned_at: iso(),
              created_by: "admin",
              created_at: iso(),
              updated_at: iso(),
              started_at: iso(),
              completed_at: null,
              completed_by: null,
              due_at: iso(),
              overdue: true,
              result: null,
              evidence: [],
              version: 1,
              allowed_transitions: ["open", "blocked", "done", "cancelled"],
            },
          ],
          total: 1,
        });
      }
      if (path === "/incidents/assignees") {
        return json(200, { items: [{ user_id: "u2", username: "maria", role: "analyst", active: true }] });
      }
      return json(404, { error: { code: "not_found", message: path } });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderPage(role: Role) {
  return render(
    <MemoryRouter>
      <WithRole role={role}>
        <MyTasksPage />
      </WithRole>
    </MemoryRouter>,
  );
}

describe("Mis tareas (Fase 7A.6)", () => {
  it("pide solo las propias y pendientes, con enlace al caso y vencimiento", async () => {
    renderPage("analyst");
    const card = await screen.findByRole("listitem", { name: "Tarea: Verificar el servicio RDP" });
    const call = urls.find((url) => url.pathname.endsWith("/tasks"));
    expect(call?.searchParams.get("mine")).toBe("true");
    expect(call?.searchParams.getAll("status")).toEqual(["open", "in_progress", "blocked"]);
    expect(within(card).getByRole("link", { name: "INC-000009" })).toHaveAttribute("href", "/incidents/i1?tab=tasks");
    expect(within(card).getByText("Vencida")).toBeInTheDocument();
    // Desde aquí no se delega: eso se hace en el caso.
    expect(within(card).queryByRole("button", { name: /Asignar a|Reasignar/ })).not.toBeInTheDocument();
    expect(within(card).getByRole("button", { name: "Quitar responsable" })).toBeInTheDocument();
  });

  it("el filtro Todas quita el estado de la consulta", async () => {
    renderPage("viewer");
    await screen.findByRole("listitem", { name: "Tarea: Verificar el servicio RDP" });
    fireEvent.change(screen.getByLabelText("Estado de las tareas"), { target: { value: "all" } });
    await waitFor(() => {
      const last = urls.filter((url) => url.pathname.endsWith("/tasks")).at(-1);
      expect(last?.searchParams.getAll("status")).toEqual([]);
    });
    // Un viewer ve sus tareas pero no las trabaja.
    expect(screen.queryByRole("group")).not.toBeInTheDocument();
  });
});

describe("OwnerSelect (Fase 7A.6)", () => {
  function renderSelect(role: Role) {
    return render(
      <WithRole role={role}>
        <OwnerSelect value="" onChange={() => undefined} />
      </WithRole>,
    );
  }

  it("un analyst solo puede elegirse a sí mismo y no pide la lista de usuarios", () => {
    renderSelect("analyst");
    const options = within(screen.getByLabelText("Responsable")).getAllByRole("option");
    expect(options.map((option) => option.textContent)).toEqual(["Sin asignar", "Yo (analyst)"]);
    expect(urls.some((url) => url.pathname.endsWith("/incidents/assignees"))).toBe(false);
  });

  it("un admin puede elegir a otros analistas", async () => {
    renderSelect("admin");
    expect(await screen.findByRole("option", { name: "maria (analyst)" })).toBeInTheDocument();
  });

  it("sin incidents:manage no se muestra", () => {
    const { container } = renderSelect("viewer");
    expect(container).toBeEmptyDOMElement();
  });
});
