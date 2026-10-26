// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TaskRead, IncidentDetail, NetworkControlRead, Role } from "../../api/types";
import { WithRole } from "../../test/auth";
import { TasksSection } from "./CaseTasks";
import { NetworkControlsSection } from "./NetworkControls";

// Datos sintéticos de test: no proceden de ningún host real.
const INCIDENT = "11111111-2222-3333-4444-555555555555";
const TASK = "22222222-2222-3333-4444-555555555555";
const CONTROL = "33333333-2222-3333-4444-555555555555";
const SESSION_USER = "00000000-0000-0000-0000-000000000001";
const iso = () => new Date().toISOString();

// Solo los campos del caso que leen las secciones de tareas y controles.
function incident(overrides: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    incident_id: INCIDENT,
    key: "INC-000007",
    status: "investigating",
    owner: null,
    asset_refs: [],
    ...overrides,
  } as IncidentDetail;
}

function task(overrides: Partial<TaskRead> = {}): TaskRead {
  return {
    task_id: TASK,
    incident_id: INCIDENT,
    incident_key: "INC-000007",
    kind: "investigate_port",
    title: "Revisar el 445 expuesto",
    description: null,
    status: "open",
    asset: null,
    assignee: null,
    assignee_name: null,
    assigned_at: null,
    created_by: "analyst",
    created_at: iso(),
    updated_at: iso(),
    started_at: null,
    completed_at: null,
    completed_by: null,
    due_at: null,
    overdue: false,
    result: null,
    evidence: [],
    version: 3,
    allowed_transitions: ["in_progress", "blocked", "done", "cancelled"],
    ...overrides,
  };
}

function control(overrides: Partial<NetworkControlRead> = {}): NetworkControlRead {
  return {
    control_id: CONTROL,
    incident_id: INCIDENT,
    incident_key: "INC-000007",
    task_id: null,
    control_type: "block_port",
    target: { port: 445, protocol: "tcp" },
    direction: "inbound",
    scope: { type: "global", asset_id: null, site_id: null, label: "Toda la organización" },
    justification: "SMB expuesto en la red de invitados",
    status: "pending_approval",
    enforcement_status: "not_evaluated",
    enforcement: null,
    expires_at: null,
    requested_by: "someone-else",
    created_at: iso(),
    updated_at: iso(),
    decided_by: null,
    decided_at: null,
    decision_note: null,
    self_approved: false,
    applied_by: null,
    applied_at: null,
    applied_note: null,
    version: 5,
    ...overrides,
  };
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

let tasks: TaskRead[];
let controls: NetworkControlRead[];
let calls: { method: string; path: string; body: unknown }[];
let nextError: Response | undefined;

beforeEach(() => {
  tasks = [task()];
  controls = [control()];
  calls = [];
  nextError = undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = new URL(input, "http://localhost");
      const path = url.pathname.replace("/api/v1", "");
      const method = init?.method ?? "GET";
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ method, path, body });
      if (method !== "GET" && nextError) {
        const response = nextError;
        nextError = undefined;
        return response;
      }
      if (path === `/incidents/${INCIDENT}/tasks`) return json(200, { items: tasks, total: tasks.length });
      if (path === `/tasks/${TASK}` && method === "PATCH") return json(200, task({ ...body, version: 4 }));
      if (path.startsWith(`/tasks/${TASK}/`)) return json(200, task({ version: 4 }));
      if (path === "/network-controls/capabilities") {
        return json(200, {
          any_available: false,
          items: [
            {
              control_type: "block_port",
              available: false,
              points: [],
              needs: "Un firewall gestionado por Sentra.",
              note: "Sentra no aplica controles en 7A.",
            },
          ],
        });
      }
      if (path === "/network-controls") return json(200, { items: controls, total: controls.length });
      if (path.startsWith(`/network-controls/${CONTROL}/`)) return json(200, control({ version: 6 }));
      if (path === "/incidents/assignees") return json(200, { items: [] });
      return json(404, { error: { code: "not_found", message: path } });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderTasks(role: Role, overrides: Partial<IncidentDetail> = {}) {
  return render(
    <MemoryRouter>
      <WithRole role={role}>
        <TasksSection incident={incident(overrides)} />
      </WithRole>
    </MemoryRouter>,
  );
}

function renderControls(role: Role, overrides: Partial<IncidentDetail> = {}) {
  return render(
    <MemoryRouter>
      <WithRole role={role}>
        <NetworkControlsSection incident={incident(overrides)} />
      </WithRole>
    </MemoryRouter>,
  );
}

describe("Tareas del caso (Fase 7A.6)", () => {
  it("las transiciones salen de allowed_transitions y llevan la versión leída", async () => {
    renderTasks("analyst");
    const card = await screen.findByRole("listitem", { name: "Tarea: Revisar el 445 expuesto" });
    const actions = within(card).getByRole("group", { name: /Acciones de la tarea/ });
    expect(within(actions).getByRole("button", { name: "Empezar" })).toBeInTheDocument();
    expect(within(actions).queryByRole("button", { name: "Reabrir" })).not.toBeInTheDocument();
    fireEvent.click(within(actions).getByRole("button", { name: "Empezar" }));
    await waitFor(() =>
      expect(calls).toContainEqual({ method: "PATCH", path: `/tasks/${TASK}`, body: { version: 3, status: "in_progress" } }),
    );
  });

  it("terminar exige un resultado antes de enviar", async () => {
    renderTasks("analyst");
    const card = await screen.findByRole("listitem", { name: "Tarea: Revisar el 445 expuesto" });
    fireEvent.click(within(card).getByRole("button", { name: "Terminar…" }));
    const dialog = await screen.findByRole("dialog", { name: "Terminar tarea" });
    const submit = within(dialog).getByRole("button", { name: "Terminar tarea" });
    expect(submit).toBeDisabled();
    expect(calls.some((call) => call.method === "PATCH")).toBe(false);
    fireEvent.change(within(dialog).getByLabelText("Resultado"), { target: { value: "Puerto cerrado en el firewall." } });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    await waitFor(() =>
      expect(calls).toContainEqual({
        method: "PATCH",
        path: `/tasks/${TASK}`,
        body: { version: 3, status: "done", result: "Puerto cerrado en el firewall." },
      }),
    );
  });

  it("un 409 de versión pide recargar y no reintenta solo", async () => {
    nextError = json(409, { error: { code: "task_conflict", message: "stale", details: { current_version: 4 } } });
    renderTasks("analyst");
    const card = await screen.findByRole("listitem", { name: "Tarea: Revisar el 445 expuesto" });
    fireEvent.click(within(card).getByRole("button", { name: "Asignármela" }));
    expect(await screen.findByText(/Otra persona modificó esta tarea/)).toBeInTheDocument();
    expect(calls.filter((call) => call.path === `/tasks/${TASK}/assign`)).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Recargar" })).toBeInTheDocument();
  });

  it("solo el responsable del caso o un admin puede asignar a otra persona", async () => {
    renderTasks("analyst");
    const card = await screen.findByRole("listitem", { name: "Tarea: Revisar el 445 expuesto" });
    expect(within(card).getByRole("button", { name: "Asignármela" })).toBeInTheDocument();
    expect(within(card).queryByRole("button", { name: "Asignar a…" })).not.toBeInTheDocument();
    cleanup();
    renderTasks("analyst", {
      owner: { user_id: SESSION_USER, username: "analyst", active: true } as IncidentDetail["owner"],
    });
    const owned = await screen.findByRole("listitem", { name: "Tarea: Revisar el 445 expuesto" });
    expect(within(owned).getByRole("button", { name: "Asignar a…" })).toBeInTheDocument();
  });

  it("un viewer ve las tareas sin acciones ni botón de crear", async () => {
    renderTasks("viewer");
    const card = await screen.findByRole("listitem", { name: "Tarea: Revisar el 445 expuesto" });
    expect(within(card).queryByRole("group")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Nueva tarea" })).not.toBeInTheDocument();
    expect(screen.getByText(/no ejecuta nada en ningún equipo/)).toBeInTheDocument();
  });

  it("en un caso cerrado no se trabajan tareas", async () => {
    renderTasks("admin", { status: "closed" });
    const card = await screen.findByRole("listitem", { name: "Tarea: Revisar el 445 expuesto" });
    expect(within(card).queryByRole("group")).not.toBeInTheDocument();
  });
});

describe("Controles de red (Fase 7A.6)", () => {
  it("deja claro que Sentra no aplica nada y muestra lo que haría falta", async () => {
    renderControls("viewer");
    const notice = await screen.findByRole("note", { name: "Sentra no aplica controles de red" });
    expect(notice).toHaveTextContent("Sentra no aplica nada en la red.");
    expect(await within(notice).findByText(/Puntos de control instalados: ninguno/)).toBeInTheDocument();
    expect(notice).toHaveTextContent("Un firewall gestionado por Sentra.");
  });

  it("viewer y analyst no ven la decisión; el analyst puede pedir", async () => {
    renderControls("viewer");
    await screen.findByRole("listitem", { name: "Solicitud: Bloquear un puerto" });
    expect(screen.queryByRole("group", { name: "Decisión sobre la solicitud" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Solicitar control" })).not.toBeInTheDocument();
    cleanup();
    renderControls("analyst");
    await screen.findByRole("listitem", { name: "Solicitud: Bloquear un puerto" });
    expect(screen.queryByRole("button", { name: "Aprobar (sin aplicar)" })).not.toBeInTheDocument();
    // La pidió otra persona: el analyst tampoco puede cancelarla.
    expect(screen.queryByRole("button", { name: "Cancelar solicitud" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Solicitar control" })).toBeInTheDocument();
  });

  it("quien pidió la solicitud puede cancelarla", async () => {
    controls = [control({ requested_by: "analyst" })];
    renderControls("analyst");
    const card = await screen.findByRole("listitem", { name: "Solicitud: Bloquear un puerto" });
    fireEvent.click(within(card).getByRole("button", { name: "Cancelar solicitud" }));
    await waitFor(() =>
      expect(calls).toContainEqual({ method: "POST", path: `/network-controls/${CONTROL}/cancel`, body: { version: 5 } }),
    );
  });

  it("el admin aprueba sin aplicar y rechazar exige nota", async () => {
    renderControls("admin");
    const card = await screen.findByRole("listitem", { name: "Solicitud: Bloquear un puerto" });
    fireEvent.click(within(card).getByRole("button", { name: "Rechazar…" }));
    let dialog = await screen.findByRole("dialog");
    const reject = within(dialog).getByRole("button", { name: /Rechazar/ });
    expect(reject).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Nota de la decisión"), { target: { value: "No procede" } });
    expect(reject).toBeEnabled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancelar" }));

    fireEvent.click(within(card).getByRole("button", { name: "Aprobar (sin aplicar)" }));
    dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("note")).toHaveTextContent("Sentra no aplicará nada en la red");
    const approve = within(dialog).getAllByRole("button").at(-1);
    expect(approve).toBeEnabled();
    fireEvent.click(approve as HTMLElement);
    await waitFor(() =>
      expect(calls.find((call) => call.path === `/network-controls/${CONTROL}/approve`)?.body).toMatchObject({ version: 5 }),
    );
  });

  it("una aprobada sin punto de control explica lo que haría falta", async () => {
    controls = [
      control({
        status: "approved",
        enforcement_status: "no_enforcement_point",
        decided_by: "admin",
        decided_at: iso(),
        enforcement: {
          points: [],
          applied_by_sentra: false,
          needs: "Un firewall perimetral gestionado.",
          note: "Aplícala a mano y regístralo.",
        },
      }),
    ];
    renderControls("admin");
    const card = await screen.findByRole("listitem", { name: "Solicitud: Bloquear un puerto" });
    expect(within(card).getByRole("note", { name: "Qué haría falta para aplicarla" })).toHaveTextContent(
      "Sentra no la ha aplicado.",
    );
    expect(within(card).getByText("Sin punto de control: Sentra no la aplica")).toBeInTheDocument();
    expect(within(card).getByRole("button", { name: "Registrar que se aplicó fuera de Sentra…" })).toBeInTheDocument();
  });
});
