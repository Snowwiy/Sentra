// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installFetch, type Call, type Handler } from "../../test/sites";
import { AddToCaseDialog } from "./AddToCaseDialog";

const INCIDENT = "17000000-0000-0000-0000-000000000001";
const ASSET = "a7000000-0000-0000-0000-000000000001";
const EXECUTION = "e7000000-0000-0000-0000-000000000001";
const TASK = "7a000000-0000-0000-0000-000000000001";
const USER = "u7000000-0000-0000-0000-000000000001";

let routes: Record<string, Handler>;
let calls: Call[];

beforeEach(() => {
  routes = {
    "GET /incidents": () => ({
      body: { items: [{ incident_id: INCIDENT, key: "INC-000001", title: "PowerShell en ravenslg" }], total: 1 },
    }),
    "GET /incidents/assignees": () => ({ body: { items: [{ user_id: USER, username: "ana", role: "analyst" }] } }),
    "POST /tools/case.link_evidence/preview": () => ({
      body: {
        execution_id: EXECUTION,
        version: 2,
        status: "previewed",
        tool_id: "case.link_evidence",
        tool_name: "Añadir evidencia al caso",
        category: "action",
        output: { preview: { allowed: true, effects: ["Se vincula el activo al caso"], blockers: [], warnings: [] } },
      },
    }),
    [`POST /tools/executions/${EXECUTION}/confirm`]: () => ({
      body: { execution_id: EXECUTION, version: 3, status: "succeeded", output: {} },
    }),
    [`POST /incidents/${INCIDENT}/tasks`]: () => ({ status: 201, body: { task_id: TASK, version: 1 } }),
    [`POST /tasks/${TASK}/evidence`]: () => ({ body: { task_id: TASK, version: 2 } }),
  };
  calls = installFetch(routes);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const posts = (path: string) =>
  calls.filter((c) => c.method === "POST" && c.path === path).map((c) => JSON.parse(String(c.init.body)) as Record<string, unknown>);

describe("AddToCaseDialog (Fase 7B.4)", () => {
  it("vincula con vista previa y confirmación, y crea la tarea con su responsable", async () => {
    const onDone = vi.fn();
    render(
      <AddToCaseDialog kind="asset" evidenceId={ASSET} label="ravenslg" assetId={ASSET} onClose={() => undefined} onDone={onDone} />,
    );
    const dialog = await screen.findByRole("dialog", { name: "Añadir al caso" });
    await within(dialog).findByRole("option", { name: "INC-000001 · PowerShell en ravenslg" });
    fireEvent.change(within(dialog).getByLabelText("Caso"), { target: { value: INCIDENT } });
    fireEvent.click(within(dialog).getByRole("checkbox"));
    await within(dialog).findByRole("option", { name: "ana" });
    fireEvent.change(within(dialog).getByLabelText("Responsable de la tarea"), { target: { value: USER } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Vista previa" }));
    expect(await within(dialog).findByText("Se vincula el activo al caso")).toBeInTheDocument();
    // Nada se vincula ni se crea antes de confirmar.
    expect(posts(`/tools/executions/${EXECUTION}/confirm`)).toHaveLength(0);
    expect(posts(`/incidents/${INCIDENT}/tasks`)).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole("button", { name: "Confirmar" }));
    await waitFor(() => expect(onDone).toHaveBeenCalledWith("Evidencia añadida al caso y tarea creada."));
    expect(posts("/tools/case.link_evidence/preview")[0]).toMatchObject({
      input: { incident_id: INCIDENT, kind: "asset", evidence_id: ASSET },
    });
    expect(posts(`/tools/executions/${EXECUTION}/confirm`)[0]).toMatchObject({ version: 2, confirm: true });
    expect(posts(`/incidents/${INCIDENT}/tasks`)[0]).toEqual({
      kind: "analyze_evidence",
      title: "Analizar: ravenslg",
      asset_id: ASSET,
      assignee_user_id: USER,
    });
    expect(posts(`/tasks/${TASK}/evidence`)[0]).toEqual({ version: 1, type: "asset", id: ASSET });
  });
});
