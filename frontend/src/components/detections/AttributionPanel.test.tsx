// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DetectionAttributionRead, Role } from "../../api/types";
import { WithRole } from "../../test/auth";
import { installFetch, type Call, type Handler } from "../../test/sites";
import { AttributionPanel } from "./AttributionPanel";

const ID = "d7000000-0000-0000-0000-000000000001";
const SHA = "a".repeat(64);
let routes: Record<string, Handler>;
let calls: Call[];

function attribution(overrides: Partial<DetectionAttributionRead> = {}): DetectionAttributionRead {
  return {
    detection_id: ID,
    rule_id: "SCR-001",
    attributable: true,
    verdict: "suspicious_unverified",
    evaluated_at: new Date().toISOString(),
    history: [],
    attribution: {
      operation: null,
      tamper_suspected: true,
      risk_effect: "kept",
      explanation: ["Ninguna operación aprobada describe el script."],
      items: [
        {
          kind: "script",
          label: "install-sentra-agent.ps1",
          occurred_at: new Date().toISOString(),
          result: "fail",
          context_only: false,
          missing: [],
          checks: [
            { check: "path", result: "pass", expected: "C:\\Sentra\\install-sentra-agent.ps1", observed: "C:\\Sentra\\install-sentra-agent.ps1" },
            { check: "sha256", result: "fail", expected: SHA, observed: "b".repeat(64) },
          ],
        },
      ],
      missing_evidence: [{ code: "process", how_to_obtain: "Activar la telemetría de procesos." }],
    },
    ...overrides,
  };
}

beforeEach(() => {
  routes = { [`GET /detections/${ID}/attribution`]: () => ({ body: attribution() }) };
  calls = installFetch(routes);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderPanel(role: Role) {
  return render(
    <WithRole role={role}>
      <AttributionPanel detectionId={ID} />
    </WithRole>,
  );
}

describe("AttributionPanel (Fase 7B.1)", () => {
  it("muestra el veredicto, cada comprobación, la posible suplantación y cómo obtener lo que falta", async () => {
    renderPanel("viewer");
    const panel = await screen.findByRole("region", { name: "Atribución" });
    expect(await within(panel).findByText("Sospechosa sin verificar")).toBeInTheDocument();
    expect(within(panel).getByRole("alert")).toHaveTextContent(/posible suplantación/);
    expect(within(panel).getByText("No coincide")).toBeInTheDocument();
    expect(within(panel).getByText(SHA)).toBeInTheDocument();
    expect(within(panel).getByText(/Activar la telemetría de procesos/)).toBeInTheDocument();
    // Un viewer no reevalúa ni decide.
    expect(within(panel).queryByRole("button", { name: "Reevaluar" })).toBeNull();
  });

  it("aprobada después de la actividad: avisa de que necesita revisión explícita", async () => {
    const base = attribution();
    routes[`GET /detections/${ID}/attribution`] = () => ({
      body: {
        ...base,
        attribution: {
          ...base.attribution,
          tamper_suspected: false,
          review_required: { operation_id: "op-1", title: "Instalación del agente 0.6.1", reason: "approved_after_activity" },
        },
      },
    });
    renderPanel("analyst");
    const panel = await screen.findByRole("region", { name: "Atribución" });
    const note = (await within(panel).findByText(/describiría esta actividad/)).closest(".banner");
    expect(note).toHaveAttribute("role", "status");
    expect(note).toHaveTextContent("«Instalación del agente 0.6.1» describiría esta actividad");
    expect(note).toHaveTextContent("se aprobó después de esta actividad");
    expect(within(panel).queryByRole("alert")).toBeNull();
  });

  it("una regla sin atribución no muestra el panel", async () => {
    routes[`GET /detections/${ID}/attribution`] = () => ({ body: attribution({ attributable: false, verdict: null, attribution: null }) });
    const { container } = renderPanel("viewer");
    await waitFor(() => expect(calls.length).toBeGreaterThan(0));
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });

  it("analista: fija un veredicto con motivo; legítima no se ofrece", async () => {
    const bodies: unknown[] = [];
    routes[`POST /detections/${ID}/attribution/verdict`] = (init) => {
      bodies.push(JSON.parse(String(init.body)));
      return { body: attribution({ verdict: "confirmed_malicious" }) };
    };
    renderPanel("analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Veredicto del analista…" }));
    const dialog = await screen.findByRole("dialog", { name: "Veredicto del analista" });
    const select = within(dialog).getByLabelText("Veredicto");
    expect(within(select).queryByRole("option", { name: "Verificada como legítima" })).toBeNull();
    const save = within(dialog).getByRole("button", { name: "Guardar veredicto" });
    expect(save).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Motivo"), { target: { value: "Hash desconocido en VirusTotal interno" } });
    fireEvent.click(save);
    await waitFor(() => expect(bodies).toEqual([{ verdict: "confirmed_malicious", reason: "Hash desconocido en VirusTotal interno" }]));
  });
});
