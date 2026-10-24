// @vitest-environment jsdom
// Fase 6E.7: la pestaña Aislamiento muestra lo que decide el servidor, nunca ofrece aislar sin
// containment:isolate y exige la confirmación escrita (nombre exacto, motivo y duración).
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { IsolationOverview, Role } from "../../api/types";
import { WithRole } from "../../test/auth";
import { ASSET_ID, isolationOverview, isolationSession } from "../../test/phase6e";
import { installFetch, type Call } from "../../test/sites";
import { IsolationTab } from "./IsolationTab";

const BASE = `/assets/${ASSET_ID}`;
let overview: IsolationOverview;
let calls: Call[];

beforeEach(() => {
  overview = isolationOverview();
  calls = installFetch({
    [`GET ${BASE}/isolation`]: () => ({ body: overview }),
    [`GET ${BASE}/isolation/sessions`]: () => ({ body: { items: [], total: 0 } }),
    [`POST ${BASE}/isolation`]: () => ({ body: isolationSession({ status: "requested" }) }),
    [`POST ${BASE}/isolation/release`]: () => ({ body: isolationSession({ status: "reverting" }) }),
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderTab(role: Role = "admin") {
  return render(
    <WithRole role={role}>
      <IsolationTab assetId={ASSET_ID} />
    </WithRole>,
  );
}

describe("IsolationTab", () => {
  it("equipo sin agente: texto exacto, motivos del servidor y recomendaciones manuales, sin botón", async () => {
    overview = isolationOverview({
      available: false,
      unavailable_message: "Aislamiento no disponible para este dispositivo",
      server_enabled: false,
      platform: null,
      reasons: [
        { code: "no_agent", message: "El dispositivo no tiene agente de Sentra." },
        { code: "isolation_disabled", message: "El aislamiento está desactivado en el servidor." },
      ],
      manual_recommendations: ["Desconecta el puerto del switch.", "Bloquea su MAC en el punto de acceso."],
    });
    renderTab("admin");
    expect(await screen.findByRole("heading", { name: "Aislamiento no disponible para este dispositivo" })).toBeInTheDocument();
    const reasons = screen.getByRole("list", { name: "Motivos" });
    expect(within(reasons).getByText(/no tiene agente/)).toBeInTheDocument();
    expect(within(reasons).getByText(/desactivado en el servidor/)).toBeInTheDocument();
    const manual = screen.getByRole("list", { name: "Recomendaciones manuales" });
    expect(within(manual).getAllByRole("listitem")).toHaveLength(2);
    // El mensaje del servidor es el mismo texto: no se repite.
    expect(screen.getAllByText("Aislamiento no disponible para este dispositivo")).toHaveLength(1);
    expect(screen.queryByRole("button", { name: /Aislar/ })).toBeNull();
  });

  it("sin containment:isolate (analyst) no hay botón de aislar", async () => {
    renderTab("analyst");
    expect(await screen.findByRole("list", { name: "Impacto del aislamiento" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Aislar/ })).toBeNull();
    expect(screen.getByText(/requiere el rol de administrador/)).toBeInTheDocument();
  });

  it("el diálogo exige el nombre exacto, un motivo y una duración dentro del máximo", async () => {
    renderTab("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Aislar equipo…" }));
    const dialog = screen.getByRole("dialog", { name: "Aislar equipo" });
    // El impacto se muestra también en el diálogo.
    expect(within(dialog).getByRole("list", { name: "Impacto del aislamiento" })).toBeInTheDocument();
    const submit = within(dialog).getByRole("button", { name: "Aislar" });
    expect(submit).toBeDisabled();

    // Nombre parecido pero no exacto (mayúsculas): sigue deshabilitado.
    fireEvent.change(within(dialog).getByLabelText("Nombre del equipo"), { target: { value: "PC-ANA" } });
    fireEvent.change(within(dialog).getByLabelText("Motivo del aislamiento"), { target: { value: "Conexiones a un C2 conocido" } });
    expect(submit).toBeDisabled();

    fireEvent.change(within(dialog).getByLabelText("Nombre del equipo"), { target: { value: "pc-ana" } });
    fireEvent.change(within(dialog).getByLabelText("Duración en minutos"), { target: { value: "241" } });
    expect(submit).toBeDisabled();
    fireEvent.submit(submit.closest("form") as HTMLFormElement);
    expect(await within(dialog).findByText("La duración no puede superar 240 minutos.")).toBeInTheDocument();
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);

    fireEvent.change(within(dialog).getByLabelText("Duración en minutos"), { target: { value: "90" } });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(1));
    const post = calls.find((c) => c.method === "POST");
    expect(post?.path).toBe(`${BASE}/isolation`);
    expect(JSON.parse(String(post?.init.body))).toEqual({
      confirm_name: "pc-ana",
      reason: "Conexiones a un C2 conocido",
      duration_minutes: 90,
    });
  });

  it("un motivo demasiado corto no se envía", async () => {
    renderTab("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Aislar equipo…" }));
    const dialog = screen.getByRole("dialog", { name: "Aislar equipo" });
    fireEvent.change(within(dialog).getByLabelText("Nombre del equipo"), { target: { value: "pc-ana" } });
    fireEvent.change(within(dialog).getByLabelText("Motivo del aislamiento"), { target: { value: "corto" } });
    expect(within(dialog).getByRole("button", { name: "Aislar" })).toBeDisabled();
  });

  it("con una sesión viva: estado, sin segundo aislamiento y liberación con motivo y versión", async () => {
    overview = isolationOverview({ current: isolationSession() });
    renderTab("admin");
    const current = await screen.findByRole("region", { name: "Sesión de aislamiento actual" });
    expect(within(current).getByText("Aislado")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Aislar equipo…" })).toBeNull();
    fireEvent.click(within(current).getByRole("button", { name: "Liberar aislamiento…" }));
    const dialog = screen.getByRole("dialog", { name: "Liberar aislamiento" });
    fireEvent.change(within(dialog).getByLabelText("Motivo de la liberación"), { target: { value: "Falsa alarma" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Liberar" }));
    await waitFor(() => expect(calls.some((c) => c.path === `${BASE}/isolation/release`)).toBe(true));
    const release = calls.find((c) => c.path === `${BASE}/isolation/release`);
    expect(JSON.parse(String(release?.init.body))).toEqual({ version: 3, reason: "Falsa alarma" });
  });

  it("analyst ve la sesión viva pero no puede liberarla", async () => {
    overview = isolationOverview({ current: isolationSession() });
    renderTab("analyst");
    const current = await screen.findByRole("region", { name: "Sesión de aislamiento actual" });
    expect(within(current).queryByRole("button", { name: /Liberar/ })).toBeNull();
  });
});
