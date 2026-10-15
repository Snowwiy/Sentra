// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Role, SensorEnrollment } from "../api/types";
import { SiteProvider } from "../site/SiteContext";
import { WithRole } from "../test/auth";
import { BRANCH_SITE_ID, SITES, installFetch, sensor, sensorJob, type Call, type Handler } from "../test/sites";
import { SensorsPage } from "./SensorsPage";

// Valor de test: la forma correcta, nunca emitido por un servidor.
const TOKEN = "sentra_st_TEST-not-a-real-token_0123456789abcdef";
const COMMAND = `sentra-sensor enroll --server https://sentra.example.test --token ${TOKEN}`;

const SENSORS = [
  sensor({ name: "sensor-online" }),
  sensor({ sensor_id: "5e000000-0000-0000-0000-000000000002", name: "sensor-offline", status: "offline" }),
  sensor({
    sensor_id: "5e000000-0000-0000-0000-000000000003",
    name: "sensor-stale",
    status: "stale",
    version_status: "outdated",
    last_job: sensorJob({ status: "failed" }),
  }),
  sensor({
    sensor_id: "5e000000-0000-0000-0000-000000000004",
    name: "sensor-revocado",
    status: "revoked",
    revoked_at: "2026-10-02T10:00:00Z",
    revoke_reason: "equipo robado",
  }),
];
const SUMMARY = { total: 4, pending: 0, online: 1, offline: 1, stale: 1, disabled: 0, revoked: 1 };

function enrollment(overrides: Partial<SensorEnrollment> = {}): SensorEnrollment {
  return {
    enrollment_id: "e0000000-0000-0000-0000-000000000001",
    site_id: BRANCH_SITE_ID,
    site_name: "Sucursal Norte",
    name: "sensor-nuevo",
    state: "active",
    created_at: "2026-10-01T10:00:00Z",
    expires_at: "2026-10-01T11:00:00Z",
    used_at: null,
    revoked_at: null,
    sensor_id: null,
    created_by: "admin",
    ...overrides,
  };
}

let calls: Call[];
let routes: Record<string, Handler>;

beforeEach(() => {
  window.localStorage.clear();
  routes = {
    "GET /sites": () => ({ body: { items: SITES } }),
    "GET /sensors": () => ({ body: { items: SENSORS, summary: SUMMARY } }),
    "GET /sensors/enrollment-tokens": () => ({ body: { items: [] } }),
    [`GET /sensors/${SENSORS[2]!.sensor_id}/jobs`]: () => ({
      body: { items: [sensorJob({ status: "failed", error_code: "sensor_timeout" })] },
    }),
  };
  calls = installFetch(routes);
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderPage(role: Role) {
  return render(
    <MemoryRouter>
      <WithRole role={role}>
        <SiteProvider>
          <SensorsPage />
        </SiteProvider>
      </WithRole>
    </MemoryRouter>,
  );
}

describe("SensorsPage", () => {
  it("muestra los estados y deja claro que offline no es comprometido", async () => {
    renderPage("viewer");
    const table = await screen.findByRole("region", { name: "Sensores" });
    const row = (name: string) => within(table).getByRole("button", { name }).closest("tr") as HTMLElement;
    expect(within(row("sensor-online")).getByText("Online")).toBeInTheDocument();
    expect(within(row("sensor-offline")).getByText("Offline")).toBeInTheDocument();
    expect(within(row("sensor-stale")).getByText("Stale")).toBeInTheDocument();
    expect(within(row("sensor-stale")).getByText("desactualizada")).toBeInTheDocument();
    expect(within(row("sensor-stale")).getByText(/Fallido/)).toBeInTheDocument();
    expect(within(row("sensor-revocado")).getByText("Revocado")).toBeInTheDocument();
    expect(within(row("sensor-offline")).getByText("Offline")).toHaveAttribute(
      "title",
      expect.stringMatching(/No significa que esté comprometido/),
    );
    expect(screen.getByRole("note")).toHaveTextContent(/no significa que\s+esté comprometido/);
    // Solo lectura: sin acciones ni tokens.
    expect(screen.queryByRole("button", { name: "+ Registrar sensor" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Revocar/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Tokens de sensor" })).not.toBeInTheDocument();
    expect(calls.some((c) => c.path === "/sensors/enrollment-tokens")).toBe(false);
  });

  it("abre el detalle con los jobs del sensor", async () => {
    renderPage("viewer");
    fireEvent.click(await screen.findByRole("button", { name: "sensor-stale" }));
    const panel = await screen.findByRole("region", { name: "Jobs del sensor sensor-stale" });
    expect(await within(panel).findByText("sensor_timeout")).toBeInTheDocument();
    const jobsCall = calls.find((c) => c.path.endsWith("/jobs"));
    expect(jobsCall?.url.searchParams.get("limit")).toBe("20");
  });

  it("admin: crea un token y lo muestra una sola vez con el comando del servidor", async () => {
    let body: unknown;
    routes["POST /sensors/enrollment-tokens"] = (init) => {
      body = JSON.parse(String(init.body));
      return { status: 201, body: { ...enrollment(), token: TOKEN, command_example: COMMAND } };
    };
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "+ Registrar sensor" }));
    const dialog = screen.getByRole("dialog", { name: "Registrar sensor" });
    // Solo sites activos (el archivado no aparece).
    const siteSelect = within(dialog).getByLabelText("Site") as HTMLSelectElement;
    expect(Array.from(siteSelect.options).map((o) => o.textContent)).toEqual(["Principal (por defecto)", "Sucursal Norte"]);
    fireEvent.change(siteSelect, { target: { value: BRANCH_SITE_ID } });
    fireEvent.change(within(dialog).getByLabelText("Nombre del sensor"), { target: { value: "sensor-nuevo" } });
    fireEvent.change(within(dialog).getByLabelText(/Caducidad/), { target: { value: "30" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Generar token" }));

    const created = await screen.findByRole("dialog", { name: "Token de sensor creado" });
    expect(body).toEqual({ site_id: BRANCH_SITE_ID, name: "sensor-nuevo", ttl_minutes: 30 });
    expect(within(created).getByLabelText("Token de enrollment del sensor")).toHaveTextContent(TOKEN);
    expect(within(created).getByLabelText("Comando de enrollment")).toHaveTextContent(COMMAND);
    expect(within(created).getByRole("button", { name: "Copiar token" })).toBeInTheDocument();
    expect(within(created).getByRole("button", { name: "Copiar comando" })).toBeInTheDocument();
    expect(created).not.toHaveTextContent("localhost");

    // Al cerrar, el token desaparece: la lista solo muestra su estado.
    routes["GET /sensors/enrollment-tokens"] = () => ({ body: { items: [enrollment()] } });
    fireEvent.click(within(created).getByRole("button", { name: "Hecho" }));
    const tokens = await screen.findByRole("region", { name: "Tokens de sensor" });
    await within(tokens).findByText("sensor-nuevo");
    expect(document.body).not.toHaveTextContent(TOKEN);
    expect(window.localStorage.length).toBe(0);
  });

  it("admin: revocar un sensor exige motivo y confirmación", async () => {
    let body: unknown;
    routes[`POST /sensors/${SENSORS[1]!.sensor_id}/revoke`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: { ...SENSORS[1], status: "revoked" } };
    };
    renderPage("admin");
    // Un sensor revocado no ofrece más acciones.
    await screen.findByRole("button", { name: "sensor-revocado" });
    expect(screen.queryByRole("button", { name: "Revocar sensor-revocado" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Revocar sensor-offline" }));
    const dialog = screen.getByRole("dialog", { name: "Revocar sensor sensor-offline" });
    const submit = within(dialog).getByRole("button", { name: "Revocar sensor" });
    fireEvent.change(within(dialog).getByLabelText("Motivo"), { target: { value: "retirado" } });
    expect(submit).toBeDisabled();
    fireEvent.click(within(dialog).getByLabelText(/Confirmo/));
    fireEvent.click(submit);
    await waitFor(() => expect(body).toEqual({ version: 1, reason: "retirado" }));
  });

  it("admin: rotar la credencial manda la versión", async () => {
    let body: unknown;
    routes[`POST /sensors/${SENSORS[0]!.sensor_id}/rotate-credential`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: { ...SENSORS[0], rotation_pending: true } };
    };
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Rotar credencial de sensor-online" }));
    const dialog = screen.getByRole("dialog", { name: /Rotar credencial: sensor-online/ });
    fireEvent.click(within(dialog).getByRole("button", { name: "Rotar credencial" }));
    await waitFor(() => expect(body).toEqual({ version: 1 }));
  });
});
