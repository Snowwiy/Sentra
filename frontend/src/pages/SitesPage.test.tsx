// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Role, Site, SiteNetwork } from "../api/types";
import { WithRole } from "../test/auth";
import { BRANCH_SITE_ID, SITES, installFetch, type Call, type Handler } from "../test/sites";
import { SitesPage } from "./SitesPage";

let calls: Call[];
let routes: Record<string, Handler>;
let sites: Site[];

const NETWORK: SiteNetwork = {
  network_id: "aa000000-0000-0000-0000-000000000001",
  site_id: BRANCH_SITE_ID,
  cidr: "10.20.0.0/24",
  name: "Oficina",
  enabled: true,
  host_count: 254,
  created_at: "2026-10-01T10:00:00Z",
  updated_at: "2026-10-01T10:00:00Z",
};

beforeEach(() => {
  sites = SITES.map((s) => ({ ...s }));
  routes = {
    "GET /sites": () => ({ body: { items: sites } }),
    [`GET /sites/${BRANCH_SITE_ID}/networks`]: () => ({ body: { items: [NETWORK] } }),
  };
  calls = installFetch(routes);
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
        <SitesPage />
      </WithRole>
    </MemoryRouter>,
  );
}

describe("SitesPage", () => {
  it("viewer: solo lectura, sin acciones de gestión", async () => {
    renderPage("viewer");
    expect(await screen.findByText("Sucursal Norte")).toBeInTheDocument();
    expect(screen.getByText(/Solo lectura/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "+ Nuevo site" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Editar/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Archivar/ })).not.toBeInTheDocument();
    // Puede ver las redes, pero no añadir ni quitar.
    fireEvent.click(screen.getByRole("button", { name: "Redes de Sucursal Norte" }));
    expect(await screen.findByText("10.20.0.0/24")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Añadir red" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Quitar red/ })).not.toBeInTheDocument();
  });

  it("oculta los archivados salvo que se pidan", async () => {
    renderPage("viewer");
    await screen.findByText("Sucursal Norte");
    expect(screen.queryByText("Almacén viejo")).not.toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/Mostrar archivados/));
    expect(screen.getByText("Almacén viejo")).toBeInTheDocument();
  });

  it("admin: crea un site", async () => {
    let body: unknown;
    routes["POST /sites"] = (init) => {
      body = JSON.parse(String(init.body));
      return { status: 201, body: { ...SITES[1], site_id: "new", name: "Planta" } };
    };
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "+ Nuevo site" }));
    const dialog = screen.getByRole("dialog", { name: "Nuevo site" });
    fireEvent.change(within(dialog).getByLabelText("Nombre"), { target: { value: "Planta" } });
    fireEvent.change(within(dialog).getByLabelText("Zona horaria (IANA)"), { target: { value: "Europe/Madrid" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Crear site" }));
    await waitFor(() => expect(body).toEqual({ name: "Planta", timezone: "Europe/Madrid" }));
  });

  it("admin: un 409 site_conflict al editar avisa y recarga", async () => {
    routes[`PATCH /sites/${BRANCH_SITE_ID}`] = () => ({
      status: 409,
      body: { error: { code: "site_conflict", message: "stale", details: [{ current_version: 2 }] } },
    });
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Editar Sucursal Norte" }));
    const dialog = screen.getByRole("dialog", { name: "Editar site Sucursal Norte" });
    fireEvent.change(within(dialog).getByLabelText("Nombre"), { target: { value: "Norte 2" } });
    const before = calls.filter((c) => c.method === "GET" && c.path === "/sites").length;
    fireEvent.click(within(dialog).getByRole("button", { name: "Guardar" }));
    expect(await screen.findByText(/Otro administrador ha modificado este site/)).toBeInTheDocument();
    const patch = calls.find((c) => c.method === "PATCH");
    expect(JSON.parse(String(patch?.init.body))).toMatchObject({ version: 1, name: "Norte 2" });
    await waitFor(() =>
      expect(calls.filter((c) => c.method === "GET" && c.path === "/sites").length).toBeGreaterThan(before),
    );
  });

  it("admin: archivar exige motivo y confirmación", async () => {
    let body: unknown;
    routes[`POST /sites/${BRANCH_SITE_ID}/archive`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: { ...SITES[1], status: "archived" } };
    };
    renderPage("admin");
    // El site por defecto no se puede archivar.
    await screen.findByText("Sucursal Norte");
    expect(screen.queryByRole("button", { name: "Archivar Principal" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Archivar Sucursal Norte" }));
    const dialog = screen.getByRole("dialog", { name: "Archivar site Sucursal Norte" });
    const submit = within(dialog).getByRole("button", { name: "Archivar site" });
    expect(submit).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Motivo"), { target: { value: "Cierre de oficina" } });
    expect(submit).toBeDisabled();
    fireEvent.click(within(dialog).getByLabelText(/Confirmo/));
    fireEvent.click(submit);
    await waitFor(() => expect(body).toEqual({ version: 1, reason: "Cierre de oficina" }));
  });

  it("admin: muestra legibles los errores de red inválida y solapada", async () => {
    let attempt = 0;
    routes[`POST /sites/${BRANCH_SITE_ID}/networks`] = () => {
      attempt += 1;
      return attempt === 1
        ? { status: 422, body: { error: { code: "site_network_invalid", message: "host bits set" } } }
        : { status: 409, body: { error: { code: "site_network_overlap", message: "overlaps" } } };
    };
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Redes de Sucursal Norte" }));
    const panel = await screen.findByRole("region", { name: "Redes del site Sucursal Norte" });
    fireEvent.change(within(panel).getByLabelText("CIDR"), { target: { value: "10.20.0.1/24" } });
    fireEvent.click(within(panel).getByRole("button", { name: "Añadir red" }));
    expect(await within(panel).findByText("Red no válida: host bits set")).toBeInTheDocument();
    fireEvent.change(within(panel).getByLabelText("CIDR"), { target: { value: "10.20.0.0/25" } });
    fireEvent.click(within(panel).getByRole("button", { name: "Añadir red" }));
    expect(await within(panel).findByText("La red se solapa con otra red de este mismo site.")).toBeInTheDocument();
  });

  it("admin: deshabilita una red del site", async () => {
    let body: unknown;
    routes[`PATCH /sites/${BRANCH_SITE_ID}/networks/${NETWORK.network_id}`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: { ...NETWORK, enabled: false } };
    };
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Redes de Sucursal Norte" }));
    fireEvent.click(await screen.findByRole("button", { name: "Deshabilitar red 10.20.0.0/24" }));
    await waitFor(() => expect(body).toEqual({ enabled: false }));
  });
});
