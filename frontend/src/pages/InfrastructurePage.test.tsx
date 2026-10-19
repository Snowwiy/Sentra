// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Role } from "../api/types";
import { SiteProvider } from "../site/SiteContext";
import { WithRole } from "../test/auth";
import { networkDevice, snmpProfile } from "../test/network";
import { BRANCH_SITE_ID, SITES, installFetch, type Call, type Handler } from "../test/sites";
import { InfrastructurePage } from "./InfrastructurePage";

// Valores de test: nunca credenciales reales.
const AUTH_SECRET = "TEST-auth-passphrase-123";
const PRIV_SECRET = "TEST-priv-passphrase-456";
const COMMUNITY = "TEST-community-789";

const COUNTS = { total: 2, by_classification: {}, by_monitoring_status: {} };
const DEVICES = [
  networkDevice(),
  networkDevice({
    device_id: "de000000-0000-0000-0000-000000000002",
    display_name: "edge-rt-01",
    name: "edge-rt-01",
    management_address: "10.20.0.1",
    classification: "router",
    classification_confidence: "medium",
    monitoring_status: "failing",
    freshness: "historical",
    sensor: null,
  }),
];

let calls: Call[];
let routes: Record<string, Handler>;

beforeEach(() => {
  window.localStorage.clear();
  routes = {
    "GET /sites": () => ({ body: { items: SITES } }),
    "GET /network/devices": () => ({ body: { items: DEVICES, total: 2, limit: 25, offset: 0, counts: COUNTS } }),
    "GET /network/snmp-profiles": () => ({
      body: { items: [snmpProfile()], secret_store_available: true, v2c_allowed: false },
    }),
    "GET /sensors": () => ({ body: { items: [], summary: {} } }),
    "GET /network/candidates": () => ({ body: { items: [] } }),
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
          <InfrastructurePage />
        </SiteProvider>
      </WithRole>
    </MemoryRouter>,
  );
}

const deviceCalls = () => calls.filter((c) => c.method === "GET" && c.path === "/network/devices");

describe("InfrastructurePage: equipos", () => {
  it("lista equipos con estado de monitorización y evidencia histórica, sin afirmar que están online", async () => {
    renderPage("viewer");
    const table = await screen.findByRole("region", { name: "Equipos de red" });
    const row = (name: string) => within(table).getByRole("link", { name }).closest("tr") as HTMLElement;
    expect(await within(table).findByRole("link", { name: "core-sw-01" })).toHaveAttribute(
      "href",
      "/infrastructure/devices/de000000-0000-0000-0000-000000000001",
    );
    expect(within(row("core-sw-01")).getByText("Consulta correcta")).toBeInTheDocument();
    expect(within(row("core-sw-01")).getByText("Evidencia reciente")).toBeInTheDocument();
    expect(within(row("core-sw-01")).getByText("Switch gestionable")).toBeInTheDocument();
    expect(within(row("core-sw-01")).getByText(/confianza alta/)).toBeInTheDocument();
    expect(within(row("core-sw-01")).getByText("20/52")).toBeInTheDocument();
    expect(within(row("edge-rt-01")).getByText("Evidencia histórica")).toBeInTheDocument();
    expect(within(row("edge-rt-01")).getByText("Consultas fallidas")).toBeInTheDocument();
    expect(within(row("edge-rt-01")).getByText("sin sensor")).toBeInTheDocument();
    expect(table).not.toHaveTextContent(/online/i);
    // Columnas con encabezado.
    expect(within(table).getByRole("columnheader", { name: "Última consulta correcta" })).toBeInTheDocument();
    // Primera página por defecto.
    const first = deviceCalls()[0]!;
    expect(first.url.searchParams.get("limit")).toBe("25");
    expect(first.url.searchParams.has("offset")).toBe(false);
  });

  it("viewer: sin botones de gestión ni pestaña de perfiles SNMP", async () => {
    renderPage("viewer");
    await screen.findByRole("link", { name: "core-sw-01" });
    expect(screen.queryByRole("button", { name: "Registrar equipo" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Perfiles SNMP" })).not.toBeInTheDocument();
    expect(calls.some((c) => c.path.startsWith("/network/snmp-profiles"))).toBe(false);
  });

  it("analyst: puede consultar (en el detalle) pero no registrar equipos ni ver perfiles", async () => {
    renderPage("analyst");
    await screen.findByRole("link", { name: "core-sw-01" });
    expect(screen.queryByRole("button", { name: "Registrar equipo" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Perfiles SNMP" })).not.toBeInTheDocument();
  });

  it("envía filtros, búsqueda y página al servidor", async () => {
    routes["GET /network/devices"] = () => ({
      body: { items: DEVICES, total: 60, limit: 25, offset: 0, counts: COUNTS },
    });
    renderPage("viewer");
    await screen.findByRole("link", { name: "core-sw-01" });

    fireEvent.change(screen.getByLabelText("Clasificación"), { target: { value: "router" } });
    await waitFor(() => expect(deviceCalls().at(-1)!.url.searchParams.get("classification")).toBe("router"));

    fireEvent.change(screen.getByLabelText("Monitorización"), { target: { value: "failing" } });
    await waitFor(() => expect(deviceCalls().at(-1)!.url.searchParams.get("monitoring_status")).toBe("failing"));

    fireEvent.change(screen.getByLabelText("Site"), { target: { value: BRANCH_SITE_ID } });
    await waitFor(() => expect(deviceCalls().at(-1)!.url.searchParams.get("site_id")).toBe(BRANCH_SITE_ID));

    fireEvent.change(screen.getByLabelText("Buscar equipos"), { target: { value: "core" } });
    await waitFor(() => expect(deviceCalls().at(-1)!.url.searchParams.get("q")).toBe("core"));

    fireEvent.click(screen.getByLabelText("Incluir archivados"));
    await waitFor(() => expect(deviceCalls().at(-1)!.url.searchParams.get("include_archived")).toBe("true"));

    fireEvent.click(await screen.findByRole("button", { name: "Siguiente" }));
    await waitFor(() => expect(deviceCalls().at(-1)!.url.searchParams.get("offset")).toBe("25"));
    const last = deviceCalls().at(-1)!.url.searchParams;
    expect(last.get("classification")).toBe("router");
    expect(last.get("monitoring_status")).toBe("failing");
    expect(last.get("q")).toBe("core");
    expect(screen.getByText(/página 2 de 3/)).toBeInTheDocument();
  });

  it("muestra error con reintento y estado vacío", async () => {
    let fail = true;
    routes["GET /network/devices"] = () =>
      fail
        ? { status: 500, body: { error: { code: "internal", message: "fallo interno" } } }
        : { body: { items: [], total: 0, limit: 25, offset: 0, counts: { ...COUNTS, total: 0 } } };
    renderPage("admin");
    expect(await screen.findByRole("alert")).toHaveTextContent("fallo interno");
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    expect(await screen.findByText("Todavía no hay equipos de red registrados")).toBeInTheDocument();
  });

  it("muestra el estado de carga", async () => {
    renderPage("viewer");
    // La primera carga se lanza tras el render: hasta entonces se ve el estado de carga.
    expect(screen.getByText("Cargando equipos de red…")).toBeInTheDocument();
    await screen.findByRole("link", { name: "core-sw-01" });
  });

  it("admin: registra un equipo con perfil y sensor del mismo site", async () => {
    let body: Record<string, unknown> | undefined;
    routes["GET /sensors"] = () => ({
      body: {
        items: [
          {
            sensor_id: "5e000000-0000-0000-0000-000000000001",
            name: "sensor-norte",
            site_id: BRANCH_SITE_ID,
            status: "online",
          },
        ],
        summary: {},
      },
    });
    routes["GET /network/candidates"] = () => ({
      body: {
        items: [
          {
            asset_id: "a5000000-0000-0000-0000-000000000009",
            site_id: BRANCH_SITE_ID,
            site_name: "Sucursal Norte",
            address: "10.20.0.9",
            hostname: "sw-planta2",
            device_type: "network_device",
            device_type_reason: null,
            mac_address: null,
            last_seen_at: null,
          },
        ],
      },
    });
    routes["POST /network/devices"] = (init) => {
      body = JSON.parse(String(init.body)) as Record<string, unknown>;
      return { status: 201, body: networkDevice({ device_id: "de000000-0000-0000-0000-000000000009" }) };
    };
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Registrar equipo" }));
    const dialog = screen.getByRole("dialog", { name: "Registrar equipo de red" });
    fireEvent.change(within(dialog).getByLabelText("Site"), { target: { value: BRANCH_SITE_ID } });
    fireEvent.change(await within(dialog).findByLabelText("Activo descubierto (opcional)"), {
      target: { value: "a5000000-0000-0000-0000-000000000009" },
    });
    expect(within(dialog).getByLabelText("Dirección de gestión (IP)")).toHaveValue("10.20.0.9");
    await within(dialog).findByRole("option", { name: /v3-norte/ });
    fireEvent.change(within(dialog).getByLabelText("Perfil SNMP"), { target: { value: snmpProfile().profile_id } });
    await within(dialog).findByRole("option", { name: /sensor-norte/ });
    fireEvent.change(within(dialog).getByLabelText("Sensor del site"), {
      target: { value: "5e000000-0000-0000-0000-000000000001" },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Registrar equipo" }));
    await waitFor(() => expect(body).toBeDefined());
    expect(body).toEqual({
      site_id: BRANCH_SITE_ID,
      management_address: "10.20.0.9",
      snmp_port: 161,
      name: "sw-planta2",
      profile_id: snmpProfile().profile_id,
      sensor_id: "5e000000-0000-0000-0000-000000000001",
      monitoring_enabled: false,
      asset_id: "a5000000-0000-0000-0000-000000000009",
    });
  });
});

describe("InfrastructurePage: registro sin sensor (Fase 6C)", () => {
  it("explica qué falta y no ofrece la consulta periódica como si fuera a funcionar", async () => {
    routes["GET /sensors"] = () => ({ body: { items: [], summary: {} } });
    routes["GET /network/candidates"] = () => ({ body: { items: [] } });
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Registrar equipo" }));
    const dialog = screen.getByRole("dialog", { name: "Registrar equipo de red" });
    fireEvent.change(within(dialog).getByLabelText("Site"), { target: { value: BRANCH_SITE_ID } });
    const note = await within(dialog).findByRole("note");
    expect(note).toHaveTextContent("falta un perfil SNMP y un sensor del site");
    await waitFor(() => expect(within(dialog).getByRole("note")).toHaveTextContent("No hay sensores en este site"));
    expect(within(dialog).getByRole("checkbox", { name: "Consultar periódicamente" })).toBeDisabled();
  });
});

describe("InfrastructurePage: perfiles SNMP", () => {
  async function openProfiles() {
    renderPage("admin");
    fireEvent.click(await screen.findByRole("tab", { name: "Perfiles SNMP" }));
    return screen.findByRole("region", { name: "Perfiles SNMP" });
  }

  it("lista perfiles con pestañas accesibles y sin mostrar secretos", async () => {
    const panel = await openProfiles();
    expect(screen.getByRole("tab", { name: "Perfiles SNMP" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel")).toHaveAttribute("aria-labelledby", "infra-tab-profiles");
    expect(await within(panel).findByText("v3-norte")).toBeInTheDocument();
    expect(within(panel).getByText("Secreto configurado")).toBeInTheDocument();
    expect(within(panel).getByText("SHA-256 / AES-128", { exact: false })).toBeInTheDocument();
  });

  it("crea un perfil v3: los secretos se envían solo en el POST y se vacían del formulario", async () => {
    let body: Record<string, unknown> | undefined;
    routes["POST /network/snmp-profiles"] = (init) => {
      body = JSON.parse(String(init.body)) as Record<string, unknown>;
      return { status: 422, body: { error: { code: "validation_error", message: "name already used" } } };
    };
    const panel = await openProfiles();
    fireEvent.click(await within(panel).findByRole("button", { name: "Nuevo perfil" }));
    const dialog = screen.getByRole("dialog", { name: "Nuevo perfil SNMP" });
    // v3 authPriv por defecto; v2c no se ofrece si el servidor no lo permite.
    const version = within(dialog).getByLabelText("Versión SNMP") as HTMLSelectElement;
    expect(version.value).toBe("v3");
    expect(Array.from(version.options).map((o) => o.value)).toEqual(["v3"]);
    fireEvent.change(within(dialog).getByLabelText("Site"), { target: { value: BRANCH_SITE_ID } });
    fireEvent.change(within(dialog).getByLabelText("Nombre del perfil"), { target: { value: "core" } });
    fireEvent.change(within(dialog).getByLabelText("Usuario SNMPv3"), { target: { value: "sentra-ro" } });
    fireEvent.change(within(dialog).getByLabelText("Protocolo de autenticación"), { target: { value: "sha512" } });
    fireEvent.change(within(dialog).getByLabelText("Protocolo de cifrado"), { target: { value: "aes256" } });
    const auth = within(dialog).getByLabelText("Password de autenticación");
    const priv = within(dialog).getByLabelText("Password de cifrado");
    for (const input of [auth, priv]) {
      expect(input).toHaveAttribute("type", "password");
      expect(input).toHaveAttribute("autocomplete", "new-password");
    }
    fireEvent.change(auth, { target: { value: AUTH_SECRET } });
    fireEvent.change(priv, { target: { value: PRIV_SECRET } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Crear perfil" }));

    expect(await within(dialog).findByRole("alert")).toBeInTheDocument();
    expect(body).toEqual({
      site_id: BRANCH_SITE_ID,
      name: "core",
      description: null,
      snmp_version: "v3",
      username: "sentra-ro",
      auth_protocol: "sha512",
      priv_protocol: "aes256",
      auth_password: AUTH_SECRET,
      priv_password: PRIV_SECRET,
    });
    // Tras el error, el formulario ya no contiene los secretos.
    expect(within(dialog).getByLabelText("Password de autenticación")).toHaveValue("");
    expect(within(dialog).getByLabelText("Password de cifrado")).toHaveValue("");
    expect(document.body.innerHTML).not.toContain(AUTH_SECRET);
    expect(document.body.innerHTML).not.toContain(PRIV_SECRET);
    // Ninguna otra petición lleva los secretos, ni en la URL ni en el cuerpo.
    const others = calls.filter((c) => !(c.method === "POST" && c.path === "/network/snmp-profiles"));
    for (const call of others) {
      const text = `${call.url.toString()} ${String(call.init.body ?? "")}`;
      expect(text).not.toContain(AUTH_SECRET);
      expect(text).not.toContain(PRIV_SECRET);
    }
    expect(JSON.stringify(window.localStorage)).not.toContain(AUTH_SECRET);
  });

  it("ofrece v2c solo si el servidor lo permite, con aviso de inseguridad", async () => {
    let body: Record<string, unknown> | undefined;
    routes["GET /network/snmp-profiles"] = () => ({
      body: { items: [], secret_store_available: true, v2c_allowed: true },
    });
    routes["POST /network/snmp-profiles"] = (init) => {
      body = JSON.parse(String(init.body)) as Record<string, unknown>;
      return { status: 201, body: snmpProfile({ snmp_version: "v2c", security_level: "community" }) };
    };
    const panel = await openProfiles();
    expect(await within(panel).findByText("Sin perfiles SNMP")).toBeInTheDocument();
    fireEvent.click(within(panel).getByRole("button", { name: "Nuevo perfil" }));
    const dialog = screen.getByRole("dialog", { name: "Nuevo perfil SNMP" });
    fireEvent.change(within(dialog).getByLabelText("Versión SNMP"), { target: { value: "v2c" } });
    expect(within(dialog).getByRole("note")).toHaveTextContent(/heredado e inseguro/);
    fireEvent.change(within(dialog).getByLabelText("Nombre del perfil"), { target: { value: "legacy" } });
    const community = within(dialog).getByLabelText("Comunidad");
    expect(community).toHaveAttribute("type", "password");
    fireEvent.change(community, { target: { value: COMMUNITY } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Crear perfil" }));
    await waitFor(() => expect(body).toBeDefined());
    expect(body).toMatchObject({ snmp_version: "v2c", community: COMMUNITY });
    expect(body).not.toHaveProperty("auth_password");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(document.body.innerHTML).not.toContain(COMMUNITY);
  });

  it("sin almacén cifrado lo explica y no ofrece crear ni rotar", async () => {
    routes["GET /network/snmp-profiles"] = () => ({
      body: { items: [snmpProfile()], secret_store_available: false, v2c_allowed: false },
    });
    const panel = await openProfiles();
    expect(await within(panel).findByRole("note")).toHaveTextContent(/almacén cifrado de secretos/);
    expect(within(panel).queryByRole("button", { name: "Nuevo perfil" })).not.toBeInTheDocument();
    expect(within(panel).queryByRole("button", { name: /Rotar secretos/ })).not.toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: "Revocar perfil v3-norte" })).toBeInTheDocument();
  });

  it("rota secretos sin reenviar lo que no cambia y vacía el formulario", async () => {
    let body: Record<string, unknown> | undefined;
    routes[`POST /network/snmp-profiles/${snmpProfile().profile_id}/rotate`] = (init) => {
      body = JSON.parse(String(init.body)) as Record<string, unknown>;
      return { body: snmpProfile({ version: 3, secret_revision: 2 }) };
    };
    const panel = await openProfiles();
    fireEvent.click(await within(panel).findByRole("button", { name: "Rotar secretos de v3-norte" }));
    const dialog = screen.getByRole("dialog", { name: "Rotar secretos de v3-norte" });
    fireEvent.change(within(dialog).getByLabelText(/Password de cifrado nueva/), { target: { value: PRIV_SECRET } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Rotar secretos" }));
    await waitFor(() => expect(body).toBeDefined());
    expect(body).toEqual({ version: 2, priv_password: PRIV_SECRET });
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(document.body.innerHTML).not.toContain(PRIV_SECRET);
  });

  it("revoca con motivo", async () => {
    let body: unknown;
    routes[`POST /network/snmp-profiles/${snmpProfile().profile_id}/revoke`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: snmpProfile({ status: "revoked" }) };
    };
    const panel = await openProfiles();
    fireEvent.click(await within(panel).findByRole("button", { name: "Revocar perfil v3-norte" }));
    const dialog = screen.getByRole("dialog", { name: "Revocar perfil v3-norte" });
    const submit = within(dialog).getByRole("button", { name: "Revocar perfil" });
    expect(submit).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Motivo"), { target: { value: "credencial filtrada" } });
    fireEvent.click(submit);
    await waitFor(() => expect(body).toEqual({ version: 2, reason: "credencial filtrada" }));
  });
});
