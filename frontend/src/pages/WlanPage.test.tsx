// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Role } from "../api/types";
import { SiteProvider } from "../site/SiteContext";
import { WithRole } from "../test/auth";
import { BRANCH_SITE_ID, SITES, installFetch, type Call, type Handler } from "../test/sites";
import {
  AP_ID,
  BSS_ID,
  CONTROLLER_ID,
  emptyOverview,
  page,
  wlanAp,
  wlanApDetail,
  wlanBss,
  wlanClient,
  wlanObservation,
  wlanOverview,
  wlanSsid,
} from "../test/wlan";
import { WlanPage } from "./WlanPage";

const AP_HISTORICAL = wlanAp({
  access_point_id: "a9000000-0000-0000-0000-000000000002",
  display_name: "ap-almacen",
  name: "ap-almacen",
  reported_status: "down",
  authorization_status: "authorized",
  freshness: "historical",
  present: true,
});
const AP_ABSENT = wlanAp({
  access_point_id: "a9000000-0000-0000-0000-000000000003",
  display_name: "ap-retirado",
  name: "ap-retirado",
  present: false,
  freshness: "historical",
});

let calls: Call[];
let routes: Record<string, Handler>;

beforeEach(() => {
  window.localStorage.clear();
  routes = {
    "GET /sites": () => ({ body: { items: SITES } }),
    "GET /network/wlan/overview": () => ({ body: wlanOverview() }),
    "GET /network/wlan/access-points": () => ({ body: page([wlanAp(), AP_HISTORICAL, AP_ABSENT]) }),
    [`GET /network/wlan/access-points/${AP_ID}`]: () => ({ body: wlanApDetail() }),
    "GET /network/wlan/ssids": () => ({ body: page([wlanSsid(), wlanSsid({ ssid: "Invitados", protections: ["open"], findings: ["open_network"] })]) }),
    "GET /network/wlan/bss": () => ({
      body: page([
        wlanBss(),
        wlanBss({
          bss_id: "b5500000-0000-0000-0000-000000000002",
          bssid: "02:aa:bb:cc:dd:01",
          bssid_randomized: true,
          ssid: "Vecino",
          protection: "wep",
          protection_reported: "WEP",
          access_point: null,
          source: "agent",
          sources: ["agent"],
          confidence: "observed",
          findings: [{ code: "wep", severity: "info", contributes_to_risk: false, detail: "WEP is broken" }],
        }),
      ]),
    }),
    "GET /network/wlan/clients": () => ({
      body: page([
        wlanClient(),
        wlanClient({
          client_id: "c1000000-0000-0000-0000-000000000002",
          mac: "00:1b:2c:00:00:99",
          mac_randomized: false,
          identity_confidence: "confirmed",
          correlation_basis: "agent_self",
          source: "agent",
          asset: { asset_id: "a5000000-0000-0000-0000-000000000001", display_name: "LAPTOP-QA" },
        }),
      ]),
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

function renderPage(role: Role, path = "/wlan") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <WithRole role={role}>
        <SiteProvider>
          <WlanPage />
        </SiteProvider>
      </WithRole>
    </MemoryRouter>,
  );
}

const callsTo = (path: string) => calls.filter((c) => c.method === "GET" && c.path === path);
const lastQuery = (path: string) => callsTo(path).at(-1)!.url.searchParams;

describe("WlanPage: resumen y disponibilidad", () => {
  it("sin datos explica cómo obtenerlos y no muestra pestañas vacías", async () => {
    routes["GET /network/wlan/overview"] = () => ({ body: emptyOverview() });
    renderPage("viewer");
    expect(await screen.findByText("Todavía no hay datos Wi-Fi en este ámbito")).toBeInTheDocument();
    const sources = screen.getByRole("region", { name: "Disponibilidad de datos Wi-Fi" });
    expect(sources).toHaveTextContent("snmp.wlan");
    expect(sources).toHaveTextContent("wireless");
    expect(within(sources).getAllByText("No configurado")).toHaveLength(2);
    expect(within(sources).getAllByText(/Última observación: nunca/)).toHaveLength(2);
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
    expect(callsTo("/network/wlan/access-points")).toHaveLength(0);
    expect(screen.queryByRole("region", { name: "Resumen Wi-Fi" })).not.toBeInTheDocument();
  });

  it("muestra recuentos, fuentes, consulta parcial y avisos inseguros informativos", async () => {
    renderPage("viewer");
    const stats = await screen.findByRole("region", { name: "Resumen Wi-Fi" });
    expect(within(stats).getByRole("button", { name: /Puntos de acceso/ })).toHaveTextContent("2");
    expect(within(stats).getByRole("button", { name: /Configuraciones inseguras/ })).toHaveTextContent("1");
    const snmp = screen.getByRole("article", { name: "Fuente: SNMP (controladoras y AP)" });
    expect(within(snmp).getByText("Parcial")).toBeInTheDocument();
    expect(within(snmp).getByText("Consulta parcial")).toBeInTheDocument();
    expect(snmp).toHaveTextContent("1 equipo fue parcial");
    expect(snmp).toHaveTextContent("1 sensor con snmp.wlan");
    expect(snmp).not.toHaveTextContent("Última observación: nunca");
    const agent = screen.getByRole("article", { name: "Fuente: Agentes (Wi-Fi de cada equipo)" });
    expect(within(agent).getByText("Informando")).toBeInTheDocument();
    expect(agent).toHaveTextContent("2 correcto, 1 sin adaptador Wi-Fi");
    const insecure = screen.getAllByRole("note").find((n) => n.textContent?.includes("Configuraciones inseguras"));
    expect(insecure).toHaveTextContent("Cifrado WEP: 1");
    expect(insecure).toHaveTextContent("No modifican el riesgo");
    // "rogue" solo aparece en la nota que explica que no existe; nunca como estado ni acción.
    const rogue = Array.from(document.querySelectorAll("button, option, .badge, .status")).filter((el) =>
      /rogue/i.test(el.textContent ?? ""),
    );
    expect(rogue).toHaveLength(0);
  });

  it("propaga el alcance de site al resumen y a la lista", async () => {
    renderPage("viewer");
    await screen.findByRole("button", { name: "Ver detalle de ap-planta1" });
    fireEvent.change(screen.getByLabelText("Site"), { target: { value: BRANCH_SITE_ID } });
    await waitFor(() => expect(lastQuery("/network/wlan/overview").get("site_id")).toBe(BRANCH_SITE_ID));
    await waitFor(() => expect(lastQuery("/network/wlan/access-points").get("site_id")).toBe(BRANCH_SITE_ID));
  });
});

describe("WlanPage: puntos de acceso", () => {
  it("lista APs con estado informado y evidencia; solo marca ausente lo que la API marca", async () => {
    renderPage("viewer");
    const table = await screen.findByRole("region", { name: "Puntos de acceso" });
    const row = (name: string) =>
      within(table).getByRole("button", { name: `Ver detalle de ${name}` }).closest("tr") as HTMLElement;
    await within(table).findByRole("button", { name: "Ver detalle de ap-planta1" });
    expect(within(row("ap-planta1")).getByText("Activo (informado)")).toBeInTheDocument();
    expect(within(row("ap-planta1")).getByText("Sin clasificar")).toBeInTheDocument();
    expect(within(row("ap-planta1")).getByText("Evidencia reciente")).toBeInTheDocument();
    expect(within(row("ap-almacen")).getByText("Evidencia histórica")).toBeInTheDocument();
    expect(within(row("ap-almacen")).queryByText("No visto en la última consulta completa")).not.toBeInTheDocument();
    expect(within(row("ap-almacen")).getByText("Autorizado")).toBeInTheDocument();
    expect(within(row("ap-retirado")).getByText("No visto en la última consulta completa")).toBeInTheDocument();
    expect(table).not.toHaveTextContent(/desaparecid/i);
    expect(lastQuery("/network/wlan/access-points").get("limit")).toBe("25");
  });

  it("envía filtros de autorización, banda, frescura, presencia y búsqueda", async () => {
    routes["GET /network/wlan/access-points"] = () => ({ body: page([wlanAp()], 60) });
    renderPage("viewer");
    await screen.findByRole("button", { name: "Ver detalle de ap-planta1" });
    const path = "/network/wlan/access-points";
    fireEvent.change(screen.getByLabelText("Autorización"), { target: { value: "external" } });
    await waitFor(() => expect(lastQuery(path).get("authorization")).toBe("external"));
    fireEvent.change(screen.getByLabelText("Banda"), { target: { value: "5" } });
    await waitFor(() => expect(lastQuery(path).get("band")).toBe("5"));
    fireEvent.change(screen.getByLabelText("Frescura"), { target: { value: "historical" } });
    await waitFor(() => expect(lastQuery(path).get("freshness")).toBe("historical"));
    fireEvent.change(screen.getByLabelText("Presencia"), { target: { value: "false" } });
    await waitFor(() => expect(lastQuery(path).get("present")).toBe("false"));
    fireEvent.change(screen.getByLabelText("Estado informado"), { target: { value: "down" } });
    await waitFor(() => expect(lastQuery(path).get("status")).toBe("down"));
    fireEvent.change(screen.getByLabelText("Buscar puntos de acceso"), { target: { value: "planta" } });
    await waitFor(() => expect(lastQuery(path).get("q")).toBe("planta"));
    fireEvent.click(await screen.findByRole("button", { name: "Siguiente" }));
    await waitFor(() => expect(lastQuery(path).get("offset")).toBe("25"));
    expect(lastQuery(path).get("authorization")).toBe("external");
  });

  it("muestra error con reintento", async () => {
    let fail = true;
    routes["GET /network/wlan/access-points"] = () =>
      fail ? { status: 500, body: { error: { code: "internal", message: "fallo interno" } } } : { body: page([wlanAp()]) };
    renderPage("viewer");
    const table = await screen.findByRole("region", { name: "Puntos de acceso" });
    expect(await within(table).findByRole("alert")).toHaveTextContent("fallo interno");
    fail = false;
    fireEvent.click(within(table).getByRole("button", { name: "Reintentar" }));
    expect(await within(table).findByRole("button", { name: "Ver detalle de ap-planta1" })).toBeInTheDocument();
  });
});

describe("WlanPage: detalle de AP y permisos", () => {
  it("viewer: ve el detalle con procedencia e historial, sin acciones", async () => {
    renderPage("viewer");
    fireEvent.click(await screen.findByRole("button", { name: "Ver detalle de ap-planta1" }));
    const panel = await screen.findByRole("dialog", { name: "Detalle del AP ap-planta1" });
    expect(await within(panel).findByText("SNMP AireOS (controladora)")).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: "wlc-01" })).toHaveAttribute(
      "href",
      `/infrastructure/devices/${CONTROLLER_ID}`,
    );
    const history = within(panel).getByRole("region", { name: "Historial de observaciones" });
    expect(history).toHaveTextContent("equipo wlc-01 · sensor sensor-norte");
    expect(history).toHaveTextContent("status: up · channel: 6");
    expect(within(panel).queryByRole("group", { name: "Acciones sobre el AP" })).not.toBeInTheDocument();
    expect(within(panel).queryByRole("button", { name: /Marcar como/ })).not.toBeInTheDocument();
    expect(within(panel).queryByRole("button", { name: "Vincular" })).not.toBeInTheDocument();
    // Escape cierra el panel.
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("analyst (sin network:manage): tampoco ve acciones de clasificación en BSS", async () => {
    renderPage("analyst", "/wlan?tab=bss");
    const table = await screen.findByRole("region", { name: "BSS" });
    await within(table).findByText("Vecino");
    expect(within(table).queryByRole("columnheader", { name: "Acciones" })).not.toBeInTheDocument();
    expect(within(table).queryByRole("button", { name: /Marcar como/ })).not.toBeInTheDocument();
  });

  it("admin: autoriza un AP tras confirmar, con motivo y versión", async () => {
    let body: unknown;
    routes[`POST /network/wlan/access-points/${AP_ID}/authorization`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: wlanApDetail({ authorization_status: "authorized", version: 4 }) };
    };
    renderPage("admin", `/wlan?ap=${AP_ID}`);
    const panel = await screen.findByRole("dialog", { name: "Detalle del AP ap-planta1" });
    const actions = await within(panel).findByRole("group", { name: "Acciones sobre el AP" });
    // Nunca se ofrece "rogue": solo autorizado y externo (el actual es "sin clasificar").
    expect(within(actions).getAllByRole("button").map((b) => b.textContent)).toEqual([
      "Marcar como autorizado",
      "Marcar como externo",
      "Vincular",
    ]);
    fireEvent.click(within(actions).getByRole("button", { name: "Marcar como autorizado" }));
    const dialog = screen.getByRole("dialog", { name: "Marcar como autorizado: ap-planta1" });
    expect(dialog).toHaveTextContent("Sentra no bloquea, desautentica ni cambia nada en la red");
    // Cancelar no envía nada.
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancelar" }));
    expect(screen.queryByRole("dialog", { name: /Marcar como autorizado:/ })).not.toBeInTheDocument();
    expect(body).toBeUndefined();

    fireEvent.click(within(actions).getByRole("button", { name: "Marcar como autorizado" }));
    const again = screen.getByRole("dialog", { name: "Marcar como autorizado: ap-planta1" });
    fireEvent.change(within(again).getByLabelText("Motivo (opcional)"), { target: { value: "AP de sistemas\tplanta 1" } });
    fireEvent.click(within(again).getByRole("button", { name: "Marcar como autorizado" }));
    await waitFor(() => expect(body).toEqual({ status: "authorized", version: 3, reason: "AP de sistemas planta 1" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: /Marcar como autorizado:/ })).not.toBeInTheDocument());
  });

  it("admin: un conflicto de versión se explica y recarga el AP", async () => {
    routes[`POST /network/wlan/access-points/${AP_ID}/authorization`] = () => ({
      status: 409,
      body: { error: { code: "wlan_version_conflict", message: "version mismatch" } },
    });
    renderPage("admin", `/wlan?ap=${AP_ID}`);
    const panel = await screen.findByRole("dialog", { name: "Detalle del AP ap-planta1" });
    fireEvent.click(await within(panel).findByRole("button", { name: "Marcar como externo" }));
    const dialog = screen.getByRole("dialog", { name: "Marcar como externo: ap-planta1" });
    const detailCalls = callsTo(`/network/wlan/access-points/${AP_ID}`).length;
    fireEvent.click(within(dialog).getByRole("button", { name: "Marcar como externo" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Otro usuario ha cambiado este elemento");
    await waitFor(() => expect(callsTo(`/network/wlan/access-points/${AP_ID}`).length).toBeGreaterThan(detailCalls));
  });

  it("admin: desvincula con confirmación", async () => {
    let body: unknown;
    routes[`GET /network/wlan/access-points/${AP_ID}`] = () => ({
      body: wlanApDetail({
        network_device: { device_id: CONTROLLER_ID, display_name: "wlc-01" },
        link_evidence: {
          network_device: { basis: "management_ip", value: "192.0.2.21", method: "automatic", at: "2026-10-01T10:00:00Z", by: null },
        },
      }),
    });
    routes[`POST /network/wlan/access-points/${AP_ID}/unlink`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: wlanApDetail({ link_suppressed: true }) };
    };
    renderPage("admin", `/wlan?ap=${AP_ID}`);
    const panel = await screen.findByRole("dialog", { name: "Detalle del AP ap-planta1" });
    expect(await within(panel).findByText(/IP de gestión coincidente \(192\.0\.2\.21\)/)).toBeInTheDocument();
    fireEvent.click(within(panel).getByRole("button", { name: "Desvincular" }));
    const dialog = screen.getByRole("dialog", { name: "Desvincular ap-planta1" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Desvincular" }));
    await waitFor(() => expect(body).toEqual({ target: "network_device" }));
  });

  it("admin: vincular exige elegir destino y confirmar", async () => {
    let body: unknown;
    routes["GET /network/devices"] = () => ({
      body: {
        items: [{ device_id: CONTROLLER_ID, display_name: "wlc-01", management_address: "192.0.2.21" }],
        total: 1,
        limit: 200,
        offset: 0,
        counts: { total: 1, by_classification: {}, by_monitoring_status: {} },
      },
    });
    routes["GET /assets"] = () => ({ body: { items: [], total: 0 } });
    routes[`POST /network/wlan/access-points/${AP_ID}/link`] = (init) => {
      body = JSON.parse(String(init.body));
      return { status: 409, body: { error: { code: "wlan_link_evidence_insufficient", message: "no evidence" } } };
    };
    renderPage("admin", `/wlan?ap=${AP_ID}`);
    const panel = await screen.findByRole("dialog", { name: "Detalle del AP ap-planta1" });
    fireEvent.click(await within(panel).findByRole("button", { name: "Vincular" }));
    const dialog = screen.getByRole("dialog", { name: "Vincular ap-planta1" });
    const submit = within(dialog).getByRole("button", { name: "Vincular" });
    expect(submit).toBeDisabled();
    await within(dialog).findByRole("option", { name: /wlc-01/ });
    fireEvent.change(within(dialog).getByLabelText("Equipo de red"), { target: { value: CONTROLLER_ID } });
    expect(submit).toBeDisabled();
    fireEvent.click(within(dialog).getByLabelText(/Confirmo que este AP/));
    fireEvent.click(submit);
    await waitFor(() => expect(body).toEqual({ network_device_id: CONTROLLER_ID }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("No hay evidencia suficiente");
  });
});

describe("WlanPage: redes, BSS y clientes", () => {
  it("SSID: abre los BSS de esa red filtrados por SSID exacto", async () => {
    renderPage("viewer", "/wlan?tab=ssids");
    const table = await screen.findByRole("region", { name: "Redes (SSID)" });
    const invitados = (await within(table).findByRole("button", { name: "Ver BSS de Invitados" })).closest("tr")!;
    expect(within(invitados as HTMLElement).getByText("Red abierta sin cifrado")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Buscar SSID"), { target: { value: "Corp" } });
    await waitFor(() => expect(lastQuery("/network/wlan/ssids").get("q")).toBe("Corp"));
    fireEvent.click(within(table).getByRole("button", { name: "Ver BSS de Corp" }));
    expect(await screen.findByRole("region", { name: "BSS" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "BSS" })).toHaveAttribute("aria-selected", "true");
    await waitFor(() => expect(lastQuery("/network/wlan/bss").get("ssid")).toBe("Corp"));
  });

  it("BSS: aviso de MAC aleatoria, configuración insegura y filtros de seguridad", async () => {
    renderPage("viewer", "/wlan?tab=bss");
    const table = await screen.findByRole("region", { name: "BSS" });
    const row = (await within(table).findByText("Vecino")).closest("tr") as HTMLElement;
    expect(within(row).getByText("MAC aleatoria")).toBeInTheDocument();
    expect(within(row).getByText("Insegura")).toBeInTheDocument();
    expect(within(row).getByText("Cifrado WEP")).toBeInTheDocument();
    expect(within(row).getByText("sin AP conocido")).toBeInTheDocument();
    const path = "/network/wlan/bss";
    fireEvent.change(screen.getByLabelText("Seguridad"), { target: { value: "wep" } });
    await waitFor(() => expect(lastQuery(path).get("protection")).toBe("wep"));
    fireEvent.click(screen.getByLabelText("Solo configuraciones inseguras"));
    await waitFor(() => expect(lastQuery(path).get("insecure")).toBe("true"));
    fireEvent.change(screen.getByLabelText("Fuente"), { target: { value: "agent" } });
    await waitFor(() => expect(lastQuery(path).get("source")).toBe("agent"));
  });

  it("la tarjeta de configuraciones inseguras abre BSS con ese filtro", async () => {
    renderPage("viewer");
    const stats = await screen.findByRole("region", { name: "Resumen Wi-Fi" });
    fireEvent.click(within(stats).getByRole("button", { name: /Configuraciones inseguras/ }));
    await screen.findByRole("region", { name: "BSS" });
    expect(screen.getByLabelText("Solo configuraciones inseguras")).toBeChecked();
    await waitFor(() => expect(lastQuery("/network/wlan/bss").get("insecure")).toBe("true"));
  });

  it("admin: clasifica un BSS como externo tras confirmar", async () => {
    let body: unknown;
    routes[`POST /network/wlan/bss/${BSS_ID}/authorization`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: wlanBss({ authorization_status: "external", version: 2 }) };
    };
    renderPage("admin", "/wlan?tab=bss");
    const table = await screen.findByRole("region", { name: "BSS" });
    fireEvent.click(await within(table).findByRole("button", { name: "Marcar como externo: 00:1b:2c:3d:4e:10" }));
    const dialog = screen.getByRole("dialog", { name: "Marcar como externo: BSS 00:1b:2c:3d:4e:10 (Corp)" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Marcar como externo" }));
    await waitFor(() => expect(body).toEqual({ status: "external", version: 1 }));
  });

  it("clientes: MAC aleatoria nunca como identidad y búsqueda por BSSID", async () => {
    renderPage("viewer", "/wlan?tab=clients");
    const table = await screen.findByRole("region", { name: "Clientes Wi-Fi" });
    const random = (await within(table).findByText("da:a1:19:00:00:01")).closest("tr") as HTMLElement;
    expect(within(random).getByText("MAC aleatoria")).toBeInTheDocument();
    expect(within(random).getByText("Sin activo asociado")).toBeInTheDocument();
    expect(within(random).getByText("Solo observación")).toBeInTheDocument();
    const confirmed = within(table).getByRole("link", { name: "LAPTOP-QA" }).closest("tr") as HTMLElement;
    expect(within(confirmed).getByText("Identidad confirmada")).toBeInTheDocument();
    expect(within(confirmed).getByText("lo informa el propio agente")).toBeInTheDocument();
    const path = "/network/wlan/clients";
    fireEvent.change(screen.getByLabelText("Buscar clientes por SSID o BSSID"), { target: { value: "00:1B:2C:3D:4E:10" } });
    await waitFor(() => expect(lastQuery(path).get("bssid")).toBe("00:1B:2C:3D:4E:10"));
    expect(lastQuery(path).has("ssid")).toBe(false);
    fireEvent.change(screen.getByLabelText("Buscar clientes por SSID o BSSID"), { target: { value: "Corp" } });
    await waitFor(() => expect(lastQuery(path).get("ssid")).toBe("Corp"));
    fireEvent.change(screen.getByLabelText("Identidad"), { target: { value: "confirmed" } });
    await waitFor(() => expect(lastQuery(path).get("identity")).toBe("confirmed"));
  });

  it("carga más observaciones del historial por páginas", async () => {
    const many = Array.from({ length: 50 }, (_, i) => wlanObservation({ observation_id: i + 1 }));
    routes[`GET /network/wlan/access-points/${AP_ID}`] = () => ({ body: wlanApDetail({ observations: many }) });
    routes[`GET /network/wlan/access-points/${AP_ID}/observations`] = () => ({
      body: { items: [wlanObservation({ observation_id: 51, data: { channel: 11 } })], total: 51, limit: 50, offset: 50 },
    });
    renderPage("viewer", `/wlan?ap=${AP_ID}`);
    const panel = await screen.findByRole("dialog", { name: "Detalle del AP ap-planta1" });
    fireEvent.click(await within(panel).findByRole("button", { name: "Cargar más observaciones" }));
    expect(await within(panel).findByText("channel: 11")).toBeInTheDocument();
    expect(lastQuery(`/network/wlan/access-points/${AP_ID}/observations`).get("offset")).toBe("50");
    expect(within(panel).queryByRole("button", { name: "Cargar más observaciones" })).not.toBeInTheDocument();
  });
});
