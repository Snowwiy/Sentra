// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { NetworkDeviceDetail, Role } from "../api/types";
import { WithRole } from "../test/auth";
import { DEVICE_ID, macEntry, neighbor, networkDetail, poll, switchInterface } from "../test/network";
import { installFetch, type Call, type Handler } from "../test/sites";
import { InfrastructureDevicePage } from "./InfrastructureDevicePage";

const BASE = `/network/devices/${DEVICE_ID}`;
let calls: Call[];
let routes: Record<string, Handler>;
let detail: NetworkDeviceDetail;

beforeEach(() => {
  detail = networkDetail();
  routes = {
    [`GET ${BASE}`]: () => ({ body: detail }),
    [`GET ${BASE}/interfaces`]: () => ({
      body: {
        items: [switchInterface(), switchInterface({ interface_id: "1f-2", if_index: 2, name: "Gi1/0/2", oper_status: "down", is_trunk: false, present: false, if_alias: null })],
        total: 2,
        limit: 50,
        offset: 0,
      },
    }),
    [`GET ${BASE}/neighbors`]: () => ({
      body: {
        items: [
          neighbor(),
          neighbor({
            neighbor_id: "4e-2",
            protocol: "cdp",
            remote_sys_name: "ap-hall",
            remote_device: null,
            remote_match_basis: null,
            reciprocal: false,
            evidence_source: "cdp_mib",
          }),
        ],
        total: 2,
        limit: 50,
        offset: 0,
      },
    }),
    [`GET ${BASE}/vlans`]: () => ({
      body: {
        items: [
          {
            vlan_id: 10,
            name: "usuarios",
            source: "q_bridge_static",
            untagged_ports: 20,
            tagged_ports: 2,
            present: true,
            first_seen_at: "2026-10-01T10:00:00Z",
            last_seen_at: "2026-10-01T10:00:00Z",
          },
        ],
      },
    }),
    [`GET ${BASE}/mac-entries`]: () => ({
      body: {
        items: [
          macEntry(),
          macEntry({
            entry_id: "3a-2",
            mac: "aa:bb:cc:dd:ee:02",
            location: "uplink_or_shared",
            location_reason: "Puerto con 40 MACs y vecino LLDP",
            port_mac_count: 40,
            asset: null,
          }),
        ],
        total: 2,
        limit: 50,
        offset: 0,
        truncated: false,
      },
    }),
    [`GET ${BASE}/polls`]: () => ({ body: { items: [poll()], total: 1, limit: 20, offset: 0 } }),
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
    <MemoryRouter initialEntries={[`/infrastructure/devices/${DEVICE_ID}`]}>
      <WithRole role={role}>
        <Routes>
          <Route path="/infrastructure/devices/:deviceId" element={<InfrastructureDevicePage />} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

describe("InfrastructureDevicePage", () => {
  it("muestra el resumen con fuentes de evidencia y pestañas accesibles", async () => {
    renderPage("viewer");
    expect(await screen.findByRole("heading", { name: "core-sw-01" })).toBeInTheDocument();
    const summary = screen.getByRole("region", { name: "Resumen del equipo" });
    expect(within(summary).getByText("Cisco")).toBeInTheDocument();
    expect(within(summary).getByText(/según sysObjectID/)).toBeInTheDocument();
    // Modelo, firmware y serie solo si existen.
    expect(within(summary).queryByText("Modelo")).not.toBeInTheDocument();
    expect(within(summary).queryByText("Número de serie")).not.toBeInTheDocument();
    const evidence = within(summary).getByRole("list", { name: "Evidencias de la clasificación" });
    expect(evidence).toHaveTextContent("BRIDGE-MIB: 48 bridge ports");
    expect(within(summary).getByText("Consulta correcta")).toBeInTheDocument();
    expect(within(summary).getByText("v3-norte")).toBeInTheDocument();
    expect(within(summary).getByText("sensor-norte")).toBeInTheDocument();
    expect(summary).toHaveTextContent("LLDP: completo");
    expect(summary).toHaveTextContent("CDP: no soportado");

    const tablist = screen.getByRole("tablist", { name: "Inventario del equipo" });
    const tabs = within(tablist).getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual([
      "Interfaces52",
      "Vecinos LLDP/CDP2",
      "VLANs3",
      "Tabla MAC120",
      "Historial de consultas",
    ]);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    const panel = screen.getByRole("tabpanel");
    expect(panel).toHaveAttribute("aria-labelledby", "device-tab-interfaces");
    expect(await within(panel).findByText("uplink")).toBeInTheDocument();
    expect(within(panel).getAllByText("1 Gb/s")).toHaveLength(2);
    expect(within(panel).getByText("trunk")).toBeInTheDocument();
    expect(within(panel).getAllByText("etiquetadas: 20-22")).toHaveLength(2);
    expect(within(panel).getByText(/ausente desde/)).toBeInTheDocument();
    expect(within(panel).getAllByText("fuente: IF-MIB").length).toBeGreaterThan(0);
  });

  it("vecinos: informados por el equipo, con base del cruce y reciprocidad", async () => {
    renderPage("viewer");
    fireEvent.click(await screen.findByRole("tab", { name: /Vecinos LLDP\/CDP/ }));
    const panel = screen.getByRole("tabpanel");
    expect(panel).toHaveAttribute("aria-labelledby", "device-tab-neighbors");
    expect(await within(panel).findByText("dist-sw-02", { selector: "td" })).toBeInTheDocument();
    expect(within(panel).getAllByText("informado por el equipo")).toHaveLength(2);
    expect(within(panel).getAllByText("recíproco")).toHaveLength(1);
    expect(within(panel).getByRole("link", { name: "dist-sw-02" })).toHaveAttribute(
      "href",
      "/infrastructure/devices/de000000-0000-0000-0000-000000000002",
    );
    expect(within(panel).getByText("por MAC de chasis")).toBeInTheDocument();
    expect(within(panel).getByText("sin correspondencia")).toBeInTheDocument();
    expect(within(panel).getByText("fuente: LLDP-MIB")).toBeInTheDocument();
    expect(within(panel).getByText("fuente: CDP-MIB")).toBeInTheDocument();
    // La tabla nunca presenta un vecino como enlace confirmado.
    expect(within(panel).getByRole("table")).not.toHaveTextContent(/confirmad/i);
    expect(within(panel).getByRole("note")).toHaveTextContent("no es un enlace confirmado");

    fireEvent.change(within(panel).getByLabelText("Protocolo"), { target: { value: "cdp" } });
    await waitFor(() =>
      expect(calls.filter((c) => c.path === `${BASE}/neighbors`).at(-1)!.url.searchParams.get("protocol")).toBe("cdp"),
    );
  });

  it("VLANs, tabla MAC con valoración y su motivo, e historial de consultas", async () => {
    renderPage("viewer");
    fireEvent.click(await screen.findByRole("tab", { name: /VLANs/ }));
    expect(await screen.findByText("usuarios")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: /Tabla MAC/ }));
    const mac = screen.getByRole("tabpanel");
    expect(await within(mac).findByText("Posible puerto de acceso")).toBeInTheDocument();
    expect(within(mac).getByText("Única MAC en un puerto sin vecinos LLDP")).toBeInTheDocument();
    expect(within(mac).getByText("Uplink o puerto compartido")).toBeInTheDocument();
    expect(within(mac).getByRole("link", { name: "pc-recepcion" })).toHaveAttribute(
      "href",
      "/assets/a5000000-0000-0000-0000-000000000001",
    );
    fireEvent.change(within(mac).getByLabelText("Filtrar por VLAN"), { target: { value: "10" } });
    await waitFor(() =>
      expect(calls.filter((c) => c.path === `${BASE}/mac-entries`).at(-1)!.url.searchParams.get("vlan_id")).toBe("10"),
    );

    fireEvent.click(screen.getByRole("tab", { name: "Historial de consultas" }));
    const history = screen.getByRole("tabpanel");
    expect(await within(history).findByText("Correcta")).toBeInTheDocument();
    expect(within(history).getByText("1 cambios de estado")).toBeInTheDocument();
    expect(within(history).getByText("Sistema: completo · Interfaces: completo")).toBeInTheDocument();
  });

  it("aviso de evidencia histórica y último error diferenciado por código", async () => {
    detail = networkDetail({
      freshness: "historical",
      monitoring_status: "failing",
      last_error_code: "auth_failed",
      last_error_at: "2026-10-02T10:00:00Z",
      consecutive_failures: 3,
    });
    renderPage("viewer");
    const notes = await screen.findAllByRole("note");
    expect(notes.some((n) => /Evidencia histórica/.test(n.textContent ?? ""))).toBe(true);
    expect(screen.getByText(/rechazó las credenciales/)).toBeInTheDocument();
    expect(screen.getByText(/3 fallos consecutivos/)).toBeInTheDocument();
  });

  it("viewer: sin botones de consulta ni de gestión", async () => {
    renderPage("viewer");
    await screen.findByRole("heading", { name: "core-sw-01" });
    expect(screen.queryByRole("button", { name: "Consultar ahora" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Editar" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Archivar" })).not.toBeInTheDocument();
  });

  it("analyst: consulta ahora y cancela la consulta abierta, sin poder editar", async () => {
    let open = false;
    routes[`POST ${BASE}/polls`] = () => {
      open = true;
      return { status: 202, body: poll({ status: "queued", finished_at: null }) };
    };
    routes[`GET ${BASE}/polls`] = () => ({
      body: { items: open ? [poll({ status: "queued", finished_at: null })] : [poll()], total: 1, limit: 20, offset: 0 },
    });
    routes[`POST /network/polls/${poll().poll_id}/cancel`] = () => {
      open = false;
      return { body: poll({ status: "cancelled" }) };
    };
    renderPage("analyst");
    const button = await screen.findByRole("button", { name: "Consultar ahora" });
    expect(screen.queryByRole("button", { name: "Editar" })).not.toBeInTheDocument();
    fireEvent.click(button);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === `${BASE}/polls`)).toBe(true));
    // Pasa al historial y ofrece cancelar la consulta en cola.
    const cancel = await screen.findByRole("button", { name: "Cancelar consulta" });
    expect(screen.getByRole("tab", { name: "Historial de consultas" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("button", { name: "Consultar ahora" })).toBeDisabled();
    fireEvent.click(cancel);
    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.path === `/network/polls/${poll().poll_id}/cancel`)).toBe(true),
    );
  });

  it("si no se puede consultar, explica los bloqueos en texto claro", async () => {
    detail = networkDetail({ can_poll: false, poll_blockers: ["sensor_missing", "profile_revoked"], monitoring_status: "sensor_pending" });
    renderPage("analyst");
    expect(await screen.findByRole("button", { name: "Consultar ahora" })).toBeDisabled();
    const blockers = screen.getByRole("status", { name: "Motivos por los que no se puede consultar" });
    expect(blockers).toHaveTextContent("No tiene sensor asignado.");
    expect(blockers).toHaveTextContent("Su perfil SNMP está revocado.");
  });

  it("muestra los bloqueos de un 409 network_poll_unavailable", async () => {
    routes[`POST ${BASE}/polls`] = () => ({
      status: 409,
      body: {
        error: { code: "network_poll_unavailable", message: "x", details: [{ blockers: ["sensor_offline"] }] },
      },
    });
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Consultar ahora" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("No se puede consultar el equipo ahora mismo.");
    expect(alert).toHaveTextContent("El sensor asignado no está conectado.");
  });

  it("admin: un 409 al editar recarga el equipo con la versión actual", async () => {
    const bodies: unknown[] = [];
    routes[`PATCH ${BASE}`] = (init) => {
      bodies.push(JSON.parse(String(init.body)));
      if (bodies.length === 1) {
        detail = networkDetail({ version: 4, name: "core-sw-01" });
        return {
          status: 409,
          body: { error: { code: "network_device_conflict", message: "x", details: [{ current_version: 4 }] } },
        };
      }
      return { body: detail };
    };
    routes["GET /network/snmp-profiles"] = () => ({ body: { items: [], secret_store_available: true, v2c_allowed: false } });
    routes["GET /sensors"] = () => ({ body: { items: [], summary: {} } });
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Editar" }));
    const dialog = screen.getByRole("dialog", { name: "Editar core-sw-01" });
    fireEvent.change(within(dialog).getByLabelText("Puerto SNMP"), { target: { value: "1161" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Guardar cambios" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(/Otro administrador ha modificado este equipo/);
    expect(bodies[0]).toEqual({ version: 3, snmp_port: 1161 });
    // El formulario vuelve a los valores actuales; el siguiente intento usa la versión nueva.
    await waitFor(() => expect(within(dialog).getByLabelText("Puerto SNMP")).toHaveValue(161));
    fireEvent.change(within(dialog).getByLabelText("Puerto SNMP"), { target: { value: "1162" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Guardar cambios" }));
    await waitFor(() => expect(bodies[1]).toEqual({ version: 4, snmp_port: 1162 }));
  });

  it("admin: archiva con motivo opcional", async () => {
    let body: unknown;
    routes[`POST ${BASE}/archive`] = (init) => {
      body = JSON.parse(String(init.body));
      return { body: networkDetail({ status: "archived" }) };
    };
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Archivar" }));
    const dialog = screen.getByRole("dialog", { name: "Archivar core-sw-01" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Archivar equipo" }));
    await waitFor(() => expect(body).toEqual({ version: 3 }));
  });

  it("estado de error al cargar el equipo", async () => {
    routes[`GET ${BASE}`] = () => ({
      status: 404,
      body: { error: { code: "network_device_not_found", message: "not found" } },
    });
    renderPage("viewer");
    expect(await screen.findByRole("alert")).toHaveTextContent("El equipo de red no existe o ya no está disponible.");
    expect(screen.getByRole("link", { name: "Volver a Infraestructura" })).toBeInTheDocument();
  });

  it("estados vacío y de carga del inventario", async () => {
    routes[`GET ${BASE}/interfaces`] = () => ({ body: { items: [], total: 0, limit: 50, offset: 0 } });
    renderPage("viewer");
    expect(screen.getByText("Cargando equipo…")).toBeInTheDocument();
    expect(await screen.findByText("Sin interfaces informadas")).toBeInTheDocument();
  });

  // Fase 6D.4: estado SNMP, pausa automática y verificación de compatibilidad.
  it("muestra el estado SNMP con el texto del contrato (nunca nombres de excepción)", async () => {
    detail = networkDetail({ snmp_status: "auth_failed" });
    renderPage("viewer");
    expect(await screen.findByTestId("snmp-status")).toHaveTextContent(
      "Autenticación SNMP rechazada (usuario, claves o protocolos del perfil)",
    );
    cleanup();
    detail = networkDetail({ snmp_status: "collector_error" });
    renderPage("viewer");
    expect(await screen.findByTestId("snmp-status")).toHaveTextContent(
      "Error interno del colector del sensor (no es un diagnóstico del equipo)",
    );
  });

  it("un error de consulta internal se muestra como «Error interno del colector» sin el detalle", async () => {
    routes[`GET ${BASE}/polls`] = () => ({
      body: {
        items: [poll({ status: "failed", error_code: "internal", error_message: "KeyError: 'sysName'" })],
        total: 1,
        limit: 20,
        offset: 0,
      },
    });
    renderPage("viewer");
    fireEvent.click(await screen.findByRole("tab", { name: "Historial de consultas" }));
    expect(await screen.findByText("Error interno del colector")).toBeInTheDocument();
    expect(screen.queryByText(/KeyError/)).not.toBeInTheDocument();
  });

  it("consultas en pausa: motivo para todos y Reanudar solo para admin", async () => {
    detail = networkDetail({
      monitoring_status: "paused",
      monitoring_paused_at: "2026-10-20T10:00:00Z",
      monitoring_pause_reason: "timeout",
    });
    renderPage("analyst");
    const banner = await screen.findByRole("status", { name: "Consultas periódicas en pausa" });
    expect(banner).toHaveTextContent("Consultas periódicas en pausa");
    expect(banner).toHaveTextContent("Motivo: Tiempo de espera agotado (respondía antes)");
    expect(within(banner).queryByRole("button", { name: "Reanudar" })).not.toBeInTheDocument();
    expect(screen.getByText("En pausa")).toBeInTheDocument();
  });

  it("admin reanuda con la versión; un 409 avisa y recarga", async () => {
    detail = networkDetail({ monitoring_paused_at: "2026-10-20T10:00:00Z", monitoring_pause_reason: "unreachable" });
    const bodies: unknown[] = [];
    routes[`POST ${BASE}/monitoring/resume`] = (init) => {
      bodies.push(JSON.parse(String(init.body)));
      return { status: 409, body: { error: { code: "network_device_conflict", message: "x" } } };
    };
    renderPage("admin");
    const banner = await screen.findByRole("status", { name: "Consultas periódicas en pausa" });
    expect(banner).toHaveTextContent("Equipo inaccesible desde el sensor");
    const gets = calls.filter((c) => c.method === "GET" && c.path === BASE).length;
    fireEvent.click(within(banner).getByRole("button", { name: "Reanudar" }));
    expect(await screen.findByText(/Otro administrador ha modificado este equipo/)).toBeInTheDocument();
    expect(bodies).toEqual([{ version: 3 }]);
    await waitFor(() => expect(calls.filter((c) => c.method === "GET" && c.path === BASE).length).toBeGreaterThan(gets));
  });

  it("verificar compatibilidad SNMP (network:poll) y su 409", async () => {
    routes[`POST ${BASE}/compatibility-check`] = () => ({
      status: 409,
      body: { error: { code: "network_poll_open", message: "x" } },
    });
    renderPage("viewer");
    await screen.findByTestId("snmp-status");
    expect(screen.queryByRole("button", { name: "Verificar compatibilidad SNMP" })).not.toBeInTheDocument();
    cleanup();
    renderPage("analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Verificar compatibilidad SNMP" }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.path === `${BASE}/compatibility-check`)).toBe(true),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("Ya hay una consulta abierta para este equipo.");
  });
});
