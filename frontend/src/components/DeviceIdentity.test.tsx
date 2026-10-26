// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { WithRole } from "../test/auth";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Asset, Role } from "../api/types";
import { AssetName, DeviceTypeCell, IdentificationPanel } from "./DeviceIdentity";

function asset(overrides: Partial<Asset> = {}): Asset {
  const now = new Date().toISOString();
  return {
    asset_id: "6f1c2a8e-0000-4000-8000-000000000001",
    display_name: "192.168.50.108",
    monitoring_method: "discovered",
    hostname: null,
    os_name: null,
    os_version: null,
    architecture: null,
    primary_ip: "192.168.50.108",
    agent_version: null,
    status: "online",
    agent_status: null,
    network_status: "online",
    first_seen_at: now,
    last_seen_at: null,
    created_at: now,
    updated_at: now,
    latest_telemetry: null,
    mac_address: "a4:00:03:00:00:12",
    reverse_dns: null,
    vendor: null,
    network_adapter_vendor: null,
    device_type: null,
    device_type_reason: null,
    device_name: null,
    name_source: null,
    device_vendor: null,
    device_model: null,
    probable_os: null,
    classification_confidence: null,
    classification_evidence: [],
    discovery_sources: ["arp"],
    discovery_network: "192.168.50.0/24",
    discovered_at: now,
    last_network_seen_at: now,
    open_ports: [],
    criticality: "medium",
    role: "unknown",
    risk_score: null,
    risk_level: null,
    risk_confidence: null,
    archived_at: null,
    archived_by: null,
    archive_reason: null,
    lifecycle_version: 0,
    custom_label: null,
    custom_label_version: 0,
    custom_label_updated_at: null,
    custom_label_updated_by: null,
    manual_device_type: null,
    observed_names: [],
    managed_history: false,
    event_coverage: null,
    event_coverage_at: null,
    lifecycle_state: "active",
    lifecycle_source: "discovered",
    missed_discovery_scans: 0,
    last_activity_at: null,
    site_id: "00000000-0000-0000-0000-00000000d5f1",
    site_name: "Principal",
    ...overrides,
  };
}

function renderIn(node: React.ReactNode, role: Role = "admin") {
  return render(
    <MemoryRouter>
      <WithRole role={role}>{node}</WithRole>
    </MemoryRouter>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("presentación de la identidad", () => {
  it("muestra nombre como dato principal e IP como secundaria", () => {
    renderIn(<AssetName asset={asset({ device_name: "MNA-LX9", primary_ip: "192.168.50.141" })} />);
    expect(screen.getByRole("link", { name: "MNA-LX9" })).toBeInTheDocument();
    expect(screen.getByText("192.168.50.141")).toBeInTheDocument();
  });

  it("usa el tipo probable o 'Dispositivo desconocido' en vez de la IP", () => {
    renderIn(
      <AssetName asset={asset({ device_type: "console", classification_confidence: "medium" })} showIp={false} />,
    );
    expect(screen.getByRole("link", { name: "Consola probable" })).toBeInTheDocument();
    expect(screen.queryByText("192.168.50.108")).not.toBeInTheDocument();
    cleanup();
    renderIn(<AssetName asset={asset()} />);
    expect(screen.getByRole("link", { name: "Dispositivo desconocido" })).toBeInTheDocument();
  });

  it("celda de tipo con fabricante del dispositivo", () => {
    renderIn(
      <DeviceTypeCell
        asset={asset({ device_type: "mobile", classification_confidence: "high", device_vendor: "Huawei" })}
      />,
    );
    expect(screen.getByText("Móvil")).toBeInTheDocument();
    expect(screen.getByText("Huawei")).toBeInTheDocument();
    cleanup();
    renderIn(<DeviceTypeCell asset={asset()} />);
    expect(screen.getByText("Desconocido")).toBeInTheDocument();
  });
});

describe("sección Identificación", () => {
  it("activo descubierto: confianza, NIC, SO probable y evidencias", () => {
    renderIn(
      <IdentificationPanel
        asset={asset({
          device_type: "console",
          classification_confidence: "medium",
          device_vendor: "Nintendo",
          network_adapter_vendor: "Realtek",
          vendor: "Realtek Semiconductor Corp.",
          probable_os: "Android",
          classification_evidence: [
            { source: "mac_vendor", value: "Realtek" },
            { source: "reverse_dns", value: "Nintendo-Switch" },
          ],
        })}
      />,
    );
    const panel = screen.getByRole("region", { name: "Identificación" });
    // Sin nombre: el título es el tipo probable, nunca la IP.
    expect(within(panel).getAllByText("Consola probable").length).toBeGreaterThan(0);
    expect(within(panel).getByText("Fabricante NIC").nextElementSibling).toHaveTextContent("Realtek");
    expect(within(panel).getByText("Fabricante dispositivo").nextElementSibling).toHaveTextContent("Nintendo");
    expect(within(panel).getByText("SO probable").nextElementSibling).toHaveTextContent("Android probable");
    expect(within(panel).getByText("Confianza").nextElementSibling).toHaveTextContent("Media");
    const evidence = within(panel).getByRole("list", { name: "Evidencias" });
    expect(within(evidence).getByText("Fabricante MAC: Realtek")).toBeInTheDocument();
    expect(within(evidence).getByText("DNS inverso: Nintendo-Switch")).toBeInTheDocument();
  });

  it("activo Managed: datos del agente y sin campos vacíos", () => {
    renderIn(
      <IdentificationPanel
        asset={asset({
          monitoring_method: "agent",
          hostname: "Ravenslg",
          device_name: "Ravenslg",
          name_source: "agent_hostname",
          os_name: "Linux",
          os_version: "Ubuntu 24.04",
          primary_ip: "192.168.50.66",
          device_type: "pc",
          classification_confidence: "high",
        })}
      />,
    );
    const panel = screen.getByRole("region", { name: "Identificación" });
    expect(within(panel).getByText("Ravenslg")).toBeInTheDocument();
    expect(within(panel).getByText("(reportado por el agente)")).toBeInTheDocument();
    expect(within(panel).getByText("SO").nextElementSibling).toHaveTextContent("Linux Ubuntu 24.04");
    expect(within(panel).getByText("Tipo").nextElementSibling).toHaveTextContent("PC");
    // Campos sin valor no se muestran.
    expect(within(panel).queryByText("Modelo")).not.toBeInTheDocument();
    expect(within(panel).queryByText("Fabricante NIC")).not.toBeInTheDocument();
    expect(within(panel).queryByText("Evidencias")).not.toBeInTheDocument();
  });
});

// Corrección 6C: el caso real de 192.168.50.78 (DNS inverso linux.local, NIC Amazon).
describe("etiqueta personalizada y nombres observados", () => {
  const echo = (overrides: Partial<Asset> = {}) =>
    asset({
      primary_ip: "192.168.50.78",
      reverse_dns: "linux.local",
      vendor: "Amazon Technologies Inc.",
      network_adapter_vendor: "Amazon",
      device_vendor: "Amazon",
      device_type: "iot",
      classification_confidence: "low",
      classification_evidence: [
        { source: "mac_vendor", value: "Amazon" },
        { source: "reverse_dns", value: "linux" },
      ],
      observed_names: [
        { source: "reverse_dns", value: "linux", kind: "generic", selected: false, confirmed: null, stale: false },
      ],
      ...overrides,
    });

  it("sin etiqueta no inventa nombre ni afirma que sea un PC con Linux", () => {
    renderIn(<IdentificationPanel asset={echo()} />);
    const panel = screen.getByRole("region", { name: "Identificación" });
    expect(within(panel).getByText("Nombre").nextElementSibling).toHaveTextContent("IoT probable");
    expect(within(panel).queryByText(/Alexa/)).not.toBeInTheDocument();
    expect(within(panel).queryByText("SO probable")).not.toBeInTheDocument();
    expect(within(panel).getByText("Tipo").nextElementSibling).not.toHaveTextContent("PC");
    const names = within(panel).getByRole("list", { name: "Nombres observados" });
    expect(names).toHaveTextContent("linux");
    expect(names).toHaveTextContent("Nombre genérico del sistema (no identifica al equipo)");
  });

  it("con etiqueta «Alexa Sala» se muestra sin perder la evidencia original", () => {
    const labelled = echo({
      custom_label: "Alexa Sala",
      custom_label_version: 1,
      custom_label_updated_by: "admin",
      display_name: "Alexa Sala",
    });
    renderIn(<AssetName asset={labelled} />);
    expect(screen.getByRole("link", { name: "Alexa Sala" })).toBeInTheDocument();
    expect(screen.getByText("auto: IoT probable")).toBeInTheDocument();
    cleanup();
    renderIn(<IdentificationPanel asset={labelled} />);
    const panel = screen.getByRole("region", { name: "Identificación" });
    expect(within(panel).getByText("Etiqueta").nextElementSibling).toHaveTextContent("Alexa Sala");
    expect(within(panel).getByText("Nombre automático").nextElementSibling).toHaveTextContent("IoT probable");
    expect(within(panel).getByRole("list", { name: "Evidencias" })).toHaveTextContent("DNS inverso: linux");
    expect(within(panel).getByRole("list", { name: "Nombres observados" })).toHaveTextContent("linux");
  });

  it("el acceso rápido a la etiqueta no navega a la fila", () => {
    const onEdit = vi.fn();
    renderIn(<AssetName asset={echo()} onEditLabel={onEdit} />);
    fireEvent.click(screen.getByRole("button", { name: "Editar etiqueta de IoT probable" }));
    expect(onEdit).toHaveBeenCalledTimes(1);
    cleanup();
    renderIn(<AssetName asset={echo()} />);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("marca los nombres no confirmados y el elegido", () => {
    renderIn(
      <IdentificationPanel
        asset={echo({
          device_name: "Echo-Salon",
          name_source: "mdns",
          observed_names: [
            { source: "mdns", value: "Echo-Salon", kind: "device", selected: true, confirmed: null, stale: false },
            { source: "reverse_dns", value: "pc-viejo", kind: "dhcp", selected: false, confirmed: false, stale: true },
          ],
        })}
      />,
    );
    const names = screen.getByRole("list", { name: "Nombres observados" });
    const [chosen, other] = within(names).getAllByRole("listitem");
    expect(chosen).toHaveTextContent("Echo-Salon elegido mDNS · Nombre publicado por el dispositivo");
    expect(other).toHaveTextContent("no confirmado: no resuelve a esta IP");
    expect(other).toHaveTextContent("sin observaciones recientes");
  });
});

// Fase 6D.3: el motivo de que un activo no tenga nombre se explica; con nombre o etiqueta no.
describe("estado del nombre (name_status)", () => {
  it("explica generic_only y unnamed en la identificación y en el tooltip", () => {
    renderIn(<IdentificationPanel asset={asset({ name_status: "generic_only" })} />);
    expect(screen.getByTestId("name-status-help")).toHaveTextContent("Solo anuncia un nombre genérico del sistema");
    cleanup();
    renderIn(<IdentificationPanel asset={asset({ name_status: "unnamed" })} />);
    expect(screen.getByTestId("name-status-help")).toHaveTextContent("Ninguna fuente lo ha nombrado");
    expect(screen.getByTestId("name-status-help")).toHaveTextContent("etiqueta manual");
    cleanup();
    renderIn(<AssetName asset={asset({ name_status: "unnamed" })} />);
    expect(screen.getByRole("link").getAttribute("title")).toMatch(/Ninguna fuente lo ha nombrado/);
  });

  it("no muestra explicación con nombre, con etiqueta ni sin el campo (backend anterior)", () => {
    renderIn(<IdentificationPanel asset={asset({ name_status: "named", device_name: "nas" })} />);
    expect(screen.queryByTestId("name-status-help")).not.toBeInTheDocument();
    cleanup();
    renderIn(<IdentificationPanel asset={asset({ name_status: "unnamed", custom_label: "Impresora" })} />);
    expect(screen.queryByTestId("name-status-help")).not.toBeInTheDocument();
    cleanup();
    renderIn(<IdentificationPanel asset={asset()} />);
    expect(screen.queryByTestId("name-status-help")).not.toBeInTheDocument();
  });
});

// Fase 7A.4: tipo manual (solo assets:manage) y huellas de servicio en la identificación.
describe("tipo manual y huellas de servicio", () => {
  const camera = (overrides: Partial<Asset> = {}) =>
    asset({
      device_type: "ip_camera",
      classification_confidence: "medium",
      device_vendor: "Hikvision",
      custom_label_version: 4,
      classification_evidence: [
        { source: "mac_vendor", value: "Hikvision" },
        { source: "mdns_service", value: "_rtsp._tcp" },
        { source: "mdns_service", value: "modelo DS-2CD2143G2" },
        { source: "web", value: "App-webs/ | Hikvision (antiguo)" },
      ],
      ...overrides,
    });

  it("automático: tipo con su confianza; el admin ve «Asignar tipo» y el analyst no", () => {
    renderIn(<IdentificationPanel asset={camera()} />);
    const panel = screen.getByRole("region", { name: "Identificación" });
    const type = within(panel).getByText("Tipo").nextElementSibling as HTMLElement;
    expect(type).toHaveTextContent("Cámara IP probable (automático, confianza media)");
    expect(within(type).getByRole("button", { name: "Asignar tipo" })).toBeInTheDocument();
    expect(within(panel).getByText("Confianza")).toBeInTheDocument();
    cleanup();
    renderIn(<IdentificationPanel asset={camera()} />, "analyst");
    expect(screen.queryByRole("button", { name: /tipo/i })).not.toBeInTheDocument();
    expect(screen.getByText("Tipo").nextElementSibling).toHaveTextContent("Cámara IP probable");
  });

  it("manual: «Asignado manualmente», sin confianza y con la contradicción visible", () => {
    renderIn(
      <IdentificationPanel
        asset={camera({
          manual_device_type: "dvr_nvr",
          device_type: "dvr_nvr",
          classification_confidence: "high",
          classification_evidence: [
            { source: "manual", value: "tipo asignado manualmente: dvr_nvr" },
            { source: "conflict", value: "la identificación automática apunta a: ip_camera" },
          ],
        })}
      />,
    );
    const panel = screen.getByRole("region", { name: "Identificación" });
    const type = within(panel).getByText("Tipo").nextElementSibling as HTMLElement;
    expect(type).toHaveTextContent("Grabador (DVR/NVR) Asignado manualmente");
    expect(type).not.toHaveTextContent("probable");
    expect(within(type).getByRole("button", { name: "Cambiar tipo" })).toBeInTheDocument();
    expect(within(panel).queryByText("Confianza")).not.toBeInTheDocument();
    const evidence = within(panel).getByRole("list", { name: "Evidencias" });
    expect(evidence).toHaveTextContent("Asignado manualmente: tipo asignado manualmente: dvr_nvr");
    expect(evidence).toHaveTextContent("Evidencia contradictoria: la identificación automática apunta a: ip_camera");
  });

  it("agrupa servicios mDNS, modelo y huella web junto a los nombres, sin repetirlos como evidencia", () => {
    renderIn(<IdentificationPanel asset={camera()} />);
    const panel = screen.getByRole("region", { name: "Identificación" });
    const prints = within(panel).getByRole("list", { name: "Huellas de servicio" });
    const items = within(prints).getAllByRole("listitem");
    expect(items.map((li) => li.textContent)).toEqual([
      "Servicios mDNS: _rtsp._tcp",
      "Modelo (mDNS): DS-2CD2143G2",
      "Web/TLS: App-webs/ | Hikvision · sin observaciones recientes",
    ]);
    const evidence = within(panel).getByRole("list", { name: "Evidencias" });
    expect(evidence).toHaveTextContent("Fabricante MAC: Hikvision");
    expect(evidence).not.toHaveTextContent("_rtsp._tcp");
  });

  it("guardar o un 409 recargan el activo con onChanged", async () => {
    const replies = [
      {
        status: 409,
        body: {
          error: {
            code: "asset_label_conflict",
            message: "conflict",
            details: [{ current_version: 5, manual_device_type: "ip_camera" }],
          },
        },
      },
      { status: 200, body: camera({ manual_device_type: "ip_camera", custom_label_version: 6 }) },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const reply = replies.shift() ?? { status: 500, body: {} };
        return new Response(JSON.stringify(reply.body), { status: reply.status });
      }),
    );
    const onChanged = vi.fn();
    renderIn(<IdentificationPanel asset={camera()} onChanged={onChanged} />);
    fireEvent.click(screen.getByRole("button", { name: "Asignar tipo" }));
    const dialog = screen.getByRole("dialog", { name: "Tipo del dispositivo" });
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Tipo de dispositivo" }), {
      target: { value: "ip_camera" },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Guardar" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Otra persona acaba de asignar el tipo «Cámara IP»");
    expect(onChanged).toHaveBeenCalledTimes(1);
    fireEvent.click(within(dialog).getByRole("button", { name: "Guardar" }));
    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("la celda de tipo de las tablas marca el tipo manual", () => {
    renderIn(<DeviceTypeCell asset={camera({ manual_device_type: "ip_camera", classification_confidence: "high" })} />);
    expect(screen.getByText("Cámara IP")).toBeInTheDocument();
    expect(screen.getByText("(manual)")).toBeInTheDocument();
  });
});
