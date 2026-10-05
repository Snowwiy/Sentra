// @vitest-environment jsdom
import { cleanup, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { WithRole } from "../test/auth";
import { afterEach, describe, expect, it } from "vitest";
import type { Asset } from "../api/types";
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
    risk_score: null,
    risk_level: null,
    risk_confidence: null,
    ...overrides,
  };
}

function renderIn(node: React.ReactNode) {
  return render(
    <MemoryRouter>
      <WithRole role="admin">{node}</WithRole>
    </MemoryRouter>,
  );
}

afterEach(cleanup);

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
