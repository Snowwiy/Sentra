// Fase 7A.5: definición única de las pestañas del hub Red.
import { describe, expect, it } from "vitest";
import { NETWORK_TABS, networkTabFor, networkTabPath, visibleNetworkTabs } from "./tabs";

describe("pestañas de Red", () => {
  it("cada ruta del hub corresponde a su pestaña", () => {
    expect(networkTabFor("/network")?.key).toBe("overview");
    expect(networkTabFor("/network/")?.key).toBe("overview");
    expect(networkTabFor("/network/devices")?.key).toBe("devices");
    expect(networkTabFor("/network/identity")?.key).toBe("identity");
    expect(networkTabFor("/network/topology/extra")?.key).toBe("topology");
    expect(networkTabFor("/network/no-existe")).toBeUndefined();
    expect(networkTabFor("/networks")).toBeUndefined();
    expect(networkTabFor("/assets/1")).toBeUndefined();
  });

  it("las rutas son únicas y Resumen es /network", () => {
    const paths = NETWORK_TABS.map(networkTabPath);
    expect(new Set(paths).size).toBe(paths.length);
    expect(paths[0]).toBe("/network");
  });

  it("sin permisos solo quedan las pestañas sin permiso propio", () => {
    expect(visibleNetworkTabs(() => false).map((t) => t.key)).toEqual(["overview", "devices", "discovery", "telemetry"]);
    expect(visibleNetworkTabs(() => true)).toHaveLength(NETWORK_TABS.length);
  });
});
