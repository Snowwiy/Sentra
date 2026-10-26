// Fase 6C: el mapa de navegación filtra por permisos y marca la entrada más específica.
import { describe, expect, it } from "vitest";
import { activeItem, groupOf, NAV_GROUPS, visibleGroups } from "./navigation";

const all = () => true;
const none = () => false;

describe("navegación", () => {
  it("sin permisos solo quedan las entradas públicas y ningún grupo vacío", () => {
    const groups = visibleGroups(none);
    const labels = groups.flatMap((g) => g.items.map((i) => i.label));
    expect(labels).toEqual(["Panel", "Alertas", "Detecciones", "Riesgo", "Red", "Agentes", "Configuración"]);
    expect(groups.every((g) => g.items.length > 0)).toBe(true);
    expect(groups.map((g) => g.id)).not.toContain("analysis");
  });

  it("cada entrada con permiso se oculta sin él", () => {
    for (const item of NAV_GROUPS.flatMap((g) => g.items).filter((i) => i.permission)) {
      const shown = visibleGroups((p) => p !== item.permission).flatMap((g) => g.items);
      expect(shown.map((i) => i.to)).not.toContain(item.to);
    }
  });

  it("la entrada activa es la de prefijo más largo", () => {
    const groups = visibleGroups(all);
    expect(activeItem(groups, "/")?.label).toBe("Panel");
    expect(activeItem(groups, "/detections")?.label).toBe("Detecciones");
    expect(activeItem(groups, "/detections/42")?.label).toBe("Detecciones");
    expect(activeItem(groups, "/detections/rules")?.label).toBe("Reglas");
    expect(activeItem(groups, "/detections/rules/new")?.label).toBe("Reglas");
    expect(activeItem(groups, "/detections/exclusions")?.label).toBe("Reglas");
    expect(activeItem(groups, "/investigations/abc")?.label).toBe("Investigaciones");
    expect(activeItem(groups, "/containment")?.label).toBe("Aislamiento");
    expect(activeItem(groups, "/settings")?.label).toBe("Configuración");
    expect(activeItem(groups, "/settings/ai")?.label).toBe("Configuración");
    expect(activeItem(groups, "/settings/sites")?.label).toBe("Sites");
    expect(activeItem(groups, "/vulnerabilities/catalog")?.label).toBe("Vulnerabilidades");
    expect(activeItem(groups, "/no-existe")).toBeUndefined();
    // Un prefijo parcial no cuenta: /riskless no es /risk.
    expect(activeItem(groups, "/riskless")).toBeUndefined();
  });

  // Fase 7A.5: Red es el hub de dispositivos; DHCP y Topología son pestañas, no entradas.
  it("Red se activa en todo el hub y en la ficha de un activo", () => {
    const groups = visibleGroups(all);
    for (const path of ["/network", "/network/devices", "/network/identity", "/assets/123", "/assets/123/x"]) {
      expect(activeItem(groups, path)?.label).toBe("Red");
    }
    // Las rutas antiguas redirigen al hub; mientras tanto también marcan Red.
    expect(activeItem(groups, "/dhcp")?.label).toBe("Red");
    expect(activeItem(groups, "/topology")?.label).toBe("Red");
    // /assets sin id no es una ficha: no hay entrada que marcar.
    expect(activeItem(groups, "/assetsx")).toBeUndefined();
  });

  it("el menú ya no tiene entradas DHCP ni Topología", () => {
    const items = NAV_GROUPS.flatMap((g) => g.items);
    expect(items.map((i) => i.label)).not.toContain("DHCP");
    expect(items.map((i) => i.label)).not.toContain("Topología");
    expect(items.map((i) => i.to)).not.toContain("/dhcp");
    expect(items.map((i) => i.to)).not.toContain("/topology");
    // Lo que no se absorbe en el hub sigue en Infraestructura.
    const infra = NAV_GROUPS.find((g) => g.id === "infrastructure")!.items.map((i) => i.label);
    expect(infra).toEqual(["Red", "Infraestructura", "Wi-Fi", "Agentes", "Sensores", "Sites"]);
  });

  it("groupOf devuelve el grupo de la entrada", () => {
    const groups = visibleGroups(all);
    expect(groupOf(groups, activeItem(groups, "/sensors"))?.id).toBe("infrastructure");
  });
});
