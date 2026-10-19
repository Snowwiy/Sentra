// Fase 6C: el mapa de navegación filtra por permisos y marca la entrada más específica.
import { describe, expect, it } from "vitest";
import { activeItem, groupOf, NAV_GROUPS, visibleGroups } from "./navigation";

const all = () => true;
const none = () => false;

describe("navegación", () => {
  it("sin permisos solo quedan las entradas públicas y ningún grupo vacío", () => {
    const groups = visibleGroups(none);
    const labels = groups.flatMap((g) => g.items.map((i) => i.label));
    expect(labels).toEqual(["Activos", "Alertas", "Detecciones", "Riesgo", "Red", "Agentes", "Configuración"]);
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
    expect(activeItem(groups, "/")?.label).toBe("Activos");
    expect(activeItem(groups, "/assets/123")?.label).toBe("Activos");
    expect(activeItem(groups, "/detections")?.label).toBe("Detecciones");
    expect(activeItem(groups, "/detections/42")?.label).toBe("Detecciones");
    expect(activeItem(groups, "/detections/rules")?.label).toBe("Reglas");
    expect(activeItem(groups, "/detections/rules/new")?.label).toBe("Reglas");
    expect(activeItem(groups, "/settings")?.label).toBe("Configuración");
    expect(activeItem(groups, "/settings/ai")?.label).toBe("Configuración");
    expect(activeItem(groups, "/settings/sites")?.label).toBe("Sites");
    expect(activeItem(groups, "/vulnerabilities/catalog")?.label).toBe("Vulnerabilidades");
    expect(activeItem(groups, "/no-existe")).toBeUndefined();
    // Un prefijo parcial no cuenta: /riskless no es /risk.
    expect(activeItem(groups, "/riskless")).toBeUndefined();
  });

  it("groupOf devuelve el grupo de la entrada", () => {
    const groups = visibleGroups(all);
    expect(groupOf(groups, activeItem(groups, "/sensors"))?.id).toBe("infrastructure");
  });
});
