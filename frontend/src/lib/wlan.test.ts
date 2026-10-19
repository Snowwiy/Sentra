import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { wlanObservation } from "../test/wlan";
import {
  authorizationTargets,
  describeSource,
  looksLikeMac,
  observationProvenance,
  summarizeObservationData,
  wlanErrorText,
} from "./wlan";

describe("wlan: utilidades", () => {
  it("las clasificaciones ofrecidas nunca incluyen rogue ni el estado actual", () => {
    expect(authorizationTargets("unknown")).toEqual(["authorized", "external"]);
    expect(authorizationTargets("authorized")).toEqual(["external", "unknown"]);
    expect(authorizationTargets("external")).toEqual(["authorized", "unknown"]);
  });

  it("reconoce MACs con : o - y nada más", () => {
    expect(looksLikeMac("00:1B:2c:3d:4e:10")).toBe(true);
    expect(looksLikeMac(" 00-1b-2c-3d-4e-10 ")).toBe(true);
    expect(looksLikeMac("001b2c3d4e10")).toBe(false);
    expect(looksLikeMac("Corp")).toBe(false);
  });

  it("describe una fuente SNMP sin consultas y otra con consulta parcial", () => {
    const idle = describeSource({
      source: "snmp",
      availability: "unavailable",
      reporters: 2,
      by_status: {},
      last_seen_at: null,
      detail: "x",
    });
    expect(idle.explanation).toMatch(/todavía no se ha consultado/);
    expect(idle.reporters).toBe("2 sensores con snmp.wlan");
    expect(idle.partialNote).toBeUndefined();
    const partial = describeSource({
      source: "snmp",
      availability: "partial",
      reporters: 1,
      by_status: { partial: 2, complete: 1 },
      last_seen_at: null,
      detail: "x",
    });
    expect(partial.breakdown).toBe("Última consulta Wi-Fi por equipo: 2 parcial, 1 completa");
    expect(partial.partialNote).toMatch(/2 equipos fue parcial/);
  });

  it("describe agentes con permisos limitados y estados desconocidos tal cual", () => {
    const text = describeSource({
      source: "agent",
      availability: "partial",
      reporters: 1,
      by_status: { permission_limited: 1, nuevo_estado: 1 },
      last_seen_at: null,
      detail: "x",
    });
    expect(text.breakdown).toContain("nuevo_estado");
    expect(text.partialNote).toMatch(/1 agente informa con permisos limitados/);
  });

  it("resume datos y procedencia de una observación, acotados", () => {
    const data = Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`k${i}`, i]));
    expect(summarizeObservationData({ ...data, vacio: null })).toMatch(/k7: 7 · \(\+2\)$/);
    expect(summarizeObservationData({ a: null })).toBe("sin datos");
    expect(
      observationProvenance(
        wlanObservation({
          source: "agent",
          sensor: null,
          reported_by: null,
          agent_asset: { asset_id: "a", display_name: "LAPTOP-QA" },
        }),
      ),
    ).toBe("Agente · activo LAPTOP-QA");
  });

  it("traduce los errores WLAN conocidos y conserva el resto", () => {
    expect(wlanErrorText(new ApiError(409, "wlan_link_site_mismatch", "x"))).toMatch(/mismo site/);
    expect(wlanErrorText(new ApiError(500, "internal", "fallo interno"))).toBe("fallo interno");
  });
});
