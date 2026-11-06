import { describe, expect, it } from "vitest";
import { evidenceText } from "./identity7b";

describe("evidenceText (Fase 7C.6)", () => {
  it("traduce las señales nuevas sin perder el detalle del servidor", () => {
    expect(evidenceText({ code: "same_dhcp_client_id", strength: "medium", detail: "01:aa:bb" })).toBe(
      "Mismo identificador de cliente DHCP: 01:aa:bb",
    );
    expect(evidenceText({ code: "private_mac_rotation", strength: "weak" })).toBe(
      "Posible rotación de MAC privada (periodos sin solape)",
    );
  });
});
