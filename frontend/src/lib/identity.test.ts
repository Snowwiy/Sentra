import { describe, expect, it } from "vitest";
import type { Asset } from "../api/types";
import { assetTitle, deviceTypeLabel, evidenceLabel, isProbable, osLabel, typeWithConfidence } from "./identity";

type Identity = Pick<
  Asset,
  "device_name" | "hostname" | "device_type" | "classification_confidence" | "os_name" | "os_version" | "probable_os"
>;

const base: Identity = {
  device_name: null,
  hostname: null,
  device_type: null,
  classification_confidence: null,
  os_name: null,
  os_version: null,
  probable_os: null,
};

describe("identificación: textos en español", () => {
  it("traduce los tipos de dispositivo", () => {
    expect(deviceTypeLabel("mobile")).toBe("Móvil");
    expect(deviceTypeLabel("console")).toBe("Consola");
    expect(deviceTypeLabel("printer")).toBe("Impresora");
    expect(deviceTypeLabel("voice_assistant")).toBe("IoT / Asistente");
    expect(deviceTypeLabel(null)).toBe("Desconocido");
    expect(deviceTypeLabel("future_type")).toBe("future_type"); // sin inventar traducción
  });

  it("marca como probable todo lo que no es confianza alta", () => {
    expect(typeWithConfidence({ device_type: "console", classification_confidence: "medium" })).toBe(
      "Consola probable",
    );
    expect(typeWithConfidence({ device_type: "mobile", classification_confidence: "high" })).toBe("Móvil");
    expect(isProbable({ device_type: null, classification_confidence: null })).toBe(false);
    expect(typeWithConfidence({ device_type: null, classification_confidence: null })).toBe("Desconocido");
  });

  it("nunca deja el título vacío ni usa la IP como nombre", () => {
    expect(assetTitle({ ...base, device_name: "MNA-LX9" })).toBe("MNA-LX9");
    expect(assetTitle({ ...base, hostname: "Ravenslg" })).toBe("Ravenslg");
    expect(assetTitle({ ...base, device_type: "console", classification_confidence: "medium" })).toBe(
      "Consola probable",
    );
    expect(assetTitle(base)).toBe("Dispositivo desconocido");
  });

  it("distingue SO real del agente y SO probable sin versión", () => {
    expect(osLabel({ ...base, os_name: "Linux", os_version: "Ubuntu 24.04" })).toBe("Linux Ubuntu 24.04");
    expect(osLabel({ ...base, probable_os: "Android" })).toBe("Android probable");
    expect(osLabel(base)).toBeNull();
  });

  it("describe las evidencias con su fuente", () => {
    expect(evidenceLabel({ source: "mac_vendor", value: "Huawei" })).toBe("Fabricante MAC: Huawei");
    expect(evidenceLabel({ source: "nueva_fuente", value: "x" })).toBe("nueva_fuente: x");
  });
});
