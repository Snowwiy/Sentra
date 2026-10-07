import { describe, expect, it } from "vitest";
import { detectFormat, epssBand, errorLabel, formatEpss, formatPercentile } from "./threatIntel";

describe("threatIntel", () => {
  it("formatea EPSS como probabilidad, nunca como % vulnerable", () => {
    expect(formatEpss(0.91234)).toBe("91,2 %");
    expect(formatEpss(null)).toBe("—");
    expect(formatPercentile(0.99876)).toBe("percentil 99");
  });

  it("usa las mismas bandas que el backend", () => {
    expect(epssBand(undefined)).toBe("none");
    expect(epssBand(0.05)).toBe("low");
    expect(epssBand(0.1)).toBe("elevated");
    expect(epssBand(0.5)).toBe("high");
  });

  it("detecta el formato del fichero por su contenido", () => {
    expect(detectFormat('{"format": "sentra-ioc/1", "indicators": []}')).toBe("sentra-ioc");
    expect(detectFormat('{"type": "bundle", "objects": []}')).toBe("stix");
    expect(detectFormat("no es json")).toBe("sentra-ioc");
  });

  it("traduce códigos de error conocidos y deja el resto tal cual", () => {
    expect(errorLabel("blocked_destination")).toMatch(/SSRF/);
    expect(errorLabel("otro_codigo")).toBe("otro_codigo");
    expect(errorLabel(null)).toBe("—");
  });
});
