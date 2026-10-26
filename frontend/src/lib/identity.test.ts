import { describe, expect, it } from "vitest";
import type { Asset } from "../api/types";
import {
  assetTitle,
  automaticTitle,
  DEVICE_TYPE_OPTIONS,
  deviceTypeLabel,
  evidenceLabel,
  fingerprints,
  isManualType,
  isProbable,
  NAME_SOURCE_LABELS,
  normalizeLabel,
  osLabel,
  typeWithConfidence,
} from "./identity";

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
    // Fase 6E.2: la concesión DHCP como fuente de nombre tiene su etiqueta propia.
    expect(evidenceLabel({ source: "dhcp_lease", value: "pixel-7" })).toBe("Concesión DHCP: pixel-7");
    expect(NAME_SOURCE_LABELS.dhcp_lease).toBe("Concesión DHCP");
  });
});

describe("Corrección 6C: etiqueta personalizada", () => {
  const named = { device_name: "Echo-Salon", hostname: null, device_type: "iot", classification_confidence: "low" as const };

  it("la etiqueta gana al nombre automático, que sigue disponible aparte", () => {
    expect(assetTitle({ ...named, custom_label: "Alexa Sala" })).toBe("Alexa Sala");
    expect(automaticTitle({ ...named })).toBe("Echo-Salon");
    expect(assetTitle({ ...named, custom_label: null })).toBe("Echo-Salon");
  });

  it("normaliza como el servidor", () => {
    expect(normalizeLabel("  Alexa \u00a0 Sala ")).toEqual({ label: "Alexa Sala" });
    expect(normalizeLabel("Salo\u0301n")).toEqual({ label: "Sal\u00f3n" });
    expect("error" in normalizeLabel("")).toBe(true);
    expect("error" in normalizeLabel("a\nb")).toBe(true);
    expect("error" in normalizeLabel("x".repeat(65))).toBe(true);
    expect(normalizeLabel("x".repeat(64))).toEqual({ label: "x".repeat(64) });
  });
});

describe("Fase 7A.4: tipos nuevos, tipo manual y huellas de servicio", () => {
  it("traduce cámaras, grabadores y equipos de red y los ofrece para asignar a mano", () => {
    expect(deviceTypeLabel("ip_camera")).toBe("Cámara IP");
    expect(deviceTypeLabel("dvr_nvr")).toBe("Grabador (DVR/NVR)");
    expect(deviceTypeLabel("network_device")).toBe("Equipo de red");
    const values = DEVICE_TYPE_OPTIONS.map((o) => o.value);
    expect(values).toEqual(expect.arrayContaining(["ip_camera", "dvr_nvr", "network_device", "pc", "nas"]));
    expect(values).toHaveLength(new Set(values).size);
    // Ordenadas por su nombre en español, no por el identificador.
    const labels = DEVICE_TYPE_OPTIONS.map((o) => o.label);
    expect(labels).toEqual([...labels].sort((a, b) => a.localeCompare(b, "es")));
  });

  it("etiqueta las fuentes de evidencia nuevas", () => {
    expect(evidenceLabel({ source: "mdns_service", value: "_ipp._tcp" })).toBe("Servicios mDNS: _ipp._tcp");
    expect(evidenceLabel({ source: "web", value: "App-webs/" })).toBe("Huella web/TLS: App-webs/");
    expect(evidenceLabel({ source: "manual", value: "tipo asignado manualmente: ip_camera" })).toBe(
      "Asignado manualmente: tipo asignado manualmente: ip_camera",
    );
  });

  it("un tipo manual nunca se presenta como probable", () => {
    const manual = { device_type: "ip_camera", classification_confidence: "low" as const, manual_device_type: "ip_camera" };
    expect(isManualType(manual)).toBe(true);
    expect(isProbable(manual)).toBe(false);
    expect(typeWithConfidence(manual)).toBe("Cámara IP");
    expect(isManualType({ manual_device_type: null })).toBe(false);
  });

  it("separa servicios mDNS, modelo y huella web, y marca las antiguas", () => {
    const found = fingerprints([
      { source: "mac_vendor", value: "Apple" },
      { source: "mdns_service", value: "_ipp._tcp, _printer._tcp" },
      { source: "mdns_service", value: "modelo MacBookPro18,3 (antiguo)" },
      { source: "web", value: "App-webs/ | Hikvision | DS-2CD2143 | Hikvision" },
      { source: "web", value: " (antiguo)" },
    ]);
    expect(found).toEqual([
      { kind: "services", value: "_ipp._tcp, _printer._tcp", stale: false },
      { kind: "model", value: "MacBookPro18,3", stale: true },
      { kind: "web", value: "App-webs/ | Hikvision | DS-2CD2143 | Hikvision", stale: false },
    ]);
    expect(fingerprints([{ source: "reverse_dns", value: "linux" }])).toEqual([]);
  });
});
