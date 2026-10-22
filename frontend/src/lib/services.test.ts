import { describe, expect, it } from "vitest";
import type { ObservedName } from "../api/types";
import { confirmedHostname, hostForAddress, portService, serviceDestination, serviceUrl } from "./services";

const dnsName = (overrides: Partial<ObservedName> = {}): ObservedName => ({
  source: "reverse_dns",
  value: "nas",
  kind: "dns",
  selected: true,
  confirmed: true,
  stale: false,
  ...overrides,
});

describe("servicio por puerto", () => {
  it("HTTP y HTTPS estándar no son una inferencia", () => {
    expect(portService(80)).toEqual({ port: 80, protocol: "HTTP", web: "http", inferred: false });
    expect(portService(443)).toEqual({ port: 443, protocol: "HTTPS", web: "https", inferred: false });
  });

  it("los puertos web alternativos se marcan como probables", () => {
    expect(portService(8080)).toMatchObject({ web: "http", inferred: true });
    expect(portService(8443)).toMatchObject({ web: "https", inferred: true });
  });

  it("SSH, DNS o SMB nunca se tratan como web", () => {
    for (const [port, protocol] of [
      [22, "SSH"],
      [53, "DNS"],
      [445, "SMB"],
      [3389, "RDP"],
    ] as const) {
      expect(portService(port)).toEqual({ port, protocol, web: null, inferred: false });
    }
    expect(portService(31337)).toEqual({ port: 31337, protocol: null, web: null, inferred: false });
  });
});

describe("URL y destino", () => {
  it("construye http(s)://IP:PUERTO y omite el puerto por defecto", () => {
    expect(serviceUrl("https", "192.168.50.1", 443)).toBe("https://192.168.50.1/");
    expect(serviceUrl("http", "192.168.50.1", 8080)).toBe("http://192.168.50.1:8080/");
    expect(serviceUrl("https", "[fd00::1]", 8443)).toBe("https://[fd00::1]:8443/");
  });

  it("rechaza hosts o puertos que alterarían la URL", () => {
    for (const host of ["evil.com/@192.168.50.1", "user@192.168.50.1", "192.168.50.1#x", "a b"]) {
      expect(serviceUrl("http", host, 80)).toBeNull();
    }
    expect(serviceUrl("http", "192.168.50.1", 0)).toBeNull();
    expect(serviceUrl("http", "192.168.50.1", 70000)).toBeNull();
    expect(serviceUrl("http", "192.168.50.1", 80.5)).toBeNull();
  });

  it("solo acepta IPs como dirección", () => {
    expect(hostForAddress("192.168.50.78")).toBe("192.168.50.78");
    expect(hostForAddress("fd00::78")).toBe("[fd00::78]");
    expect(hostForAddress("javascript:alert(1)")).toBeNull();
    expect(hostForAddress("linux.local")).toBeNull();
    expect(serviceDestination("192.168.50.78", 22)).toBe("192.168.50.78:22");
    expect(serviceDestination("fd00::78", 22)).toBe("[fd00::78]:22");
    expect(serviceDestination("192.168.50.78", 0)).toBeNull();
  });
});

describe("nombre DNS confirmado", () => {
  it("solo con DNS inverso confirmado, no genérico y reciente", () => {
    const base = { reverse_dns: "nas.casa.lan" };
    expect(confirmedHostname({ ...base, observed_names: [dnsName()] })).toBe("nas.casa.lan");
    expect(confirmedHostname({ ...base, observed_names: [dnsName({ confirmed: false })] })).toBeNull();
    expect(confirmedHostname({ ...base, observed_names: [dnsName({ confirmed: null })] })).toBeNull();
    expect(confirmedHostname({ ...base, observed_names: [dnsName({ stale: true })] })).toBeNull();
    expect(confirmedHostname({ ...base, observed_names: [] })).toBeNull();
    // linux.local: genérico, aunque resuelva a la IP no identifica al equipo.
    expect(
      confirmedHostname({ reverse_dns: "linux.local", observed_names: [dnsName({ kind: "generic" })] }),
    ).toBeNull();
    // Un nombre suelto o con caracteres raros nunca llega a una URL.
    expect(confirmedHostname({ reverse_dns: "nas", observed_names: [dnsName()] })).toBeNull();
    expect(confirmedHostname({ reverse_dns: "nas.lan/x", observed_names: [dnsName()] })).toBeNull();
  });
});
