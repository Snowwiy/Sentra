import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { buildTarget, describeTarget, EMPTY_TARGET, isVersionConflict } from "./caseOperations";

describe("objetivos de los controles de red (Fase 7A.6)", () => {
  it("usa las claves exactas de cada tipo", () => {
    expect(buildTarget("block_port", { ...EMPTY_TARGET, port: "445", protocol: "tcp" })).toEqual({
      target: { port: 445, protocol: "tcp" },
    });
    expect(buildTarget("block_service", { ...EMPTY_TARGET, service: "SMB" })).toEqual({ target: { service: "smb" } });
    expect(buildTarget("block_service", { ...EMPTY_TARGET, service: "rdp", port: "3389" })).toEqual({
      target: { service: "rdp", port: 3389 },
    });
    expect(buildTarget("block_address", { ...EMPTY_TARGET, cidr: "10.0.0.0/24" })).toEqual({ target: { cidr: "10.0.0.0/24" } });
    expect(buildTarget("block_domain", { ...EMPTY_TARGET, domain: "*.Ejemplo.com." })).toEqual({
      target: { domain: "*.ejemplo.com" },
    });
    expect(buildTarget("restrict_site_access", { ...EMPTY_TARGET, domain: "ejemplo.com" })).toEqual({
      target: { domain: "ejemplo.com" },
    });
    expect(buildTarget("prevent_upload", { ...EMPTY_TARGET, destination: "subidas.ejemplo.com" })).toEqual({
      target: { destination: "subidas.ejemplo.com" },
    });
  });

  it("rechaza objetivos mal formados antes de enviarlos", () => {
    expect(buildTarget("block_port", { ...EMPTY_TARGET, port: "0" })).toHaveProperty("errors");
    expect(buildTarget("block_port", { ...EMPTY_TARGET, port: "70000" })).toHaveProperty("errors");
    expect(buildTarget("block_domain", { ...EMPTY_TARGET, domain: "localhost" })).toHaveProperty("errors");
    expect(buildTarget("block_address", { ...EMPTY_TARGET, cidr: "no es una ip" })).toHaveProperty("errors");
    expect(buildTarget("prevent_upload", { ...EMPTY_TARGET, destination: "" })).toHaveProperty("errors");
  });

  it("describe el objetivo guardado como texto", () => {
    expect(describeTarget("block_port", { port: 445, protocol: "tcp" })).toBe("445/tcp");
    expect(describeTarget("block_service", { service: "smb", port: 445 })).toBe("smb (445)");
    expect(describeTarget("prevent_upload", { destination: "x.ejemplo.com" })).toBe("x.ejemplo.com");
  });

  it("solo los 409 de versión cuentan como conflicto que pide recargar", () => {
    expect(isVersionConflict(new ApiError(409, "task_conflict", "stale"))).toBe(true);
    expect(isVersionConflict(new ApiError(409, "network_control_conflict", "stale"))).toBe(true);
    expect(isVersionConflict(new ApiError(409, "task_invalid_state", "no"))).toBe(false);
    expect(isVersionConflict(new Error("x"))).toBe(false);
  });
});
