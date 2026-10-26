import { describe, expect, it } from "vitest";
import { allowedFields, draftFromDetection, explainTooBroad, policyErrors, type ExclusionDraft } from "./exclusionPolicy";

const NOW = Date.UTC(2026, 9, 24, 12);
const DAY = 86_400_000;
const SHA = "a".repeat(64);

function draft(overrides: Partial<ExclusionDraft>): ExclusionDraft {
  return {
    ruleId: "SCR-001",
    field: "script_sha256",
    value: SHA,
    requireSha256: "",
    port: "",
    assetId: "",
    expiresAt: new Date(NOW + 30 * DAY),
    ...overrides,
  };
}

describe("política de excepciones (Fase 7A.8)", () => {
  it("SCR-001 por SHA-256 del script con caducidad válida no tiene problemas", () => {
    expect(policyErrors(draft({}), NOW)).toEqual([]);
  });

  it("la ruta del script exige el SHA-256 que debe coincidir", () => {
    const errors = policyErrors(draft({ field: "script_path", value: "C:\\scripts\\a.ps1" }), NOW);
    expect(errors).toContain("Una excepción por ruta de script exige también el SHA-256 del script.");
    expect(policyErrors(draft({ field: "script_path", value: "C:\\scripts\\a.ps1", requireSha256: SHA }), NOW)).toEqual([]);
  });

  it("caducidad obligatoria, futura y de 90 días como mucho", () => {
    expect(policyErrors(draft({ expiresAt: undefined }), NOW)).toContain(
      "SCR-001 exige una fecha de caducidad (máximo 90 días).",
    );
    expect(policyErrors(draft({ expiresAt: new Date(NOW - DAY) }), NOW)).toContain(
      "La caducidad debe ser una fecha futura.",
    );
    expect(policyErrors(draft({ expiresAt: new Date(NOW + 91 * DAY) }), NOW)).toContain(
      "La caducidad de SCR-001 no puede superar 90 días.",
    );
  });

  it("NET-001 exige ejecutable, puerto y equipo, y rechaza un intérprete entero", () => {
    const base = draft({ ruleId: "NET-001", field: "exe", value: "C:\\apps\\srv.exe" });
    const errors = policyErrors(base, NOW);
    expect(errors).toContain("NET-001 exige el puerto.");
    expect(errors).toContain("NET-001 exige indicar el equipo.");
    expect(policyErrors({ ...base, port: "8443", assetId: "x" }, NOW)).toEqual([]);
    expect(policyErrors({ ...base, port: "8443", assetId: "x", value: "python.exe" }, NOW)[0]).toMatch(
      /intérprete del sistema/,
    );
    expect(policyErrors({ ...base, port: "70000", assetId: "x" }, NOW)).toContain("El puerto debe estar entre 1 y 65535.");
  });

  it("las demás reglas no admiten campos de script, SHA-256 exigido ni puerto", () => {
    const errors = policyErrors(
      draft({ ruleId: "PROC-001", field: "script_path", value: "a.ps1", requireSha256: SHA, port: "80", expiresAt: undefined }),
      NOW,
    );
    expect(errors).toContain("Los campos de script solo valen para SCR-001 y CORR-002.");
    expect(errors).toContain("Esta regla no usa SHA-256 exigido ni puerto.");
    expect(allowedFields("PROC-001", ["exe", "name", "script_path", "script_sha256"])).toEqual(["exe", "name"]);
    expect(allowedFields("NET-001", ["exe", "name"])).toEqual(["exe", "sha256"]);
  });

  it("parte de los datos exactos de la detección", () => {
    expect(
      draftFromDetection({
        rule_id: "SCR-001",
        asset_id: "a1",
        details: { script: { script_path: "C:\\s\\a.ps1", script_sha256: SHA } },
      }),
    ).toEqual({ ruleId: "SCR-001", field: "script_path", value: "C:\\s\\a.ps1", requireSha256: SHA });
    expect(
      draftFromDetection({
        rule_id: "CORR-002",
        asset_id: "a1",
        details: { scripts: [{ script: { script_sha256: "b".repeat(64) } }, { script: { script_sha256: SHA } }] },
      }),
    ).toEqual({ ruleId: "CORR-002", field: "script_sha256", value: SHA });
    expect(
      draftFromDetection({ rule_id: "NET-001", asset_id: "a1", details: { port: 8443, owner: { exe: "C:\\srv.exe" } } }),
    ).toEqual({ ruleId: "NET-001", field: "exe", value: "C:\\srv.exe", port: "8443", assetId: "a1" });
  });

  it("traduce el motivo de exclusion_too_broad", () => {
    expect(explainTooBroad("NET-001 exclusions require a port")).toBe("Excepción demasiado amplia: la regla exige el puerto.");
    expect(explainTooBroad("SCR-001 exclusions expire within 90 days")).toMatch(/no puede superar 90 días/);
    expect(explainTooBroad("algo nuevo")).toBe("Excepción demasiado amplia: algo nuevo");
  });
});
