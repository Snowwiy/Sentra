// Fase 6E.7: la confirmación escrita del aislamiento (nombre exacto, motivo, duración ≤ máximo).
import { describe, expect, it } from "vitest";
import { isLiveIsolation, validateIsolation } from "./isolation";

const ok = { confirmName: "pc-ana", expectedName: "pc-ana", reason: "Conexiones a un C2 conocido", minutes: "60", maxMinutes: 240 };

describe("validateIsolation", () => {
  it("acepta una confirmación completa", () => {
    expect(validateIsolation(ok)).toEqual([]);
    expect(validateIsolation({ ...ok, minutes: "240" })).toEqual([]);
  });

  it("el nombre se compara exacto: ni mayúsculas ni espacios", () => {
    expect(validateIsolation({ ...ok, confirmName: "PC-ANA" })).toHaveLength(1);
    expect(validateIsolation({ ...ok, confirmName: " pc-ana" })).toHaveLength(1);
  });

  it("exige un motivo de al menos 10 caracteres y como máximo 500", () => {
    expect(validateIsolation({ ...ok, reason: "   corto   " })[0]).toMatch(/al menos 10/);
    expect(validateIsolation({ ...ok, reason: "x".repeat(501) })[0]).toMatch(/como máximo 500/);
  });

  it("la duración es un entero positivo que no supera el máximo del servidor", () => {
    expect(validateIsolation({ ...ok, minutes: "241" })).toEqual(["La duración no puede superar 240 minutos."]);
    for (const minutes of ["0", "-5", "1.5", "", "abc"]) {
      expect(validateIsolation({ ...ok, minutes })).toEqual(["La duración debe ser un número entero de minutos."]);
    }
  });
});

describe("isLiveIsolation", () => {
  it("solo las sesiones activas se pueden liberar", () => {
    expect(isLiveIsolation("isolated")).toBe(true);
    expect(isLiveIsolation("unknown")).toBe(true);
    expect(isLiveIsolation("restored")).toBe(false);
    expect(isLiveIsolation("expired")).toBe(false);
  });
});
