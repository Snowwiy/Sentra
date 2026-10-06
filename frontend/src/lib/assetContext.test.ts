import { describe, expect, it } from "vitest";
import type { AssetContext } from "../api/types";
import {
  buildUpdate,
  exposureFromForm,
  exposureLabel,
  exposureToForm,
  invalidTags,
  parseTags,
  toForm,
  validateForm,
} from "./assetContext";

const LIMITS = { owner: 128, department: 64, rationale: 200, tags: 20 };

function contextFixture(overrides: Partial<AssetContext> = {}): AssetContext {
  return {
    asset_id: "aaaaaaaa-0000-0000-0000-000000000001",
    version: 3,
    criticality: "medium",
    criticality_confirmed: false,
    criticality_rationale: null,
    criticality_updated_at: null,
    criticality_updated_by: null,
    role: "unknown",
    role_suggestion: null,
    environment: "unknown",
    owner: null,
    department: null,
    data_sensitivity: "unknown",
    network_zone: "unknown",
    internet_exposed: null,
    tags: [],
    managed_state: "MANAGED",
    visibility_sources: ["agent"],
    provenance: {},
    completeness: { percent: 0, complete: false, known: [], missing: ["role"] },
    updated_at: null,
    updated_by: null,
    ...overrides,
  };
}

describe("assetContext", () => {
  it("exposición tri-estado: null es desconocido, nunca 'no expuesto'", () => {
    expect(exposureLabel(null)).toBe("Desconocida");
    expect(exposureLabel(false)).toBe("No expuesto");
    expect(exposureToForm(null)).toBe("unknown");
    expect(exposureToForm(true)).toBe("true");
    expect(exposureFromForm("unknown")).toBeNull();
    expect(exposureFromForm("false")).toBe(false);
  });

  it("normaliza tags como el backend y detecta las no válidas", () => {
    expect(parseTags(" Critical Service, pci,PCI, ,")).toEqual(["critical-service", "pci"]);
    expect(invalidTags(["ok", "-bad", "a".repeat(33), "x<y"])).toEqual(["-bad", "a".repeat(33), "x<y"]);
  });

  it("buildUpdate envía solo lo que cambió, con la versión leída", () => {
    const ctx = contextFixture({ owner: "IT", tags: ["pci"] });
    const form = { ...toForm(ctx), role: "server" as const, owner: "  IT  ", tags: "pci" };
    expect(buildUpdate(ctx, form)).toEqual({ version: 3, role: "server" });
    const cleared = { ...toForm(ctx), owner: "", internet_exposed: "true" as const, tags: "" };
    expect(buildUpdate(ctx, cleared)).toEqual({ version: 3, owner: null, internet_exposed: true, tags: [] });
  });

  it("validateForm rechaza longitudes, marcado y tags inválidas", () => {
    const form = toForm(contextFixture());
    expect(validateForm(form, LIMITS)).toEqual([]);
    const bad = { ...form, owner: "a".repeat(129), department: "<b>IT</b>", tags: "-x" };
    const errors = validateForm(bad, LIMITS);
    expect(errors.some((e) => e.startsWith("Owner: máximo 128"))).toBe(true);
    expect(errors.some((e) => e.includes("solo texto plano"))).toBe(true);
    expect(errors.some((e) => e.startsWith("Tags no válidos"))).toBe(true);
    const many = { ...form, tags: Array.from({ length: 21 }, (_, i) => `t${i}`).join(",") };
    expect(validateForm(many, LIMITS)).toContain("Máximo 20 tags por activo.");
  });
});
