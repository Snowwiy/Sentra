import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { countBySoftware } from "../components/asset/VulnerabilitiesTab";
import { softwareKey } from "../components/asset/SoftwareTab";
import type { FindingSummary } from "../api/types";
import { findingConflict, formatCvss, safeReference } from "./vulnerabilities";

describe("safeReference", () => {
  it("solo acepta http/https sin credenciales", () => {
    expect(safeReference("https://example.org/a?b=1")).toBe("https://example.org/a?b=1");
    expect(safeReference("http://example.org")).toBe("http://example.org/");
    for (const bad of [
      "javascript:alert(1)",
      "JAVASCRIPT:alert(1)",
      "data:text/html,<b>x</b>",
      "file:///etc/passwd",
      "//example.org",
      "https://user:pass@example.org",
      "no es una url",
      `https://example.org/${"a".repeat(2100)}`,
    ]) {
      expect(safeReference(bad)).toBeNull();
    }
  });
});

describe("findingConflict", () => {
  it("lee versión y estado del 409 vulnerability_conflict", () => {
    const error = new ApiError(409, "vulnerability_conflict", "changed", [{ version: 5, status: "resolved" }]);
    expect(findingConflict(error)).toEqual({ currentVersion: 5, status: "resolved" });
    expect(findingConflict(new ApiError(409, "incident_conflict", "x"))).toBeNull();
    expect(findingConflict(new Error("x"))).toBeNull();
  });
});

describe("helpers", () => {
  it("formatea CVSS con su versión", () => {
    expect(formatCvss(9.8, "3.1")).toBe("9.8 (v3.1)");
    expect(formatCvss(7, null)).toBe("7.0");
    expect(formatCvss(null, "3.1")).toBe("—");
  });

  it("cuenta vulnerabilidades por programa y versión instalada", () => {
    const f = (name: string, version: string | null) => ({ component_name: name, installed_version: version }) as FindingSummary;
    const counts = countBySoftware([f("ExampleApp", "2.4.1"), f("exampleapp ", "2.4.1"), f("ExampleApp", "3.0")]);
    expect(counts.get(softwareKey("ExampleApp", "2.4.1"))).toBe(2);
    expect(counts.get(softwareKey("ExampleApp", "3.0"))).toBe(1);
    expect(counts.get(softwareKey("ExampleApp", null))).toBeUndefined();
  });
});
