import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { conflictInfo, formatDuration, isActive, linkedIncident } from "./incidents";

describe("incidents helpers", () => {
  it("formatDuration muestra tiempos observados cortos", () => {
    expect(formatDuration(null)).toBe("—");
    expect(formatDuration(42)).toBe("42 s");
    expect(formatDuration(25 * 60)).toBe("25 min");
    expect(formatDuration(3 * 3600 + 5 * 60)).toBe("3 h 5 min");
    expect(formatDuration(2 * 86400 + 4 * 3600)).toBe("2 d 4 h");
  });

  it("isActive solo para estados de trabajo", () => {
    expect(["open", "triage", "investigating", "contained"].every((s) => isActive(s as never))).toBe(true);
    expect(["resolved", "closed", "merged"].some((s) => isActive(s as never))).toBe(false);
  });

  it("conflictInfo lee el 409 incident_conflict y nada más", () => {
    const conflict = new ApiError(409, "incident_conflict", "m", [
      { current_version: 5, updated_by: "luis", status: "triage" },
    ]);
    expect(conflictInfo(conflict)).toEqual({ currentVersion: 5, updatedBy: "luis", status: "triage" });
    expect(conflictInfo(new ApiError(409, "incident_conflict", "m"))).toEqual({
      currentVersion: null,
      updatedBy: null,
      status: null,
    });
    expect(conflictInfo(new ApiError(409, "incident_invalid_state", "m"))).toBeNull();
    expect(conflictInfo(new Error("x"))).toBeNull();
  });

  it("linkedIncident valida el detalle antes de enlazar", () => {
    const err = new ApiError(409, "incident_already_linked", "m", [{ incident_id: "i1", key: "INC-000001" }]);
    expect(linkedIncident(err)).toEqual({ incidentId: "i1", key: "INC-000001" });
    expect(linkedIncident(new ApiError(409, "incident_already_linked", "m", [{ incident_id: 1 }]))).toBeNull();
  });
});
