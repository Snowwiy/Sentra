import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import {
  blockedInfo,
  buildParameters,
  initialParamValues,
  isActiveExecution,
  missingParameters,
  newIdempotencyKey,
  paramFields,
} from "./response";

// Esquema tal como lo genera pydantic para open_incident (enum por $ref y opcional con anyOf).
const OPEN_INCIDENT = {
  $defs: { IncidentLevel: { enum: ["low", "medium", "high", "critical"], title: "IncidentLevel", type: "string" } },
  additionalProperties: false,
  properties: {
    title: { anyOf: [{ maxLength: 200, minLength: 3, type: "string" }, { type: "null" }], default: null, title: "Title" },
    severity: { $ref: "#/$defs/IncidentLevel", default: "medium" },
    priority: { $ref: "#/$defs/IncidentLevel", default: "medium" },
  },
  type: "object",
};

describe("paramFields", () => {
  it("resolves pydantic $ref enums and optional anyOf strings", () => {
    const fields = paramFields(OPEN_INCIDENT);
    expect(fields.map((f) => [f.name, f.kind, f.required])).toEqual([
      ["title", "string", false],
      ["severity", "enum", false],
      ["priority", "enum", false],
    ]);
    expect(fields[1]?.options).toEqual(["low", "medium", "high", "critical"]);
    expect(initialParamValues(fields)).toEqual({ title: "", severity: "medium", priority: "medium" });
  });

  it("reads integer bounds and returns nothing for actions without parameters", () => {
    const [hours] = paramFields({ properties: { hours: { default: 24, maximum: 168, minimum: 1, type: "integer" } } });
    expect(hours).toMatchObject({ kind: "integer", minimum: 1, maximum: 168, defaultValue: 24 });
    expect(paramFields({ properties: {}, type: "object" })).toEqual([]);
  });
});

describe("buildParameters", () => {
  it("omits empty optional fields, sends integers as numbers and checks required ones", () => {
    const fields = paramFields(OPEN_INCIDENT);
    expect(buildParameters(fields, { title: "  ", severity: "high", priority: "low" })).toEqual({
      severity: "high",
      priority: "low",
    });
    const lookback = paramFields({ properties: { hours: { type: "integer" } } });
    expect(buildParameters(lookback, { hours: "48" })).toEqual({ hours: 48 });

    const archive = paramFields({ properties: { reason: { minLength: 3, type: "string" } }, required: ["reason"] });
    expect(missingParameters(archive, { reason: "" })).toBe(true);
    expect(missingParameters(archive, { reason: "ab" })).toBe(true);
    expect(missingParameters(archive, { reason: "retirado" })).toBe(false);
  });
});

describe("blockedInfo", () => {
  it("extracts the recorded execution or run and the blockers of a 409 response_blocked", () => {
    const error = new ApiError(409, "response_blocked", "blocked", [
      { run_id: "r1" },
      { code: "agent_offline", message: "Agente sin conexión" },
    ]);
    expect(blockedInfo(error)).toEqual({
      executionId: null,
      runId: "r1",
      blockers: [{ code: "agent_offline", message: "Agente sin conexión" }],
    });
    expect(blockedInfo(new ApiError(409, "response_conflict", "x"))).toBeNull();
    expect(blockedInfo(new Error("x"))).toBeNull();
  });
});

describe("helpers", () => {
  it("generates idempotency keys the API accepts, distinct per dialog", () => {
    const a = newIdempotencyKey();
    expect(a).toMatch(/^[A-Za-z0-9_-]{8,64}$/);
    expect(newIdempotencyKey()).not.toBe(a);
  });

  it("only treats pending, approval_required, queued and running as cancellable", () => {
    expect(["pending", "approval_required", "queued", "running"].every(isActiveExecution)).toBe(true);
    expect(["succeeded", "failed", "cancelled", "timed_out", "blocked"].some(isActiveExecution)).toBe(false);
  });
});
