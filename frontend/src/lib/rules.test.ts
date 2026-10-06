import { describe, expect, it } from "vitest";
import type { RuleField } from "../api/types";
import {
  definitionFromEditor,
  displayValue,
  editorFromDefinition,
  emptyEditor,
  newRow,
  parseSyntheticEvents,
} from "./rules";

const FIELDS = new Map<string, RuleField>([
  ["event.code", { name: "event.code", type: "integer", description: "", values: [], operators: ["equals", "in"] }],
  [
    "event.data.TargetUserName",
    { name: "event.data.TargetUserName", type: "string", description: "", values: [], operators: ["equals", "starts_with"] },
  ],
]);

describe("editor <-> sentra-rule/1", () => {
  it("builds typed values, negation, threshold and group_by", () => {
    const state = emptyEditor("windows_security");
    state.rows = [
      { ...newRow("event.code", "in"), value: "4625, 4624" },
      { ...newRow("event.data.TargetUserName", "starts_with"), value: "svc_", negate: true, caseSensitive: true },
    ];
    state.thresholdEnabled = true;
    state.thresholdCount = 6;
    state.windowMinutes = 15;
    state.groupBy = ["event.data.TargetUserName"];
    const definition = definitionFromEditor(state, FIELDS);
    expect(definition).toEqual({
      format: "sentra-rule/1",
      logsource: "windows_security",
      condition: {
        all: [
          { field: "event.code", op: "in", value: [4625, 4624] },
          { not: { field: "event.data.TargetUserName", op: "starts_with", value: "svc_", case_sensitive: true } },
        ],
      },
      threshold: { count: 6, window_minutes: 15 },
      group_by: ["event.data.TargetUserName"],
    });
    const back = editorFromDefinition(definition);
    expect(back?.rows.map((r) => [r.field, r.op, r.value, r.negate])).toEqual([
      ["event.code", "in", "4625, 4624", false],
      ["event.data.TargetUserName", "starts_with", "svc_", true],
    ]);
    expect(back?.thresholdCount).toBe(6);
  });

  it("a single condition is not wrapped and nested groups need the advanced mode", () => {
    const state = emptyEditor("windows_security");
    state.rows = [{ ...newRow("event.code", "equals"), value: "1102" }];
    expect(definitionFromEditor(state, FIELDS).condition).toEqual({ field: "event.code", op: "equals", value: 1102 });
    expect(
      editorFromDefinition({
        logsource: "windows_security",
        condition: { all: [{ any: [{ field: "event.code", op: "equals", value: 1 }] }] },
      }),
    ).toBeNull();
  });

  it("parses synthetic events as plain data", () => {
    const events = parseSyntheticEvents(
      "event.code = 4625\nevent.data.TargetUserName = <script>x</script>\n\nevent.code = 4624\nbasura sin igual",
      FIELDS,
    );
    expect(events).toEqual([
      { fields: { "event.code": 4625, "event.data.TargetUserName": "<script>x</script>" } },
      { fields: { "event.code": 4624 } },
    ]);
  });

  it("displays values as text", () => {
    expect(displayValue(null)).toBe("—");
    expect(displayValue({ a: 1 })).toContain('"a": 1');
  });
});
