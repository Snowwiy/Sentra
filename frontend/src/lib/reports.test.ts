import { describe, expect, it } from "vitest";
import type { ReportTypeInfo } from "../api/types";
import {
  buildReportRequest,
  dayToUtcIso,
  describeFilters,
  effectiveFormat,
  formatScope,
  initialFormState,
  localInputToUtcIso,
  newReportKey,
  parseIdList,
  parsePrefill,
  reportHref,
  safeFilename,
  shortHash,
} from "./reports";

const INCIDENT_ID = "11111111-2222-3333-4444-555555555555";

function reportType(overrides: Partial<ReportTypeInfo> = {}): ReportTypeInfo {
  return {
    id: "detection",
    name: "Informe de detecciones",
    description: "",
    audience: "technical",
    template_version: 1,
    supported_formats: ["html", "pdf", "csv", "evidence"],
    filters: ["asset_ids", "detection_ids", "severities", "statuses"],
    required_filters: [],
    status_values: ["open", "resolved"],
    severity_values: ["critical", "high"],
    uses_range: true,
    max_range_days: 365,
    can_generate: true,
    ...overrides,
  };
}

describe("reports helpers", () => {
  it("parses prefill query parameters into id filters", () => {
    const prefill = parsePrefill(new URLSearchParams(`type=incident&incident_id=${INCIDENT_ID}&unknown=x`));
    expect(prefill).toEqual({ type: "incident", ids: { incident_ids: INCIDENT_ID } });
    expect(parsePrefill(new URLSearchParams("type=response_activity&execution_id=a&playbook_id=b")).ids).toEqual({
      execution_ids: "a",
      playbook_ids: "b",
    });
  });

  it("builds prefill links", () => {
    expect(reportHref("asset", { asset_id: "x y" })).toBe("/reports?type=asset&asset_id=x+y");
    expect(reportHref("response_activity")).toBe("/reports?type=response_activity");
  });

  it("splits id lists and drops duplicates", () => {
    expect(parseIdList(" a, b;c a\n")).toEqual(["a", "b", "c"]);
  });

  it("keeps only supported, non-empty filters and the preset range", () => {
    const form = {
      ...initialFormState({ type: "detection", ids: { detection_ids: "d1, d2", incident_ids: "ignored" } }),
      multi: { severities: ["high", "low"], statuses: [], platforms: ["linux"] },
      preset: "7d" as const,
    };
    const { request, problems } = buildReportRequest(reportType(), form);
    expect(problems).toEqual([]);
    expect(request).toEqual({
      report_type: "detection",
      format: "html",
      classification: "internal",
      range: { preset: "7d" },
      // "low" no está en severity_values del tipo; platforms no lo admite el tipo.
      filters: { detection_ids: ["d1", "d2"], severities: ["high"] },
    });
  });

  it("omits the range when the type does not use it and checks required filters", () => {
    const type = reportType({
      id: "incident",
      filters: ["incident_ids"],
      required_filters: ["incident_ids"],
      uses_range: false,
    });
    expect(buildReportRequest(type, initialFormState({ type: "incident", ids: {} })).problems).toHaveLength(1);
    const ok = buildReportRequest(type, initialFormState({ type: "incident", ids: { incident_ids: INCIDENT_ID } }));
    expect(ok.request).toEqual({
      report_type: "incident",
      format: "html",
      classification: "internal",
      filters: { incident_ids: [INCIDENT_ID] },
    });
    const two = buildReportRequest(type, initialFormState({ type: "incident", ids: { incident_ids: "a, b" } }));
    expect(two.request).toBeUndefined();
  });

  it("sends custom ranges in UTC and validates them", () => {
    const base = { ...initialFormState({ type: undefined, ids: {} }), preset: "custom" as const };
    const ok = buildReportRequest(reportType(), { ...base, customFrom: "2026-10-01T00:00", customTo: "2026-10-07T12:30" });
    expect(ok.request?.range).toEqual({ preset: "custom", from: "2026-10-01T00:00:00Z", to: "2026-10-07T12:30:00Z" });
    expect(buildReportRequest(reportType(), { ...base, customFrom: "2026-10-07T00:00", customTo: "2026-10-01T00:00" }).request).toBeUndefined();
    expect(buildReportRequest(reportType({ max_range_days: 2 }), { ...base, customFrom: "2026-10-01T00:00", customTo: "2026-10-07T00:00" }).problems[0]).toMatch(/2 días/);
    expect(localInputToUtcIso("bad")).toBeUndefined();
    expect(dayToUtcIso("2026-10-14", true)).toBe("2026-10-14T23:59:59Z");
  });

  it("falls back to the first supported format", () => {
    expect(effectiveFormat(reportType({ supported_formats: ["pdf", "html"] }), "csv")).toBe("pdf");
    expect(effectiveFormat(reportType(), "csv")).toBe("csv");
  });

  it("formats hashes, scope, filters and filenames", () => {
    expect(shortHash("a".repeat(64))).toBe(`${"a".repeat(12)}…`);
    expect(shortHash(null)).toBe("—");
    expect(formatScope({ assets: 3, detections: 12 })).toBe("Activos: 3 · Detecciones: 12");
    expect(describeFilters({ severities: ["high"], include_archived: true, asset_ids: [] })).toEqual([
      { label: "Severidades", value: "Alto" },
      { label: "Incluir archivados", value: "Sí" },
    ]);
    expect(safeFilename("../../etc/passwd", "x")).toBe("passwd");
    expect(safeFilename("", "fallback.pdf")).toBe("fallback.pdf");
  });

  it("generates uuid v4 idempotency keys", () => {
    const a = newReportKey();
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(newReportKey()).not.toBe(a);
  });
});
