import { describe, expect, it } from "vitest";
import type { EvidenceRef } from "../api/types";
import { refLink } from "./ai";

const ref = (type: string, id: string, asset: string | null = "a-1"): EvidenceRef => ({
  ref: "X1",
  type,
  id,
  label: "x",
  asset_id: asset,
});

describe("refLink", () => {
  it("links only to Sentra's own routes", () => {
    expect(refLink(ref("detection", "d-1"))).toBe("/detections/d-1");
    expect(refLink(ref("asset", "a-1"))).toBe("/assets/a-1");
    expect(refLink(ref("risk_contribution", "a-1#0"))).toBe("/assets/a-1?tab=risk");
    expect(refLink(ref("exposure", "a-1:tcp/3389"))).toBe("/assets/a-1?tab=exposure");
    expect(refLink(ref("event", "e-1"))).toBe("/assets/a-1?tab=events");
    expect(refLink(ref("alert", "l-1", null))).toBe("/alerts");
    expect(refLink(ref("unknown", "x"))).toBeNull();
  });

  it("encodes identifiers so a crafted id cannot change the route", () => {
    expect(refLink(ref("detection", "../../admin/users"))).toBe("/detections/..%2F..%2Fadmin%2Fusers");
  });
});
