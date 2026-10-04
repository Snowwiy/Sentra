import { describe, expect, it } from "vitest";
import type { AssetChange } from "../../api/types";
import { describeChange } from "./ChangesList";
import { endpoint, splitAddresses } from "./NetworkTab";
import { serviceStatusClass } from "./ServicesTab";

function change(details: AssetChange["details"]): AssetChange {
  return {
    change_id: "c1",
    category: "software",
    kind: "version_changed",
    item: "Google Chrome",
    details,
    collected_at: "2026-10-04T10:00:00Z",
    detected_at: "2026-10-04T10:00:01Z",
  };
}

describe("describeChange", () => {
  // Shapes produced by backend/app/services/change_detection.py.
  it("shows before → after, joining version lists", () => {
    expect(describeChange(change({ before: ["129.0.1"], after: ["129.0.2", "130.0"] }))).toBe(
      "129.0.1 → 129.0.2, 130.0",
    );
    expect(describeChange(change({ before: "automatic", after: "manual" }))).toBe("automatic → manual");
  });

  it("shows a dash for missing or empty values", () => {
    expect(describeChange(change({ before: null, after: "running" }))).toBe("— → running");
    // Software without a version is reported as [""].
    expect(describeChange(change({ versions: [""] }))).toBe("—");
  });

  it("describes added services by status and start type", () => {
    expect(describeChange(change({ status: "running", start_type: "automatic" }))).toBe(
      "running · automatic",
    );
    expect(describeChange(change({ status: "stopped", start_type: null }))).toBe("stopped");
  });

  it("is empty when there are no details", () => {
    expect(describeChange(change(null))).toBe("");
    expect(describeChange(change({ is_admin: true }))).toBe("");
  });
});

describe("network helpers", () => {
  it("formats endpoints, bracketing IPv6 before a port", () => {
    expect(endpoint("10.0.0.5", 443)).toBe("10.0.0.5:443");
    expect(endpoint("fe80::1", 443)).toBe("[fe80::1]:443");
    expect(endpoint("::", null)).toBe("::");
    expect(endpoint(null, 135)).toBe("*:135");
    expect(endpoint(null, null)).toBe("—");
  });

  it("splits IPv4 and IPv6 addresses keeping their order", () => {
    expect(splitAddresses(["192.168.1.2", "fe80::1", "10.0.0.1", "::1"])).toEqual({
      v4: ["192.168.1.2", "10.0.0.1"],
      v6: ["fe80::1", "::1"],
    });
  });
});

describe("serviceStatusClass", () => {
  it("highlights running and failed services only", () => {
    expect(serviceStatusClass("running")).toBe("text-ok");
    expect(serviceStatusClass("failed")).toBe("text-crit");
    expect(serviceStatusClass("stopped")).toBe("muted");
  });
});
