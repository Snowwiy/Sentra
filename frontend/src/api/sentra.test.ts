import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sentraApi } from "./sentra";

let requested: string[];

beforeEach(() => {
  requested = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      requested.push(url);
      return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Path and query of the last request, independent of VITE_API_BASE_URL. */
function lastPath(): string {
  const url = requested.at(-1) ?? "";
  return url.slice(url.indexOf("/api/v1"));
}

describe("sentraApi query strings", () => {
  it("only sends the alert filters that are set", async () => {
    await sentraApi.listAlerts({});
    expect(lastPath()).toBe("/api/v1/alerts");

    await sentraApi.listAlerts({ status: "open", assetId: "a1", limit: 5 });
    expect(lastPath()).toBe("/api/v1/alerts?status=open&asset_id=a1&limit=5");
  });

  it("maps event filters to the API parameter names", async () => {
    await sentraApi.listEvents({ minLevel: "warning", limit: 10 });
    expect(lastPath()).toBe("/api/v1/events?min_level=warning&limit=10");
  });

  it("encodes ids taken from the URL so they cannot change the request path", async () => {
    await sentraApi.getAsset("../alerts?x=1");
    expect(lastPath()).toBe("/api/v1/assets/..%2Falerts%3Fx%3D1");

    await sentraApi.getTelemetry("a/b", 120);
    expect(lastPath()).toBe("/api/v1/assets/a%2Fb/telemetry?limit=120");
  });
});

describe("sentraApi.readiness", () => {
  it("treats a not-ready 503 as data, not as a failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        requested.push(url);
        return new Response(JSON.stringify({ status: "not_ready", checks: { database: "error" } }), { status: 503 });
      }),
    );

    await expect(sentraApi.readiness()).resolves.toMatchObject({ status: "not_ready" });
    expect(lastPath()).toBe("/api/v1/health/ready");
  });
});

describe("sentraApi.listAssets (Fase 4M)", () => {
  it("always sends the page, sort and filters to the server", async () => {
    await sentraApi.listAssets(undefined, { status: "offline", q: "pc", sort: "ip", order: "desc", limit: 50, offset: 100 });
    expect(lastPath()).toBe("/api/v1/assets?status=offline&q=pc&sort=ip&order=desc&limit=50&offset=100");
  });

  it("reads the dashboard summary from its aggregate endpoint", async () => {
    await sentraApi.dashboardSummary();
    expect(lastPath()).toBe("/api/v1/dashboard/summary");
  });
});
