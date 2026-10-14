import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { responseApi, sentraApi } from "./sentra";

let requested: string[];
let inits: RequestInit[];

beforeEach(() => {
  requested = [];
  inits = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit = {}) => {
      requested.push(url);
      inits.push(init);
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

describe("responseApi (Fase 5D)", () => {
  it("maps the execution filters to the API parameter names", async () => {
    await responseApi.executions({});
    expect(lastPath()).toBe("/api/v1/response/executions");

    await responseApi.executions({ status: "running", actionId: "collect_events", assetId: "a1", limit: 25, offset: 50 });
    expect(lastPath()).toBe(
      "/api/v1/response/executions?status=running&action_id=collect_events&asset_id=a1&limit=25&offset=50",
    );

    await responseApi.actions("a1");
    expect(lastPath()).toBe("/api/v1/response/actions?asset_id=a1");
  });

  it("posts the request body as JSON and encodes ids from the URL", async () => {
    await responseApi.execute({ action_id: "recalculate_risk", target_id: "t1", confirm: false, idempotency_key: "abcdef12" });
    expect(lastPath()).toBe("/api/v1/response/executions");
    expect(inits.at(-1)?.method).toBe("POST");
    expect(JSON.parse(String(inits.at(-1)?.body))).toEqual({
      action_id: "recalculate_risk",
      target_id: "t1",
      confirm: false,
      idempotency_key: "abcdef12",
    });

    await responseApi.setPlaybookEnabled("../x", 3, false);
    expect(lastPath()).toBe("/api/v1/response/playbooks/..%2Fx/disable");
    expect(JSON.parse(String(inits.at(-1)?.body))).toEqual({ revision: 3 });

    await responseApi.cancelRun("r1", 2);
    expect(lastPath()).toBe("/api/v1/response/runs/r1/cancel");
    expect(JSON.parse(String(inits.at(-1)?.body))).toEqual({ version: 2, reason: null });
  });
});
