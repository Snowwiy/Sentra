import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiGet, apiPost } from "./client";

function respond(status: number, body: string, contentType = "application/json") {
  const fetchMock = vi.fn(async () => new Response(body, { status, headers: { "Content-Type": contentType } }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function failure(promise: Promise<unknown>): Promise<ApiError> {
  const error = await promise.then(
    () => undefined,
    (err: unknown) => err,
  );
  expect(error).toBeInstanceOf(ApiError);
  return error as ApiError;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiGet", () => {
  it("calls the versioned API path and returns the parsed body", async () => {
    const fetchMock = respond(200, JSON.stringify({ items: [], total: 0 }));

    await expect(apiGet("/assets")).resolves.toEqual({ items: [], total: 0 });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/assets$/);
    expect(init.headers).toEqual({ Accept: "application/json" });
  });

  it("turns the API error envelope into an ApiError with its code", async () => {
    respond(404, JSON.stringify({ error: { code: "not_found", message: "Asset not found" } }));

    const error = await failure(apiGet("/assets/x"));
    expect(error.status).toBe(404);
    expect(error.code).toBe("not_found");
    expect(error.message).toBe("Asset not found");
  });

  it("reports a gateway error without envelope as the API being unreachable", async () => {
    respond(502, "<html>Bad Gateway</html>", "text/html");

    const error = await failure(apiGet("/assets"));
    expect(error.code).toBe("network_error");
    expect(error.message).toBe("No se pudo conectar con la API de Sentra (HTTP 502)");
  });

  it("keeps the API's own message for a 503 that carries the envelope", async () => {
    respond(
      503,
      JSON.stringify({ error: { code: "database_unavailable", message: "Database temporarily unavailable" } }),
    );

    const error = await failure(apiGet("/assets"));
    expect(error.code).toBe("database_unavailable");
  });

  it("falls back to a generic error for other unexpected bodies", async () => {
    respond(500, JSON.stringify({ detail: "something else" }));

    const error = await failure(apiGet("/assets"));
    expect(error.code).toBe("http_error");
    expect(error.message).toBe("HTTP 500");
  });

  it("returns the body of accepted non-2xx statuses (degraded health)", async () => {
    const degraded = { status: "degraded", version: "0.1.0", checks: { database: "error" } };
    respond(503, JSON.stringify(degraded));

    await expect(apiGet("/health", { acceptStatuses: [503] })).resolves.toEqual(degraded);
  });

  it("maps network failures to a network_error with status 0", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );

    const error = await failure(apiGet("/assets"));
    expect(error.status).toBe(0);
    expect(error.code).toBe("network_error");
  });

  it("lets aborts through untouched so callers can ignore them", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new DOMException("The operation was aborted.", "AbortError");
      }),
    );

    await expect(apiGet("/assets")).rejects.toMatchObject({ name: "AbortError" });
  });

  it("rejects a 2xx answer that is not JSON", async () => {
    respond(200, "<html>captive portal</html>", "text/html");

    const error = await failure(apiGet("/assets"));
    expect(error.code).toBe("invalid_response");
  });
});

describe("apiPost and console calls", () => {
  it("sends JSON, the console marker and never uses the HTTP cache", async () => {
    const fetchMock = respond(201, JSON.stringify({ ok: true }));

    await expect(apiPost("/console/enrollment-tokens", { max_uses: 1 }, { console: true })).resolves.toEqual({
      ok: true,
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/console\/enrollment-tokens$/);
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ max_uses: 1 }));
    expect(init.cache).toBe("no-store");
    expect(init.headers).toEqual({
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-Sentra-Console": "1",
    });
  });

  it("never sends an admin key", async () => {
    const fetchMock = respond(200, "{}");
    await apiGet("/console", { console: true });
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.stringify(init.headers).toLowerCase()).not.toContain("admin");
  });
});
