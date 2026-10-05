import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiGet, apiPost, onUnauthorized, setCsrfToken } from "./client";

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

  it("keeps the envelope details and translates incident errors", async () => {
    const details = [{ incident_id: "i1", current_version: 4, updated_by: "luis" }];
    respond(409, JSON.stringify({ error: { code: "incident_conflict", message: "changed", details } }));

    const error = await failure(apiGet("/incidents/i1"));
    expect(error.code).toBe("incident_conflict");
    expect(error.details).toEqual(details);
    expect(error.message).toMatch(/Otro operador ha modificado este incidente/);

    respond(422, JSON.stringify({ error: { code: "incident_invalid_reference", message: "Asset not found: x" } }));
    expect((await failure(apiGet("/incidents"))).message).toBe("Referencia no válida: Asset not found: x");
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

describe("apiPost, CSRF y sesión (Fase 4G)", () => {
  afterEach(() => {
    setCsrfToken(undefined);
    onUnauthorized(undefined);
  });

  it("sends JSON with the in-memory CSRF token, the session cookie and no HTTP cache", async () => {
    const fetchMock = respond(201, JSON.stringify({ ok: true }));
    setCsrfToken("csrf-123");

    await expect(apiPost("/console/enrollment-tokens", { max_uses: 1 })).resolves.toEqual({ ok: true });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/console\/enrollment-tokens$/);
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ max_uses: 1 }));
    expect(init.cache).toBe("no-store");
    expect(init.credentials).toBe("include");
    expect(init.headers).toEqual({
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": "csrf-123",
    });
  });

  it("does not send the CSRF token on reads", async () => {
    const fetchMock = respond(200, "{}");
    setCsrfToken("csrf-123");
    await apiGet("/assets");
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.headers).toEqual({ Accept: "application/json" });
    expect(init.credentials).toBe("include");
  });

  it("never sends an admin key or the old console marker", async () => {
    const fetchMock = respond(200, "{}");
    setCsrfToken("csrf-123");
    await apiPost("/console/agents/x/revoke");
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const headers = JSON.stringify(init.headers).toLowerCase();
    expect(headers).not.toContain("admin");
    expect(headers).not.toContain("x-sentra-console");
  });

  it("notifies a 401 once per call and translates auth errors", async () => {
    const handler = vi.fn();
    onUnauthorized(handler);
    respond(401, JSON.stringify({ error: { code: "not_authenticated", message: "Authentication required" } }));
    const error = await failure(apiGet("/assets"));
    expect(error.status).toBe(401);
    expect(error.message).toMatch(/sesión ha caducado/);
    expect(handler).toHaveBeenCalledTimes(1);
    // Login y /auth/me gestionan su propio 401: no disparan la salida global.
    respond(401, JSON.stringify({ error: { code: "invalid_credentials", message: "x" } }));
    await failure(apiPost("/auth/login", {}, { skipUnauthorized: true }));
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("explains a 403 from the backend", async () => {
    respond(403, JSON.stringify({ error: { code: "permission_denied", message: "Your role..." } }));
    const error = await failure(apiPost("/alerts/x/resolve"));
    expect(error.code).toBe("permission_denied");
    expect(error.message).toBe("Tu rol no permite esta acción.");
  });

  it("accepts 204 No Content", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
    await expect(apiPost("/auth/logout")).resolves.toBeUndefined();
  });
});

describe("mensajes de política", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("traduce los motivos de la política de contraseñas", async () => {
    respond(422, JSON.stringify({ error: { code: "policy_violation", message: "Password must be at least 12 characters" } }));
    expect((await failure(apiPost("/users", {}))).message).toBe("La contraseña debe tener al menos 12 caracteres.");
    respond(409, JSON.stringify({ error: { code: "conflict", message: "Username already exists" } }));
    expect((await failure(apiPost("/users", {}))).message).toBe("Ya existe un usuario con ese nombre.");
    respond(409, JSON.stringify({ error: { code: "conflict", message: "Something else" } }));
    expect((await failure(apiPost("/users", {}))).message).toBe("Something else");
  });
});
