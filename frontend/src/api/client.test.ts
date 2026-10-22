import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiDownload, apiGet, apiPost, onUnauthorized, setCsrfToken } from "./client";

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

  it("translates response engine errors and keeps the blocked details (Fase 5D)", async () => {
    const details = [{ execution_id: "e1" }, { code: "agent_offline", message: "offline" }];
    respond(409, JSON.stringify({ error: { code: "response_blocked", message: "blocked", details } }));
    const blocked = await failure(apiGet("/response/executions"));
    expect(blocked.code).toBe("response_blocked");
    expect(blocked.details).toEqual(details);

    respond(409, JSON.stringify({ error: { code: "response_conflict", message: "The execution changed" } }));
    expect((await failure(apiGet("/x"))).message).toMatch(/Otro operador ha modificado/);

    respond(409, JSON.stringify({ error: { code: "response_invalid_state", message: "x" } }));
    expect((await failure(apiGet("/x"))).message).toBe("La ejecución ya ha terminado y no se puede cancelar.");

    respond(422, JSON.stringify({ error: { code: "playbook_continue_not_allowed", message: "step 2 is medium" } }));
    expect((await failure(apiGet("/x"))).message).toBe("Playbook no válido: step 2 is medium");

    respond(422, JSON.stringify({ error: { code: "response_invalid_parameters", message: "hours too large" } }));
    expect((await failure(apiGet("/x"))).message).toBe("Parámetros no válidos: hours too large");
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

// Fase 6D.6: lo que pasa DESPUÉS de recibir cabeceras no es "API no disponible".
describe("apiDownload", () => {
  it("devuelve blob, nombre y SHA-256 de las cabeceras", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("abc", {
            status: 200,
            headers: { "Content-Disposition": 'attachment; filename="../x/informe.pdf"', "X-Sentra-SHA256": " ABCDEF " },
          }),
      ),
    );
    const file = await apiDownload("/reports/1/artifact");
    expect(file.filename).toBe("informe.pdf");
    expect(file.sha256).toBe("abcdef");
    expect(file.blob.size).toBe(3);
  });

  it("un cuerpo cortado a mitad es download_interrupted con el estado HTTP real", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            new ReadableStream({
              start(controller) {
                controller.error(new TypeError("terminated"));
              },
            }),
            { status: 200 },
          ),
      ),
    );
    const error = await failure(apiDownload("/reports/1/artifact"));
    expect(error.code).toBe("download_interrupted");
    expect(error.status).toBe(200);
  });

  it("un plazo vencido (AbortSignal.timeout) es timeout, no network_error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new DOMException("signal timed out", "TimeoutError");
      }),
    );
    const error = await failure(apiDownload("/reports/1/artifact"));
    expect(error.code).toBe("timeout");
    expect(error.status).toBe(0);
  });

  it("una cancelación se propaga como AbortError (la UI no avisa)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new DOMException("aborted", "AbortError");
      }),
    );
    await expect(apiDownload("/reports/1/artifact")).rejects.toMatchObject({ name: "AbortError" });
  });

  it("un 502 del proxy sin sobre conserva network_error con el estado", async () => {
    respond(502, "", "text/plain");
    const error = await failure(apiDownload("/reports/1/artifact"));
    expect(error.code).toBe("network_error");
    expect(error.status).toBe(502);
  });
});

describe("mensajes de topología", () => {
  it("traduce el conflicto de revisión y la reconstrucción en curso", async () => {
    respond(409, JSON.stringify({ error: { code: "topology_link_conflict", message: "x" } }));
    expect((await failure(apiPost("/topology/links/1/review", {}))).message).toMatch(/Otro administrador ha revisado/);
    respond(409, JSON.stringify({ error: { code: "topology_build_running", message: "x" } }));
    expect((await failure(apiPost("/topology/rebuild", {}))).message).toMatch(/reconstrucción de la topología en curso/);
  });
});
