import { config } from "../config";
import type { ApiErrorBody } from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

function isErrorEnvelope(value: unknown): value is { error: ApiErrorBody } {
  if (typeof value !== "object" || value === null || !("error" in value)) return false;
  const error = (value as { error: unknown }).error;
  return typeof error === "object" && error !== null && "message" in error;
}

const GATEWAY_STATUSES = new Set([502, 503, 504]);

async function parseError(response: Response): Promise<ApiError> {
  try {
    const body: unknown = await response.json();
    if (isErrorEnvelope(body)) {
      return new ApiError(response.status, body.error.code, body.error.message);
    }
  } catch {
    // Body is not JSON (e.g. a proxy error page); fall through to a generic error.
  }
  // A gateway status without the API's error envelope comes from the proxy in front of the
  // API (Vite in development, a reverse proxy in production): the API itself is unreachable.
  if (GATEWAY_STATUSES.has(response.status)) {
    return new ApiError(
      response.status,
      "network_error",
      `No se pudo conectar con la API de Sentra (HTTP ${response.status})`,
    );
  }
  return new ApiError(response.status, "http_error", `HTTP ${response.status}`);
}

/**
 * Marks calls to the dashboard console (/api/v1/console): the API only answers them for a
 * browser on the Sentra server, and a custom header cannot be set by forms or simple
 * cross-site requests. This is not a secret: there is no admin key in the frontend.
 */
export const CONSOLE_HEADER = "X-Sentra-Console";

interface RequestOptions {
  signal?: AbortSignal;
  /** Non-2xx statuses whose body is still a valid `T` (e.g. 503 from /health). */
  acceptStatuses?: number[];
  /** Send the console marker header (agent management calls). */
  console?: boolean;
}

async function request<T>(
  method: "GET" | "POST",
  path: string,
  body: unknown,
  { signal, acceptStatuses = [], console: isConsole = false }: RequestOptions,
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (isConsole) headers[CONSOLE_HEADER] = "1";
  let response: Response;
  try {
    response = await fetch(`${config.apiBaseUrl}/api/v1${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      // Responses may hold a one-time token: never from or into the HTTP cache.
      cache: "no-store",
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "network_error", "No se pudo conectar con la API de Sentra");
  }
  if (!response.ok && !acceptStatuses.includes(response.status)) throw await parseError(response);
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError(response.status, "invalid_response", "Respuesta no válida de la API");
  }
}

export function apiGet<T>(path: string, options: RequestOptions = {}): Promise<T> {
  return request<T>("GET", path, undefined, options);
}

export function apiPost<T>(path: string, body?: unknown, options: RequestOptions = {}): Promise<T> {
  return request<T>("POST", path, body ?? {}, options);
}
