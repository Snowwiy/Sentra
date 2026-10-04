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

interface GetOptions {
  signal?: AbortSignal;
  /** Non-2xx statuses whose body is still a valid `T` (e.g. 503 from /health). */
  acceptStatuses?: number[];
}

export async function apiGet<T>(path: string, { signal, acceptStatuses = [] }: GetOptions = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${config.apiBaseUrl}/api/v1${path}`, {
      headers: { Accept: "application/json" },
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
