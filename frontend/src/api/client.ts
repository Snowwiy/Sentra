import { config } from "../config";
import type { ApiErrorBody } from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** `details` del sobre de error (p. ej. la versión actual en un 409 incident_conflict). */
  readonly details: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function isErrorEnvelope(value: unknown): value is { error: ApiErrorBody } {
  if (typeof value !== "object" || value === null || !("error" in value)) return false;
  const error = (value as { error: unknown }).error;
  return typeof error === "object" && error !== null && "message" in error;
}

const GATEWAY_STATUSES = new Set([502, 503, 504]);

// Mensajes en español para los errores de autenticación y permisos; el resto conserva el
// mensaje del backend.
const AUTH_MESSAGES: Record<string, string> = {
  not_authenticated: "La sesión ha caducado. Inicia sesión de nuevo.",
  invalid_credentials: "Usuario o contraseña incorrectos.",
  permission_denied: "Tu rol no permite esta acción.",
  csrf_failed: "La sesión no es válida para esta acción. Recarga la página.",
  rate_limited: "Demasiados intentos. Espera unos minutos y vuelve a intentarlo.",
  last_admin: "Sentra debe conservar al menos un administrador activo.",
};

// Errores de AI Security Insights (Fase 4J): mensajes claros sin detalles del proveedor.
const AI_MESSAGES: Record<string, string> = {
  ai_not_configured: "IA no configurada en el servidor.",
  ai_busy: "Hay otros análisis de IA en curso. Inténtalo en unos segundos.",
  ai_timeout: "El modelo de IA no respondió a tiempo.",
  ai_provider_unavailable: "El proveedor de IA no está disponible.",
  ai_provider_rate_limited: "El proveedor de IA está limitando peticiones. Inténtalo más tarde.",
  ai_provider_auth_failed: "El proveedor de IA rechazó las credenciales del servidor.",
  ai_invalid_response: "El modelo devolvió una respuesta no válida.",
  ai_ungrounded_response: "La respuesta del modelo no citaba evidencia válida de Sentra y se descartó.",
  // Gestor de modelos locales (Fase 4J.2).
  ai_benchmark_busy: "Ya hay un benchmark en curso. Espera a que termine o cancélalo.",
  ai_runtime_operation_unsupported: "El runtime configurado no permite esa operación.",
  local_model_runtime_mismatch: "El modelo pertenece a otro runtime; cambia de runtime o registra el modelo de nuevo.",
  local_model_unavailable: "El modelo no está disponible en el runtime ni en disco.",
};

// Gestión de incidentes (Fase 4K). incident_conflict: otro operador cambió el caso; la UI
// recarga antes de reintentar (nunca se sobrescribe en silencio).
const INCIDENT_MESSAGES: Record<string, string> = {
  incident_conflict: "Otro operador ha modificado este incidente. Recarga para ver los cambios antes de volver a intentarlo.",
  incident_invalid_state: "Esa acción no está permitida en el estado actual del incidente.",
  incident_already_linked: "Ya está vinculado a un incidente abierto.",
};

// Asset Context (Fase 4L). asset_context_conflict: otro admin cambió el contexto; la UI
// recarga antes de reintentar (nunca se sobrescribe en silencio).
const ASSET_CONTEXT_MESSAGES: Record<string, string> = {
  asset_context_conflict:
    "Otro administrador ha modificado el contexto de este activo. Se han recargado los datos: revisa y vuelve a guardar.",
  asset_tag_limit: "Se ha alcanzado el máximo de etiquetas distintas. Reutiliza una etiqueta existente.",
};

// Errores del gestor de modelos locales cuyo detalle (en inglés) dice qué corregir: se
// conserva tras un prefijo en español, porque sin él el administrador no sabría qué falla.
const AI_DETAIL_PREFIXES: Record<string, string> = {
  local_model_path_rejected: "Ruta de modelo rechazada",
  local_model_invalid_file: "Fichero de modelo no válido",
  local_model_not_loaded: "El runtime no tiene cargado este modelo",
};

// Motivos de la política de usuarios/contraseñas (backend core/passwords.py), en español.
const POLICY_MESSAGES: [RegExp, string][] = [
  [/^Password must be at least (\d+)/, "La contraseña debe tener al menos $1 caracteres."],
  [/^Password must be at most (\d+)/, "La contraseña puede tener como máximo $1 caracteres."],
  [/^Password must not start or end/, "La contraseña no puede empezar ni terminar con espacios."],
  [/^Password is too common/, "La contraseña es demasiado común o repetitiva."],
  [/^Password must not contain the username/, "La contraseña no puede contener el nombre de usuario."],
  [/^Current password is not correct/, "La contraseña actual no es correcta."],
  [/^Username must be (\d+-\d+)/, "El usuario debe tener $1 caracteres."],
  [/^Username may only contain/, "El usuario solo admite a-z, 0-9, punto, guion y guion bajo."],
  [/^Username already exists/, "Ya existe un usuario con ese nombre."],
  [/^You cannot remove your own admin access/, "No puedes quitarte a ti mismo el acceso de administrador."],
];

function translate(code: string, message: string): string {
  if (AUTH_MESSAGES[code]) return AUTH_MESSAGES[code];
  // ai_not_configured trae el motivo concreto del servidor (ya en español).
  if (code === "ai_not_configured") return message || "IA no configurada en el servidor.";
  if (AI_MESSAGES[code]) return AI_MESSAGES[code];
  if (INCIDENT_MESSAGES[code]) return INCIDENT_MESSAGES[code];
  if (ASSET_CONTEXT_MESSAGES[code]) return ASSET_CONTEXT_MESSAGES[code];
  // El motivo (inglés) dice qué referencia falla; se conserva tras un prefijo en español.
  if (code === "incident_invalid_reference") return `Referencia no válida: ${message}`;
  if (AI_DETAIL_PREFIXES[code]) return `${AI_DETAIL_PREFIXES[code]}: ${message}`;
  for (const [pattern, spanish] of POLICY_MESSAGES) {
    if (pattern.test(message)) return message.replace(pattern, spanish).replace(/^(.*?\.).*$/, "$1");
  }
  return message;
}

async function parseError(response: Response): Promise<ApiError> {
  try {
    const body: unknown = await response.json();
    if (isErrorEnvelope(body)) {
      const message = translate(body.error.code, body.error.message);
      return new ApiError(response.status, body.error.code, message, body.error.details);
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

// --- Sesión del dashboard (Fase 4G) ------------------------------------------------------
//
// La sesión viaja solo en una cookie HttpOnly que este código no puede leer ni escribir. Lo
// único que el frontend guarda es el token CSRF, y SOLO en memoria (esta variable): nunca en
// el almacenamiento del navegador ni en la URL. Al recargar la página se vuelve a pedir a
// /auth/me, que otro sitio web no puede leer.

/** Cabecera anti-CSRF que el backend exige en toda petición mutable con sesión. */
export const CSRF_HEADER = "X-CSRF-Token";

let csrfToken: string | undefined;
let unauthorizedHandler: (() => void) | undefined;

export function setCsrfToken(token: string | undefined): void {
  csrfToken = token;
}

/**
 * Se llama cuando la API responde 401 (sesión caducada, revocada o usuario desactivado).
 * El AuthProvider lo usa para limpiar el estado y volver a /login una sola vez, en lugar
 * de que cada panel siga reintentando.
 */
export function onUnauthorized(handler: (() => void) | undefined): void {
  unauthorizedHandler = handler;
}

type Method = "GET" | "POST" | "PATCH";

interface RequestOptions {
  signal?: AbortSignal;
  /** Non-2xx statuses whose body is still a valid `T` (e.g. 503 from /health). */
  acceptStatuses?: number[];
  /** No avisar al AuthProvider en un 401 (login y /auth/me gestionan el suyo). */
  skipUnauthorized?: boolean;
}

async function request<T>(
  method: Method,
  path: string,
  body: unknown,
  { signal, acceptStatuses = [], skipUnauthorized = false }: RequestOptions,
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers[CSRF_HEADER] = csrfToken;
  let response: Response;
  try {
    response = await fetch(`${config.apiBaseUrl}/api/v1${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      // Responses may hold a one-time token: never from or into the HTTP cache.
      cache: "no-store",
      // La cookie de sesión también cuando la API está en otro origen (VITE_API_BASE_URL);
      // el backend solo lo acepta para los orígenes de CORS_ORIGINS.
      credentials: "include",
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "network_error", "No se pudo conectar con la API de Sentra");
  }
  if (!response.ok && !acceptStatuses.includes(response.status)) {
    const error = await parseError(response);
    if (response.status === 401 && !skipUnauthorized) unauthorizedHandler?.();
    throw error;
  }
  if (response.status === 204) return undefined as T;
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

export function apiPatch<T>(path: string, body: unknown, options: RequestOptions = {}): Promise<T> {
  return request<T>("PATCH", path, body, options);
}
