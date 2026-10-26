import { config } from "../config";
import { explainTooBroad } from "../lib/exclusionPolicy";
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
  // Fase 7A.6: tareas y solicitudes de control de red (versión vieja o estado que no lo permite).
  task_conflict: "Otra persona ha modificado esta tarea. Recarga para ver los cambios antes de volver a intentarlo.",
  task_invalid_state: "Esa acción no está permitida en el estado actual de la tarea.",
  network_control_conflict:
    "Otra persona ha modificado esta solicitud de control. Recarga para ver los cambios antes de volver a intentarlo.",
  network_control_invalid_state: "Esa acción no está permitida en el estado actual de la solicitud.",
};

// Asset Context (Fase 4L). asset_context_conflict: otro admin cambió el contexto; la UI
// recarga antes de reintentar (nunca se sobrescribe en silencio).
const ASSET_CONTEXT_MESSAGES: Record<string, string> = {
  asset_context_conflict:
    "Otro administrador ha modificado el contexto de este activo. Se han recargado los datos: revisa y vuelve a guardar.",
  asset_tag_limit: "Se ha alcanzado el máximo de etiquetas distintas. Reutiliza una etiqueta existente.",
};

// Response Engine y Playbooks (Fase 5D). response_conflict: versión obsoleta o clave de
// idempotencia reutilizada; la UI recarga antes de reintentar (nunca se sobrescribe en silencio).
const RESPONSE_MESSAGES: Record<string, string> = {
  response_conflict: "Otro operador ha modificado esta ejecución o playbook. Se han recargado los datos: revisa y vuelve a intentarlo.",
  response_invalid_state: "La ejecución ya ha terminado y no se puede cancelar.",
  response_disabled: "Response está desactivado en este servidor.",
  response_blocked: "La política de respuesta bloquea esta acción.",
  confirmation_required: "Esta acción cambia datos: confírmala explícitamente.",
};

// Informes y exportación de evidencias (Fase 5E).
const REPORT_MESSAGES: Record<string, string> = {
  reports_disabled: "La generación de informes está desactivada en este servidor.",
  report_queue_full: "Hay demasiados informes en cola. Inténtalo de nuevo en unos minutos.",
  report_conflict: "La solicitud ha cambiado desde el último intento. Revisa el formulario y vuelve a pulsar Generar.",
  report_not_ready: "El informe aún no está listo para descargar.",
  report_artifact_unavailable: "El fichero del informe ya no está disponible (caducado o borrado).",
  report_integrity_failed: "El fichero del informe no ha superado la comprobación de integridad del servidor.",
  report_invalid_state: "El informe ya no está en un estado que permita esta acción.",
  report_asset_archived: "El activo está archivado: marca «Incluir archivados» para incluirlo en el informe.",
  report_target_not_found: "No se encontró el elemento indicado o no tienes acceso a él.",
};

// Multi-site y sensores (Fase 5F). site_conflict/sensor_conflict: otro admin cambió el site o
// el sensor; la UI recarga antes de reintentar (nunca se sobrescribe en silencio).
const SITE_MESSAGES: Record<string, string> = {
  site_conflict: "Otro administrador ha modificado este site. Se han recargado los datos: revisa y vuelve a intentarlo.",
  site_slug_taken: "Ya existe un site con ese identificador (slug). Elige otro.",
  site_default_protected: "El site por defecto no se puede deshabilitar, archivar ni borrar.",
  site_archived: "El site está archivado: restáuralo antes de editarlo.",
  site_has_data: "El site tiene datos (activos, sensores, jobs o tokens): archívalo en lugar de borrarlo.",
  site_not_found: "El site no existe o ya no está disponible.",
  site_not_active: "El site no está activo (deshabilitado o archivado).",
  site_network_overlap: "La red se solapa con otra red de este mismo site.",
  sensor_conflict: "Otro administrador ha modificado este sensor. Se han recargado los datos: revisa y vuelve a intentarlo.",
  sensor_revoked: "El sensor está revocado: no admite más acciones.",
  sensor_not_found: "El sensor no existe o ya no está disponible.",
  sensor_not_available: "El sensor no está disponible (deshabilitado, revocado, de otro site o sin la capacidad de discovery).",
  site_network_not_found: "La red no existe o ya no está disponible.",
  sensor_enrollment_consumed: "El token ya se usó: revoca el sensor en lugar del token.",
  discovery_local_default_site_only: "El servidor local solo descubre redes del site por defecto: usa un sensor del site.",
};

// Infraestructura de red: SNMP / LLDP / CDP (Fase 6B). *_conflict: otro admin cambió el perfil o
// el equipo; la UI recarga antes de reintentar (nunca se sobrescribe en silencio).
const NETWORK_MESSAGES: Record<string, string> = {
  snmp_profile_not_found: "El perfil SNMP no existe o ya no está disponible.",
  snmp_profile_conflict: "Otro administrador ha modificado este perfil SNMP. Se han recargado los datos: revisa y vuelve a intentarlo.",
  snmp_profile_revoked: "El perfil SNMP está revocado: no admite más cambios ni puede asignarse.",
  snmp_profile_name_taken: "Ya existe un perfil SNMP con ese nombre en este site.",
  snmp_v2c_disabled: "SNMPv2c está deshabilitado en este servidor: usa SNMPv3 (authPriv).",
  snmp_profile_site_mismatch: "El perfil SNMP pertenece a otro site: elige uno del mismo site que el equipo.",
  snmp_secret_store_unavailable:
    "El servidor no tiene configurado el almacén cifrado de secretos: no se pueden guardar credenciales SNMP.",
  network_device_not_found: "El equipo de red no existe o ya no está disponible.",
  network_device_conflict: "Otro administrador ha modificado este equipo. Se han recargado los datos: revisa y vuelve a intentarlo.",
  network_device_exists: "Ya hay un equipo registrado con esa dirección de gestión en este site.",
  network_device_archived: "El equipo está archivado: no admite cambios ni consultas.",
  network_poll_not_found: "La consulta no existe o ya no está disponible.",
  network_poll_unavailable: "No se puede consultar el equipo ahora mismo.",
  network_poll_busy: "Ya hay una consulta en curso para este equipo. Espera a que termine o cancélala.",
  network_poll_open: "Ya hay una consulta abierta para este equipo. Espera a que termine o cancélala.",
  network_poll_finished: "La consulta ya ha terminado y no se puede cancelar.",
};

// Topología de red (Fase 6D). topology_link_conflict: otro admin revisó el enlace; la UI
// recarga antes de reintentar (nunca se sobrescribe en silencio).
const TOPOLOGY_MESSAGES: Record<string, string> = {
  topology_link_conflict: "Otro administrador ha revisado este enlace. Se han recargado los datos: revisa y vuelve a intentarlo.",
  topology_build_running: "Ya hay una reconstrucción de la topología en curso para este site. Espera a que termine.",
  topology_link_not_found: "El enlace no existe o ya no está disponible.",
  topology_node_not_found: "El nodo no existe en este site o ya no está disponible.",
};

// Fase 6E. *_conflict: otro operador cambió el recurso; la UI recarga antes de reintentar
// (nunca se sobrescribe en silencio). evidence_integrity_mismatch lo trata además la vista
// de la investigación: pide aceptar el aviso de forma explícita antes de reintentar.
const PHASE_6E_MESSAGES: Record<string, string> = {
  topology_snapshot_not_found: "El snapshot de topología no existe o ya no está disponible.",
  topology_history_not_found: "No hay historial para ese elemento de la topología.",
  network_change_not_found: "El cambio de red no existe o ya no está disponible.",
  network_change_conflict: "Otro administrador ha revisado este cambio. Se han recargado los datos: revisa y vuelve a intentarlo.",
  topology_rebuild_cooldown: "La topología se reconstruyó hace muy poco. Espera un minuto y vuelve a intentarlo.",
  dhcp_source_not_found: "La fuente DHCP no existe o ya no está disponible.",
  dhcp_source_conflict: "Otro administrador ha modificado esta fuente DHCP. Se han recargado los datos: revisa y vuelve a intentarlo.",
  dhcp_source_name_taken: "Ya existe una fuente DHCP con ese nombre en este site.",
  dhcp_sensor_source_taken: "Ese sensor ya tiene otra fuente con el mismo nombre de fichero.",
  dhcp_source_disabled: "La fuente DHCP está deshabilitada: habilítala antes de importar o leer.",
  dhcp_source_kind: "Esa acción no corresponde al tipo de la fuente (importación manual o fichero del sensor).",
  dhcp_sensor_unavailable: "El sensor no está disponible o su versión no lee ficheros DHCP (requiere 0.6.0 o posterior).",
  dhcp_read_in_progress: "Ya hay una lectura en curso para esta fuente. Espera a que termine.",
  dhcp_file_too_large: "El fichero de concesiones supera el tamaño máximo que admite el servidor.",
  dhcp_format_invalid: "El fichero no se puede leer con el formato de la fuente. Revisa el formato elegido.",
  exclusion_rule_unknown: "La regla indicada no existe o no admite excepciones.",
  exclusion_limit: "Se ha alcanzado el máximo de excepciones activas para esa regla.",
  investigation_not_found: "La investigación no existe o no tienes acceso a ella.",
  investigation_closed: "La investigación está cerrada: reábrela antes de añadir evidencias o notas.",
  investigation_version_conflict: "Otro operador ha modificado esta investigación. Se han recargado los datos: revisa y vuelve a intentarlo.",
  evidence_integrity_mismatch: "Hay evidencias cuyo SHA-256 no coincide con el que calculó el agente.",
  evidence_package_too_large: "El paquete de evidencias supera el tamaño máximo que admite el servidor.",
  evidence_empty: "La investigación no tiene evidencias que empaquetar.",
  isolation_disabled: "El aislamiento está desactivado en este servidor.",
  isolation_unavailable: "Aislamiento no disponible para este dispositivo",
  isolation_active: "El equipo ya tiene una sesión de aislamiento en curso.",
  isolation_confirmation_mismatch: "El nombre escrito no coincide exactamente con el del equipo.",
  isolation_duration_exceeds_policy: "La duración supera el máximo permitido por la política.",
  isolation_state_conflict: "El estado del aislamiento ha cambiado. Se han recargado los datos: revisa y vuelve a intentarlo.",
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
  if (RESPONSE_MESSAGES[code]) return RESPONSE_MESSAGES[code];
  if (REPORT_MESSAGES[code]) return REPORT_MESSAGES[code];
  if (SITE_MESSAGES[code]) return SITE_MESSAGES[code];
  if (NETWORK_MESSAGES[code]) return NETWORK_MESSAGES[code];
  if (TOPOLOGY_MESSAGES[code]) return TOPOLOGY_MESSAGES[code];
  if (PHASE_6E_MESSAGES[code]) return PHASE_6E_MESSAGES[code];
  // Dirección fuera de las redes del site: el detalle (inglés) dice qué dirección y por qué.
  if (code === "network_address_out_of_scope") return `Dirección fuera de las redes autorizadas del site: ${message}`;
  // CIDR rechazado: el detalle (inglés) dice el motivo (host bits, /0, multicast, tamaño...).
  if (code === "site_network_invalid") return `Red no válida: ${message}`;
  if (code === "discovery_target_refused") return `Destino de descubrimiento no válido: ${message}`;
  // Validación de informes (422): el detalle (inglés) dice qué filtro o rango falla.
  if (code === "report_range_too_large" || code === "report_range_invalid") return `Rango no válido: ${message}`;
  if (code === "report_scope_too_large") return `Alcance demasiado grande: ${message}`;
  if (code.startsWith("report_")) return `Solicitud de informe no válida: ${message}`;
  // Parámetros o definición de playbook inválidos: el detalle (inglés) dice qué corregir.
  if (code === "response_invalid_parameters") return `Parámetros no válidos: ${message}`;
  if (code.startsWith("playbook_")) return `Playbook no válido: ${message}`;
  // El motivo (inglés) dice qué referencia falla; se conserva tras un prefijo en español.
  if (code === "incident_invalid_reference") return `Referencia no válida: ${message}`;
  // Fase 7A.8: el detalle (inglés) dice qué condición de la política falta; se explica en español.
  if (code === "exclusion_too_broad") return explainTooBroad(message);
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

/**
 * Error lanzado por fetch() antes de recibir cabeceras. Una cancelación (AbortError) se
 * propaga tal cual para que la UI la ignore; un plazo vencido (AbortSignal.timeout →
 * TimeoutError) se distingue de "API no disponible" porque el remedio es distinto.
 */
function fetchFailure(error: unknown): unknown {
  if (error instanceof DOMException && error.name === "AbortError") return error;
  if (error instanceof DOMException && error.name === "TimeoutError") {
    return new ApiError(0, "timeout", "La API de Sentra no respondió a tiempo.");
  }
  return new ApiError(0, "network_error", "No se pudo conectar con la API de Sentra");
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

type Method = "GET" | "POST" | "PATCH" | "DELETE";

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
    throw fetchFailure(error);
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

export function apiDelete<T>(path: string, options: RequestOptions = {}): Promise<T> {
  return request<T>("DELETE", path, undefined, options);
}

/** Fichero descargado de la API (p. ej. el artefacto de un informe, Fase 5E). */
export interface DownloadedFile {
  /** Los bytes recibidos como Blob, listo para guardarse con un enlace temporal. */
  blob: Blob;
  /**
   * Los mismos bytes, leídos directamente de la respuesta. El SHA-256 se calcula sobre ellos:
   * releer un Blob depende de que implemente arrayBuffer() (con Node >= 24 y jsdom no siempre)
   * y antes un fallo ahí acababa en un aviso de error aunque la descarga era correcta.
   */
  bytes: Uint8Array<ArrayBuffer>;
  /** Nombre de Content-Disposition, si el servidor lo envía (y es seguro). */
  filename: string | undefined;
  /** Cabecera X-Sentra-SHA256 (hex), si el servidor la envía. */
  sha256: string | undefined;
}

function filenameFromDisposition(header: string | null): string | undefined {
  if (!header) return undefined;
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(header);
  if (!match) return undefined;
  let name = match[1] ?? "";
  try {
    name = decodeURIComponent(name);
  } catch {
    // Nombre sin codificar: se usa tal cual.
  }
  // Nunca rutas: solo el nombre del fichero.
  return name.split(/[\\/]/).pop() || undefined;
}

interface DownloadOptions {
  signal?: AbortSignal;
  /** POST cuando la descarga deja registro en el servidor (paquete de evidencias, Fase 6E.6). */
  method?: "GET" | "POST";
  body?: unknown;
}

/**
 * Descarga binaria con la cookie de sesión. Devuelve el contenido como bytes y Blob; quien
 * llama decide cómo guardarlo (nunca se interpreta ni se inserta en la página).
 */
export async function apiDownload(path: string, { signal, method = "GET", body }: DownloadOptions = {}): Promise<DownloadedFile> {
  const headers: Record<string, string> = { Accept: "*/*" };
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    if (csrfToken) headers[CSRF_HEADER] = csrfToken;
  }
  let response: Response;
  try {
    response = await fetch(`${config.apiBaseUrl}/api/v1${path}`, {
      method,
      headers,
      body: method === "GET" ? undefined : JSON.stringify(body ?? {}),
      cache: "no-store",
      credentials: "include",
      signal,
    });
  } catch (error) {
    throw fetchFailure(error);
  }
  if (!response.ok) {
    const error = await parseError(response);
    if (response.status === 401) unauthorizedHandler?.();
    throw error;
  }
  // Fase 6D.6: el cuerpo llega DESPUÉS de las cabeceras. Si la conexión se corta a mitad
  // (proxy que cierra, servidor que cae, red), la lectura rechaza con un TypeError genérico; se
  // distingue de "API no disponible": el servidor sí respondió.
  let bytes: Uint8Array<ArrayBuffer>;
  try {
    bytes = new Uint8Array(await response.arrayBuffer());
  } catch (error) {
    if (signal?.aborted || (error instanceof DOMException && error.name === "AbortError")) {
      throw new DOMException("Descarga cancelada", "AbortError");
    }
    throw new ApiError(
      response.status,
      "download_interrupted",
      "La descarga se interrumpió antes de completarse (conexión cortada). El fichero no se ha guardado: vuelve a intentarlo.",
    );
  }
  const type = response.headers.get("Content-Type") ?? "application/octet-stream";
  return {
    blob: new Blob([bytes], { type }),
    bytes,
    filename: filenameFromDisposition(response.headers.get("Content-Disposition")),
    sha256: response.headers.get("X-Sentra-SHA256")?.trim().toLowerCase() || undefined,
  };
}
