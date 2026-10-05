import { apiGet, apiPatch, apiPost } from "./client";
import type {
  Agent,
  AgentList,
  Alert,
  AlertList,
  AlertRule,
  AlertSeverity,
  AlertStatus,
  Asset,
  AssetList,
  AssetStatus,
  AuditEventList,
  AuthState,
  ChangeCategory,
  ChangeList,
  ConsoleInfo,
  DiscoveryJobDetail,
  DiscoveryJobList,
  DiscoverySchedule,
  DiscoveryScope,
  EventLevel,
  EnrollmentToken,
  EnrollmentTokenCreated,
  EnrollmentTokenList,
  EnrollmentTokenRequest,
  EventList,
  Exposure,
  Health,
  Inventory,
  MonitoringMethod,
  ProcessSnapshot,
  Role,
  TelemetryHistory,
  User,
  UserList,
} from "./types";

export interface AlertQuery {
  status?: AlertStatus;
  /** Open or acknowledged; ignored when `status` is set. */
  active?: boolean;
  severity?: AlertSeverity;
  rule?: AlertRule;
  assetId?: string;
  /** Text in the message or hostname. */
  q?: string;
  limit?: number;
  offset?: number;
}

export interface AssetQuery {
  method?: MonitoringMethod;
  status?: AssetStatus;
  /** A device type, or "unknown". */
  deviceType?: string;
  /** CIDR, e.g. 192.168.1.0/24. */
  subnet?: string;
  q?: string;
}

export interface EventQuery {
  assetId?: string;
  minLevel?: EventLevel;
  channel?: string;
  /** Text in the message or provider. */
  q?: string;
  limit?: number;
  offset?: number;
}

/** `?a=1&b=2` from the parameters that are set (unset, empty, 0 or false are left out), or "". */
function queryString(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (typeof value === "string" ? value.trim() : value) search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}

export const sentraApi = {
  // /health answers 503 with a valid body when degraded; that is data, not a failure.
  health: (signal?: AbortSignal) => apiGet<Health>("/health", { signal, acceptStatuses: [503] }),
  listAssets: (signal?: AbortSignal, query: AssetQuery = {}) =>
    apiGet<AssetList>(
      `/assets${queryString({
        method: query.method,
        status: query.status,
        device_type: query.deviceType,
        subnet: query.subnet,
        q: query.q,
      })}`,
      { signal },
    ),
  getAsset: (assetId: string, signal?: AbortSignal) =>
    apiGet<Asset>(`/assets/${encodeURIComponent(assetId)}`, { signal }),
  getTelemetry: (assetId: string, limit: number, signal?: AbortSignal) =>
    apiGet<TelemetryHistory>(
      `/assets/${encodeURIComponent(assetId)}/telemetry${queryString({ limit })}`,
      { signal },
    ),
  getInventory: (assetId: string, signal?: AbortSignal) =>
    apiGet<Inventory>(`/assets/${encodeURIComponent(assetId)}/inventory`, { signal }),
  getProcesses: (assetId: string, signal?: AbortSignal) =>
    apiGet<ProcessSnapshot>(`/assets/${encodeURIComponent(assetId)}/processes`, { signal }),
  getChanges: (
    assetId: string,
    query: { category?: ChangeCategory; limit?: number; offset?: number },
    signal?: AbortSignal,
  ) =>
    apiGet<ChangeList>(
      `/assets/${encodeURIComponent(assetId)}/changes${queryString({ ...query })}`,
      { signal },
    ),
  listEvents: ({ assetId, minLevel, channel, q, limit, offset }: EventQuery, signal?: AbortSignal) =>
    apiGet<EventList>(
      `/events${queryString({ asset_id: assetId, min_level: minLevel, channel, q, limit, offset })}`,
      { signal },
    ),
  listAlerts: (
    { status, active, severity, rule, assetId, q, limit, offset }: AlertQuery,
    signal?: AbortSignal,
  ) =>
    apiGet<AlertList>(
      `/alerts${queryString({ status, active, severity, rule, asset_id: assetId, q, limit, offset })}`,
      { signal },
    ),
  getExposure: (assetId: string, signal?: AbortSignal) =>
    apiGet<Exposure>(`/assets/${encodeURIComponent(assetId)}/exposure`, { signal }),
  discoveryScope: (signal?: AbortSignal) => apiGet<DiscoveryScope>("/discovery/scope", { signal }),
  discoveryJobs: (limit: number, signal?: AbortSignal) =>
    apiGet<DiscoveryJobList>(`/discovery/jobs${queryString({ limit })}`, { signal }),
  discoveryJob: (jobId: string, signal?: AbortSignal) =>
    apiGet<DiscoveryJobDetail>(`/discovery/jobs/${encodeURIComponent(jobId)}`, { signal }),
  discoverySchedule: (signal?: AbortSignal) =>
    apiGet<DiscoverySchedule>("/discovery/schedule", { signal }),
  getAlert: (alertId: string, signal?: AbortSignal) =>
    apiGet<Alert>(`/alerts/${encodeURIComponent(alertId)}`, { signal }),
  listAgents: (signal?: AbortSignal) => apiGet<AgentList>("/agents", { signal }),
  getAssetAgent: (assetId: string, signal?: AbortSignal) =>
    apiGet<Agent>(`/assets/${encodeURIComponent(assetId)}/agent`, { signal }),
};

/**
 * Gestión de agentes desde el dashboard (/console): la API exige sesión y el permiso
 * correspondiente (enrollment:manage, agents:manage, discovery:run). No hay ninguna clave de
 * administración en el frontend. El token de `createEnrollmentToken` solo existe en esa
 * respuesta: nunca se guarda ni se registra.
 */
export const consoleApi = {
  info: (signal?: AbortSignal) => apiGet<ConsoleInfo>("/console", { signal }),
  listEnrollmentTokens: (signal?: AbortSignal) =>
    apiGet<EnrollmentTokenList>("/console/enrollment-tokens", { signal }),
  createEnrollmentToken: (request: EnrollmentTokenRequest) =>
    apiPost<EnrollmentTokenCreated>("/console/enrollment-tokens", request),
  revokeEnrollmentToken: (tokenId: string) =>
    apiPost<EnrollmentToken>(`/console/enrollment-tokens/${encodeURIComponent(tokenId)}/revoke`),
  revokeAgent: (assetId: string) =>
    apiPost<Agent>(`/console/agents/${encodeURIComponent(assetId)}/revoke`),
  reinstateAgent: (assetId: string) =>
    apiPost<Agent>(`/console/agents/${encodeURIComponent(assetId)}/reinstate`),
  // Descubrimiento de red: el backend vuelve a validar el target contra
  // DISCOVERY_ALLOWED_NETWORKS; la lista del frontend es solo una comodidad.
  startDiscovery: (target: string) =>
    apiPost<DiscoveryJobDetail>("/console/discovery/jobs", { target }),
  cancelDiscovery: (jobId: string) =>
    apiPost<DiscoveryJobDetail>(`/console/discovery/jobs/${encodeURIComponent(jobId)}/cancel`),
};

/** Acciones sobre alertas (permiso alerts:manage). */
export const alertsApi = {
  acknowledge: (alertId: string) =>
    apiPost<Alert>(`/alerts/${encodeURIComponent(alertId)}/acknowledge`),
  resolve: (alertId: string) => apiPost<Alert>(`/alerts/${encodeURIComponent(alertId)}/resolve`),
};

/**
 * Sesión del dashboard. La contraseña solo pasa por `login`/`changePassword` y no se guarda
 * en ningún sitio; la cookie de sesión la gestiona el navegador.
 */
export const authApi = {
  // skipUnauthorized: un 401 aquí es "credenciales incorrectas" o "sin sesión", no una
  // sesión que caduca a mitad de uso.
  login: (username: string, password: string) =>
    apiPost<AuthState>("/auth/login", { username, password }, { skipUnauthorized: true }),
  me: (signal?: AbortSignal) => apiGet<AuthState>("/auth/me", { signal, skipUnauthorized: true }),
  logout: () => apiPost<void>("/auth/logout", undefined, { skipUnauthorized: true }),
};

/** Administración de usuarios y auditoría (users:manage, audit:read: solo admin). */
export const usersApi = {
  list: (signal?: AbortSignal) => apiGet<UserList>("/users", { signal }),
  create: (username: string, password: string, role: Role) =>
    apiPost<User>("/users", { username, password, role }),
  update: (userId: string, change: { role?: Role; is_active?: boolean }) =>
    apiPatch<User>(`/users/${encodeURIComponent(userId)}`, change),
  resetPassword: (userId: string, newPassword: string) =>
    apiPost<User>(`/users/${encodeURIComponent(userId)}/password`, { new_password: newPassword }),
  revokeSessions: (userId: string) =>
    apiPost<User>(`/users/${encodeURIComponent(userId)}/sessions/revoke`),
  audit: (limit: number, signal?: AbortSignal) =>
    apiGet<AuditEventList>(`/audit?limit=${limit}`, { signal }),
};
