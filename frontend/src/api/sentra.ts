import { apiGet, apiPost } from "./client";
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
  TelemetryHistory,
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
 * Agent administration through the dashboard console. The API performs these itself and
 * answers only a browser on the Sentra server (no admin key in the frontend). The token in
 * `createEnrollmentToken`'s answer exists only there: never store or log it.
 */
export const consoleApi = {
  info: (signal?: AbortSignal) => apiGet<ConsoleInfo>("/console", { signal, console: true }),
  listEnrollmentTokens: (signal?: AbortSignal) =>
    apiGet<EnrollmentTokenList>("/console/enrollment-tokens", { signal, console: true }),
  createEnrollmentToken: (request: EnrollmentTokenRequest) =>
    apiPost<EnrollmentTokenCreated>("/console/enrollment-tokens", request, { console: true }),
  revokeEnrollmentToken: (tokenId: string) =>
    apiPost<EnrollmentToken>(
      `/console/enrollment-tokens/${encodeURIComponent(tokenId)}/revoke`,
      undefined,
      { console: true },
    ),
  revokeAgent: (assetId: string) =>
    apiPost<Agent>(`/console/agents/${encodeURIComponent(assetId)}/revoke`, undefined, {
      console: true,
    }),
  reinstateAgent: (assetId: string) =>
    apiPost<Agent>(`/console/agents/${encodeURIComponent(assetId)}/reinstate`, undefined, {
      console: true,
    }),
  // Descubrimiento de red: el backend vuelve a validar el target contra
  // DISCOVERY_ALLOWED_NETWORKS; la lista del frontend es solo una comodidad.
  startDiscovery: (target: string) =>
    apiPost<DiscoveryJobDetail>("/console/discovery/jobs", { target }, { console: true }),
  cancelDiscovery: (jobId: string) =>
    apiPost<DiscoveryJobDetail>(
      `/console/discovery/jobs/${encodeURIComponent(jobId)}/cancel`,
      undefined,
      { console: true },
    ),
};
