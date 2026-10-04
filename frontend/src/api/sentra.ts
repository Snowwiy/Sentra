import { apiGet } from "./client";
import type {
  Alert,
  AlertList,
  AlertRule,
  AlertSeverity,
  AlertStatus,
  Asset,
  AssetList,
  ChangeCategory,
  ChangeList,
  EventLevel,
  EventList,
  Health,
  Inventory,
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
  listAssets: (signal?: AbortSignal) => apiGet<AssetList>("/assets", { signal }),
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
  getAlert: (alertId: string, signal?: AbortSignal) =>
    apiGet<Alert>(`/alerts/${encodeURIComponent(alertId)}`, { signal }),
};
