import { apiGet } from "./client";
import type {
  AlertList,
  AlertStatus,
  Asset,
  AssetList,
  EventLevel,
  EventList,
  Health,
  Inventory,
  TelemetryHistory,
} from "./types";

export interface AlertQuery {
  status?: AlertStatus;
  assetId?: string;
  limit?: number;
}

function alertQuery({ status, assetId, limit }: AlertQuery): string {
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  if (assetId) params.set("asset_id", assetId);
  if (limit) params.set("limit", String(limit));
  const query = params.toString();
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
      `/assets/${encodeURIComponent(assetId)}/telemetry?limit=${limit}`,
      { signal },
    ),
  getInventory: (assetId: string, signal?: AbortSignal) =>
    apiGet<Inventory>(`/assets/${encodeURIComponent(assetId)}/inventory`, { signal }),
  listEvents: (
    query: { assetId?: string; minLevel?: EventLevel; limit?: number },
    signal?: AbortSignal,
  ) => {
    const params = new URLSearchParams();
    if (query.assetId) params.set("asset_id", query.assetId);
    if (query.minLevel) params.set("min_level", query.minLevel);
    if (query.limit) params.set("limit", String(query.limit));
    const qs = params.toString();
    return apiGet<EventList>(`/events${qs ? `?${qs}` : ""}`, { signal });
  },
  listAlerts: (query: AlertQuery, signal?: AbortSignal) =>
    apiGet<AlertList>(`/alerts${alertQuery(query)}`, { signal }),
};
