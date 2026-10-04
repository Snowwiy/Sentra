const MIN_REFRESH_SECONDS = 5;
const DEFAULT_REFRESH_SECONDS = 15;

function refreshIntervalMs(): number {
  const seconds = Number(import.meta.env.VITE_REFRESH_INTERVAL_SECONDS);
  if (!Number.isFinite(seconds) || seconds <= 0) return DEFAULT_REFRESH_SECONDS * 1000;
  return Math.max(seconds, MIN_REFRESH_SECONDS) * 1000;
}

export const config = {
  /** Empty means same origin; in development Vite proxies /api to the backend. */
  apiBaseUrl: (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, ""),
  refreshIntervalMs: refreshIntervalMs(),
} as const;
