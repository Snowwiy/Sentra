import { useCallback, useEffect, useRef, useState } from "react";

type Fetcher<T> = (signal: AbortSignal) => Promise<T>;

export interface PollingState<T> {
  data: T | undefined;
  error: Error | undefined;
  /** True until the first response (success or failure) for the current fetcher arrives. */
  loading: boolean;
  refreshing: boolean;
  updatedAt: Date | undefined;
  refresh: () => void;
}

interface Result<T> {
  /** Fetcher that produced this result; a new fetcher (e.g. another asset id) starts fresh. */
  source: Fetcher<T>;
  data?: T;
  error?: Error;
  updatedAt?: Date;
}

/**
 * Runs `fetcher` now and every `intervalMs` while the tab is visible.
 * The last good data is kept when a later refresh fails, so callers can show it as stale.
 * `fetcher` must be memoized (useCallback); changing it restarts polling.
 */
export function usePolling<T>(fetcher: Fetcher<T>, intervalMs: number): PollingState<T> {
  const [result, setResult] = useState<Result<T>>();
  const [refreshing, setRefreshing] = useState(false);
  const controllerRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setRefreshing(true);
    try {
      const data = await fetcher(controller.signal);
      setResult({ source: fetcher, data, updatedAt: new Date() });
    } catch (err) {
      if (controller.signal.aborted) return;
      const error = err instanceof Error ? err : new Error(String(err));
      setResult((prev) =>
        prev?.source === fetcher ? { ...prev, error } : { source: fetcher, error },
      );
    } finally {
      if (!controller.signal.aborted) setRefreshing(false);
    }
  }, [fetcher]);

  useEffect(() => {
    // Background tabs skip polling to avoid hammering the API, but the first load
    // always runs so a page opened in a background tab is not stuck on "loading".
    const tick = () => {
      if (document.visibilityState === "visible") void load();
    };
    // Deferred so no state update happens synchronously inside the effect.
    const initial = window.setTimeout(() => void load(), 0);
    const timer = window.setInterval(tick, intervalMs);
    document.addEventListener("visibilitychange", tick);

    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", tick);
      controllerRef.current?.abort();
    };
  }, [load, intervalMs]);

  const refresh = useCallback(() => void load(), [load]);
  const current = result?.source === fetcher ? result : undefined;

  return {
    data: current?.data,
    error: current?.error,
    loading: current === undefined,
    refreshing,
    updatedAt: current?.updatedAt,
    refresh,
  };
}
