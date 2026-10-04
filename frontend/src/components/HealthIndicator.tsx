import { useCallback } from "react";
import { sentraApi } from "../api/sentra";
import { config } from "../config";
import { usePolling } from "../lib/usePolling";

export function HealthIndicator() {
  const fetchHealth = useCallback((signal: AbortSignal) => sentraApi.health(signal), []);
  const { data, error, loading } = usePolling(fetchHealth, config.refreshIntervalMs);

  let tone: "ok" | "warn" | "crit" | "idle" = "idle";
  let label = "Comprobando API…";
  let detail = "";

  if (error) {
    tone = "crit";
    label = "API no disponible";
    detail = error.message;
  } else if (data) {
    tone = data.status === "ok" ? "ok" : "warn";
    label = data.status === "ok" ? "API operativa" : "API degradada";
    detail = Object.entries(data.checks)
      .map(([name, status]) => `${name}: ${status}`)
      .join(" · ");
  } else if (!loading) {
    tone = "crit";
    label = "API no disponible";
  }

  return (
    <span className={`health health--${tone}`} title={detail || undefined}>
      <span className="health__dot" aria-hidden="true" />
      {label}
      {data?.version && <span className="health__version">v{data.version}</span>}
    </span>
  );
}
