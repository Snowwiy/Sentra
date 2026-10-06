import { useCallback } from "react";
import { sentraApi } from "../api/sentra";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import { usePolling } from "../lib/usePolling";

// Nombres legibles de las comprobaciones de /health/ready.
const CHECK_LABELS: Record<string, string> = {
  api: "API",
  database: "base de datos",
  migrations: "esquema",
};

export function HealthIndicator() {
  // Fase 4M: /health/ready (listo para atender: base de datos y esquema al día). La IA no
  // cuenta: sin modelo local Sentra sigue operativo.
  const fetchReady = useCallback((signal: AbortSignal) => sentraApi.readiness(signal), []);
  const { data, error, loading } = usePolling(fetchReady, config.refreshIntervalMs);
  const { serverVersion } = useAuth();

  let tone: "ok" | "warn" | "crit" | "idle" = "idle";
  let label = "Comprobando API…";
  let detail = "";

  if (error) {
    tone = "crit";
    label = "API no disponible";
    detail = error.message;
  } else if (data) {
    tone = data.status === "ready" ? "ok" : "warn";
    label = data.status === "ready" ? "API operativa" : "API degradada";
    detail = Object.entries(data.checks)
      .map(([name, status]) => `${CHECK_LABELS[name] ?? name}: ${status}`)
      .join(" · ");
  } else if (!loading) {
    tone = "crit";
    label = "API no disponible";
  }

  return (
    <span className={`health health--${tone}`} title={detail || undefined}>
      <span className="health__dot" aria-hidden="true" />
      {label}
      {serverVersion && <span className="health__version">v{serverVersion}</span>}
    </span>
  );
}
