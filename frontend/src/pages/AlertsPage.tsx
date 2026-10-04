import { useCallback, useState } from "react";
import { sentraApi } from "../api/sentra";
import type { AlertStatus } from "../api/types";
import { AlertTable } from "../components/AlertTable";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { errorMessage } from "../lib/format";
import { usePolling } from "../lib/usePolling";

type Filter = AlertStatus | "all";

const FILTERS: { key: Filter; label: string }[] = [
  { key: "open", label: "Abiertas" },
  { key: "resolved", label: "Resueltas" },
  { key: "all", label: "Todas" },
];

export function AlertsPage() {
  const [filter, setFilter] = useState<Filter>("open");
  const fetchAlerts = useCallback(
    (signal: AbortSignal) =>
      sentraApi.listAlerts({ status: filter === "all" ? undefined : filter, limit: 200 }, signal),
    [filter],
  );
  const { data, error, loading, refresh } = usePolling(fetchAlerts, config.refreshIntervalMs);

  return (
    <div className="page">
      <div className="page__header">
        <h1>Alertas</h1>
        <div className="segmented" role="group" aria-label="Filtrar alertas">
          {FILTERS.map(({ key, label }) => (
            <button
              key={key}
              type="button"
              className={`segmented__item${filter === key ? " segmented__item--active" : ""}`}
              aria-pressed={filter === key}
              onClick={() => setFilter(key)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {error && data && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      <section className="panel">
        {loading ? (
          <LoadingState label="Cargando alertas…" />
        ) : !data && error ? (
          <ErrorState message={errorMessage(error)} onRetry={refresh} />
        ) : data && data.items.length > 0 ? (
          <AlertTable alerts={data.items} />
        ) : (
          <EmptyState title={filter === "open" ? "Sin alertas abiertas" : "Sin alertas"}>
            Las alertas se generan por activos offline y por CPU, RAM o disco por encima del umbral.
          </EmptyState>
        )}
      </section>
    </div>
  );
}
