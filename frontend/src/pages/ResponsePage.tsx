import { useCallback } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { responseApi } from "../api/sentra";
import { config } from "../config";
import { ActionsCatalog } from "../components/response/ActionsCatalog";
import { GenerateReportLink } from "../components/reports/GenerateReportLink";
import { ExecutionsTable } from "../components/response/HistoryTables";
import { usePolling } from "../lib/usePolling";

const TABS = [
  { key: "actions", label: "Acciones" },
  { key: "executions", label: "Ejecuciones" },
] as const;
type Tab = (typeof TABS)[number]["key"];

function ExecutionsTab() {
  const [params, setParams] = useSearchParams();
  // El catálogo solo da nombres al filtro de acción; si falla, el filtro no aparece.
  const fetcher = useCallback((signal: AbortSignal) => responseApi.actions(undefined, signal), []);
  const catalog = usePolling(fetcher, config.refreshIntervalMs * 10);
  const actionOptions = (catalog.data?.items ?? [])
    .filter((a) => a.availability === "available")
    .map((a) => ({ value: a.id, label: a.name }));
  return (
    <ExecutionsTable
      actionOptions={actionOptions}
      selected={params.get("execution") ?? undefined}
      onSelect={(id) => setParams(id ? { tab: "executions", execution: id } : { tab: "executions" }, { replace: true })}
    />
  );
}

/** Response Engine (Fase 5D): catálogo de acciones permitidas e historial de ejecuciones. */
export function ResponsePage() {
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab");
  const tab: Tab = TABS.some((t) => t.key === requested) ? (requested as Tab) : "actions";
  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Response</h1>
          <p className="muted small">
            Acciones de respuesta de una lista cerrada (nunca comandos libres). Cada ejecución se previsualiza, se
            comprueba con la política del servidor y queda auditada. Ver también los{" "}
            <Link to="/playbooks">playbooks</Link>.
          </p>
        </div>
        <div className="actions">
          <GenerateReportLink type="response_activity" label="Exportar actividad" />
        </div>
      </div>
      <nav className="tabs" role="tablist" aria-label="Secciones de response">
        {TABS.map(({ key, label }) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={`tabs__item${tab === key ? " tabs__item--active" : ""}`}
            onClick={() => setParams(key === "actions" ? {} : { tab: key }, { replace: true })}
          >
            {label}
          </button>
        ))}
      </nav>
      <div role="tabpanel">
        {tab === "actions" && <ActionsCatalog />}
        {tab === "executions" && <ExecutionsTab />}
      </div>
    </div>
  );
}
