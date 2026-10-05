import { Fragment, useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { alertsApi, sentraApi } from "../api/sentra";
import { useAuth } from "../auth/AuthContext";
import type { Alert, AlertRule, AlertSeverity, AlertStatus } from "../api/types";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { useDebounced } from "../lib/useDebounced";
import { usePolling } from "../lib/usePolling";
import { RULE_LABELS, SeverityBadge } from "./AlertTable";
import { FilterSelect, Pager, SearchInput, Toolbar } from "./ListControls";
import { EmptyState, ErrorState, LoadingState } from "./StateViews";

const PAGE_SIZE = 50;

type StatusFilter = "active" | AlertStatus | "all";

const STATUS_FILTERS: { key: StatusFilter; label: string }[] = [
  { key: "active", label: "Activas" },
  { key: "open", label: "Abiertas" },
  { key: "acknowledged", label: "Reconocidas" },
  { key: "resolved", label: "Resueltas" },
  { key: "all", label: "Todas" },
];

const SEVERITIES: { value: AlertSeverity; label: string }[] = [
  { value: "critical", label: "Critical" },
  { value: "warning", label: "Warning" },
  { value: "info", label: "Info" },
];

function StatusCell({ alert }: { alert: Alert }) {
  if (alert.status === "open") return <span className="alert-state alert-state--open">Abierta</span>;
  if (alert.status === "acknowledged") {
    return (
      <span className="alert-state" title={formatDateTime(alert.acknowledged_at)}>
        Reconocida
      </span>
    );
  }
  return (
    <span className="muted" title={formatDateTime(alert.resolved_at)}>
      Resuelta {formatRelative(alert.resolved_at)}
    </span>
  );
}

/**
 * Reconocer / resolver (permiso alerts:manage: admin y analyst). Para un viewer no se
 * muestra nada; aun así el backend rechazaría la acción con 403.
 */
function AlertActions({ alert, onChanged }: { alert: Alert; onChanged: () => void }) {
  const auth = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  if (!auth.can("alerts:manage") || alert.status === "resolved") return null;

  async function run(action: (id: string) => Promise<Alert>) {
    setBusy(true);
    setError(undefined);
    try {
      await action(alert.alert_id);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="actions alert-detail__actions">
      {alert.status === "open" && (
        <button type="button" className="button" disabled={busy} onClick={() => void run(alertsApi.acknowledge)}>
          Reconocer
        </button>
      )}
      <button
        type="button"
        className="button button--primary"
        disabled={busy}
        onClick={() => void run(alertsApi.resolve)}
      >
        Resolver
      </button>
      {error && (
        <span className="banner banner--warn" role="alert">
          {error}
        </span>
      )}
    </div>
  );
}

function AlertDetail({ alert, onChanged }: { alert: Alert; onChanged: () => void }) {
  return (
    <div className="alert-detail">
      <dl className="fields">
        <div className="field">
          <dt>Abierta</dt>
          <dd>{formatDateTime(alert.opened_at)}</dd>
        </div>
        <div className="field">
          <dt>Ocurrencias</dt>
          <dd>
            {alert.occurrences}
            {alert.last_triggered_at && (
              <span className="muted"> · última {formatRelative(alert.last_triggered_at)}</span>
            )}
          </dd>
        </div>
        <div className="field">
          <dt>Reconocida</dt>
          <dd>{formatDateTime(alert.acknowledged_at)}</dd>
        </div>
        <div className="field">
          <dt>Resuelta</dt>
          <dd>{formatDateTime(alert.resolved_at)}</dd>
        </div>
      </dl>
      {alert.details && <pre className="details-json">{JSON.stringify(alert.details, null, 2)}</pre>}
      <AlertActions alert={alert} onChanged={onChanged} />
    </div>
  );
}

export function AlertsView({ assetId }: { assetId?: string }) {
  const [status, setStatus] = useState<StatusFilter>("active");
  const [severity, setSeverity] = useState("");
  const [rule, setRule] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<string | null>(null);
  const q = useDebounced(query);

  const fetchAlerts = useCallback(
    (signal: AbortSignal) =>
      sentraApi.listAlerts(
        {
          assetId,
          active: status === "active",
          status: status === "active" || status === "all" ? undefined : status,
          severity: (severity || undefined) as AlertSeverity | undefined,
          rule: (rule || undefined) as AlertRule | undefined,
          q,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      ),
    [assetId, status, severity, rule, q, page],
  );
  const { data, error, loading, refresh } = usePolling(fetchAlerts, config.refreshIntervalMs);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE));
  const reset = <T,>(set: (v: T) => void) => (value: T) => {
    set(value);
    setPage(1);
  };

  return (
    <section className="panel">
      <Toolbar>
        <div className="segmented" role="group" aria-label="Filtrar por estado">
          {STATUS_FILTERS.map(({ key, label }) => (
            <button
              key={key}
              type="button"
              className={`segmented__item${status === key ? " segmented__item--active" : ""}`}
              aria-pressed={status === key}
              onClick={() => reset(setStatus)(key)}
            >
              {label}
            </button>
          ))}
        </div>
        <FilterSelect label="Severidad" value={severity} options={SEVERITIES} onChange={reset(setSeverity)} allLabel="Todas" />
        <FilterSelect
          label="Regla"
          value={rule}
          options={Object.entries(RULE_LABELS).map(([value, label]) => ({ value, label }))}
          onChange={reset(setRule)}
          allLabel="Todas"
        />
        <SearchInput value={query} onChange={reset(setQuery)} placeholder="Buscar en mensaje o activo" label="Buscar alertas" />
      </Toolbar>
      {error && data && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}
      {loading ? (
        <LoadingState label="Cargando alertas…" />
      ) : !data && error ? (
        <ErrorState message={errorMessage(error)} onRetry={refresh} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="Sin alertas para este filtro">
          Las alertas se generan por activos offline, CPU/RAM sostenidas, disco, servicios vigilados detenidos,
          eventos críticos, ráfagas de errores y cambios de administradores.
        </EmptyState>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Severidad</th>
                  <th>Regla</th>
                  {!assetId && <th>Activo</th>}
                  <th>Detalle</th>
                  <th>Abierta</th>
                  <th>Veces</th>
                  <th>Estado</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((alert) => (
                  <Fragment key={alert.alert_id}>
                    <tr
                      className="table__row--link"
                      aria-expanded={expanded === alert.alert_id}
                      onClick={() => setExpanded(expanded === alert.alert_id ? null : alert.alert_id)}
                    >
                      <td>
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td>{RULE_LABELS[alert.rule]}</td>
                      {!assetId && (
                        <td>
                          <Link to={`/assets/${alert.asset_id}`} className="strong" onClick={(e) => e.stopPropagation()}>
                            {alert.hostname}
                          </Link>
                        </td>
                      )}
                      <td className="muted event-message-cell">{alert.message}</td>
                      <td title={formatDateTime(alert.opened_at)}>{formatRelative(alert.opened_at)}</td>
                      <td className="mono">{alert.occurrences}</td>
                      <td>
                        <StatusCell alert={alert} />
                      </td>
                    </tr>
                    {expanded === alert.alert_id && (
                      <tr className="table__row--detail">
                        <td colSpan={assetId ? 6 : 7}>
                          <AlertDetail alert={alert} onChanged={refresh} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={Math.min(page, pages)} pages={pages} total={data.total} onPage={setPage} noun="alertas" />
        </>
      )}
    </section>
  );
}
