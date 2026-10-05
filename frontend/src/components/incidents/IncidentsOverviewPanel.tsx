// Vista SOC compacta para el dashboard (Fase 4K): cuántos casos hay en cada fase y la
// actividad reciente. No es un KPI de MTTR ni un SLA: solo recuentos observados.
import { useCallback } from "react";
import { Link } from "react-router-dom";
import { incidentsApi } from "../../api/sentra";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import { formatDateTime, formatRelative } from "../../lib/format";
import { ACTION_LABELS } from "../../lib/incidents";
import { usePolling } from "../../lib/usePolling";

export function IncidentsOverviewPanel() {
  const auth = useAuth();
  const allowed = auth.can("incidents:read");
  const fetchOverview = useCallback((signal: AbortSignal) => incidentsApi.overview(signal), []);
  const { data } = usePolling(fetchOverview, config.refreshIntervalMs, allowed);
  if (!allowed || !data) return null;
  const active = data.open + data.triage + data.investigating + data.contained;
  return (
    <section className="panel" aria-label="Incidentes activos">
      <div className="panel__toolbar">
        <h2>Incidentes activos</h2>
        <span className="muted small">
          {active} activos · {data.open} abiertos · {data.triage} en triage · {data.investigating} investigando ·{" "}
          {data.contained} contenidos · {data.critical} críticos · {data.unassigned} sin asignar
        </span>
        <Link to="/incidents" className="small">
          Ver incidentes
        </Link>
      </div>
      {data.recent_activity.length > 0 && (
        <div className="table-wrap">
          <table className="table table--compact">
            <tbody>
              {data.recent_activity.slice(0, 5).map((item, index) => (
                <tr key={`${item.incident_id}-${item.occurred_at}-${index}`}>
                  <td title={formatDateTime(item.occurred_at)}>{formatRelative(item.occurred_at)}</td>
                  <td>
                    <Link to={`/incidents/${item.incident_id}`} className="incident-key">
                      {item.incident_key}
                    </Link>
                  </td>
                  <td>{ACTION_LABELS[item.action] ?? item.action}</td>
                  <td className="muted">{item.summary}</td>
                  <td className="muted small">{item.actor}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
