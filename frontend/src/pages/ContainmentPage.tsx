import { useCallback } from "react";
import { Link } from "react-router-dom";
import { isolationApi } from "../api/sentra6e";
import { IsolationStatusBadge } from "../components/isolation/IsolationTab";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { usePolling } from "../lib/usePolling";

// Las sesiones vivas cambian de estado en segundos (aplicando, aislado, revirtiendo).
const REFRESH_MS = 10_000;

/**
 * Sesiones de aislamiento vivas de todos los activos (Fase 6E.7). Solo lectura
 * (containment:preview): aislar y liberar se hace desde la pestaña Aislamiento de cada activo,
 * con su confirmación escrita.
 */
export function ContainmentPage() {
  const fetchSessions = useCallback((signal: AbortSignal) => isolationApi.active(signal), []);
  const { data, error, loading, refresh } = usePolling(fetchSessions, REFRESH_MS);

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Aislamiento</h1>
          <p className="muted small">
            Equipos aislados o con un aislamiento en curso. Se actualiza solo cada {REFRESH_MS / 1000} s. Para aislar o
            liberar un equipo, abre su ficha y la pestaña Aislamiento.
          </p>
        </div>
      </div>
      {error && data && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}
      {loading ? (
        <LoadingState label="Cargando sesiones…" />
      ) : !data ? (
        <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
      ) : data.items.length === 0 ? (
        <EmptyState title="Ningún equipo aislado">No hay sesiones de aislamiento vivas en este momento.</EmptyState>
      ) : (
        <section className="panel">
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Equipo</th>
                  <th>Estado</th>
                  <th>Expira</th>
                  <th className="col-secondary">Solicitado por</th>
                  <th className="col-secondary">Verificado</th>
                  <th className="col-secondary">Motivo</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <Link to={`/assets/${encodeURIComponent(s.asset_id)}?tab=isolation`}>{s.asset_label}</Link>
                    </td>
                    <td>
                      <IsolationStatusBadge session={s} />
                    </td>
                    <td title={formatDateTime(s.expires_at)}>{formatRelative(s.expires_at)}</td>
                    <td className="col-secondary">
                      {s.requested_by} · {formatDateTime(s.requested_at)}
                    </td>
                    <td className="col-secondary">{s.verified ? "Sí" : "No"}</td>
                    <td className="col-secondary">{s.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
