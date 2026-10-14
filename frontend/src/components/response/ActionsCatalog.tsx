import { useCallback, useState } from "react";
import { responseApi } from "../../api/sentra";
import type { ResponseAction } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import { errorMessage } from "../../lib/format";
import { CATEGORY_LABELS, ROLE_REQUIRED_LABELS } from "../../lib/response";
import { usePolling } from "../../lib/usePolling";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import { RiskBadge } from "./ResponseViews";
import { RunActionDialog } from "./RunActionDialog";

/** Por qué no se puede pulsar Ejecutar (o undefined si se puede). */
function disabledReason(action: ResponseAction, enabled: boolean): string | undefined {
  if (!enabled) return "Response está desactivado en el servidor";
  if (action.availability !== "available") return "Acción reservada: no implementada";
  if (!action.permitted) return `Requiere rol ${ROLE_REQUIRED_LABELS[action.required_role] ?? action.required_role}`;
  if (action.blockers.length > 0) return action.blockers.map((b) => b.message).join(" · ");
  // Su objetivo es un incidente: este catálogo no tiene uno de contexto.
  if (action.target_type === "incident") return "Se ejecuta sobre un incidente";
  return undefined;
}

/**
 * Catálogo de acciones (allowlist del servidor). Con `assetId` muestra la disponibilidad y los
 * bloqueos de cada acción en ese activo; las acciones reservadas se ven pero nunca se ejecutan.
 */
export function ActionsCatalog({
  assetId,
  hideIncidentActions = false,
  onExecuted,
}: {
  assetId?: string;
  /** Oculta las acciones cuyo objetivo es un incidente (sin contexto de incidente no aplican). */
  hideIncidentActions?: boolean;
  onExecuted?: () => void;
}) {
  const auth = useAuth();
  const canExecute = auth.can("response:execute");
  const fetcher = useCallback((signal: AbortSignal) => responseApi.actions(assetId, signal), [assetId]);
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs);
  const [running, setRunning] = useState<ResponseAction>();

  if (loading) return <LoadingState label="Cargando acciones…" />;
  if (!data) return <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />;
  const items = data.items.filter((a) => !hideIncidentActions || a.target_type !== "incident");
  return (
    <div className="stack">
      {!data.response_enabled && (
        <div className="banner banner--warn" role="note">
          Response está desactivado en este servidor: el catálogo es solo informativo.
        </div>
      )}
      {items.length === 0 ? (
        <EmptyState title="Sin acciones" />
      ) : (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Acción</th>
                <th>Categoría</th>
                <th>Dónde</th>
                <th>Riesgo</th>
                <th>Rol mínimo</th>
                <th>Disponibilidad</th>
                {canExecute && <th />}
              </tr>
            </thead>
            <tbody>
              {items.map((action) => {
                const reason = disabledReason(action, data.response_enabled);
                const notImplemented = action.availability !== "available";
                return (
                  <tr key={action.id} className={notImplemented ? "muted" : undefined}>
                    <td>
                      <div className="strong">{action.name}</div>
                      <div className="muted small">{action.description}</div>
                      {assetId && action.blockers.length > 0 && (
                        <div className="small">
                          {action.blockers.map((b) => (
                            <div key={b.code}>
                              Bloqueo: {b.message} <span className="muted mono">({b.code})</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </td>
                    <td>{CATEGORY_LABELS[action.category] ?? action.category}</td>
                    <td>
                      {action.scope === "agent" ? "Agente" : "Servidor"}
                      {action.target_type === "incident" && <div className="muted small">Sobre un incidente</div>}
                    </td>
                    <td>
                      <RiskBadge risk={action.risk_level} />
                      {action.requires_confirmation && <div className="muted small">Confirmación</div>}
                    </td>
                    <td>{ROLE_REQUIRED_LABELS[action.required_role] ?? action.required_role}</td>
                    <td>
                      {notImplemented ? (
                        <span className="badge badge--muted">No implementada</span>
                      ) : (
                        <span className="badge badge--ok">Disponible</span>
                      )}
                    </td>
                    {canExecute && (
                      <td>
                        <button
                          type="button"
                          className="button button--small"
                          disabled={reason !== undefined}
                          title={reason}
                          onClick={() => setRunning(action)}
                        >
                          Ejecutar
                        </button>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {running && (
        <RunActionDialog
          action={running}
          assetId={assetId}
          onClose={() => setRunning(undefined)}
          onDone={() => {
            refresh();
            onExecuted?.();
          }}
        />
      )}
    </div>
  );
}
