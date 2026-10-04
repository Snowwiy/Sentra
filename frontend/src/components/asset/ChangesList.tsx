import { useCallback } from "react";
import { sentraApi } from "../../api/sentra";
import type { AssetChange, ChangeCategory, ChangeKind } from "../../api/types";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";

// Changes are detected when an inventory arrives (every 15 min): no need to poll faster.
const REFRESH_MS = 60_000;

const KIND_LABELS: Record<ChangeKind, string> = {
  added: "Nuevo",
  removed: "Eliminado",
  started: "Iniciado",
  stopped: "Detenido",
  start_type_changed: "Cambio de inicio",
  version_changed: "Cambio de versión",
  enabled: "Habilitada",
  disabled: "Deshabilitada",
  admin_granted: "Ahora administrador",
  admin_revoked: "Ya no es administrador",
};

const CATEGORY_LABELS: Record<ChangeCategory, string> = {
  service: "Servicio",
  software: "Software",
  account: "Cuenta",
};

const ATTENTION: ChangeKind[] = ["stopped", "removed", "admin_granted", "disabled"];

function show(value: unknown): string {
  if (Array.isArray(value)) return value.filter((v) => v !== "").join(", ") || "—";
  return value == null || value === "" ? "—" : String(value);
}

export function describeChange(change: AssetChange): string {
  const details = change.details ?? {};
  if ("before" in details || "after" in details) return `${show(details.before)} → ${show(details.after)}`;
  if ("versions" in details) return show(details.versions);
  if ("status" in details) return [details.status, details.start_type].filter(Boolean).join(" · ");
  return "";
}

export function ChangesList({
  assetId,
  category,
  limit = 20,
  title = "Cambios recientes",
}: {
  assetId: string;
  category?: ChangeCategory;
  limit?: number;
  title?: string;
}) {
  const fetchChanges = useCallback(
    (signal: AbortSignal) => sentraApi.getChanges(assetId, { category, limit }, signal),
    [assetId, category, limit],
  );
  const { data, error, loading, refresh } = usePolling(fetchChanges, REFRESH_MS);

  return (
    <section className="panel">
      <div className="panel__toolbar">
        <h2>{title}</h2>
        <span className="muted small">detectados entre inventarios sucesivos</span>
      </div>
      {loading ? (
        <LoadingState label="Cargando cambios…" />
      ) : !data && error ? (
        <ErrorState message={errorMessage(error)} onRetry={refresh} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="Sin cambios registrados">
          Se registran al comparar cada inventario con el anterior.
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Cuándo</th>
                {!category && <th>Tipo</th>}
                <th>Cambio</th>
                <th>Elemento</th>
                <th>Detalle</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((change) => (
                <tr key={change.change_id}>
                  <td className="nowrap" title={formatDateTime(change.detected_at)}>
                    {formatRelative(change.detected_at)}
                  </td>
                  {!category && <td className="muted">{CATEGORY_LABELS[change.category]}</td>}
                  <td>
                    <span className={`badge${ATTENTION.includes(change.kind) ? " badge--crit" : ""}`}>
                      {KIND_LABELS[change.kind]}
                    </span>
                  </td>
                  <td className="strong">{change.item}</td>
                  <td className="muted">{describeChange(change)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
