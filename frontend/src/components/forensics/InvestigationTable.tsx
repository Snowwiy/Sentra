import { Link } from "react-router-dom";
import type { Investigation } from "../../api/types";
import { formatDateTime } from "../../lib/format";
import { INVESTIGATION_STATUS_LABELS } from "../../lib/forensics";

/** Tabla de investigaciones (página general y pestaña del activo). */
export function InvestigationTable({ items, showAsset = true }: { items: Investigation[]; showAsset?: boolean }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Título</th>
            {showAsset && <th>Equipo</th>}
            <th>Estado</th>
            <th>Evidencias</th>
            <th className="col-secondary">Abierta</th>
          </tr>
        </thead>
        <tbody>
          {items.map((inv) => (
            <tr key={inv.id}>
              <td>
                <Link to={`/investigations/${encodeURIComponent(inv.id)}`}>{inv.title}</Link>
                {inv.legal_hold && <span className="badge badge--warn">retención legal</span>}
              </td>
              {showAsset && <td>{inv.asset_label}</td>}
              <td>
                <span className={inv.status === "open" ? "badge badge--info" : "badge badge--muted"}>
                  {INVESTIGATION_STATUS_LABELS[inv.status]}
                </span>
              </td>
              <td>
                {inv.artifact_count}
                {inv.mismatch_count > 0 && (
                  <span className="badge badge--crit" title="Evidencias cuyo SHA-256 no coincide con el del agente">
                    {inv.mismatch_count} sin verificar
                  </span>
                )}
              </td>
              <td className="col-secondary">
                {formatDateTime(inv.created_at)} <span className="muted small">· {inv.created_by}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
