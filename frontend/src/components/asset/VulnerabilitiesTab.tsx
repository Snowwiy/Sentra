import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { vulnerabilitiesApi } from "../../api/sentra";
import type { FindingSummary } from "../../api/types";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { formatCvss, LIMITATION_LABELS, SEVERITY_LABELS, SEVERITY_ORDER } from "../../lib/vulnerabilities";
import { Pager } from "../ListControls";
import { softwareKey } from "./SoftwareTab";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import {
  ExposureBadge,
  FindingStatusBadge,
  MatchBadge,
  PriorityBadge,
  VulnSeverityBadge,
} from "../vulnerabilities/VulnBadges";

const PAGE_SIZE = 50;

/** Vulnerabilidades activas por programa instalado, para la pestaña Software. */
export function countBySoftware(findings: FindingSummary[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const f of findings) {
    const key = softwareKey(f.component_name, f.installed_version);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

/** Pestaña "Vulnerabilidades" de Asset Detail: estado de la evaluación y findings del activo. */
export function VulnerabilitiesTab({ assetId }: { assetId: string }) {
  const [all, setAll] = useState(false);
  const [page, setPage] = useState(1);
  const fetchFindings = useCallback(
    (signal: AbortSignal) =>
      vulnerabilitiesApi.asset(
        assetId,
        { active: !all, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE },
        signal,
      ),
    [assetId, all, page],
  );
  const { data, error, loading, refresh } = usePolling(fetchFindings, config.refreshIntervalMs);

  if (loading) return <LoadingState label="Cargando vulnerabilidades…" />;
  if (!data) return <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />;
  const s = data.status;
  const pages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
  return (
    <div className="stack">
      <section className="panel panel--padded">
        <h2>Evaluación</h2>
        <p className="small">
          {SEVERITY_ORDER.filter((sev) => sev !== "informational")
            .map((sev) => `${SEVERITY_LABELS[sev]}: ${data.by_severity[sev] ?? 0}`)
            .join(" · ")}{" "}
          <span className="muted">(confirmadas y probables activas)</span>
        </p>
        <p className="muted small">
          {s.evaluated_at ? (
            <span title={formatDateTime(s.evaluated_at)}>Evaluado {formatRelative(s.evaluated_at)}</span>
          ) : (
            "Aún no evaluado"
          )}
          {` · ${s.components} componentes inventariados`}
          {s.inventory_collected_at && ` · inventario de ${formatRelative(s.inventory_collected_at)}`}
          {s.pending && " · reevaluación pendiente"}
        </p>
        {s.stale && (
          <div className="banner banner--warn" role="note">
            El inventario es antiguo: los findings se mantienen pero no se resuelve nada por ausencia.
          </div>
        )}
        {s.error && (
          <div className="banner banner--warn" role="alert">
            La última evaluación falló: {s.error}
          </div>
        )}
        {s.limitations.length > 0 && (
          <ul className="small">
            {s.limitations.map((code) => (
              <li key={code}>{LIMITATION_LABELS[code] ?? code}</li>
            ))}
          </ul>
        )}
      </section>

      <section className="panel">
        <div className="panel__toolbar">
          <label className="form-field form-field--inline">
            <input
              type="checkbox"
              checked={all}
              onChange={(e) => {
                setAll(e.target.checked);
                setPage(1);
              }}
            />
            <span className="small">Incluir resueltas, aceptadas y falsos positivos</span>
          </label>
        </div>
        {data.items.length === 0 ? (
          <EmptyState title="Sin vulnerabilidades">
            Ningún componente inventariado coincide con el catálogo local. Un puerto abierto no es una vulnerabilidad.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Prioridad</th>
                    <th>Vulnerabilidad</th>
                    <th>Severidad</th>
                    <th>CVSS</th>
                    <th>Evidencia</th>
                    <th>Componente</th>
                    <th>Exposición</th>
                    <th>Estado</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((f) => (
                    <tr key={f.finding_id}>
                      <td>
                        <PriorityBadge score={f.priority_score} level={f.priority_level} />
                      </td>
                      <td>
                        <Link className="vuln-id" to={`/vulnerabilities/${f.finding_id}`}>
                          {f.vulnerability_id}
                        </Link>
                        <div className="muted small">{f.title}</div>
                      </td>
                      <td>
                        <VulnSeverityBadge severity={f.severity} />
                      </td>
                      <td>{formatCvss(f.cvss_score, f.cvss_version)}</td>
                      <td>
                        <MatchBadge state={f.match_state} confidence={f.confidence} />
                      </td>
                      <td>
                        {f.component_name}
                        <div className="muted small">
                          {f.installed_version ?? "versión desconocida"}
                          {f.fixed_version && ` → ${f.fixed_version}`}
                        </div>
                      </td>
                      <td>
                        <ExposureBadge state={f.exposure_state} />
                      </td>
                      <td>
                        <FindingStatusBadge status={f.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={Math.min(page, pages)} pages={pages} total={data.total} onPage={setPage} noun="vulnerabilidades" />
          </>
        )}
      </section>
    </div>
  );
}
