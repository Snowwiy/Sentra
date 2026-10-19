import { Link } from "react-router-dom";
import type { DashboardVulnerabilities } from "../../api/types";
import {
  EVALUATION_STATE_CLASSES,
  EVALUATION_STATE_HINTS,
  EVALUATION_STATE_LABELS,
} from "../../lib/vulnSources";

/**
 * Tarjeta de vulnerabilidades del dashboard (Fase 6C.4). Distingue «sin vulnerabilidades
 * conocidas» (el catálogo cubre el software evaluado y no hay findings) de «no se puede
 * saber» (sin catálogo, catálogo insuficiente o evaluación pendiente): un cero sin catálogo
 * no es una buena noticia.
 */
export function VulnSummaryCard({ data }: { data: DashboardVulnerabilities }) {
  const state = data.evaluation_state;
  const found = state === "vulnerabilities_found";
  return (
    <section className="panel panel--padded" aria-label="Resumen de vulnerabilidades">
      <div className="panel__toolbar">
        <h2>
          <Link to="/vulnerabilities">Vulnerabilidades</Link>
        </h2>
        <span className={`badge ${EVALUATION_STATE_CLASSES[state]}`}>{EVALUATION_STATE_LABELS[state]}</span>
        {data.catalog_stale && <span className="badge badge--warn">Catálogo desactualizado</span>}
      </div>
      <p className="small">{EVALUATION_STATE_HINTS[state]}</p>
      {data.catalog_stale && (
        <p className="small" role="note">
          El catálogo lleva demasiado tiempo sin actualizarse: las vulnerabilidades publicadas después no aparecen.{" "}
          <Link to="/vulnerabilities/catalog">Ver el estado del catálogo</Link>
        </p>
      )}
      {(state === "no_catalog" || state === "insufficient_catalog") && !data.catalog_stale && (
        <p className="small">
          <Link to="/vulnerabilities/catalog">Ver el estado del catálogo</Link>
        </p>
      )}
      {found && (
        <p className="small">
          Críticas {data.by_severity.critical ?? 0} · altas {data.by_severity.high ?? 0} · medias{" "}
          {data.by_severity.medium ?? 0} · bajas {data.by_severity.low ?? 0} · {data.assets_affected} activos afectados ·{" "}
          {data.potential} potenciales sin confirmar
        </p>
      )}
      <p className="muted small" aria-label="Cobertura de la evaluación">
        Cobertura: {data.assets_evaluated} activos evaluados · {data.assets_covered} cubiertos por el catálogo ·{" "}
        {data.assets_pending} pendientes
      </p>
    </section>
  );
}
