import { Fragment, useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { sentraApi, type ObservationQuery } from "../../api/sentra";
import type { Observation } from "../../api/types";
import {
  CONFIDENCE_LABELS,
  EVIDENCE_STATE_LABELS,
  METHOD_NAMES,
  OBSERVATION_CHANGE_LABELS,
  REACHABILITY_CLASS,
  REACHABILITY_LABELS,
  observationSource,
} from "../../lib/discovery";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { Pager } from "../ListControls";
import { PortList } from "../NetworkBadges";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";

export const OBSERVATION_PAGE_SIZE = 50;

/** Las observaciones de un job terminado no cambian: se consultan con poca frecuencia. */
const IDLE_MS = 5 * 60_000;

/** Paginación en el servidor: cada página es una petición, nunca se descarga todo. */
export function useObservations(query: ObservationQuery, page: number, intervalMs = IDLE_MS, refreshKey = 0) {
  const { jobId, siteId, network, sensorId, executor, method, reachability, q, latest } = query;
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      sentraApi.discoveryObservations(
        {
          jobId,
          siteId,
          network,
          sensorId,
          executor,
          method,
          reachability,
          q,
          latest,
          limit: OBSERVATION_PAGE_SIZE,
          offset: (page - 1) * OBSERVATION_PAGE_SIZE,
        },
        signal,
      ),
    // refreshKey fuerza una consulta nueva cuando el job añade observaciones.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [jobId, siteId, network, sensorId, executor, method, reachability, q, latest, page, refreshKey],
  );
  return usePolling(fetcher, intervalMs, true, true);
}

export function ReachabilityBadge({ value }: { value: Observation["reachability"] }) {
  return <span className={REACHABILITY_CLASS[value] ?? "badge"}>{REACHABILITY_LABELS[value] ?? value}</span>;
}

export function ConfidenceText({ value }: { value: Observation["confidence"] }) {
  return <span className="small">{CONFIDENCE_LABELS[value] ?? value}</span>;
}

/** Nombre del host; un DNS inverso que no se confirma con DNS directo se marca como tal. */
export function HostnameCell({ observation }: { observation: Observation }) {
  const name = observation.hostname ?? observation.reverse_dns;
  if (!name) return <span className="muted">—</span>;
  return (
    <span>
      {name}
      {observation.forward_dns_match === false && (
        <span className="muted small" title="El DNS directo no devuelve esta IP">
          {" "}
          (DNS sin confirmar)
        </span>
      )}
    </span>
  );
}

/**
 * Puertos que respondieron y, aparte, las pistas por número de puerto. Una pista nunca es un
 * servicio confirmado: el puerto 22 abierto sugiere SSH, pero no se ha hablado con él.
 */
export function PortsCell({ observation }: { observation: Observation }) {
  return (
    <div>
      <PortList ports={observation.open_ports} address={observation.address} />
      {observation.port_hints.length > 0 && (
        <div className="small muted observation-hints">
          {observation.port_hints.map((hint) => (
            <span
              key={`${hint.port}-${hint.hint}`}
              className="badge badge--muted"
              title="Pista deducida del número de puerto; no es un servicio confirmado"
            >
              {hint.port}: {hint.hint}? (pista)
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function ChangesCell({ observation }: { observation: Observation }) {
  if (observation.changes.length === 0) return <span className="muted">—</span>;
  return (
    <ul className="plain-list small">
      {observation.changes.map((change, index) => (
        <li key={`${change.kind}-${index}`}>
          {OBSERVATION_CHANGE_LABELS[change.kind] ?? change.kind}
          {(change.previous || change.current) && (
            <span className="mono">
              {" "}
              {change.previous ?? "—"} → {change.current ?? "—"}
            </span>
          )}
          {change.state === "inferred" && <span className="muted"> (inferido)</span>}
        </li>
      ))}
    </ul>
  );
}

function EvidenceList({ observation }: { observation: Observation }) {
  if (observation.evidence.length === 0) return <p className="muted small">Sin evidencia registrada.</p>;
  return (
    <ul className="plain-list small" aria-label={`Evidencia de ${observation.address}`}>
      {observation.evidence.map((item, index) => (
        <li key={`${item.field}-${index}`}>
          <span className="strong">{item.field}</span>: <span className="mono">{item.value}</span>{" "}
          <span className="muted">
            ({METHOD_NAMES[item.method as keyof typeof METHOD_NAMES] ?? item.method})
          </span>{" "}
          <span className={item.state === "observed" ? "badge badge--ok" : "badge badge--muted"}>
            {EVIDENCE_STATE_LABELS[item.state] ?? item.state}
          </span>
        </li>
      ))}
    </ul>
  );
}

function AddressCell({ observation }: { observation: Observation }) {
  return observation.asset_id ? (
    <Link to={`/assets/${observation.asset_id}`} className="mono">
      {observation.address}
    </Link>
  ) : (
    <span className="mono">{observation.address}</span>
  );
}

/** Observaciones de un job concreto, con evidencia y cambios (detalle del job). */
export function JobObservations({ jobId, active, refreshKey }: { jobId: string; active: boolean; refreshKey: number }) {
  const [page, setPage] = useState(1);
  // Mientras el job está activo llegan observaciones nuevas: se refresca con el contador del job.
  const observations = useObservations({ jobId }, page, active ? 5_000 : IDLE_MS, refreshKey);
  const [open, setOpen] = useState<string>();
  const data = observations.data;
  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / OBSERVATION_PAGE_SIZE));

  let body;
  if (!data) {
    body = observations.error ? (
      <ErrorState message={errorMessage(observations.error)} onRetry={observations.refresh} />
    ) : (
      <LoadingState label="Cargando observaciones…" />
    );
  } else if (data.items.length === 0 && page === 1) {
    body = (
      <EmptyState title="Sin observaciones">
        {active
          ? "Las observaciones aparecen a medida que el scan avanza."
          : "Este descubrimiento no registró observaciones."}
      </EmptyState>
    );
  } else {
    body = (
      <>
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th>IP</th>
                <th>Hostname</th>
                <th>MAC</th>
                <th>Métodos</th>
                <th>Alcance</th>
                <th>Puertos</th>
                <th>RTT</th>
                <th>Confianza</th>
                <th>Evidencia</th>
                <th>Cambios</th>
                <th>Fuente</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((o) => {
                const expanded = open === o.observation_id;
                const detailId = `evidence-${o.observation_id}`;
                return (
                  <Fragment key={o.observation_id}>
                    <tr>
                      <td>
                        <AddressCell observation={o} />
                      </td>
                      <td className="small">
                        <HostnameCell observation={o} />
                      </td>
                      <td className="mono small">{o.mac ?? "—"}</td>
                      <td className="small">{o.methods.map((m) => METHOD_NAMES[m] ?? m).join(", ") || "—"}</td>
                      <td>
                        <ReachabilityBadge value={o.reachability} />
                      </td>
                      <td>
                        <PortsCell observation={o} />
                      </td>
                      {/* Sin medida no se inventa un 0: se muestra "—". */}
                      <td className="small" title={o.rtt_ms == null ? "No medido" : undefined}>
                        {o.rtt_ms == null ? "—" : `${o.rtt_ms} ms`}
                      </td>
                      <td>
                        <ConfidenceText value={o.confidence} />
                      </td>
                      <td>
                        <button
                          type="button"
                          className="link-button small"
                          aria-expanded={expanded}
                          aria-controls={detailId}
                          onClick={() => setOpen(expanded ? undefined : o.observation_id)}
                        >
                          {o.evidence.length} {o.evidence.length === 1 ? "evidencia" : "evidencias"}
                        </button>
                      </td>
                      <td>
                        <ChangesCell observation={o} />
                      </td>
                      <td className="small">{observationSource(o)}</td>
                    </tr>
                    {expanded && (
                      <tr className="table__row--detail" id={detailId}>
                        <td colSpan={11}>
                          <EvidenceList observation={o} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
        <Pager page={page} pages={pages} total={total} onPage={setPage} noun="observaciones" />
      </>
    );
  }

  return (
    <section className="stack" aria-label="Observaciones del descubrimiento">
      <h4>Observaciones</h4>
      <p className="muted small">
        «Observado» es evidencia directa; «inferido» y las pistas de puerto son deducciones, no
        servicios confirmados.
      </p>
      {body}
    </section>
  );
}

/** Columnas de la vista de red (última observación por site e IP). */
export function LatestObservationRows({ items, showSite }: { items: Observation[]; showSite: boolean }) {
  return (
    <>
      {items.map((o) => (
        <tr key={o.observation_id}>
          <td>
            <AddressCell observation={o} />
          </td>
          <td className="small">
            <HostnameCell observation={o} />
          </td>
          <td className="mono small">{o.mac ?? "—"}</td>
          {showSite && <td className="small">{o.site_name}</td>}
          <td className="small">{observationSource(o)}</td>
          <td>
            <ReachabilityBadge value={o.reachability} />
          </td>
          <td>
            <PortsCell observation={o} />
          </td>
          <td className="muted" title={formatDateTime(o.observed_at)}>
            {formatRelative(o.observed_at)}
          </td>
          <td>
            <ConfidenceText value={o.confidence} />
          </td>
        </tr>
      ))}
    </>
  );
}
