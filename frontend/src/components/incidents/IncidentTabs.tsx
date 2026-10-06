// Pestañas del detalle de incidente (Fase 4K): timeline, evidencia, detecciones, activos,
// notas y auditoría. Todo el texto (notas, resúmenes, hostnames) se pinta como texto plano:
// React lo escapa y nunca se interpreta como HTML.
import { useCallback, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { incidentsApi } from "../../api/sentra";
import type {
  AssetContextBrief,
  AssetContextSnapshot,
  RiskContribution,
  IncidentAuditList,
  IncidentDetail,
  IncidentDetectionRef,
  IncidentNoteList,
  TimelineItem,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import { usePolling } from "../../lib/usePolling";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { ACTION_LABELS, SOURCE_LABELS } from "../../lib/incidents";
import { CRITICALITY_LABELS, formatPoints, RISK_CATEGORY_LABELS } from "../../lib/risk";
import { ENVIRONMENT_LABELS, exposureLabel, ROLE_LABELS, ZONE_LABELS } from "../../lib/assetContext";
import { CriticalityBadge } from "../risk/RiskBadges";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import type { RunAction } from "./IncidentActions";


function entityLink(item: TimelineItem): string | null {
  if (!item.entity_id) return null;
  if (item.entity_type === "detection") return `/detections/${encodeURIComponent(item.entity_id)}`;
  if (item.entity_type === "asset") return `/assets/${encodeURIComponent(item.entity_id)}`;
  if (item.entity_type === "incident") return `/incidents/${encodeURIComponent(item.entity_id)}`;
  return null;
}

/**
 * Timeline paginado por cursor: la primera página se refresca sola; "Cargar más antiguos"
 * añade páginas con el cursor opaco que devuelve el servidor.
 */
export function TimelineTab({ incident }: { incident: IncidentDetail }) {
  const { incident_id: id, version, notes_total: notes } = incident;
  // Versión y número de notas en las dependencias: un cambio del caso recarga ya, sin esperar al sondeo.
  const fetchFirst = useCallback(
    (signal: AbortSignal) => incidentsApi.timeline(id, undefined, signal),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [id, version, notes],
  );
  const first = usePolling(fetchFirst, config.refreshIntervalMs);
  const [older, setOlder] = useState<TimelineItem[]>([]);
  // undefined = aún no se pidió ninguna página antigua (usa el cursor de la primera).
  const [olderCursor, setOlderCursor] = useState<string | null>();
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string>();
  const cursor = olderCursor === undefined ? first.data?.next_cursor : olderCursor;

  async function loadMore() {
    if (!cursor) return;
    setLoadingMore(true);
    setError(undefined);
    try {
      const page = await incidentsApi.timeline(incident.incident_id, cursor);
      setOlder((current) => [...current, ...page.items]);
      setOlderCursor(page.next_cursor);
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
    } finally {
      setLoadingMore(false);
    }
  }

  if (first.loading) return <LoadingState label="Cargando timeline…" />;
  if (!first.data) return <ErrorState message={first.error ? errorMessage(first.error) : "Sin datos"} onRetry={first.refresh} />;
  const seen = new Set(first.data.items.map((item) => item.item_id));
  const items = [...first.data.items, ...older.filter((item) => !seen.has(item.item_id))];
  if (items.length === 0) return <EmptyState title="Sin actividad todavía" />;
  return (
    <section className="panel panel--padded">
      <ol className="timeline" aria-label="Timeline del incidente">
        {items.map((item) => {
          const href = entityLink(item);
          return (
            <li key={item.item_id} className="timeline__item">
              <div className="timeline__when" title={formatDateTime(item.occurred_at)}>
                {formatDateTime(item.occurred_at)}
              </div>
              <div className="timeline__body">
                <div>
                  <span className="badge">{SOURCE_LABELS[item.source_type]}</span>
                  {item.action && <span className="badge">{ACTION_LABELS[item.action] ?? item.action}</span>}
                  {item.actor && <span className="muted small"> · {item.actor}</span>}
                  {item.incident_key !== incident.key && (
                    <span className="muted small"> · desde {item.incident_key}</span>
                  )}
                </div>
                <div className="note-body">{href ? <Link to={href}>{item.summary}</Link> : item.summary}</div>
              </div>
            </li>
          );
        })}
      </ol>
      {error && (
        <p className="banner banner--warn" role="alert">
          {error}
        </p>
      )}
      {cursor && (
        <button type="button" className="button" disabled={loadingMore} onClick={() => void loadMore()}>
          {loadingMore ? "Cargando…" : "Cargar más antiguos"}
        </button>
      )}
    </section>
  );
}

/** Contribuciones al riesgo tal como las calculó 4I (aquí no se recalcula nada). */
export function RiskContributionsTable({ items, assetId }: { items: RiskContribution[]; assetId: string }) {
  if (items.length === 0) return <p className="muted small panel__toolbar">Sin contribuciones vigentes.</p>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Factor</th>
            <th>Categoría</th>
            <th>Puntos</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, index) => (
            <tr key={`${item.factor}-${item.detection_id ?? item.port ?? index}`}>
              <td>
                {item.detection_id ? (
                  <Link to={`/detections/${item.detection_id}`}>{item.label}</Link>
                ) : item.factor === "exposure" ? (
                  <Link to={`/assets/${assetId}?tab=exposure`}>{item.label}</Link>
                ) : (
                  item.label
                )}
              </td>
              <td>{RISK_CATEGORY_LABELS[item.category] ?? item.category}</td>
              <td className="mono">{formatPoints(item.points)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DetectionRows({ items }: { items: IncidentDetectionRef[] }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Severidad</th>
            <th>Regla</th>
            <th>Título</th>
            <th>Activo</th>
            <th>Última vez</th>
            <th>Estado</th>
            <th>Origen</th>
          </tr>
        </thead>
        <tbody>
          {items.map((d) => (
            <tr key={d.detection_id}>
              <td>
                <span className={`dseverity dseverity--${d.severity}`}>{d.severity}</span>
              </td>
              <td className="mono">
                {d.rule_id}
                {d.rule_version !== null && <span className="muted small"> v{d.rule_version}</span>}
                {d.rule_source && d.rule_source !== "builtin" && (
                  <span className="muted small"> · {d.rule_source === "sigma" ? "Sigma" : "personalizada"}</span>
                )}
                {d.kind === "correlation" && <span className="muted small"> · correlación</span>}
              </td>
              <td>
                {d.available ? <Link to={`/detections/${d.detection_id}`}>{d.title}</Link> : d.title}
                {!d.available && <span className="muted small"> (purgada por retención)</span>}
              </td>
              <td>
                {d.asset_id && d.hostname ? <Link to={`/assets/${d.asset_id}`}>{d.hostname}</Link> : "—"}
              </td>
              <td title={formatDateTime(d.last_seen_at)}>{formatRelative(d.last_seen_at)}</td>
              <td>{d.status ?? "—"}</td>
              <td className="muted small">{d.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function DetectionsTab({ incident }: { incident: IncidentDetail }) {
  if (incident.detections.length === 0) return <EmptyState title="Sin detecciones vinculadas" />;
  return (
    <section className="panel">
      {incident.detections_total > incident.detections.length && (
        <p className="muted small panel__toolbar">
          Se muestran {incident.detections.length} de {incident.detections_total} detecciones.
        </p>
      )}
      <DetectionRows items={incident.detections} />
    </section>
  );
}

export function EvidenceTab({ incident }: { incident: IncidentDetail }) {
  const { incident_id: id, version, detections_total: detections, alerts_total: alerts } = incident;
  const fetchEvidence = useCallback(
    (signal: AbortSignal) => incidentsApi.evidence(id, signal),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [id, version, detections, alerts],
  );
  const { data, error } = usePolling(fetchEvidence, config.refreshIntervalMs);
  if (error) return <ErrorState message={errorMessage(error)} />;
  if (!data) return <LoadingState label="Cargando evidencias…" />;
  const empty =
    data.detections.length + data.correlations.length + data.events.length + data.exposure.length + data.alerts.length ===
    0;
  if (empty) return <EmptyState title="Sin evidencia vinculada">Vincula detecciones, alertas o activos al caso.</EmptyState>;
  return (
    <>
      {data.correlations.length > 0 && (
        <section className="panel">
          <h2 className="panel__toolbar">Correlaciones</h2>
          <DetectionRows items={data.correlations} />
        </section>
      )}
      {data.detections.length > 0 && (
        <section className="panel">
          <h2 className="panel__toolbar">Detecciones</h2>
          <DetectionRows items={data.detections} />
        </section>
      )}
      {data.events.length > 0 && (
        <section className="panel panel--padded">
          <h2>Eventos de evidencia</h2>
          {data.events_total > data.events.length && (
            <p className="muted small">
              Se muestran {data.events.length} de {data.events_total} evidencias.
            </p>
          )}
          <ol className="timeline" aria-label="Eventos de evidencia">
            {data.events.map((event, index) => (
              <li key={`${event.detection_id}-${event.occurred_at}-${index}`} className="timeline__item">
                <div className="timeline__when">{formatDateTime(event.occurred_at)}</div>
                <div className="timeline__body">
                  <span className="badge">{event.signal_kind}</span>
                  <span className="muted small"> · {event.source_type}</span>
                  <div className="note-body">{event.summary}</div>
                </div>
              </li>
            ))}
          </ol>
        </section>
      )}
      {data.exposure.length > 0 && (
        <section className="panel">
          <h2 className="panel__toolbar">Exposición</h2>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Activo</th>
                  <th>Puerto</th>
                  <th>Servicio</th>
                  <th>Abierto desde</th>
                </tr>
              </thead>
              <tbody>
                {data.exposure.map((port) => (
                  <tr key={`${port.asset_id}-${port.protocol}-${port.port}`}>
                    <td>
                      <Link to={`/assets/${port.asset_id}?tab=exposure`}>{port.asset_name}</Link>
                    </td>
                    <td className="mono">
                      {port.port}/{port.protocol}
                    </td>
                    <td>{port.service_hint ?? "—"}</td>
                    <td>{formatDateTime(port.opened_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
      {data.alerts.length > 0 && (
        <section className="panel">
          <h2 className="panel__toolbar">Alertas</h2>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Severidad</th>
                  <th>Regla</th>
                  <th>Mensaje</th>
                  <th>Activo</th>
                  <th>Estado</th>
                </tr>
              </thead>
              <tbody>
                {data.alerts.map((alert) => (
                  <tr key={alert.alert_id}>
                    <td>{alert.severity}</td>
                    <td className="mono">{alert.rule}</td>
                    <td className="muted">{alert.message}</td>
                    <td>
                      {alert.asset_id && alert.hostname ? (
                        <Link to={`/assets/${alert.asset_id}?tab=alerts`}>{alert.hostname}</Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>{alert.status ?? "purgada"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
      {data.risk_contributions.map((risk) => (
        <section className="panel" key={risk.asset_id}>
          <h2 className="panel__toolbar">Contribuciones al riesgo · {risk.asset_name}</h2>
          <RiskContributionsTable items={risk.contributions} assetId={risk.asset_id} />
        </section>
      ))}
    </>
  );
}

/** Valor de contexto o "?" si se desconoce (desconocido no es amenaza ni se inventa). */
function known<T extends string>(value: T | null | undefined, labels: Record<string, string>): string {
  return value && value !== "unknown" ? (labels[value] ?? value) : "?";
}

function snapshotLine(snapshot: AssetContextSnapshot): string {
  return [
    snapshot.criticality ? `criticidad ${known(snapshot.criticality, CRITICALITY_LABELS)}` : null,
    `rol ${known(snapshot.role, ROLE_LABELS)}`,
    `entorno ${known(snapshot.environment, ENVIRONMENT_LABELS)}`,
  ]
    .filter(Boolean)
    .join(" · ");
}

/**
 * Fase 4L: contexto ACTUAL del activo (rol, criticidad, entorno, owner, zona, exposición) y,
 * si difiere, el que tenía al vincularse y al resolver el caso.
 */
export function AssetContextSummary({
  context,
  snapshot,
  resolved,
}: {
  context: AssetContextBrief | null;
  snapshot: AssetContextSnapshot | null;
  resolved: AssetContextSnapshot | null;
}) {
  if (!context) return <span className="muted small">—</span>;
  return (
    <div className="small">
      <CriticalityBadge criticality={context.criticality} /> {known(context.role, ROLE_LABELS)} ·{" "}
      {known(context.environment, ENVIRONMENT_LABELS)}
      <div className="muted">
        Owner: {context.owner ?? "?"} · Zona: {known(context.network_zone, ZONE_LABELS)} · Internet:{" "}
        {exposureLabel(context.internet_exposed)}
      </div>
      {!context.context_complete && <div className="muted">Contexto incompleto</div>}
      {snapshot && <div className="muted">Al vincular: {snapshotLine(snapshot)}</div>}
      {resolved && <div className="muted">Al resolver: {snapshotLine(resolved)}</div>}
    </div>
  );
}

export function AssetsTab({ incident }: { incident: IncidentDetail }) {
  if (incident.asset_refs.length === 0) return <EmptyState title="Sin activos vinculados" />;
  return (
    <section className="panel">
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Activo</th>
              <th>IP</th>
              <th>Contexto actual</th>
              <th>Origen</th>
              <th>Añadido</th>
            </tr>
          </thead>
          <tbody>
            {incident.asset_refs.map((asset) => (
              <tr key={asset.asset_id}>
                <td>
                  {asset.exists ? (
                    <Link to={`/assets/${asset.asset_id}`} className="strong">
                      {asset.name}
                    </Link>
                  ) : (
                    <span className="muted">{asset.name} (ya no existe)</span>
                  )}
                </td>
                <td className="mono">{asset.primary_ip ?? "—"}</td>
                <td>
                  <AssetContextSummary
                    context={asset.context}
                    snapshot={asset.context_snapshot}
                    resolved={asset.resolved_context_snapshot}
                  />
                </td>
                <td className="muted small">{asset.source}</td>
                <td>{formatDateTime(asset.added_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function NotesTab({ incident, run }: { incident: IncidentDetail; run: RunAction }) {
  const auth = useAuth();
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [offset, setOffset] = useState(0);
  const { incident_id: id, notes_total: notes } = incident;
  const fetchNotes = useCallback(
    (signal: AbortSignal): Promise<IncidentNoteList> => incidentsApi.notes(id, offset, signal),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [id, offset, notes],
  );
  const { data, error } = usePolling(fetchNotes, config.refreshIntervalMs);
  const writable = auth.can("incidents:manage") && incident.status !== "closed" && incident.status !== "merged";

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    // Las notas son de solo añadir: no exigen versión ni se pueden editar después.
    const ok = await run(() => incidentsApi.addNote(incident.incident_id, body.trim()));
    setBusy(false);
    if (ok) {
      setBody("");
      setOffset(0);
    }
  }

  return (
    <section className="panel panel--padded">
      {writable && (
        <form className="incident-note" onSubmit={(e) => void submit(e)}>
          <textarea
            className="input"
            maxLength={5000}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            aria-label="Nueva nota"
            placeholder="Nota del analista (texto plano; no se puede editar después)"
          />
          <div>
            <button type="submit" className="button button--primary" disabled={busy || !body.trim()}>
              Añadir nota
            </button>
          </div>
        </form>
      )}
      {error ? (
        <ErrorState message={errorMessage(error)} />
      ) : !data ? (
        <LoadingState label="Cargando notas…" />
      ) : data.items.length === 0 ? (
        <EmptyState title="Sin notas" />
      ) : (
        <>
          <ol className="timeline" aria-label="Notas">
            {data.items.map((note) => (
              <li key={note.note_id} className="timeline__item">
                <div className="timeline__when">{formatDateTime(note.created_at)}</div>
                <div className="timeline__body">
                  <div>
                    <span className="strong">{note.author}</span>
                    {note.incident_key !== incident.key && (
                      <span className="muted small"> · escrita en {note.incident_key}</span>
                    )}
                  </div>
                  <div className="note-body">{note.body}</div>
                </div>
              </li>
            ))}
          </ol>
          {data.total > offset + data.items.length && (
            <button type="button" className="button" onClick={() => setOffset(offset + data.items.length)}>
              Siguientes
            </button>
          )}
        </>
      )}
    </section>
  );
}

export function AuditTab({ incident }: { incident: IncidentDetail }) {
  const { incident_id: id, version, notes_total: notes } = incident;
  const fetchAudit = useCallback(
    (signal: AbortSignal): Promise<IncidentAuditList> => incidentsApi.audit(id, 0, signal),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [id, version, notes],
  );
  const { data, error } = usePolling(fetchAudit, config.refreshIntervalMs);
  if (error) return <ErrorState message={errorMessage(error)} />;
  if (!data) return <LoadingState label="Cargando auditoría…" />;
  if (data.items.length === 0) return <EmptyState title="Sin eventos de auditoría" />;
  return (
    <section className="panel">
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Fecha</th>
              <th>Usuario</th>
              <th>Acción</th>
              <th>Resultado</th>
              <th>Detalle</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((event, index) => (
              <tr key={`${event.created_at}-${index}`}>
                <td>{formatDateTime(event.created_at)}</td>
                <td>{event.actor}</td>
                <td className="mono">{event.action}</td>
                <td>{event.result === "success" ? "OK" : <span className="badge badge--warn">{event.result}</span>}</td>
                <td className="muted small mono">{event.details ? JSON.stringify(event.details) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
