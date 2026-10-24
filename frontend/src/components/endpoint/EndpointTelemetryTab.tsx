import { useCallback, useEffect, useState } from "react";
import { endpointApi } from "../../api/sentra6e";
import type { ActivityCategory, ActivityEvent, EndpointTelemetryStatus } from "../../api/types";
import {
  ACTIVITY_CATEGORY_LABELS,
  activitySummary,
  CMDLINE_POLICY_LABELS,
  COLLECTOR_STATE_LABELS,
  formatSeconds,
  PARENT_RELATION_LABELS,
} from "../../lib/endpoint";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { FilterSelect } from "../ListControls";
import { ErrorState, LoadingState } from "../StateViews";
import { ProcessTreePanel } from "./ProcessTreePanel";

const STATUS_REFRESH_MS = 60_000;
const ACTIVITY_PAGE = 50;

const toError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));

/**
 * Telemetría avanzada del endpoint (Fase 6E.3/6E.4): estado de los colectores, árbol de
 * procesos con carga diferida, detalle de una instancia y actividad reciente. Requiere
 * telemetry:read: líneas de comando, usuarios y conexiones son datos sensibles.
 */
export function EndpointTelemetryTab({ assetId }: { assetId: string }) {
  const [selected, setSelected] = useState<string>();
  return (
    <div className="stack">
      <TelemetryStatusPanel assetId={assetId} />
      <div className="proc-layout">
        <ProcessTreePanel assetId={assetId} selected={selected} onSelect={setSelected} />
        {selected && <ProcessDetail key={selected} assetId={assetId} instanceKey={selected} onSelect={setSelected} />}
      </div>
      <ActivityPanel assetId={assetId} />
    </div>
  );
}

function collectorEntries(status: EndpointTelemetryStatus): [string, string][] {
  const collectors = status.stats?.["collectors"];
  if (typeof collectors !== "object" || collectors === null) return [];
  return Object.entries(collectors as Record<string, unknown>).map(([k, v]) => [k, String(v)]);
}

function TelemetryStatusPanel({ assetId }: { assetId: string }) {
  const fetchStatus = useCallback((signal: AbortSignal) => endpointApi.telemetryStatus(assetId, signal), [assetId]);
  const { data, error, loading, refresh } = usePolling(fetchStatus, STATUS_REFRESH_MS);
  if (loading) return <LoadingState label="Cargando estado de la telemetría…" />;
  if (!data) return <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />;
  const queued = data.stats?.["queued"];
  const dropped = data.stats?.["dropped_total"];
  const collectors = collectorEntries(data);
  return (
    <section className="panel panel--padded stack" aria-label="Estado de la telemetría">
      <h2 className="panel__title">
        Telemetría del endpoint{" "}
        <span className={data.enabled ? "badge badge--ok" : "badge badge--muted"}>{data.enabled ? "activa" : "sin datos"}</span>
      </h2>
      {!data.enabled && (
        <p className="small">
          El agente de este equipo no envía actividad: requiere el agente 0.5.0 con la telemetría de actividad activada.
        </p>
      )}
      <dl className="fields">
        <div className="field">
          <dt>Último evento</dt>
          <dd title={formatDateTime(data.last_event_at)}>{formatRelative(data.last_event_at)}</dd>
        </div>
        <div className="field">
          <dt>Eventos en la última hora</dt>
          <dd>{data.events_last_hour}</dd>
        </div>
        <div className="field">
          <dt>Retraso de ingesta (p50 / p95)</dt>
          <dd>
            {formatSeconds(data.ingest_lag_p50_seconds)} / {formatSeconds(data.ingest_lag_p95_seconds)}
          </dd>
        </div>
        <div className="field">
          <dt>Líneas de comando</dt>
          <dd>{CMDLINE_POLICY_LABELS[data.cmdline_policy] ?? data.cmdline_policy}</dd>
        </div>
        {typeof queued === "number" && (
          <div className="field">
            <dt>En cola en el agente</dt>
            <dd>{queued}</dd>
          </div>
        )}
        {typeof dropped === "number" && (
          <div className="field">
            <dt>Descartados por cola llena</dt>
            <dd className={dropped > 0 ? "text-warn" : undefined}>{dropped}</dd>
          </div>
        )}
      </dl>
      {collectors.length > 0 && (
        <ul className="plain-list small" aria-label="Colectores">
          {collectors.map(([name, state]) => (
            <li key={name}>
              <span className="mono">{name}</span>:{" "}
              <span className={state === "active" ? "text-ok" : "text-warn"}>{COLLECTOR_STATE_LABELS[state] ?? state}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="muted small">
        El inicio y fin de procesos se observa por sondeo (cada pocos segundos): un proceso muy breve puede no aparecer.
      </p>
    </section>
  );
}

function ProcessDetail({
  assetId,
  instanceKey,
  onSelect,
}: {
  assetId: string;
  instanceKey: string;
  onSelect: (key: string) => void;
}) {
  const fetchDetail = useCallback(
    (signal: AbortSignal) => endpointApi.processInstance(assetId, instanceKey, signal),
    [assetId, instanceKey],
  );
  // Sin sondeo periódico: el detalle de una instancia se pide una vez (intervalo de una hora).
  const { data, error, loading, refresh } = usePolling(fetchDetail, 3_600_000);
  if (loading) return <LoadingState label="Cargando proceso…" />;
  if (!data) return <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />;
  const p = data.process;
  const rows: [string, string | null][] = [
    ["PID", String(p.pid)],
    ["PPID", p.ppid === null ? null : String(p.ppid)],
    ["Ejecutable", p.exe],
    ["Línea de comando", p.cmdline],
    ["Usuario", p.username],
    ["SHA-256", p.sha256],
    ["Firmante", p.signer],
    ["Integridad", p.integrity],
    ["Inicio", p.started_at ? formatDateTime(p.started_at) : null],
    ["Fin", p.ended_at ? formatDateTime(p.ended_at) : null],
    ["Padre", p.parent_relation ? (PARENT_RELATION_LABELS[p.parent_relation] ?? p.parent_relation) : null],
    ["Fuente", p.source],
  ];
  return (
    <section className="panel panel--padded stack" aria-label="Detalle del proceso">
      <h2 className="panel__title">{p.name ?? "(sin nombre)"}</h2>
      {data.ancestors.length > 0 && (
        <nav aria-label="Antecesores" className="small">
          {[...data.ancestors].reverse().map((a) => (
            <span key={a.instance_key}>
              <button type="button" className="link-button" onClick={() => onSelect(a.instance_key)}>
                {a.name ?? a.pid}
              </button>
              {" › "}
            </span>
          ))}
          <strong>{p.name ?? p.pid}</strong>
        </nav>
      )}
      <dl className="fields">
        {rows
          .filter(([, value]) => value !== null && value !== "")
          .map(([label, value]) => (
            <div className="field" key={label}>
              <dt>{label}</dt>
              <dd className="mono small proc-detail__value">{value}</dd>
            </div>
          ))}
      </dl>
      <h3 className="small strong">Conexiones recientes ({data.connections.length})</h3>
      {data.connections.length === 0 ? (
        <p className="muted small">Sin conexiones registradas para este proceso.</p>
      ) : (
        <ul className="plain-list small mono">
          {data.connections.map((c) => (
            <li key={c.id}>
              {formatDateTime(c.occurred_at)} · {activitySummary(c)}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function ActivityPanel({ assetId }: { assetId: string }) {
  const [category, setCategory] = useState<ActivityCategory | "">("");
  const [items, setItems] = useState<ActivityEvent[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();

  const load = useCallback(
    async (beforeId: number | undefined, signal?: AbortSignal) => {
      setLoading(true);
      setError(undefined);
      try {
        const page = await endpointApi.activity(
          assetId,
          { category: category || undefined, beforeId, limit: ACTIVITY_PAGE },
          signal,
        );
        setItems((prev) => (beforeId ? [...prev, ...page.items] : page.items));
        setNext(page.next_before_id);
      } catch (err) {
        if (signal?.aborted) return;
        setError(errorMessage(toError(err)));
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [assetId, category],
  );

  useEffect(() => {
    const controller = new AbortController();
    const initial = window.setTimeout(() => void load(undefined, controller.signal), 0);
    return () => {
      window.clearTimeout(initial);
      controller.abort();
    };
  }, [load]);

  return (
    <section className="panel" aria-label="Actividad del endpoint">
      <div className="panel__toolbar panel__toolbar--filters">
        <h2>Actividad</h2>
        <FilterSelect
          label="Categoría"
          value={category}
          allLabel="todas"
          options={Object.entries(ACTIVITY_CATEGORY_LABELS).map(([value, label]) => ({ value, label }))}
          onChange={(v) => setCategory(v as ActivityCategory | "")}
        />
      </div>
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      {items.length === 0 && !loading && !error ? (
        <p className="muted small panel--padded">Sin actividad registrada.</p>
      ) : (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Cuándo</th>
                <th>Categoría</th>
                <th>Acción</th>
                <th>Detalle</th>
                <th className="col-secondary">Fuente</th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id}>
                  <td title={formatDateTime(e.occurred_at)}>{formatDateTime(e.occurred_at)}</td>
                  <td>{ACTIVITY_CATEGORY_LABELS[e.category] ?? e.category}</td>
                  <td className="mono small">{e.action}</td>
                  <td className="small">{activitySummary(e) || "—"}</td>
                  <td className="col-secondary mono small">{e.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="panel__toolbar">
        {loading && <span className="muted small">Cargando…</span>}
        {!loading && next !== null && (
          <button type="button" className="button" onClick={() => void load(next)}>
            Cargar más antiguos
          </button>
        )}
      </div>
    </section>
  );
}
