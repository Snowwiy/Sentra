import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { consoleApi, sentraApi } from "../../api/sentra";
import type { DiscoveryJob, DiscoveryJobDetail } from "../../api/types";
import {
  JOB_STATUS_CLASS,
  JOB_STATUS_LABELS,
  PHASE_LABELS,
  exactProgress,
  formatClock,
  isActive,
  jobElapsedSeconds,
  originLabel,
  profileLabel,
  stopReasonLabel,
} from "../../lib/discovery";
import { errorMessage, formatDateTime } from "../../lib/format";
import { deviceTypeLabel } from "../../lib/identity";
import { usePolling } from "../../lib/usePolling";
import { ErrorState, LoadingState } from "../StateViews";

// Un scan dura segundos o minutos: consultar cada 1,5 s da sensación de tiempo real sin
// cargar la API (una consulta barata por pestaña abierta, solo mientras está activo).
const ACTIVE_POLL_MS = 1500;

export interface JobActions {
  /** Navegar a la tabla Red filtrada por la red del job. */
  onShowDevices: (target: string) => void;
  /** Lanzar otro descubrimiento de la misma red. */
  onRunAgain: (target: string) => void;
  /** El job cambió de estado (para refrescar historial y activos). */
  onChanged: (job: DiscoveryJob) => void;
  /** Si este navegador puede iniciar/cancelar (consola local). */
  canAdminister: boolean;
  adminReason: string | undefined;
}

function useNow(enabled: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [enabled]);
  return now;
}

/** Estado, progreso y resultado de un job; consulta el backend mientras está activo. */
export function DiscoveryJobView({ jobId, actions }: { jobId: string; actions: JobActions }) {
  const [active, setActive] = useState(true);
  const fetchJob = useCallback(
    async (signal: AbortSignal) => {
      const result = await sentraApi.discoveryJob(jobId, signal);
      // Terminado el job se deja de consultar; "Cancelar" o un reintento usan refresh().
      setActive(isActive(result));
      return result;
    },
    [jobId],
  );
  const job = usePolling(fetchJob, ACTIVE_POLL_MS, active);
  const data = job.data;
  const now = useNow(data?.status === "running");
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState<string>();
  const [showChanges, setShowChanges] = useState(false);

  // Cada cambio de estado se avisa una vez al padre (refrescar historial y tabla Red).
  const lastStatus = useRef<string | undefined>(undefined);
  const onChanged = actions.onChanged;
  useEffect(() => {
    if (data && lastStatus.current !== data.status) {
      lastStatus.current = data.status;
      onChanged(data);
    }
  }, [data, onChanged]);

  if (!data) {
    return job.error ? (
      <ErrorState message={errorMessage(job.error)} onRetry={job.refresh} />
    ) : (
      <LoadingState label="Cargando descubrimiento…" />
    );
  }

  const cancel = async () => {
    setCancelling(true);
    setCancelError(undefined);
    try {
      await consoleApi.cancelDiscovery(data.job_id);
      job.refresh();
    } catch (err) {
      setCancelError(errorMessage(err instanceof Error ? err : new Error(String(err))));
    } finally {
      setCancelling(false);
    }
  };

  return (
    <div className="stack discovery-job">
      <dl className="fields fields--inline">
        <div className="field">
          <dt>Red</dt>
          <dd className="mono">{data.target}</dd>
        </div>
        <div className="field">
          <dt>Estado</dt>
          <dd>
            <span className={JOB_STATUS_CLASS[data.status]}>{JOB_STATUS_LABELS[data.status]}</span>
            {data.baseline && data.status === "completed" && (
              <span className="badge" title="Primer scan completo de esta red: establece la línea base sin alertas">
                {" "}
                baseline
              </span>
            )}
          </dd>
        </div>
        <div className="field">
          <dt>Origen</dt>
          <dd>{originLabel(data)}</dd>
        </div>
        <div className="field">
          <dt>Perfil</dt>
          <dd className="small">{profileLabel(data.parameters)}</dd>
        </div>
      </dl>

      {isActive(data) ? (
        <ActiveJob job={data} now={now} />
      ) : (
        <FinishedJob job={data} showChanges={showChanges} />
      )}

      {job.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar el estado: {errorMessage(job.error)}. Se muestran los últimos datos.
        </div>
      )}
      {cancelError && (
        <div className="banner banner--warn" role="alert">
          {cancelError}
        </div>
      )}

      <div className="modal__actions">
        {isActive(data) ? (
          <button
            type="button"
            className="button button--danger"
            onClick={() => void cancel()}
            disabled={!actions.canAdminister || cancelling || data.cancel_requested}
            title={actions.adminReason}
          >
            {data.cancel_requested || cancelling ? "Cancelando…" : "Cancelar"}
          </button>
        ) : (
          <>
            <button type="button" className="button" onClick={() => actions.onShowDevices(data.target)}>
              Ver dispositivos
            </button>
            <button
              type="button"
              className="button"
              aria-pressed={showChanges}
              onClick={() => setShowChanges((value) => !value)}
            >
              Ver cambios
            </button>
            <button
              type="button"
              className="button button--primary"
              onClick={() => actions.onRunAgain(data.target)}
              disabled={!actions.canAdminister}
              title={actions.adminReason}
            >
              Ejecutar nuevamente
            </button>
          </>
        )}
      </div>
    </div>
  );
}

function ActiveJob({ job, now }: { job: DiscoveryJob; now: number }) {
  const exact = exactProgress(job);
  const phase = job.progress ? (PHASE_LABELS[job.progress.phase] ?? job.progress.phase) : undefined;
  return (
    <section aria-label="Progreso del descubrimiento" className="stack">
      <h3 className="discovery-job__title">
        {job.status === "queued" ? "Descubrimiento en cola" : "Descubrimiento en curso"}
      </h3>
      {job.status === "queued" ? (
        <p className="muted small">
          Espera a que termine otro descubrimiento: los lanzados desde el dashboard se ejecutan de
          uno en uno para no saturar la red.
        </p>
      ) : exact ? (
        <div>
          <div className="muted small">
            {phase} · {exact.label}: {exact.done} / {exact.total}
          </div>
          <div
            className="progress"
            role="progressbar"
            aria-label={exact.label}
            aria-valuemin={0}
            aria-valuemax={exact.total}
            aria-valuenow={exact.done}
          >
            <div className="progress__bar" style={{ width: `${Math.min(100, (100 * exact.done) / exact.total)}%` }} />
          </div>
        </div>
      ) : (
        // Sin total exacto no se inventa un porcentaje: spinner y contadores reales.
        <div className="muted small" role="status">
          <span className="spinner spinner--inline" aria-hidden="true" /> {phase ?? "Preparando"}…
        </div>
      )}
      <dl className="fields fields--inline">
        <Counter label="Hosts procesados" value={`${job.hosts_scanned} / ${job.hosts_total}`} />
        <Counter label="Encontrados" value={job.hosts_alive} />
        <Counter label="Nuevos" value="al terminar" title="Se calcula al aplicar el resultado" />
        <Counter label="Actualizados" value="al terminar" title="Se calcula al aplicar el resultado" />
        <Counter label="Errores" value={job.error_count} />
        <Counter label="Duración" value={formatClock(jobElapsedSeconds(job, now))} />
      </dl>
      {job.cancel_requested && (
        <div className="banner" role="status">
          Cancelación solicitada: el scan se detiene en unos segundos. Un scan cancelado no marca
          dispositivos como desaparecidos ni puertos como cerrados.
        </div>
      )}
    </section>
  );
}

function FinishedJob({ job, showChanges }: { job: DiscoveryJobDetail; showChanges: boolean }) {
  const reason = stopReasonLabel(job.stop_reason);
  const title =
    job.status === "completed"
      ? "Descubrimiento completado"
      : job.status === "cancelled"
        ? "Descubrimiento cancelado"
        : "Descubrimiento fallido";
  return (
    <section aria-label="Resultado del descubrimiento" className="stack">
      <h3 className="discovery-job__title">{title}</h3>
      {job.status === "completed" && job.baseline && (
        <div className="banner" role="status">
          Primer scan completo de esta red: establece la línea base. No se generan alertas de
          dispositivos ni puertos nuevos en esta ejecución.
        </div>
      )}
      {job.status !== "completed" && (
        <div className="banner banner--warn" role="status">
          {reason ? `Motivo: ${reason}. ` : ""}Resultado parcial: no se infiere que ningún
          dispositivo haya desaparecido ni que ningún puerto se haya cerrado.
        </div>
      )}
      <dl className="fields fields--inline">
        <Counter label="Hosts evaluados" value={`${job.hosts_scanned} / ${job.hosts_total}`} />
        <Counter label="Dispositivos encontrados" value={job.hosts_alive} />
        <Counter label="Nuevos dispositivos" value={job.hosts_new} />
        <Counter label="Actualizados" value={job.hosts_updated ?? "—"} />
        <Counter label="Nuevos puertos" value={job.ports_opened} />
        <Counter label="Puertos cerrados" value={job.ports_closed} />
        <Counter label="Duración" value={formatClock(job.duration_seconds)} />
        <Counter label="Errores" value={job.error_count} />
      </dl>
      {job.errors.length > 0 && (
        <details>
          <summary className="muted small">Errores ({job.errors.length})</summary>
          <pre className="code-block small">{job.errors.join("\n")}</pre>
        </details>
      )}
      <p className="muted small">
        Inicio {formatDateTime(job.started_at)} · fin {formatDateTime(job.completed_at)}
      </p>
      {showChanges && <JobChanges job={job} />}
    </section>
  );
}

function JobChanges({ job }: { job: DiscoveryJobDetail }) {
  if (job.new_assets.length === 0 && job.changes.length === 0) {
    return <p className="muted small">Este descubrimiento no detectó cambios.</p>;
  }
  return (
    <div className="stack" aria-label="Cambios del descubrimiento">
      {job.new_assets.length > 0 && (
        <div>
          <h4>Dispositivos nuevos</h4>
          <ul className="plain-list">
            {job.new_assets.map((asset) => (
              <li key={asset.asset_id}>
                <Link to={`/assets/${asset.asset_id}`} className="mono">
                  {asset.primary_ip}
                </Link>{" "}
                <span className="muted small">
                  {asset.display_name !== asset.primary_ip ? asset.display_name : ""}
                  {asset.mac_address ? ` ${asset.mac_address}` : ""}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {job.changes.length > 0 && (
        <div>
          <h4>Cambios de red y exposición</h4>
          <ul className="plain-list">
            {job.changes.map((change, index) => (
              <li key={`${change.asset_id}-${index}`}>
                <Link to={`/assets/${change.asset_id}`} className="mono">
                  {change.primary_ip}
                </Link>{" "}
                {CHANGE_LABELS[change.kind] ?? change.kind}{" "}
                <span className="mono small">
                  {change.kind === "reclassified" ? reclassifiedText(change.item) : change.item}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/** "mobile -> console" (identificadores de la API) → "Móvil → Consola". */
function reclassifiedText(item: string): string {
  const [from, to] = item.split(" -> ");
  if (from === undefined || to === undefined) return item;
  const label = (value: string) => (value === "unknown" ? "Desconocido" : deviceTypeLabel(value));
  return `${label(from)} → ${label(to)}`;
}

const CHANGE_LABELS: Record<string, string> = {
  port_opened: "puerto abierto",
  port_closed: "puerto cerrado",
  appeared: "volvió a aparecer",
  disappeared: "desapareció",
  reclassified: "reclasificado",
};

function Counter({ label, value, title }: { label: string; value: string | number; title?: string }) {
  return (
    <div className="field" title={title}>
      <dt>{label}</dt>
      <dd className="strong">{value}</dd>
    </div>
  );
}
