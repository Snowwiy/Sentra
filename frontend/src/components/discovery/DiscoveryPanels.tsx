import type { DiscoveryJob, DiscoverySchedule, DiscoveryScope } from "../../api/types";
import {
  JOB_STATUS_CLASS,
  JOB_STATUS_LABELS,
  formatClock,
  jobElapsedSeconds,
  originLabel,
  profileLabel,
} from "../../lib/discovery";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import { DISABLED_MESSAGE } from "./DiscoveryModal";

const SCHEDULE_OFF: Record<string, string> = {
  no_networks: "No hay redes autorizadas (DISCOVERY_ALLOWED_NETWORKS).",
  no_interval: "Configure DISCOVERY_INTERVAL_MINUTES en el servidor para activarlo.",
  background_jobs_disabled: "Las tareas en segundo plano están desactivadas (BACKGROUND_JOBS_ENABLED).",
};

/** Estado del scheduler: solo lectura, se configura con variables de entorno del servidor. */
export function SchedulePanel({ schedule, error }: { schedule: DiscoverySchedule | undefined; error: Error | undefined }) {
  return (
    <section className="panel" aria-label="Descubrimiento automático">
      <div className="panel__toolbar">
        <h2>Descubrimiento automático</h2>
      </div>
      {!schedule ? (
        error ? (
          <p className="muted small">No se pudo leer el estado: {errorMessage(error)}</p>
        ) : (
          <p className="muted small">Cargando…</p>
        )
      ) : (
        <dl className="fields fields--inline">
          <div className="field">
            <dt>Estado</dt>
            <dd>
              <span className={schedule.enabled ? "badge badge--ok" : "badge"}>
                {schedule.enabled ? "ON" : "OFF"}
              </span>
              {schedule.running && <span className="muted small"> · ejecutándose</span>}
            </dd>
          </div>
          <div className="field">
            <dt>Intervalo</dt>
            <dd>{schedule.interval_minutes ? `${schedule.interval_minutes} minutos` : "—"}</dd>
          </div>
          <div className="field">
            <dt>Última ejecución</dt>
            <dd title={formatDateTime(schedule.last_run_at)}>
              {schedule.last_run_at ? formatRelative(schedule.last_run_at) : "Nunca"}
              {schedule.last_run_status && (
                <span className="muted small"> · {JOB_STATUS_LABELS[schedule.last_run_status]}</span>
              )}
            </dd>
          </div>
          <div className="field">
            <dt>Próxima ejecución</dt>
            <dd title={formatDateTime(schedule.next_run_at)}>
              {schedule.next_run_at ? formatRelative(schedule.next_run_at) : "—"}
            </dd>
          </div>
          {!schedule.enabled && schedule.disabled_reason && (
            <p className="muted small">{SCHEDULE_OFF[schedule.disabled_reason] ?? schedule.disabled_reason}</p>
          )}
        </dl>
      )}
    </section>
  );
}

export function ScopePanel({ scope, error }: { scope: DiscoveryScope | undefined; error: Error | undefined }) {
  return (
    <section className="panel" aria-label="Redes autorizadas">
      <div className="panel__toolbar">
        <h2>Redes autorizadas</h2>
      </div>
      {!scope ? (
        error ? (
          <div className="banner banner--warn" role="alert">
            No se pudo leer la configuración de descubrimiento: {errorMessage(error)}
          </div>
        ) : (
          <p className="muted small">Cargando…</p>
        )
      ) : !scope.enabled ? (
        <div className="banner" role="status">
          {DISABLED_MESSAGE}
        </div>
      ) : (
        <dl className="fields fields--inline">
          <div className="field">
            <dt>Redes</dt>
            <dd className="mono">
              {scope.networks.map((n) => (
                <div key={n.network}>
                  {n.network} <span className="muted small">({n.hosts} direcciones)</span>
                </div>
              ))}
            </dd>
          </div>
          {scope.excluded.length > 0 && (
            <div className="field">
              <dt>Excluidas</dt>
              <dd className="mono">{scope.excluded.join(", ")}</dd>
            </div>
          )}
          <div className="field">
            <dt>Puertos TCP</dt>
            <dd className="mono small">{scope.ports.join(", ")}</dd>
          </div>
        </dl>
      )}
    </section>
  );
}

export function JobsPanel({
  jobs,
  loading,
  error,
  onOpen,
}: {
  jobs: DiscoveryJob[] | undefined;
  loading: boolean;
  error: Error | undefined;
  onOpen: (job: DiscoveryJob) => void;
}) {
  return (
    <section className="panel" aria-label="Ejecuciones recientes">
      <div className="panel__toolbar">
        <h2>Ejecuciones recientes</h2>
      </div>
      {jobs && jobs.length > 0 ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Fecha/hora</th>
                <th>Red</th>
                <th>Estado</th>
                <th>Encontrados</th>
                <th>Nuevos</th>
                <th>Actualizados</th>
                <th>Duración</th>
                <th>Perfil</th>
                <th>Origen</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.job_id} className="table__row--link" onClick={() => onOpen(job)}>
                  <td title={formatRelative(job.started_at)}>
                    {/* Botón real dentro de la fila: se puede abrir el detalle con teclado. */}
                    <button
                      type="button"
                      className="link-button"
                      onClick={(event) => {
                        event.stopPropagation();
                        onOpen(job);
                      }}
                    >
                      {formatDateTime(job.started_at)}
                    </button>
                  </td>
                  <td className="mono">{job.target}</td>
                  <td>
                    <span className={JOB_STATUS_CLASS[job.status]} title={job.errors.join("\n") || undefined}>
                      {JOB_STATUS_LABELS[job.status]}
                    </span>
                    {job.baseline && (
                      <span className="badge" title="Primer scan completo: establece la línea base sin alertas">
                        {" "}
                        baseline
                      </span>
                    )}
                  </td>
                  <td>{job.hosts_alive}</td>
                  <td>{job.status === "completed" || job.status === "cancelled" ? job.hosts_new : "—"}</td>
                  <td>{job.hosts_updated ?? "—"}</td>
                  <td className="muted">{formatClock(jobElapsedSeconds(job))}</td>
                  <td className="muted small">{profileLabel(job.parameters)}</td>
                  <td className="muted">{originLabel(job)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : loading ? (
        <LoadingState label="Cargando ejecuciones…" />
      ) : error ? (
        <ErrorState message={errorMessage(error)} />
      ) : (
        <EmptyState title="Sin ejecuciones">
          Pulsa «Iniciar descubrimiento» o configura DISCOVERY_INTERVAL_MINUTES para ejecutarlo de
          forma periódica.
        </EmptyState>
      )}
    </section>
  );
}
