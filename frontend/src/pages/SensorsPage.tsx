import { useCallback, useState, type FormEvent } from "react";
import { ApiError } from "../api/client";
import { sensorsApi } from "../api/sentra";
import type { Sensor, SensorEnrollment, SensorStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ConfirmDialog, Modal } from "../components/Modal";
import { EnrollSensorModal } from "../components/sensors/EnrollSensorModal";
import {
  ENROLLMENT_STATE_LABELS,
  SENSOR_JOB_STATUS_LABELS,
  SensorStatusBadge,
  VersionStatusBadge,
} from "../components/sensors/SensorBadges";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";
import { SiteScopeChip } from "../site/SiteSelector";

const CARDS: { key: SensorStatus | ""; label: string; className: string }[] = [
  { key: "", label: "Total", className: "" },
  { key: "online", label: "En línea", className: "stat--online" },
  { key: "offline", label: "Sin conexión", className: "stat--offline" },
  { key: "stale", label: "Stale", className: "" },
  { key: "pending", label: "Pendientes", className: "stat--unknown" },
  { key: "revoked", label: "Revocados", className: "stat--revoked" },
];

function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

/** Detalle de un sensor: últimos jobs que ha recibido. */
function SensorJobsPanel({ sensor, onClose }: { sensor: Sensor; onClose: () => void }) {
  const fetchJobs = useCallback((signal: AbortSignal) => sensorsApi.jobs(sensor.sensor_id, 20, signal), [sensor.sensor_id]);
  const jobs = usePolling(fetchJobs, config.refreshIntervalMs);
  const items = jobs.data?.items ?? [];
  return (
    <section className="panel" aria-label={`Jobs del sensor ${sensor.name}`}>
      <div className="panel__toolbar">
        <h2>Jobs de {sensor.name}</h2>
        <span className="muted small">
          {sensor.hostname ?? "sin hostname"} · site {sensor.site_name}
          {sensor.rotation_pending && " · rotación de credencial pendiente"}
          {sensor.revoke_reason && ` · revocado: ${sensor.revoke_reason}`}
        </span>
        <button type="button" className="button button--small" onClick={onClose}>
          Cerrar detalle
        </button>
      </div>
      <dl className="fields fields--inline">
        <div className="field">
          <dt>Cola</dt>
          <dd>{sensor.queue_depth ?? "—"}</dd>
        </div>
        <div className="field">
          <dt>Spool</dt>
          <dd>{sensor.spool_items ?? "—"}</dd>
        </div>
        <div className="field">
          <dt>Último job correcto</dt>
          <dd title={formatDateTime(sensor.last_successful_job_at)}>{formatRelative(sensor.last_successful_job_at)}</dd>
        </div>
        <div className="field">
          <dt>Desfase de reloj</dt>
          <dd>{sensor.clock_skew_seconds == null ? "—" : `${sensor.clock_skew_seconds} s`}</dd>
        </div>
        <div className="field">
          <dt>Credencial emitida</dt>
          <dd>{formatDateTime(sensor.credential_issued_at)}</dd>
        </div>
      </dl>
      {jobs.loading ? (
        <LoadingState label="Cargando jobs…" />
      ) : !jobs.data && jobs.error ? (
        <ErrorState message={errorMessage(jobs.error)} onRetry={jobs.refresh} />
      ) : items.length === 0 ? (
        <EmptyState title="Este sensor aún no ha recibido trabajos" />
      ) : (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Creado</th>
                <th>Red</th>
                <th>Estado</th>
                <th>Intento</th>
                <th>Observaciones</th>
                <th>Lotes</th>
                <th>Terminado</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {items.map((job) => (
                <tr key={job.job_id}>
                  <td title={formatDateTime(job.created_at)}>{formatRelative(job.created_at)}</td>
                  <td className="mono">{job.target ?? "—"}</td>
                  <td>{SENSOR_JOB_STATUS_LABELS[job.status] ?? job.status}</td>
                  <td>
                    {job.attempt}/{job.max_attempts}
                  </td>
                  <td>{job.observations_received}</td>
                  <td>{job.batches_received}</td>
                  <td title={formatDateTime(job.finished_at)}>{job.finished_at ? formatRelative(job.finished_at) : "—"}</td>
                  <td className="mono small">{job.error_code ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** Revocar exige motivo y confirmación: el sensor no podrá volver a conectarse. */
function RevokeSensorModal({
  sensor,
  onClose,
  onDone,
}: {
  sensor: Sensor;
  onClose: () => void;
  onDone: (error?: unknown) => void;
}) {
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!reason.trim() || !confirmed) return;
    setBusy(true);
    setError(undefined);
    try {
      await sensorsApi.revoke(sensor.sensor_id, sensor.version, reason.trim());
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(asError(err)));
      setBusy(false);
      // Con un 409 de versión se recarga la lista para que el operador vea el estado actual.
      if (err instanceof ApiError && err.code === "sensor_conflict") onDone(err);
    }
  };
  return (
    <Modal title={`Revocar sensor ${sensor.name}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        <p>
          La credencial del sensor deja de valer de inmediato y no podrá volver a conectarse; habría que registrarlo
          de nuevo con otro token. Sus datos y su historial se conservan.
        </p>
        <label>
          <span>Motivo</span>
          <textarea className="input" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} required />
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> Confirmo que
          quiero revocar este sensor
        </label>
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--danger" disabled={busy || !reason.trim() || !confirmed}>
            {busy ? "Revocando…" : "Revocar sensor"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Tokens de enrollment de sensor: solo su estado, el valor nunca se lista. */
function EnrollmentsPanel({
  enrollments,
  loading,
  error,
  showSite,
  onChanged,
}: {
  enrollments: SensorEnrollment[] | undefined;
  loading: boolean;
  error: Error | undefined;
  showSite: boolean;
  onChanged: () => void;
}) {
  const [revoking, setRevoking] = useState<SensorEnrollment>();
  return (
    <section className="panel" aria-label="Tokens de sensor">
      <div className="panel__toolbar">
        <h2>Tokens de sensor</h2>
        <span className="muted small">Un token solo se muestra al crearlo; aquí solo aparece su estado.</span>
      </div>
      {enrollments && enrollments.length > 0 ? (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Nombre</th>
                {showSite && <th>Site</th>}
                <th>Estado</th>
                <th>Creado</th>
                <th>Expira</th>
                <th>Usado</th>
                <th>Creado por</th>
                <th aria-label="Acciones" />
              </tr>
            </thead>
            <tbody>
              {enrollments.map((token) => (
                <tr key={token.enrollment_id}>
                  <td>{token.name}</td>
                  {showSite && <td className="small">{token.site_name}</td>}
                  <td>{ENROLLMENT_STATE_LABELS[token.state] ?? token.state}</td>
                  <td title={formatDateTime(token.created_at)}>{formatRelative(token.created_at)}</td>
                  <td>{formatDateTime(token.expires_at)}</td>
                  <td>{token.used_at ? formatRelative(token.used_at) : "—"}</td>
                  <td className="muted small">{token.created_by}</td>
                  <td>
                    {token.state === "active" && (
                      <button
                        type="button"
                        className="button button--small button--danger"
                        aria-label={`Revocar token ${token.name}`}
                        onClick={() => setRevoking(token)}
                      >
                        Revocar
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : loading ? (
        <LoadingState label="Cargando tokens…" />
      ) : error ? (
        <ErrorState message={errorMessage(error)} />
      ) : (
        <EmptyState title="Sin tokens">Pulsa «Registrar sensor» para generar uno.</EmptyState>
      )}
      {revoking && (
        <ConfirmDialog
          title="Revocar token de sensor"
          confirmLabel="Revocar token"
          danger
          onClose={() => setRevoking(undefined)}
          onConfirm={async () => {
            await sensorsApi.revokeEnrollment(revoking.enrollment_id);
            onChanged();
          }}
        >
          <p>El token «{revoking.name}» dejará de servir inmediatamente. Ningún sensor podrá registrarse con él.</p>
        </ConfirmDialog>
      )}
    </section>
  );
}

type Action = { kind: "revoke" | "disable" | "enable" | "rotate"; sensor: Sensor };

const ACTION_TEXT: Record<"disable" | "enable" | "rotate", { title: string; label: string; body: string }> = {
  disable: {
    title: "Deshabilitar sensor",
    label: "Deshabilitar",
    body: "El sensor deja de recibir trabajos hasta que se vuelva a habilitar. Su credencial sigue siendo válida.",
  },
  enable: { title: "Habilitar sensor", label: "Habilitar", body: "El sensor vuelve a recibir trabajos de su site." },
  rotate: {
    title: "Rotar credencial",
    label: "Rotar credencial",
    body: "El sensor obtendrá una credencial nueva en su próximo heartbeat; la anterior deja de valer entonces.",
  },
};

/**
 * Sensores distribuidos (Fase 5F). Todos los roles ven el estado; registrar, revocar,
 * deshabilitar y rotar exige sensors:manage (el servidor lo comprueba siempre).
 */
export function SensorsPage() {
  const auth = useAuth();
  const canManage = auth.can("sensors:manage");
  const site = useSite();
  const { scopeId } = site;
  const showSite = !scopeId && site.sites.length > 1;
  const fetchSensors = useCallback((signal: AbortSignal) => sensorsApi.list(scopeId, signal), [scopeId]);
  const sensors = usePolling(fetchSensors, config.refreshIntervalMs);
  const fetchEnrollments = useCallback((signal: AbortSignal) => sensorsApi.enrollments(scopeId, signal), [scopeId]);
  const enrollments = usePolling(fetchEnrollments, config.refreshIntervalMs, canManage);
  const [filter, setFilter] = useState<SensorStatus | "">("");
  const [enrolling, setEnrolling] = useState(false);
  const [action, setAction] = useState<Action>();
  const [detail, setDetail] = useState<string>();
  const [notice, setNotice] = useState<string>();

  const refreshSensors = sensors.refresh;
  const refreshEnrollments = enrollments.refresh;
  const changed = useCallback(() => {
    refreshSensors();
    refreshEnrollments();
  }, [refreshSensors, refreshEnrollments]);

  if (sensors.loading) return <LoadingState label="Cargando sensores…" />;
  if (!sensors.data && sensors.error) {
    return <ErrorState message={errorMessage(sensors.error)} onRetry={sensors.refresh} />;
  }

  const items = sensors.data?.items ?? [];
  const summary = sensors.data?.summary;
  const visible = items.filter((s) => !filter || s.status === filter);
  const detailSensor = items.find((s) => s.sensor_id === detail);
  const activeSites = site.sites.filter((s) => s.status === "active");

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Sensores</h1>
          <p className="muted small page__scope">
            <SiteScopeChip />
            <span>Sensores de descubrimiento desplegados en cada site.</span>
            {sensors.updatedAt && <span>Actualizado {formatRelative(sensors.updatedAt.toISOString())}.</span>}
          </p>
        </div>
        {canManage && (
          <button type="button" className="button button--primary nowrap" onClick={() => setEnrolling(true)}>
            + Registrar sensor
          </button>
        )}
      </div>

      <div className="banner" role="note">
        Offline o Stale solo indican que el sensor no envía heartbeat (equipo apagado, sin red…): no significa que
        esté comprometido ni que se haya borrado. Revocado sí corta su acceso.
      </div>
      {notice && (
        <div className="banner banner--warn" role="alert">
          {notice}
        </div>
      )}
      {sensors.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(sensors.error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      <section className="stats stats--6" aria-label="Sensores por estado">
        {CARDS.map((card) => (
          <button
            key={card.label}
            type="button"
            className={`stat ${card.className}${filter === card.key ? " stat--active" : ""}`}
            aria-pressed={filter === card.key}
            onClick={() => setFilter(filter === card.key ? "" : card.key)}
          >
            <span className="stat__label">{card.label}</span>
            <span className="stat__value">{!summary ? 0 : card.key === "" ? summary.total : summary[card.key]}</span>
          </button>
        ))}
      </section>

      <section className="panel" aria-label="Sensores">
        {items.length === 0 ? (
          <EmptyState title="Todavía no hay sensores">
            {canManage
              ? "Pulsa «Registrar sensor», genera un token y ejecuta el comando en el equipo del site."
              : "Un administrador puede registrar sensores para descubrir redes de otros sites."}
          </EmptyState>
        ) : visible.length === 0 ? (
          <EmptyState title="Ningún sensor coincide con el filtro" />
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Nombre</th>
                  {showSite && <th>Site</th>}
                  <th>Estado</th>
                  <th>Plataforma</th>
                  <th>Versión</th>
                  <th>Último contacto</th>
                  <th>Capacidades</th>
                  <th>Jobs pendientes</th>
                  <th>Último job</th>
                  <th>Creado</th>
                  <th aria-label="Acciones" />
                </tr>
              </thead>
              <tbody>
                {visible.map((sensor) => {
                  const final = sensor.status === "revoked";
                  return (
                    <tr key={sensor.sensor_id}>
                      <td>
                        <button
                          type="button"
                          className="link-button strong"
                          aria-expanded={detail === sensor.sensor_id}
                          onClick={() => setDetail(detail === sensor.sensor_id ? undefined : sensor.sensor_id)}
                        >
                          {sensor.name}
                        </button>
                        {sensor.hostname && <div className="muted small mono">{sensor.hostname}</div>}
                      </td>
                      {showSite && <td className="small">{sensor.site_name}</td>}
                      <td>
                        <SensorStatusBadge status={sensor.status} />
                        {sensor.rotation_pending && <div className="muted small">rotación pendiente</div>}
                      </td>
                      <td>{sensor.platform ?? <span className="muted">—</span>}</td>
                      <td className="small">
                        <span className="mono">{sensor.sensor_version ?? "—"}</span>{" "}
                        <VersionStatusBadge status={sensor.version_status} />
                      </td>
                      <td className="muted" title={formatDateTime(sensor.last_seen_at)}>
                        {sensor.last_seen_at ? formatRelative(sensor.last_seen_at) : "nunca"}
                      </td>
                      <td className="small">
                        {sensor.capabilities.length ? sensor.capabilities.join(", ") : <span className="muted">—</span>}
                      </td>
                      <td>{sensor.pending_jobs}</td>
                      <td className="small">
                        {sensor.last_job ? (
                          <span title={formatDateTime(sensor.last_job.created_at)}>
                            {SENSOR_JOB_STATUS_LABELS[sensor.last_job.status] ?? sensor.last_job.status} ·{" "}
                            {formatRelative(sensor.last_job.created_at)}
                          </span>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td className="muted" title={formatDateTime(sensor.created_at)}>
                        {formatRelative(sensor.created_at)}
                      </td>
                      <td>
                        {canManage && !final && (
                          <div className="actions">
                            {sensor.status === "disabled" ? (
                              <button
                                type="button"
                                className="button button--small"
                                aria-label={`Habilitar ${sensor.name}`}
                                onClick={() => setAction({ kind: "enable", sensor })}
                              >
                                Habilitar
                              </button>
                            ) : (
                              <button
                                type="button"
                                className="button button--small"
                                aria-label={`Deshabilitar ${sensor.name}`}
                                onClick={() => setAction({ kind: "disable", sensor })}
                              >
                                Deshabilitar
                              </button>
                            )}
                            <button
                              type="button"
                              className="button button--small"
                              aria-label={`Rotar credencial de ${sensor.name}`}
                              disabled={sensor.rotation_pending}
                              title={sensor.rotation_pending ? "Ya hay una rotación pendiente" : undefined}
                              onClick={() => setAction({ kind: "rotate", sensor })}
                            >
                              Rotar
                            </button>
                            <button
                              type="button"
                              className="button button--small button--danger"
                              aria-label={`Revocar ${sensor.name}`}
                              onClick={() => setAction({ kind: "revoke", sensor })}
                            >
                              Revocar
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {detailSensor && <SensorJobsPanel key={detailSensor.sensor_id} sensor={detailSensor} onClose={() => setDetail(undefined)} />}

      {canManage && (
        <EnrollmentsPanel
          enrollments={enrollments.data?.items}
          loading={enrollments.loading}
          error={enrollments.error}
          showSite={showSite}
          onChanged={enrollments.refresh}
        />
      )}

      {enrolling && (
        <EnrollSensorModal
          sites={activeSites}
          initialSiteId={scopeId}
          onClose={() => {
            setEnrolling(false);
            // El token nuevo aparece en la lista (sin su valor).
            changed();
          }}
        />
      )}
      {action?.kind === "revoke" && (
        <RevokeSensorModal
          sensor={action.sensor}
          onClose={() => setAction(undefined)}
          onDone={(err) => {
            if (err) setNotice(errorMessage(asError(err)));
            changed();
          }}
        />
      )}
      {action && action.kind !== "revoke" && (
        <ConfirmDialog
          title={`${ACTION_TEXT[action.kind].title}: ${action.sensor.name}`}
          confirmLabel={ACTION_TEXT[action.kind].label}
          danger={action.kind === "disable"}
          onClose={() => setAction(undefined)}
          onConfirm={async () => {
            const { sensor } = action;
            try {
              if (action.kind === "disable") await sensorsApi.disable(sensor.sensor_id, sensor.version);
              else if (action.kind === "enable") await sensorsApi.enable(sensor.sensor_id, sensor.version);
              else await sensorsApi.rotateCredential(sensor.sensor_id, sensor.version);
              setNotice(undefined);
              changed();
            } catch (err) {
              // 409 sensor_conflict: se recarga para mostrar el estado actual antes de reintentar.
              if (err instanceof ApiError && err.code === "sensor_conflict") changed();
              throw err;
            }
          }}
        >
          <p>{ACTION_TEXT[action.kind].body}</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
