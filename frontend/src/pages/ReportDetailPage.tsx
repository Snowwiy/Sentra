import { useCallback, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { reportsApi } from "../api/sentra";
import { CopyButton } from "../components/CopyButton";
import { ConfirmDialog } from "../components/Modal";
import { DownloadReportButton, ReportStatusBadge } from "../components/reports/ReportViews";
import { ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage, formatBytes, formatDateTime } from "../lib/format";
import {
  CLASSIFICATION_LABELS,
  describeFilters,
  FORMAT_LABELS,
  formatScope,
  formatUtc,
  isActiveReport,
} from "../lib/reports";
import { usePolling } from "../lib/usePolling";

/** Sondeo cada 3 s mientras el informe está pendiente o generándose. */
const REPORT_POLL_MS = 3_000;
const IDLE_POLL_MS = 3_600_000;

/** Detalle de un informe (Fase 5E). El contenido del informe nunca se muestra aquí: solo se descarga. */
export function ReportDetailPage() {
  const { reportId = "" } = useParams();
  const fetcher = useCallback((signal: AbortSignal) => reportsApi.get(reportId, signal), [reportId]);
  const [active, setActive] = useState(true);
  const { data, error, loading, refresh } = usePolling(fetcher, active ? REPORT_POLL_MS : IDLE_POLL_MS);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string>();
  const [confirmDelete, setConfirmDelete] = useState(false);

  // Ajusta el ritmo del sondeo al estado recibido (sin efectos: se deriva en el render).
  const nowActive = data ? isActiveReport(data.status) : true;
  if (nowActive !== active) setActive(nowActive);

  if (loading) return <LoadingState label="Cargando informe…" />;
  if (!data) {
    return (
      <div className="page">
        <Link to="/reports" className="muted">
          ← Informes
        </Link>
        <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />
      </div>
    );
  }
  const report = data;

  const cancel = async () => {
    setBusy(true);
    setActionError(undefined);
    try {
      await reportsApi.cancel(report.id);
      refresh();
    } catch (err) {
      setActionError(errorMessage(err instanceof Error ? err : new Error(String(err))));
      refresh();
    } finally {
      setBusy(false);
    }
  };

  const filters = describeFilters(report.filters);
  return (
    <div className="page">
      <Link to="/reports" className="muted">
        ← Informes
      </Link>
      <div className="page__header">
        <div>
          <h1>{report.title || report.name}</h1>
          <div className="detection-badges">
            <ReportStatusBadge status={report.status} cancelRequested={report.cancel_requested} />
            <span className="badge">{FORMAT_LABELS[report.format] ?? report.format}</span>
            <span className="badge">{CLASSIFICATION_LABELS[report.classification] ?? report.classification}</span>
            <span className="muted small">
              {report.name} · plantilla v{report.template_version}
            </span>
          </div>
        </div>
        <div className="actions">
          <DownloadReportButton report={report} small={false} />
          {report.can_cancel && isActiveReport(report.status) && (
            <button type="button" className="button" disabled={busy || report.cancel_requested} onClick={() => void cancel()}>
              {report.cancel_requested ? "Cancelación solicitada" : "Cancelar"}
            </button>
          )}
          {report.can_delete && !isActiveReport(report.status) && report.status !== "expired" && (
            <button type="button" className="button button--danger" onClick={() => setConfirmDelete(true)}>
              Borrar
            </button>
          )}
        </div>
      </div>
      {error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}
      {actionError && (
        <div className="banner banner--warn" role="alert">
          {actionError}
        </div>
      )}
      {isActiveReport(report.status) && (
        <div className="banner" role="status">
          {report.status === "pending" ? "En cola: el servidor generará el informe en breve." : "Generando el informe…"}{" "}
          Esta página se actualiza sola.
        </div>
      )}
      {report.status === "failed" && (
        <div className="banner banner--warn" role="alert">
          La generación falló{report.error_code ? ` (${report.error_code})` : ""}
          {report.error_message ? `: ${report.error_message}` : "."}
        </div>
      )}

      <section className="panel panel--padded stack">
        <h2>Datos del informe</h2>
        <dl className="fields">
          <div className="field">
            <dt>Datos a fecha de</dt>
            <dd>{report.cutoff_at ? formatUtc(report.cutoff_at) : "Pendiente de generar"}</dd>
          </div>
          <div className="field">
            <dt>Rango</dt>
            <dd>
              {report.time_from || report.time_to
                ? `${formatUtc(report.time_from)} → ${formatUtc(report.time_to)}`
                : "No aplica"}
            </dd>
          </div>
          <div className="field">
            <dt>Zona horaria</dt>
            <dd>{report.timezone || "UTC"}</dd>
          </div>
          <div className="field">
            <dt>Solicitado por</dt>
            <dd>{report.requested_by}</dd>
          </div>
          <div className="field">
            <dt>Creado</dt>
            <dd>{formatDateTime(report.created_at)}</dd>
          </div>
          <div className="field">
            <dt>Iniciado</dt>
            <dd>{formatDateTime(report.started_at)}</dd>
          </div>
          <div className="field">
            <dt>Terminado</dt>
            <dd>{formatDateTime(report.finished_at)}</dd>
          </div>
          <div className="field">
            <dt>Alcance</dt>
            <dd>{formatScope(report.scope)}</dd>
          </div>
        </dl>
        <h3>Filtros</h3>
        {filters.length ? (
          <dl className="fields fields--inline">
            {filters.map((f) => (
              <div className="field" key={f.label}>
                <dt>{f.label}</dt>
                <dd className="mono small">{f.value}</dd>
              </div>
            ))}
          </dl>
        ) : (
          <p className="muted small">Sin filtros.</p>
        )}
      </section>

      <section className="panel panel--padded stack" aria-label="Artefacto">
        <h2>Fichero</h2>
        {report.artifact ? (
          <dl className="fields">
            <div className="field">
              <dt>Nombre</dt>
              <dd className="mono">{report.artifact.filename}</dd>
            </div>
            <div className="field">
              <dt>Tamaño</dt>
              <dd>{formatBytes(report.artifact.size_bytes)}</dd>
            </div>
            <div className="field">
              <dt>SHA-256</dt>
              <dd>
                <span className="mono small" data-testid="artifact-sha256">
                  {report.artifact.sha256}
                </span>{" "}
                <CopyButton text={report.artifact.sha256} />
              </dd>
            </div>
            {report.snapshot_sha256 && (
              <div className="field">
                <dt>SHA-256 de la instantánea</dt>
                <dd className="mono small">{report.snapshot_sha256}</dd>
              </div>
            )}
          </dl>
        ) : (
          <p className="muted small">
            {report.status === "expired" ? "El fichero ha caducado o se ha borrado." : "Aún no hay fichero."}
          </p>
        )}
      </section>

      <section className="panel panel--padded stack" aria-label="Resumen">
        <h2>Resumen</h2>
        {report.summary.length ? (
          <ul>
            {report.summary.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        ) : (
          <p className="muted small">El resumen estará disponible cuando termine la generación.</p>
        )}
      </section>

      {confirmDelete && (
        <ConfirmDialog
          title="Borrar informe"
          confirmLabel="Borrar"
          danger
          onClose={() => setConfirmDelete(false)}
          onConfirm={async () => {
            await reportsApi.remove(report.id);
            refresh();
          }}
        >
          El fichero del informe se borrará y el informe quedará como caducado. Esta acción no se puede deshacer.
        </ConfirmDialog>
      )}
    </div>
  );
}
