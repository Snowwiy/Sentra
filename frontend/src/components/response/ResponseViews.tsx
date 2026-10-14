import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../../api/client";
import { responseApi } from "../../api/sentra";
import type { PlaybookRun, ResponseExecution, ResponseIssue } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  EXECUTION_STATUS_LABELS,
  formatDurationMs,
  isActiveExecution,
  jsonText,
  RISK_LABELS,
  riskClass,
  RUN_STATUS_LABELS,
  statusClass,
} from "../../lib/response";
import { usePolling } from "../../lib/usePolling";

// Mientras una ejecución o un run siguen vivos se refrescan más a menudo que el resto del
// dashboard: el resultado de una acción de servidor llega en segundos.
const ACTIVE_REFRESH_MS = 3_000;

export function RiskBadge({ risk }: { risk: string }) {
  return <span className={riskClass(risk)}>{RISK_LABELS[risk] ?? risk}</span>;
}

export function ExecutionStatusBadge({ status }: { status: string }) {
  return <span className={statusClass(status)}>{EXECUTION_STATUS_LABELS[status] ?? status}</span>;
}

export function RunStatusBadge({ status }: { status: string }) {
  return <span className={statusClass(status)}>{RUN_STATUS_LABELS[status] ?? status}</span>;
}

/** Bloqueos o avisos del servidor, como texto. */
export function IssueList({ issues, title, warn = true }: { issues: ResponseIssue[]; title: string; warn?: boolean }) {
  if (issues.length === 0) return null;
  return (
    <div className={`banner${warn ? " banner--warn" : ""}`} role={warn ? "alert" : "note"}>
      <strong>{title}</strong>
      <ul>
        {issues.map((issue, i) => (
          <li key={`${issue.code}-${i}`}>
            {issue.message} <span className="muted small mono">({issue.code})</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function useCancel(onDone: () => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
      onDone();
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
      // Versión obsoleta o ya terminada: se recarga para mostrar el estado real.
      if (err instanceof ApiError && (err.code === "response_conflict" || err.code === "response_invalid_state")) onDone();
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, run };
}

/**
 * Detalle de una ejecución: estado, bloqueos, resumen y resultado. Todo lo que viene del
 * servidor se muestra como texto (el resultado con JSON.stringify en un <pre>), nunca como HTML.
 */
export function ExecutionDetail({ execution, onChanged }: { execution: ResponseExecution; onChanged?: () => void }) {
  const auth = useAuth();
  const cancel = useCancel(() => onChanged?.());
  const canCancel = auth.can("response:manage") && isActiveExecution(execution.status);
  return (
    <div className="stack">
      <div className="detection-badges">
        <ExecutionStatusBadge status={execution.status} />
        <RiskBadge risk={execution.risk_level} />
        {execution.requires_agent && <span className="badge">Agente</span>}
        {execution.deduplicated && (
          <span className="badge badge--info" title="La petición coincidió con una ejecución ya existente">
            Ejecución existente
          </span>
        )}
      </div>
      <dl className="fields">
        <div className="field">
          <dt>Acción</dt>
          <dd>
            {execution.action_name} <span className="muted small mono">{execution.action_id}</span>
          </dd>
        </div>
        <div className="field">
          <dt>Objetivo</dt>
          <dd>
            {execution.asset_id ? <Link to={`/assets/${execution.asset_id}`}>{execution.target_label}</Link> : execution.target_label}
          </dd>
        </div>
        {execution.incident_id && (
          <div className="field">
            <dt>Incidente</dt>
            <dd>
              <Link to={`/incidents/${execution.incident_id}`}>Ver incidente</Link>
            </dd>
          </div>
        )}
        {execution.detection_id && (
          <div className="field">
            <dt>Detección</dt>
            <dd>
              <Link to={`/detections/${execution.detection_id}`}>Ver detección</Link>
            </dd>
          </div>
        )}
        <div className="field">
          <dt>Solicitada por</dt>
          <dd>
            {execution.actor} · <span title={formatDateTime(execution.created_at)}>{formatRelative(execution.created_at)}</span>
          </dd>
        </div>
        <div className="field">
          <dt>Duración</dt>
          <dd>{formatDurationMs(execution.duration_ms)}</dd>
        </div>
        {execution.reason && (
          <div className="field">
            <dt>Motivo</dt>
            <dd>{execution.reason}</dd>
          </div>
        )}
      </dl>
      <IssueList issues={execution.blockers} title="Bloqueada por la política de respuesta" />
      {execution.result_summary && (
        <div className="banner" role="status">
          {execution.result_summary}
        </div>
      )}
      {execution.error_code && (
        <div className="banner banner--warn" role="alert">
          {execution.error_message ?? "Error"} <span className="muted small mono">({execution.error_code})</span>
        </div>
      )}
      {Object.keys(execution.parameters).length > 0 && (
        <div>
          <span className="muted small">Parámetros</span>
          <pre className="code-block small">{jsonText(execution.parameters)}</pre>
        </div>
      )}
      {execution.result && (
        <div>
          <span className="muted small">Resultado</span>
          <pre className="code-block small">{jsonText(execution.result)}</pre>
        </div>
      )}
      <p className="muted small mono">
        {execution.execution_id} · correlación {execution.correlation_id}
      </p>
      {cancel.error && (
        <div className="banner banner--warn" role="alert">
          {cancel.error}
        </div>
      )}
      {canCancel && (
        <div className="actions">
          <button
            type="button"
            className="button button--danger"
            disabled={cancel.busy}
            onClick={() => void cancel.run(() => responseApi.cancelExecution(execution.execution_id, execution.version))}
          >
            Cancelar ejecución
          </button>
        </div>
      )}
    </div>
  );
}

/** Ejecución que se sigue refrescando mientras está activa (tras lanzarla o en el historial). */
export function LiveExecution({ initial, onChanged }: { initial: ResponseExecution; onChanged?: () => void }) {
  const id = initial.execution_id;
  const [latest, setLatest] = useState<ResponseExecution>();
  // El fetcher guarda la última respuesta: el sondeo sigue solo mientras ese estado es activo
  // y se detiene solo cuando la ejecución termina.
  const fetcher = useCallback(
    async (signal: AbortSignal) => {
      const found = await responseApi.execution(id, signal);
      setLatest(found);
      return found;
    },
    [id],
  );
  const execution = latest ?? initial;
  const polled = usePolling(fetcher, ACTIVE_REFRESH_MS, isActiveExecution(execution.status));
  return (
    <ExecutionDetail
      execution={{ ...execution, deduplicated: initial.deduplicated }}
      onChanged={() => {
        // refresh() pide el estado aunque el sondeo esté parado.
        polled.refresh();
        onChanged?.();
      }}
    />
  );
}

/** Run de un playbook con sus pasos; se refresca mientras sigue en curso. */
export function LiveRun({ initial, onChanged }: { initial: PlaybookRun; onChanged?: () => void }) {
  const auth = useAuth();
  const id = initial.run_id;
  const [latest, setLatest] = useState<PlaybookRun>();
  // Mismo criterio que LiveExecution: sondeo solo mientras el run sigue en curso.
  const fetcher = useCallback(
    async (signal: AbortSignal) => {
      const found = await responseApi.run(id, signal);
      setLatest(found);
      return found;
    },
    [id],
  );
  const run = latest ?? initial;
  const polled = usePolling(fetcher, ACTIVE_REFRESH_MS, run.status === "running");
  const cancel = useCancel(() => {
    polled.refresh();
    onChanged?.();
  });
  return (
    <div className="stack">
      <div className="detection-badges">
        <RunStatusBadge status={run.status} />
        <RiskBadge risk={run.risk_level} />
        <span className="badge">v{run.playbook_version}</span>
        {initial.deduplicated && <span className="badge badge--info">Run existente</span>}
      </div>
      <dl className="fields">
        <div className="field">
          <dt>Playbook</dt>
          <dd>{run.playbook_name}</dd>
        </div>
        <div className="field">
          <dt>Objetivo</dt>
          <dd>
            <Link to={`/assets/${run.target_id}`}>{run.target_label}</Link>
          </dd>
        </div>
        <div className="field">
          <dt>Lanzado por</dt>
          <dd>
            {run.actor} · <span title={formatDateTime(run.created_at)}>{formatRelative(run.created_at)}</span>
          </dd>
        </div>
        {run.incident_id && (
          <div className="field">
            <dt>Incidente</dt>
            <dd>
              <Link to={`/incidents/${run.incident_id}`}>Ver incidente</Link>
            </dd>
          </div>
        )}
      </dl>
      {run.error_code && (
        <div className="banner banner--warn" role="alert">
          {run.error_message ?? "Error"} <span className="muted small mono">({run.error_code})</span>
        </div>
      )}
      <div className="table-wrap">
        <table className="table table--compact">
          <thead>
            <tr>
              <th>#</th>
              <th>Acción</th>
              <th>Estado</th>
              <th>Si falla</th>
              <th>Resultado</th>
              <th>Duración</th>
            </tr>
          </thead>
          <tbody>
            {run.steps.map((step) => (
              <tr key={step.order}>
                <td>{step.order}</td>
                <td>{step.action_name}</td>
                <td>
                  <ExecutionStatusBadge status={step.status} />
                </td>
                <td>{step.on_failure === "continue" ? "Continuar" : "Parar"}</td>
                <td>
                  {step.result_summary ?? ""}
                  {step.error_code && (
                    <div className="muted small">
                      {step.error_message} <span className="mono">({step.error_code})</span>
                    </div>
                  )}
                </td>
                <td>{formatDurationMs(step.duration_ms)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {cancel.error && (
        <div className="banner banner--warn" role="alert">
          {cancel.error}
        </div>
      )}
      {auth.can("response:manage") && run.status === "running" && (
        <div className="actions">
          <button
            type="button"
            className="button button--danger"
            disabled={cancel.busy}
            onClick={() => void cancel.run(() => responseApi.cancelRun(run.run_id, run.version))}
          >
            Cancelar playbook
          </button>
        </div>
      )}
    </div>
  );
}
