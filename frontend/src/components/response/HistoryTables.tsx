import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { responseApi } from "../../api/sentra";
import type { ExecutionStatus, PlaybookRun, PlaybookRunStatus, ResponseExecution } from "../../api/types";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  EXECUTION_STATUS_LABELS,
  EXECUTION_STATUSES,
  formatDurationMs,
  RUN_STATUS_LABELS,
  RUN_STATUSES,
} from "../../lib/response";
import { usePolling } from "../../lib/usePolling";
import { FilterSelect, Pager, Toolbar } from "../ListControls";
import { Modal } from "../Modal";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import { ExecutionStatusBadge, LiveExecution, LiveRun, RiskBadge, RunStatusBadge } from "./ResponseViews";

const PAGE_SIZE = 25;

/** Detalle de una ejecución por id (desde el historial o un enlace ?execution=). */
export function ExecutionModal({ executionId, onClose }: { executionId: string; onClose: () => void }) {
  const fetcher = useCallback((signal: AbortSignal) => responseApi.execution(executionId, signal), [executionId]);
  // Sin intervalo propio: LiveExecution sigue refrescando mientras la ejecución está activa.
  const { data, error, loading, refresh } = usePolling(fetcher, 3_600_000);
  return (
    <Modal title="Ejecución" onClose={onClose} wide>
      {loading ? (
        <LoadingState label="Cargando ejecución…" />
      ) : data ? (
        <LiveExecution initial={data} />
      ) : (
        <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />
      )}
    </Modal>
  );
}

export function RunModal({ runId, onClose }: { runId: string; onClose: () => void }) {
  const fetcher = useCallback((signal: AbortSignal) => responseApi.run(runId, signal), [runId]);
  const { data, error, loading, refresh } = usePolling(fetcher, 3_600_000);
  return (
    <Modal title="Ejecución de playbook" onClose={onClose} wide>
      {loading ? (
        <LoadingState label="Cargando playbook…" />
      ) : data ? (
        <LiveRun initial={data} />
      ) : (
        <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />
      )}
    </Modal>
  );
}

/**
 * Historial de ejecuciones con filtros. Con `assetId` o `incidentId` se limita a ese objetivo
 * (sección Response del activo); `selected`/`onSelect` permiten guardar el detalle en la URL.
 */
export function ExecutionsTable({
  assetId,
  incidentId,
  compact = false,
  actionOptions = [],
  selected,
  onSelect,
}: {
  assetId?: string;
  incidentId?: string;
  compact?: boolean;
  actionOptions?: { value: string; label: string }[];
  selected?: string;
  onSelect?: (executionId: string | undefined) => void;
}) {
  const [status, setStatus] = useState("");
  const [actionId, setActionId] = useState("");
  const [page, setPage] = useState(1);
  const [localSelected, setLocalSelected] = useState<string>();
  const open = onSelect ? selected : localSelected;
  const select = onSelect ?? setLocalSelected;
  const limit = compact ? 10 : PAGE_SIZE;

  const fetcher = useCallback(
    (signal: AbortSignal) =>
      responseApi.executions(
        {
          status: (status || undefined) as ExecutionStatus | undefined,
          actionId: actionId || undefined,
          assetId,
          incidentId,
          limit,
          offset: (page - 1) * limit,
        },
        signal,
      ),
    [status, actionId, assetId, incidentId, limit, page],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs, true, true);

  return (
    <div className="stack">
      {!compact && (
        <Toolbar>
          <FilterSelect
            label="Estado"
            value={status}
            options={EXECUTION_STATUSES.map((s) => ({ value: s, label: EXECUTION_STATUS_LABELS[s] ?? s }))}
            onChange={(value) => {
              setStatus(value);
              setPage(1);
            }}
          />
          {actionOptions.length > 0 && (
            <FilterSelect
              label="Acción"
              value={actionId}
              allLabel="Todas"
              options={actionOptions}
              onChange={(value) => {
                setActionId(value);
                setPage(1);
              }}
            />
          )}
        </Toolbar>
      )}
      {loading ? (
        <LoadingState label="Cargando ejecuciones…" />
      ) : !data ? (
        <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />
      ) : data.items.length === 0 ? (
        <EmptyState title="Sin ejecuciones">Aún no se ha ejecutado ninguna acción de respuesta con estos filtros.</EmptyState>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Cuándo</th>
                  <th>Acción</th>
                  {!assetId && <th>Objetivo</th>}
                  <th>Estado</th>
                  <th>Riesgo</th>
                  <th>Resumen</th>
                  <th>Usuario</th>
                  <th>Duración</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((e: ResponseExecution) => (
                  <tr key={e.execution_id}>
                    <td title={formatDateTime(e.created_at)}>
                      <button type="button" className="button button--ghost button--small" onClick={() => select(e.execution_id)}>
                        {formatRelative(e.created_at)}
                      </button>
                    </td>
                    <td>
                      {e.action_name}
                      {e.playbook_run_id && <div className="muted small">Paso de playbook</div>}
                    </td>
                    {!assetId && (
                      <td>{e.asset_id ? <Link to={`/assets/${e.asset_id}`}>{e.target_label}</Link> : e.target_label}</td>
                    )}
                    <td>
                      <ExecutionStatusBadge status={e.status} />
                    </td>
                    <td>
                      <RiskBadge risk={e.risk_level} />
                    </td>
                    <td className="small">{e.result_summary ?? e.error_message ?? e.blockers[0]?.message ?? "—"}</td>
                    <td>{e.actor}</td>
                    <td>{formatDurationMs(e.duration_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager
            page={page}
            pages={Math.max(1, Math.ceil(data.total / limit))}
            total={data.total}
            onPage={setPage}
            noun="ejecuciones"
          />
        </>
      )}
      {open && <ExecutionModal executionId={open} onClose={() => select(undefined)} />}
    </div>
  );
}

/** Historial de ejecuciones de playbooks (runs) con filtro de estado. */
export function RunsTable({
  assetId,
  incidentId,
  compact = false,
  selected,
  onSelect,
}: {
  assetId?: string;
  incidentId?: string;
  compact?: boolean;
  selected?: string;
  onSelect?: (runId: string | undefined) => void;
}) {
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);
  const [localSelected, setLocalSelected] = useState<string>();
  const open = onSelect ? selected : localSelected;
  const select = onSelect ?? setLocalSelected;
  const limit = compact ? 10 : PAGE_SIZE;
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      responseApi.runs(
        {
          status: (status || undefined) as PlaybookRunStatus | undefined,
          assetId,
          incidentId,
          limit,
          offset: (page - 1) * limit,
        },
        signal,
      ),
    [status, assetId, incidentId, limit, page],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs, true, true);
  return (
    <div className="stack">
      {!compact && (
        <Toolbar>
          <FilterSelect
            label="Estado"
            value={status}
            options={RUN_STATUSES.map((s) => ({ value: s, label: RUN_STATUS_LABELS[s] ?? s }))}
            onChange={(value) => {
              setStatus(value);
              setPage(1);
            }}
          />
        </Toolbar>
      )}
      {loading ? (
        <LoadingState label="Cargando ejecuciones de playbooks…" />
      ) : !data ? (
        <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />
      ) : data.items.length === 0 ? (
        <EmptyState title="Sin ejecuciones de playbooks" />
      ) : (
        <>
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Cuándo</th>
                  <th>Playbook</th>
                  {!assetId && <th>Objetivo</th>}
                  <th>Estado</th>
                  <th>Pasos</th>
                  <th>Usuario</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((r: PlaybookRun) => (
                  <tr key={r.run_id}>
                    <td title={formatDateTime(r.created_at)}>
                      <button type="button" className="button button--ghost button--small" onClick={() => select(r.run_id)}>
                        {formatRelative(r.created_at)}
                      </button>
                    </td>
                    <td>
                      {r.playbook_name} <span className="muted small">v{r.playbook_version}</span>
                    </td>
                    {!assetId && (
                      <td>
                        <Link to={`/assets/${r.target_id}`}>{r.target_label}</Link>
                      </td>
                    )}
                    <td>
                      <RunStatusBadge status={r.status} />
                    </td>
                    <td>
                      {r.steps.filter((s) => s.status === "succeeded").length} / {r.steps.length}
                    </td>
                    <td>{r.actor}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager
            page={page}
            pages={Math.max(1, Math.ceil(data.total / limit))}
            total={data.total}
            onPage={setPage}
            noun="ejecuciones"
          />
        </>
      )}
      {open && <RunModal runId={open} onClose={() => select(undefined)} />}
    </div>
  );
}
