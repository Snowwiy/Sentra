import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { tasksApi } from "../api/caseOperations";
import type { CaseTaskStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import { TaskCard, useTaskRunner, type TaskPermissions } from "../components/incidents/CaseTasks";
import { Pager, Toolbar } from "../components/ListControls";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { ACTIVE_TASK_STATUSES, TASK_STATUS_LABELS } from "../lib/caseOperations";
import { errorMessage } from "../lib/format";
import { usePolling } from "../lib/usePolling";

const PAGE_SIZE = 50;

type StatusFilter = "active" | "all" | CaseTaskStatus;

const FILTERS: { value: StatusFilter; label: string }[] = [
  { value: "active", label: "Pendientes (abiertas, en curso o bloqueadas)" },
  { value: "all", label: "Todas" },
  ...(Object.keys(TASK_STATUS_LABELS) as CaseTaskStatus[]).map((status) => ({
    value: status as StatusFilter,
    label: TASK_STATUS_LABELS[status],
  })),
];

function statusesFor(filter: StatusFilter): CaseTaskStatus[] | undefined {
  if (filter === "all") return undefined;
  if (filter === "active") return ACTIVE_TASK_STATUSES;
  return [filter];
}

/**
 * Mis tareas (Fase 7A.6): las tareas de caso asignadas al usuario de la sesión, de todos los
 * incidentes que puede ver. Desde aquí solo se trabaja la propia tarea (estado, resultado,
 * evidencia); delegar se hace en el caso, donde se sabe quién es su responsable.
 */
export function MyTasksPage() {
  const auth = useAuth();
  const [filter, setFilter] = useState<StatusFilter>("active");
  const [page, setPage] = useState(1);
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      tasksApi.list({ mine: true, status: statusesFor(filter), limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }, signal),
    [filter, page],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs);
  const { run, busy, banners } = useTaskRunner(refresh);
  const permissions: TaskPermissions = {
    canWork: auth.can("incidents:manage"),
    canDelegate: false,
    userId: auth.user?.user_id,
  };
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <div className="page">
      <Link to="/incidents" className="muted">
        ← Incidentes
      </Link>
      <div className="page__header">
        <div>
          <h1>Mis tareas</h1>
          <p className="muted small">
            Tareas de caso asignadas a ti. Son trabajo humano: cambiar su estado no ejecuta nada en ningún equipo.
          </p>
        </div>
      </div>
      <Toolbar>
        <label className="form-field">
          <span className="muted small">Estado</span>
          <select
            className="input input--select"
            aria-label="Estado de las tareas"
            value={filter}
            onChange={(event) => {
              setFilter(event.target.value as StatusFilter);
              setPage(1);
            }}
          >
            {FILTERS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </Toolbar>
      {banners}
      {error && data && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}
      {loading ? (
        <LoadingState label="Cargando tareas…" />
      ) : !data ? (
        <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />
      ) : data.items.length === 0 ? (
        <EmptyState title="Sin tareas">
          {filter === "active"
            ? "No tienes tareas pendientes. Las tareas se crean y se asignan dentro de cada incidente."
            : "No hay tareas asignadas a ti con este filtro."}
        </EmptyState>
      ) : (
        <>
          <ul className="task-list">
            {data.items.map((task) => (
              <TaskCard key={task.task_id} task={task} permissions={permissions} run={run} busy={busy} showIncident />
            ))}
          </ul>
          <Pager page={page} pages={pages} total={data.total} onPage={setPage} noun="tareas" />
        </>
      )}
    </div>
  );
}
