// Tareas de un caso (Fase 7A.6). Una tarea es trabajo humano: cambia de estado, acumula
// evidencia y termina con un resultado. Asignarla o terminarla NO ejecuta nada en ningún equipo;
// las acciones técnicas (herramientas, Response, aislamiento) tienen su propio flujo.
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { tasksApi } from "../../api/caseOperations";
import { incidentsApi } from "../../api/sentra";
import type {
  AssignableUser,
  CaseEvidenceType,
  TaskRead,
  CaseTaskKind,
  CaseTaskStatus,
  IncidentDetail,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import {
  EVIDENCE_TYPE_LABELS,
  evidenceLink,
  isVersionConflict,
  TASK_KIND_LABELS,
  TASK_STATUS_BADGES,
  TASK_STATUS_LABELS,
  TASK_TRANSITION_LABELS,
} from "../../lib/caseOperations";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { Modal } from "../Modal";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TERMINAL: ReadonlySet<CaseTaskStatus> = new Set(["done", "cancelled"]);

const toMessage = (err: unknown) => (err instanceof Error ? errorMessage(err) : String(err));

/** Ejecuta una mutación: 409 de versión → aviso de recarga (nunca se reintenta sola). */
export function useTaskRunner(reload: () => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [conflict, setConflict] = useState(false);
  const run = useCallback(
    async (action: () => Promise<unknown>): Promise<boolean> => {
      setBusy(true);
      setError(undefined);
      setConflict(false);
      try {
        await action();
        reload();
        return true;
      } catch (err) {
        if (isVersionConflict(err)) setConflict(true);
        else setError(toMessage(err));
        return false;
      } finally {
        setBusy(false);
      }
    },
    [reload],
  );
  const banners = (
    <>
      {conflict && (
        <div className="banner banner--warn" role="alert">
          Otra persona modificó esta tarea mientras la tenías abierta. Tu cambio no se aplicó.{" "}
          <button
            type="button"
            className="button button--small"
            onClick={() => {
              setConflict(false);
              reload();
            }}
          >
            Recargar
          </button>
        </div>
      )}
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
    </>
  );
  return { run, busy, banners };
}

export type TaskRunner = ReturnType<typeof useTaskRunner>["run"];

/** Qué puede hacer la persona con las tareas (la API vuelve a comprobarlo en cada petición). */
export interface TaskPermissions {
  /** incidents:manage y caso no cerrado: crear y trabajar tareas. */
  canWork: boolean;
  /** Owner del caso o admin: asignar a otra persona y reasignar. */
  canDelegate: boolean;
  /** Usuario de la sesión. */
  userId: string | undefined;
}

function useAssignees(enabled: boolean): AssignableUser[] {
  const [users, setUsers] = useState<AssignableUser[]>([]);
  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    incidentsApi
      .assignees(controller.signal)
      .then((list) => setUsers(list.items))
      .catch(() => undefined);
    return () => controller.abort();
  }, [enabled]);
  return users;
}

function ResultDialog({ task, run, onClose }: { task: TaskRead; run: TaskRunner; onClose: () => void }) {
  const [result, setResult] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    const ok = await run(() => tasksApi.update(task.task_id, task.version, { status: "done", result: result.trim() }));
    setBusy(false);
    if (ok) onClose();
  }
  return (
    <Modal title="Terminar tarea" onClose={busy ? () => undefined : onClose}>
      <form className="incident-form" onSubmit={(e) => void submit(e)}>
        <p className="muted small">
          Para terminar una tarea hay que dejar su resultado: qué se comprobó y qué se concluyó. Terminarla no ejecuta nada.
        </p>
        <label>
          <span className="muted small">Resultado (obligatorio)</span>
          <textarea
            className="input"
            required
            maxLength={10000}
            rows={4}
            value={result}
            onChange={(e) => setResult(e.target.value)}
            aria-label="Resultado"
          />
        </label>
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || result.trim().length === 0}>
            Terminar tarea
          </button>
        </div>
      </form>
    </Modal>
  );
}

function AssignDialog({ task, run, onClose }: { task: TaskRead; run: TaskRunner; onClose: () => void }) {
  const users = useAssignees(true);
  const [userId, setUserId] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    const ok = await run(() => tasksApi.assign(task.task_id, task.version, userId));
    setBusy(false);
    if (ok) onClose();
  }
  return (
    <Modal title="Asignar tarea" onClose={busy ? () => undefined : onClose}>
      <form className="incident-form" onSubmit={(e) => void submit(e)}>
        <p className="muted small">
          Asignar delega el trabajo en otra persona; no ejecuta ninguna acción. Solo analistas y administradores activos.
        </p>
        <select
          className="input input--select"
          value={userId}
          required
          onChange={(e) => setUserId(e.target.value)}
          aria-label="Responsable de la tarea"
        >
          <option value="">Elige un usuario</option>
          {users.map((user) => (
            <option key={user.user_id} value={user.user_id}>
              {user.username} ({user.role})
            </option>
          ))}
        </select>
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || !userId}>
            Asignar
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EvidenceDialog({ task, run, onClose }: { task: TaskRead; run: TaskRunner; onClose: () => void }) {
  const [type, setType] = useState<CaseEvidenceType>("detection");
  const [id, setId] = useState("");
  const [busy, setBusy] = useState(false);
  const valid = UUID.test(id.trim());
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!valid) return;
    setBusy(true);
    const ok = await run(() => tasksApi.addEvidence(task.task_id, task.version, type, id.trim()));
    setBusy(false);
    if (ok) onClose();
  }
  return (
    <Modal title="Añadir evidencia" onClose={busy ? () => undefined : onClose}>
      <form className="incident-form" onSubmit={(e) => void submit(e)}>
        <p className="muted small">
          Una referencia a algo que ya existe en Sentra. El servidor comprueba que existe y pone su etiqueta.
        </p>
        <label>
          <span className="muted small">Tipo</span>
          <select
            className="input input--select"
            value={type}
            onChange={(e) => setType(e.target.value as CaseEvidenceType)}
            aria-label="Tipo de evidencia"
          >
            {(Object.keys(EVIDENCE_TYPE_LABELS) as CaseEvidenceType[]).map((value) => (
              <option key={value} value={value}>
                {EVIDENCE_TYPE_LABELS[value]}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="muted small">Identificador</span>
          <input
            className="input mono"
            value={id}
            onChange={(e) => setId(e.target.value)}
            aria-label="Identificador de la evidencia"
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </label>
        {id && !valid && <p className="small text-crit">El identificador no es válido.</p>}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || !valid}>
            Añadir
          </button>
        </div>
      </form>
    </Modal>
  );
}

type TaskDialog = "done" | "assign" | "evidence" | null;

/** Una tarea con sus datos y, si se puede trabajar, sus acciones. */
export function TaskCard({
  task,
  permissions,
  run,
  busy,
  showIncident = false,
}: {
  task: TaskRead;
  permissions: TaskPermissions;
  run: TaskRunner;
  busy: boolean;
  showIncident?: boolean;
}) {
  const [dialog, setDialog] = useState<TaskDialog>(null);
  const terminal = TERMINAL.has(task.status);
  const mine = task.assignee !== null && task.assignee.user_id === permissions.userId;
  const assigneeName = task.assignee?.username ?? task.assignee_name;
  const canUnassign = task.assignee !== null && (mine || permissions.canDelegate);
  // Sin responsable cualquiera con incidents:manage la toma; con responsable, solo quien delega.
  const canTake = !mine && (task.assignee === null || permissions.canDelegate);

  const transition = (status: CaseTaskStatus) => {
    if (status === "done") setDialog("done");
    else void run(() => tasksApi.update(task.task_id, task.version, { status }));
  };

  return (
    <li className="task-card" aria-label={`Tarea: ${task.title}`}>
      <div className="task-card__head">
        <div>
          <strong>{task.title}</strong>{" "}
          <span className={TASK_STATUS_BADGES[task.status]}>{TASK_STATUS_LABELS[task.status]}</span>
          {task.overdue && <span className="badge badge--crit">Vencida</span>}
          <div className="muted small">
            {TASK_KIND_LABELS[task.kind]}
            {showIncident && (
              <>
                {" · "}
                <Link to={`/incidents/${task.incident_id}?tab=tasks`} className="incident-key">
                  {task.incident_key}
                </Link>
              </>
            )}
            {task.asset && (
              <>
                {" · "}
                <Link to={`/assets/${task.asset.asset_id}`}>{task.asset.name}</Link>
              </>
            )}
          </div>
        </div>
      </div>
      <dl className="fields fields--inline">
        <div className="field">
          <dt>Responsable</dt>
          <dd>{assigneeName ?? <span className="muted">Sin asignar</span>}</dd>
        </div>
        <div className="field">
          <dt>Vence</dt>
          <dd className={task.overdue ? "text-crit" : undefined}>
            {task.due_at ? `${formatDateTime(task.due_at)} (${formatRelative(task.due_at)})` : <span className="muted">Sin fecha</span>}
          </dd>
        </div>
        <div className="field">
          <dt>Creada</dt>
          <dd>
            {task.created_by} · {formatRelative(task.created_at)}
          </dd>
        </div>
      </dl>
      {task.description && <p className="note-body small">{task.description}</p>}
      {task.result && (
        <div className="task-card__result">
          <span className="muted small">
            Resultado{task.completed_by ? ` (${task.completed_by}, ${formatDateTime(task.completed_at)})` : ""}:
          </span>
          <p className="note-body">{task.result}</p>
        </div>
      )}
      {task.evidence.length > 0 && (
        <ul className="plain-list small" aria-label="Evidencia de la tarea">
          {task.evidence.map((item) => {
            const href = evidenceLink(item.type, item.id);
            return (
              <li key={`${item.type}-${item.id}`}>
                {EVIDENCE_TYPE_LABELS[item.type]}: {href ? <Link to={href}>{item.label}</Link> : item.label}
                <span className="muted"> · {item.added_by}</span>
              </li>
            );
          })}
        </ul>
      )}
      {permissions.canWork && (
        <div className="actions" role="group" aria-label={`Acciones de la tarea ${task.title}`}>
          {task.allowed_transitions.map((status) => (
            <button key={status} type="button" className="button button--small" disabled={busy} onClick={() => transition(status)}>
              {TASK_TRANSITION_LABELS[status]}
            </button>
          ))}
          {!terminal && canTake && (
            <button
              type="button"
              className="button button--small"
              disabled={busy}
              onClick={() => void run(() => tasksApi.assign(task.task_id, task.version))}
            >
              Asignármela
            </button>
          )}
          {!terminal && permissions.canDelegate && (
            <button type="button" className="button button--small" disabled={busy} onClick={() => setDialog("assign")}>
              {task.assignee ? "Reasignar…" : "Asignar a…"}
            </button>
          )}
          {!terminal && canUnassign && (
            <button
              type="button"
              className="button button--small button--ghost"
              disabled={busy}
              onClick={() => void run(() => tasksApi.unassign(task.task_id, task.version))}
            >
              Quitar responsable
            </button>
          )}
          {!terminal && (
            <button type="button" className="button button--small button--ghost" disabled={busy} onClick={() => setDialog("evidence")}>
              Añadir evidencia
            </button>
          )}
        </div>
      )}
      {dialog === "done" && <ResultDialog task={task} run={run} onClose={() => setDialog(null)} />}
      {dialog === "assign" && <AssignDialog task={task} run={run} onClose={() => setDialog(null)} />}
      {dialog === "evidence" && <EvidenceDialog task={task} run={run} onClose={() => setDialog(null)} />}
    </li>
  );
}

function CreateTaskDialog({
  incident,
  canDelegate,
  run,
  onClose,
}: {
  incident: IncidentDetail;
  canDelegate: boolean;
  run: TaskRunner;
  onClose: () => void;
}) {
  const auth = useAuth();
  const users = useAssignees(canDelegate);
  const [kind, setKind] = useState<CaseTaskKind>("analyze_evidence");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [assetId, setAssetId] = useState("");
  const [assignee, setAssignee] = useState("");
  const [due, setDue] = useState("");
  const [busy, setBusy] = useState(false);
  const dueAt = due ? new Date(due) : undefined;
  const dueInvalid = dueAt !== undefined && Number.isNaN(dueAt.getTime());
  const me = auth.user;
  const others = users.filter((user) => user.user_id !== me?.user_id);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    const ok = await run(() =>
      tasksApi.create(incident.incident_id, {
        kind,
        title: title.trim(),
        description: description.trim() || null,
        asset_id: assetId || null,
        assignee_user_id: assignee || null,
        due_at: dueAt ? dueAt.toISOString() : null,
      }),
    );
    setBusy(false);
    if (ok) onClose();
  }

  return (
    <Modal title="Nueva tarea" onClose={busy ? () => undefined : onClose}>
      <form className="incident-form" onSubmit={(e) => void submit(e)}>
        <label>
          <span className="muted small">Tipo</span>
          <select
            className="input input--select"
            value={kind}
            onChange={(e) => setKind(e.target.value as CaseTaskKind)}
            aria-label="Tipo de tarea"
          >
            {(Object.keys(TASK_KIND_LABELS) as CaseTaskKind[]).map((value) => (
              <option key={value} value={value}>
                {TASK_KIND_LABELS[value]}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="muted small">Título</span>
          <input
            className="input"
            required
            minLength={3}
            maxLength={200}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            aria-label="Título de la tarea"
          />
        </label>
        <label>
          <span className="muted small">Descripción (opcional)</span>
          <textarea
            className="input"
            maxLength={10000}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            aria-label="Descripción de la tarea"
          />
        </label>
        <label>
          <span className="muted small">Activo del caso (opcional)</span>
          <select
            className="input input--select"
            value={assetId}
            onChange={(e) => setAssetId(e.target.value)}
            aria-label="Activo de la tarea"
          >
            <option value="">Ninguno</option>
            {incident.asset_refs
              .filter((asset) => asset.exists)
              .map((asset) => (
                <option key={asset.asset_id} value={asset.asset_id}>
                  {asset.name}
                </option>
              ))}
          </select>
        </label>
        <label>
          <span className="muted small">Responsable</span>
          <select
            className="input input--select"
            value={assignee}
            onChange={(e) => setAssignee(e.target.value)}
            aria-label="Responsable de la nueva tarea"
          >
            <option value="">Sin asignar</option>
            {me && <option value={me.user_id}>Yo ({me.username})</option>}
            {others.map((user) => (
              <option key={user.user_id} value={user.user_id}>
                {user.username} ({user.role})
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="muted small">Vence (opcional)</span>
          <input
            className="input"
            type="datetime-local"
            value={due}
            onChange={(e) => setDue(e.target.value)}
            aria-label="Vencimiento"
          />
        </label>
        <p className="muted small">Crear o asignar una tarea no ejecuta ninguna acción sobre los equipos.</p>
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || title.trim().length < 3 || dueInvalid}>
            {busy ? "Creando…" : "Crear tarea"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Pestaña Tareas del detalle de un incidente. */
export function TasksSection({ incident, onChanged }: { incident: IncidentDetail; onChanged?: () => void }) {
  const auth = useAuth();
  const fetcher = useCallback((signal: AbortSignal) => tasksApi.forIncident(incident.incident_id, signal), [incident.incident_id]);
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs);
  const reload = useCallback(() => {
    refresh();
    onChanged?.();
  }, [refresh, onChanged]);
  const { run, busy, banners } = useTaskRunner(reload);
  const [creating, setCreating] = useState(false);
  const writable = incident.status !== "closed" && incident.status !== "merged";
  const permissions: TaskPermissions = {
    canWork: auth.can("incidents:manage") && writable,
    canDelegate:
      auth.can("incidents:manage") &&
      (auth.can("incidents:admin") || (incident.owner !== null && incident.owner.user_id === auth.user?.user_id)),
    userId: auth.user?.user_id,
  };

  return (
    <section className="panel panel--padded stack" aria-label="Tareas del caso">
      <div className="panel__toolbar">
        <h2>Tareas</h2>
        <Link to="/incidents/tasks" className="small">
          Mis tareas
        </Link>
        {permissions.canWork && (
          <button type="button" className="button button--primary button--small" onClick={() => setCreating(true)}>
            Nueva tarea
          </button>
        )}
      </div>
      <p className="muted small">
        Trabajo humano dentro del caso. Asignar o terminar una tarea no ejecuta nada en ningún equipo: las acciones
        técnicas (herramientas, Response, aislamiento) tienen su propio flujo y solo se citan aquí como evidencia.
      </p>
      {banners}
      {loading ? (
        <LoadingState label="Cargando tareas…" />
      ) : !data ? (
        <ErrorState message={toMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
      ) : data.items.length === 0 ? (
        <EmptyState title="Sin tareas">
          {permissions.canWork ? "Crea una tarea para repartir el trabajo del caso." : "Este caso no tiene tareas."}
        </EmptyState>
      ) : (
        <ul className="task-list">
          {data.items.map((task) => (
            <TaskCard key={task.task_id} task={task} permissions={permissions} run={run} busy={busy} />
          ))}
        </ul>
      )}
      {creating && (
        <CreateTaskDialog
          incident={incident}
          canDelegate={permissions.canDelegate}
          run={run}
          onClose={() => setCreating(false)}
        />
      )}
    </section>
  );
}
