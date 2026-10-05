// Acciones sobre un incidente (Fase 4K). La UI solo muestra lo que el rol y el estado
// permiten; el backend vuelve a validar permiso, transición y `version` en cada petición.
import { useEffect, useState, type FormEvent } from "react";
import { incidentsApi } from "../../api/sentra";
import type {
  AssignableUser,
  IncidentDetail,
  IncidentLevel,
  IncidentStatus,
  IncidentSummary,
  ResolutionCategory,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { errorMessage } from "../../lib/format";
import {
  isActive,
  LEVEL_LABELS,
  LEVEL_ORDER,
  RESOLUTION_LABELS,
  RESOLUTION_ORDER,
  STATUS_LABELS,
} from "../../lib/incidents";
import { useDebounced } from "../../lib/useDebounced";
import { ConfirmDialog, Modal } from "../Modal";

/** Ejecuta una acción del caso; la página gestiona errores, 409 y recarga. */
export type RunAction = (action: () => Promise<unknown>) => Promise<boolean>;

const TRANSITION_LABELS: Partial<Record<IncidentStatus, string>> = {
  triage: "Pasar a triage",
  investigating: "Investigar",
  contained: "Marcar contenido",
};

type Dialog = "edit" | "resolve" | "assign" | "close" | "reopen" | "merge" | null;

/** Busca otro incidente por número, título, hostname o IP (para duplicado o fusión). */
function IncidentPicker({
  excludeId,
  onPick,
  picked,
}: {
  excludeId: string;
  onPick: (incident: IncidentSummary | undefined) => void;
  picked?: IncidentSummary;
}) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<IncidentSummary[]>([]);
  const q = useDebounced(query);
  useEffect(() => {
    if (!q.trim()) return;
    const controller = new AbortController();
    incidentsApi
      .list({ q, limit: 8 }, controller.signal)
      .then((list) =>
        setResults(list.items.filter((i) => i.incident_id !== excludeId && i.status !== "merged")),
      )
      .catch(() => setResults([]));
    return () => controller.abort();
  }, [q, excludeId]);

  return (
    <div className="stack">
      <input
        type="search"
        className="input"
        placeholder="INC-000123, título, hostname o IP"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        aria-label="Buscar incidente"
      />
      {picked ? (
        <p>
          Seleccionado: <span className="incident-key">{picked.key}</span> · {picked.title}{" "}
          <button type="button" className="link-button" onClick={() => onPick(undefined)}>
            cambiar
          </button>
        </p>
      ) : (
        q.trim() &&
        results.length > 0 && (
          <ul className="related-list" aria-label="Resultados">
            {results.map((incident) => (
              <li key={incident.incident_id}>
                <span>
                  <span className="incident-key">{incident.key}</span> · {incident.title}{" "}
                  <span className="muted small">({STATUS_LABELS[incident.status]})</span>
                </span>
                <button type="button" className="button button--small" onClick={() => onPick(incident)}>
                  Elegir
                </button>
              </li>
            ))}
          </ul>
        )
      )}
    </div>
  );
}

function EditDialog({ incident, run, onClose }: { incident: IncidentDetail; run: RunAction; onClose: () => void }) {
  const [title, setTitle] = useState(incident.title);
  const [description, setDescription] = useState(incident.description ?? "");
  const [severity, setSeverity] = useState<IncidentLevel>(incident.severity);
  const [priority, setPriority] = useState<IncidentLevel>(incident.priority);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    // Solo se envía lo que cambió: el PATCH es parcial y no pisa otros campos.
    const changes: Record<string, unknown> = {};
    if (title.trim() !== incident.title) changes.title = title.trim();
    if ((description.trim() || null) !== incident.description) changes.description = description.trim() || null;
    if (severity !== incident.severity) changes.severity = severity;
    if (priority !== incident.priority) changes.priority = priority;
    const ok = await run(() => incidentsApi.update(incident.incident_id, incident.version, changes));
    setBusy(false);
    if (ok) onClose();
  }

  return (
    <Modal title={`Editar ${incident.key}`} onClose={busy ? () => undefined : onClose}>
      <form className="incident-form" onSubmit={(e) => void submit(e)}>
        <label>
          <span className="muted small">Título</span>
          <input
            className="input"
            minLength={3}
            maxLength={200}
            required
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            aria-label="Título"
          />
        </label>
        <label>
          <span className="muted small">Descripción</span>
          <textarea
            className="input"
            maxLength={10000}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            aria-label="Descripción"
          />
        </label>
        <div className="actions">
          <label>
            <span className="muted small">Severidad (impacto)</span>
            <select
              className="input input--select"
              value={severity}
              onChange={(e) => setSeverity(e.target.value as IncidentLevel)}
              aria-label="Severidad"
            >
              {LEVEL_ORDER.map((level) => (
                <option key={level} value={level}>
                  {LEVEL_LABELS[level]}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="muted small">Prioridad (urgencia)</span>
            <select
              className="input input--select"
              value={priority}
              onChange={(e) => setPriority(e.target.value as IncidentLevel)}
              aria-label="Prioridad"
            >
              {LEVEL_ORDER.map((level) => (
                <option key={level} value={level}>
                  {LEVEL_LABELS[level]}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy}>
            Guardar
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ResolveDialog({ incident, run, onClose }: { incident: IncidentDetail; run: RunAction; onClose: () => void }) {
  const [category, setCategory] = useState<ResolutionCategory | "">("");
  const [summary, setSummary] = useState("");
  const [duplicate, setDuplicate] = useState<IncidentSummary>();
  const [busy, setBusy] = useState(false);
  const ready = category !== "" && (category !== "duplicate" || duplicate !== undefined);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!category) return;
    setBusy(true);
    const ok = await run(() =>
      incidentsApi.resolve(incident.incident_id, incident.version, {
        category,
        summary: summary.trim(),
        duplicateOf: category === "duplicate" ? duplicate?.incident_id : undefined,
      }),
    );
    setBusy(false);
    if (ok) onClose();
  }

  return (
    <Modal title={`Resolver ${incident.key}`} onClose={busy ? () => undefined : onClose}>
      <form className="incident-form" onSubmit={(e) => void submit(e)}>
        <label>
          <span className="muted small">Categoría de resolución (obligatoria)</span>
          <select
            className="input input--select"
            value={category}
            required
            onChange={(e) => setCategory(e.target.value as ResolutionCategory)}
            aria-label="Categoría de resolución"
          >
            <option value="">Elige una categoría</option>
            {RESOLUTION_ORDER.map((value) => (
              <option key={value} value={value}>
                {RESOLUTION_LABELS[value]}
              </option>
            ))}
          </select>
        </label>
        {category === "false_positive" && (
          <p className="muted small">
            Se guarda como feedback estructurado de las reglas implicadas. No cambia reglas ni severidades.
          </p>
        )}
        {category === "duplicate" && (
          <>
            <p className="muted small">
              Duplicado solo referencia el incidente principal: no mueve evidencias ni notas (eso es fusionar).
            </p>
            <IncidentPicker excludeId={incident.incident_id} picked={duplicate} onPick={setDuplicate} />
          </>
        )}
        <label>
          <span className="muted small">Resumen (opcional)</span>
          <textarea
            className="input"
            maxLength={2000}
            value={summary}
            onChange={(e) => setSummary(e.target.value)}
            aria-label="Resumen de resolución"
          />
        </label>
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || !ready}>
            Resolver
          </button>
        </div>
      </form>
    </Modal>
  );
}

function AssignDialog({ incident, run, onClose }: { incident: IncidentDetail; run: RunAction; onClose: () => void }) {
  const [users, setUsers] = useState<AssignableUser[]>([]);
  const [userId, setUserId] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    incidentsApi
      .assignees(controller.signal)
      .then((list) => setUsers(list.items))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(err instanceof Error ? errorMessage(err) : String(err));
      });
    return () => controller.abort();
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    const ok = await run(() => incidentsApi.assign(incident.incident_id, incident.version, userId));
    setBusy(false);
    if (ok) onClose();
  }

  return (
    <Modal title={`Asignar ${incident.key}`} onClose={busy ? () => undefined : onClose}>
      <form className="incident-form" onSubmit={(e) => void submit(e)}>
        <p className="muted small">Solo analistas y administradores activos pueden ser responsables.</p>
        <select
          className="input input--select"
          value={userId}
          required
          onChange={(e) => setUserId(e.target.value)}
          aria-label="Responsable"
        >
          <option value="">Elige un usuario</option>
          {users.map((user) => (
            <option key={user.user_id} value={user.user_id}>
              {user.username} ({user.role})
            </option>
          ))}
        </select>
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
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

function MergeDialog({ incident, run, onClose }: { incident: IncidentDetail; run: RunAction; onClose: () => void }) {
  const [target, setTarget] = useState<IncidentSummary>();
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!target) return;
    setBusy(true);
    // La versión del destino se lee justo antes: si alguien lo cambia entretanto, 409.
    const ok = await run(async () => {
      const current = await incidentsApi.get(target.incident_id);
      return incidentsApi.merge(incident.incident_id, incident.version, target.incident_id, current.version);
    });
    setBusy(false);
    if (ok) onClose();
  }

  return (
    <Modal title={`Fusionar ${incident.key}`} onClose={busy ? () => undefined : onClose}>
      <div className="stack">
        <p className="muted small">
          {incident.key} quedará como “Fusionado” y sus detecciones, alertas y activos se añadirán al incidente
          elegido. El historial y las notas se conservan y se ven desde el principal.
        </p>
        <IncidentPicker excludeId={incident.incident_id} picked={target} onPick={setTarget} />
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button
            type="button"
            className="button button--danger"
            disabled={busy || !target || !isActive(target.status)}
            onClick={() => void submit()}
          >
            Fusionar en {target?.key ?? "…"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export function IncidentActions({ incident, run, busy }: { incident: IncidentDetail; run: RunAction; busy: boolean }) {
  const auth = useAuth();
  const [dialog, setDialog] = useState<Dialog>(null);
  const canManage = auth.can("incidents:manage");
  const isAdmin = auth.can("incidents:admin");
  if (!canManage) return null;

  const active = isActive(incident.status);
  const mine = incident.owner?.user_id === auth.user?.user_id;
  const close = () => setDialog(null);
  const v = incident.version;
  const id = incident.incident_id;

  return (
    <section className="panel panel--padded" aria-label="Acciones del incidente">
      <div className="actions">
        {incident.allowed_transitions
          .filter((status) => TRANSITION_LABELS[status])
          .map((status) => (
            <button
              key={status}
              type="button"
              className="button"
              disabled={busy}
              onClick={() => void run(() => incidentsApi.update(id, v, { status }))}
            >
              {TRANSITION_LABELS[status]}
            </button>
          ))}
        {incident.allowed_transitions.includes("resolved") && (
          <button type="button" className="button button--primary" disabled={busy} onClick={() => setDialog("resolve")}>
            Resolver
          </button>
        )}
        {active && !incident.owner && (
          <button type="button" className="button" disabled={busy} onClick={() => void run(() => incidentsApi.assign(id, v))}>
            Asignarme
          </button>
        )}
        {active && isAdmin && (
          <button type="button" className="button" disabled={busy} onClick={() => setDialog("assign")}>
            {incident.owner ? "Reasignar" : "Asignar a…"}
          </button>
        )}
        {active && incident.owner && (isAdmin || mine) && (
          <button type="button" className="button" disabled={busy} onClick={() => void run(() => incidentsApi.unassign(id, v))}>
            Quitar responsable
          </button>
        )}
        {incident.status !== "closed" && incident.status !== "merged" && (
          <button type="button" className="button" disabled={busy} onClick={() => setDialog("edit")}>
            Editar
          </button>
        )}
        {isAdmin && incident.status === "resolved" && (
          <button type="button" className="button" disabled={busy} onClick={() => setDialog("close")}>
            Cerrar
          </button>
        )}
        {isAdmin && incident.status === "closed" && (
          <button type="button" className="button" disabled={busy} onClick={() => setDialog("reopen")}>
            Reabrir
          </button>
        )}
        {isAdmin && active && (
          <button type="button" className="button button--danger" disabled={busy} onClick={() => setDialog("merge")}>
            Fusionar…
          </button>
        )}
      </div>
      {dialog === "edit" && <EditDialog incident={incident} run={run} onClose={close} />}
      {dialog === "resolve" && <ResolveDialog incident={incident} run={run} onClose={close} />}
      {dialog === "assign" && <AssignDialog incident={incident} run={run} onClose={close} />}
      {dialog === "merge" && <MergeDialog incident={incident} run={run} onClose={close} />}
      {dialog === "close" && (
        <ConfirmDialog
          title={`Cerrar ${incident.key}`}
          confirmLabel="Cerrar incidente"
          onClose={close}
          onConfirm={() => incidentsApi.close(id, v).then(() => run(async () => undefined))}
        >
          Un incidente cerrado no admite cambios ni notas hasta que un administrador lo reabra.
        </ConfirmDialog>
      )}
      {dialog === "reopen" && (
        <ConfirmDialog
          title={`Reabrir ${incident.key}`}
          confirmLabel="Reabrir"
          onClose={close}
          onConfirm={() => incidentsApi.reopen(id, v).then(() => run(async () => undefined))}
        >
          El incidente vuelve a “Abierto”; la resolución anterior queda en el historial.
        </ConfirmDialog>
      )}
    </section>
  );
}
