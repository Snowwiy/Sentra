import { useEffect, useState } from "react";
import { tasksApi } from "../../api/caseOperations";
import { incidentsApi } from "../../api/sentra";
import { toolsApi } from "../../api/sentra7b";
import type { AssignableUser, IncidentSummary, ToolExecutionOut } from "../../api/types";
import { errorMessage } from "../../lib/format";
import { useDebounced } from "../../lib/useDebounced";
import { Modal } from "../Modal";
import { ToolOutput } from "./ToolOutput";

export type CaseEvidenceKind = "tool_execution" | "asset" | "detection";

/**
 * Añadir una evidencia (el resultado de una herramienta, un activo o una detección) a un caso
 * abierto. Usa la herramienta case.link_evidence del motor 7A con su vista previa y una
 * confirmación explícita, así queda en el historial de ejecuciones como cualquier otra.
 * Opcionalmente crea una tarea "analizar evidencia" con esa evidencia adjunta.
 */
export function AddToCaseDialog({
  kind,
  evidenceId,
  label,
  assetId,
  onClose,
  onDone,
}: {
  kind: CaseEvidenceKind;
  evidenceId: string;
  label: string;
  assetId?: string;
  onClose: () => void;
  onDone: (message: string) => void;
}) {
  const [q, setQ] = useState("");
  const term = useDebounced(q.trim(), 300);
  const [cases, setCases] = useState<IncidentSummary[]>([]);
  const [incidentId, setIncidentId] = useState("");
  const [preview, setPreview] = useState<ToolExecutionOut>();
  const [withTask, setWithTask] = useState(false);
  const [assignees, setAssignees] = useState<AssignableUser[]>([]);
  const [assignee, setAssignee] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    const controller = new AbortController();
    incidentsApi
      .list({ active: true, q: term || undefined, limit: 20 }, controller.signal)
      .then((list) => setCases(list.items))
      .catch(() => undefined);
    return () => controller.abort();
  }, [term]);

  // Solo hace falta la lista al pedir la tarea. Si falla (rol sin incidents:manage), la tarea
  // se crea sin responsable y el servidor sigue siendo quien decide.
  useEffect(() => {
    if (!withTask) return;
    const controller = new AbortController();
    incidentsApi
      .assignees(controller.signal)
      .then((list) => setAssignees(list.items))
      .catch(() => undefined);
    return () => controller.abort();
  }, [withTask]);

  const fail = (err: unknown) => setError(errorMessage(err instanceof Error ? err : new Error(String(err))));

  const requestPreview = async () => {
    setBusy(true);
    setError(undefined);
    try {
      setPreview(
        await toolsApi.preview("case.link_evidence", {
          input: { incident_id: incidentId, kind, evidence_id: evidenceId },
          incidentId,
        }),
      );
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    if (!preview) return;
    setBusy(true);
    setError(undefined);
    try {
      await toolsApi.confirm(preview.execution_id, preview.version);
      let message = "Evidencia añadida al caso.";
      if (withTask && (kind === "tool_execution" || kind === "asset" || kind === "detection")) {
        const task = await tasksApi.create(incidentId, {
          kind: "analyze_evidence",
          title: `Analizar: ${label}`.slice(0, 200),
          asset_id: assetId ?? null,
          assignee_user_id: assignee || null,
        });
        await tasksApi.addEvidence(task.task_id, task.version, kind, evidenceId);
        message = "Evidencia añadida al caso y tarea creada.";
      }
      onDone(message);
      onClose();
    } catch (err) {
      fail(err);
      setBusy(false);
    }
  };

  const allowed =
    preview?.status === "previewed" &&
    Boolean((preview.output?.preview as { allowed?: boolean } | undefined)?.allowed);

  return (
    <Modal title="Añadir al caso" onClose={busy ? () => undefined : onClose}>
      <div className="stack">
        <p className="small">
          Evidencia: <strong>{label}</strong>
        </p>
        <label className="field">
          <span>Buscar caso abierto</span>
          <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="INC-000123 o título" />
        </label>
        <label className="field">
          <span>Caso</span>
          <select
            className="input input--select"
            value={incidentId}
            onChange={(e) => {
              setIncidentId(e.target.value);
              setPreview(undefined);
            }}
          >
            <option value="">Elige un caso…</option>
            {cases.map((c) => (
              <option key={c.incident_id} value={c.incident_id}>
                {c.key} · {c.title}
              </option>
            ))}
          </select>
        </label>
        <label className="checkbox small">
          <input type="checkbox" checked={withTask} onChange={(e) => setWithTask(e.target.checked)} /> Crear también una
          tarea «Analizar evidencia» con esta evidencia
        </label>
        {withTask && (
          <label className="field">
            <span>Responsable de la tarea</span>
            <select className="input input--select" value={assignee} onChange={(e) => setAssignee(e.target.value)}>
              <option value="">Sin asignar</option>
              {assignees.map((u) => (
                <option key={u.user_id} value={u.user_id}>
                  {u.username}
                </option>
              ))}
            </select>
          </label>
        )}
        {preview && <ToolOutput execution={preview} />}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          {!preview ? (
            <button
              type="button"
              className="button button--primary"
              disabled={busy || !incidentId}
              onClick={() => void requestPreview()}
            >
              Vista previa
            </button>
          ) : (
            <button type="button" className="button button--primary" disabled={busy || !allowed} onClick={() => void confirm()}>
              {busy ? "Añadiendo…" : "Confirmar"}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}
