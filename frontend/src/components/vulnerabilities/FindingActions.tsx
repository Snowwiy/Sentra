// Acciones del flujo de trabajo de un finding (Fase 5B).
//
// Los botones salen de `finding.actions` (lo decide el servidor según rol y estado) y cada
// petición lleva la `version` leída: si otro analista o la evaluación lo cambió, el servidor
// responde 409 y la página lo muestra sin reintentar ni pisar nada.
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { vulnerabilitiesApi } from "../../api/sentra";
import type { FindingAction, FindingDetail, IncidentLevel } from "../../api/types";
import { LEVEL_LABELS, LEVEL_ORDER } from "../../lib/incidents";
import { ACTION_LABELS, REASON_REQUIRED } from "../../lib/vulnerabilities";
import { Modal } from "../Modal";

export type RunFindingAction = (action: () => Promise<unknown>) => Promise<boolean>;

const WORKFLOW: FindingAction[] = ["acknowledge", "mitigating", "resolve", "accept-risk", "false-positive", "reopen"];

/** Fecha local "YYYY-MM-DD" dentro de `days` días (límites del selector de caducidad). */
function dateIn(days: number): string {
  const date = new Date(Date.now() + days * 86_400_000);
  return date.toISOString().slice(0, 10);
}

function ActionDialog({
  finding,
  action,
  run,
  onClose,
}: {
  finding: FindingDetail;
  action: FindingAction;
  run: RunFindingAction;
  onClose: () => void;
}) {
  const [reason, setReason] = useState("");
  const [override, setOverride] = useState(false);
  const [until, setUntil] = useState("");
  const [busy, setBusy] = useState(false);
  const required = REASON_REQUIRED.has(action);
  // Resolver a mano algo que la evidencia sigue viendo vulnerable exige confirmarlo.
  const evidenceSaysVulnerable =
    action === "resolve" && (finding.match_state === "confirmed" || finding.match_state === "probable");
  const valid = (!required || reason.trim().length >= 3) && (!evidenceSaysVulnerable || override);

  const submit = async () => {
    setBusy(true);
    const ok = await run(() =>
      vulnerabilitiesApi.act(finding.finding_id, action, finding.version, {
        reason,
        overrideEvidence: override,
        // Fin del día elegido, en hora local del navegador.
        acceptedUntil: until ? new Date(`${until}T23:59:59`).toISOString() : null,
      }),
    );
    setBusy(false);
    if (ok) onClose();
  };

  return (
    <Modal title={`${ACTION_LABELS[action]} · ${finding.vulnerability_id}`} onClose={busy ? () => undefined : onClose}>
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          if (valid) void submit();
        }}
      >
        <label className="form-field">
          <span className="muted small">Motivo{required ? " (obligatorio)" : " (opcional)"}</span>
          <textarea
            className="input"
            rows={3}
            maxLength={1000}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
        {evidenceSaysVulnerable && (
          <label className="form-field form-field--inline">
            <input type="checkbox" checked={override} onChange={(event) => setOverride(event.target.checked)} />
            <span className="small">
              La evidencia sigue indicando que la versión instalada es vulnerable. Confirmo que está corregida por
              otra vía (se audita).
            </span>
          </label>
        )}
        {action === "accept-risk" && (
          <label className="form-field">
            <span className="muted small">Caduca el (opcional, máximo 2 años; al vencer vuelve a abierta)</span>
            <input
              type="date"
              className="input"
              min={dateIn(1)}
              max={dateIn(729)}
              value={until}
              onChange={(event) => setUntil(event.target.value)}
            />
          </label>
        )}
        {action === "false-positive" && (
          <p className="muted small">
            Si cambian la versión instalada, el registro del catálogo o el estado técnico, Sentra lo vuelve a evaluar.
          </p>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || !valid}>
            {busy ? "Procesando…" : ACTION_LABELS[action]}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function IncidentDialog({ finding, onClose }: { finding: FindingDetail; onClose: () => void }) {
  const navigate = useNavigate();
  const [title, setTitle] = useState("");
  const [priority, setPriority] = useState<IncidentLevel | "">("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const incident = await vulnerabilitiesApi.createIncident(finding.finding_id, finding.version, {
        title: title || undefined,
        priority: priority || undefined,
      });
      navigate(`/incidents/${incident.incident_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  };
  return (
    <Modal title="Crear incidente desde la vulnerabilidad" onClose={busy ? () => undefined : onClose}>
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <label className="form-field">
          <span className="muted small">Título (opcional)</span>
          <input
            className="input"
            maxLength={200}
            placeholder={`${finding.vulnerability_id} en ${finding.asset.name}`}
            value={title}
            onChange={(event) => setTitle(event.target.value)}
          />
        </label>
        <label className="form-field">
          <span className="muted small">Prioridad (opcional)</span>
          <select
            className="input input--select"
            value={priority}
            onChange={(event) => setPriority(event.target.value as IncidentLevel | "")}
          >
            <option value="">Según la prioridad del finding</option>
            {LEVEL_ORDER.map((level) => (
              <option key={level} value={level}>
                {LEVEL_LABELS[level]}
              </option>
            ))}
          </select>
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
          <button type="submit" className="button button--primary" disabled={busy}>
            {busy ? "Creando…" : "Crear incidente"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function FindingActions({
  finding,
  run,
  busy,
}: {
  finding: FindingDetail;
  run: RunFindingAction;
  busy: boolean;
}) {
  const [action, setAction] = useState<FindingAction>();
  const [incident, setIncident] = useState(false);
  const available = WORKFLOW.filter((a) => finding.actions.includes(a));
  if (available.length === 0 && !finding.actions.includes("incident")) return null;
  return (
    <div className="actions" aria-label="Acciones">
      {available.map((a) => (
        <button key={a} type="button" className="button" disabled={busy} onClick={() => setAction(a)}>
          {ACTION_LABELS[a]}
        </button>
      ))}
      {finding.actions.includes("incident") && (
        <button type="button" className="button button--primary" disabled={busy} onClick={() => setIncident(true)}>
          Crear incidente
        </button>
      )}
      {action && <ActionDialog finding={finding} action={action} run={run} onClose={() => setAction(undefined)} />}
      {incident && <IncidentDialog finding={finding} onClose={() => setIncident(false)} />}
    </div>
  );
}
