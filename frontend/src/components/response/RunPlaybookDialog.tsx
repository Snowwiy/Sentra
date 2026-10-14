import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../../api/client";
import { responseApi } from "../../api/sentra";
import type { PlaybookPreview, PlaybookRun, ResponseIssue } from "../../api/types";
import { errorMessage } from "../../lib/format";
import { blockedInfo, newIdempotencyKey, ROLE_REQUIRED_LABELS } from "../../lib/response";
import { usePolling } from "../../lib/usePolling";
import { config } from "../../config";
import { Modal } from "../Modal";
import { ErrorState, LoadingState } from "../StateViews";
import { IssueList, LiveRun, RiskBadge } from "./ResponseViews";

function asError(err: unknown): string {
  if (err instanceof ApiError && err.code === "confirmation_required") {
    return "Este playbook cambia datos: marca la confirmación explícita antes de ejecutarlo.";
  }
  return err instanceof Error ? errorMessage(err) : String(err);
}

export interface TargetOption {
  assetId: string;
  label: string;
}

function PlaybookPreviewView({ preview }: { preview: PlaybookPreview }) {
  return (
    <div className="stack">
      <dl className="fields">
        <div className="field">
          <dt>Playbook</dt>
          <dd>
            {preview.name} <span className="muted small">v{preview.version}</span>
          </dd>
        </div>
        <div className="field">
          <dt>Objetivo</dt>
          <dd>{preview.target_label}</dd>
        </div>
        <div className="field">
          <dt>Riesgo</dt>
          <dd>
            <RiskBadge risk={preview.risk_level} />
          </dd>
        </div>
        <div className="field">
          <dt>Rol mínimo</dt>
          <dd>{ROLE_REQUIRED_LABELS[preview.required_role] ?? preview.required_role}</dd>
        </div>
        <div className="field">
          <dt>Requiere confirmación</dt>
          <dd>{preview.requires_confirmation ? "Sí" : "No"}</dd>
        </div>
      </dl>
      <div className="table-wrap">
        <table className="table table--compact">
          <thead>
            <tr>
              <th>#</th>
              <th>Acción</th>
              <th>Riesgo</th>
              <th>Bloqueos y avisos</th>
            </tr>
          </thead>
          <tbody>
            {preview.steps.map((step) => (
              <tr key={step.order}>
                <td>{step.order}</td>
                <td>
                  {step.action_name}
                  {step.requires_agent && <span className="muted small"> · agente</span>}
                </td>
                <td>
                  <RiskBadge risk={step.risk_level} />
                </td>
                <td>
                  {step.blockers.length === 0 && step.warnings.length === 0 && <span className="muted">—</span>}
                  {step.blockers.map((b, i) => (
                    <div key={`b${i}`} className="small">
                      Bloqueo: {b.message} <span className="muted mono">({b.code})</span>
                    </div>
                  ))}
                  {step.warnings.map((w, i) => (
                    <div key={`w${i}`} className="muted small">
                      Aviso: {w.message} <span className="mono">({w.code})</span>
                    </div>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <IssueList issues={preview.blockers} title="No se puede ejecutar:" />
    </div>
  );
}

/**
 * Lanza un playbook sobre un activo: elige playbook y objetivo, previsualiza en el servidor y
 * ejecuta solo sin bloqueos (con confirmación explícita si algún paso la exige). `playbookKeys`
 * limita los playbooks ofrecidos (p. ej. "Investigar" desde una detección).
 */
export function RunPlaybookDialog({
  targets,
  playbookKeys,
  incidentId,
  detectionId,
  title = "Ejecutar playbook",
  onClose,
  onDone,
}: {
  targets: TargetOption[];
  playbookKeys?: string[];
  incidentId?: string;
  detectionId?: string;
  title?: string;
  onClose: () => void;
  onDone?: (run: PlaybookRun) => void;
}) {
  const [idempotencyKey] = useState(newIdempotencyKey);
  const [assetId, setAssetId] = useState(targets[0]?.assetId ?? "");
  const [chosen, setChosen] = useState("");
  const [reason, setReason] = useState("");
  const [preview, setPreview] = useState<PlaybookPreview>();
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [blocked, setBlocked] = useState<{ runId: string | null; blockers: ResponseIssue[] }>();
  const [run, setRun] = useState<PlaybookRun>();

  const fetchPlaybooks = useCallback(
    (signal: AbortSignal) => responseApi.playbooks(assetId || undefined, signal),
    [assetId],
  );
  const list = usePolling(fetchPlaybooks, config.refreshIntervalMs, !run, true);
  const playbooks = (list.data?.items ?? []).filter((p) => !playbookKeys || playbookKeys.includes(p.key));
  // Sin elección explícita se propone el primer playbook activo de la lista.
  const playbookId = chosen || playbooks.find((p) => p.enabled)?.playbook_id || "";

  // La previsualización se pide al tener playbook y activo; solo cambia estado al responder.
  useEffect(() => {
    if (!playbookId || !assetId) return;
    let cancelled = false;
    responseApi
      .previewPlaybook(playbookId, {
        target_id: assetId,
        incident_id: incidentId ?? null,
        detection_id: detectionId ?? null,
        idempotency_key: idempotencyKey,
      })
      .then(
        (result) => !cancelled && setPreview(result),
        (err: unknown) => !cancelled && setError(asError(err)),
      );
    return () => {
      cancelled = true;
    };
  }, [playbookId, assetId, incidentId, detectionId, idempotencyKey]);

  const invalidate = () => {
    setPreview(undefined);
    setConfirmed(false);
    setBlocked(undefined);
    setError(undefined);
  };

  const execute = async () => {
    if (!preview) return;
    setBusy(true);
    setError(undefined);
    setBlocked(undefined);
    try {
      const result = await responseApi.executePlaybook(preview.playbook_id, {
        target_id: assetId,
        incident_id: incidentId ?? null,
        detection_id: detectionId ?? null,
        confirm: preview.requires_confirmation && confirmed,
        reason: reason.trim() || null,
        idempotency_key: idempotencyKey,
      });
      setRun(result);
      onDone?.(result);
    } catch (err) {
      const info = blockedInfo(err);
      if (info) setBlocked({ runId: info.runId, blockers: info.blockers });
      else setError(asError(err));
    } finally {
      setBusy(false);
    }
  };

  // La previsualización debe corresponder a la selección actual (evita ejecutar una anterior).
  const current = preview && preview.playbook_id === playbookId && preview.target_id === assetId ? preview : undefined;
  const canExecute =
    !busy &&
    current !== undefined &&
    current.allowed &&
    current.blockers.length === 0 &&
    (!current.requires_confirmation || confirmed);

  return (
    <Modal title={title} onClose={busy ? () => undefined : onClose} wide>
      {run ? (
        <div className="stack">
          <LiveRun initial={run} />
          <div className="modal__actions">
            <button type="button" className="button button--primary" onClick={onClose}>
              Cerrar
            </button>
          </div>
        </div>
      ) : list.loading ? (
        <LoadingState label="Cargando playbooks…" />
      ) : !list.data ? (
        <ErrorState message={list.error ? errorMessage(list.error) : "Sin datos"} onRetry={list.refresh} />
      ) : (
        <div className="stack">
          {playbooks.length === 0 ? (
            <div className="banner" role="note">
              No hay playbooks disponibles para esta acción.
            </div>
          ) : (
            <label className="form-field">
              <span className="muted small">Playbook</span>
              <select
                className="input input--select"
                aria-label="Playbook"
                value={playbookId}
                onChange={(e) => {
                  setChosen(e.target.value);
                  invalidate();
                }}
              >
                {playbooks.map((p) => (
                  <option key={p.playbook_id} value={p.playbook_id} disabled={!p.enabled}>
                    {p.name}
                    {p.enabled ? "" : " (desactivado)"}
                  </option>
                ))}
              </select>
            </label>
          )}
          {targets.length > 1 && (
            <label className="form-field">
              <span className="muted small">Activo objetivo</span>
              <select
                className="input input--select"
                aria-label="Activo objetivo"
                value={assetId}
                onChange={(e) => {
                  setAssetId(e.target.value);
                  invalidate();
                }}
              >
                {targets.map((t) => (
                  <option key={t.assetId} value={t.assetId}>
                    {t.label}
                  </option>
                ))}
              </select>
            </label>
          )}
          {targets.length === 0 && (
            <div className="banner banner--warn" role="alert">
              No hay ningún activo existente sobre el que ejecutar el playbook.
            </div>
          )}
          <label className="form-field">
            <span className="muted small">Motivo (opcional, queda en la auditoría)</span>
            <input className="input" maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Motivo de la ejecución" />
          </label>
          {current ? (
            <PlaybookPreviewView preview={current} />
          ) : (
            playbookId && assetId && !error && <p className="muted small">Calculando previsualización…</p>
          )}
          {current?.requires_confirmation && current.blockers.length === 0 && (
            <label className="checkbox">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> Confirmo
              que quiero ejecutar este playbook sobre {current.target_label}
            </label>
          )}
          {blocked && (
            <div className="stack">
              <IssueList issues={blocked.blockers} title="La política de respuesta bloqueó el playbook:" />
              {blocked.runId && (
                <p className="muted small">
                  El intento quedó registrado:{" "}
                  <Link to={`/playbooks?tab=runs&run=${encodeURIComponent(blocked.runId)}`}>ver run bloqueado</Link>
                </p>
              )}
            </div>
          )}
          {error && (
            <div className="banner banner--warn" role="alert">
              {error}
            </div>
          )}
          <div className="modal__actions">
            <button type="button" className="button" onClick={onClose} disabled={busy}>
              Cancelar
            </button>
            <button
              type="button"
              className={`button ${current?.requires_confirmation ? "button--danger" : "button--primary"}`}
              disabled={!canExecute}
              onClick={() => void execute()}
            >
              {busy ? "Procesando…" : "Ejecutar playbook"}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
