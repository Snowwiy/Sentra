import { useCallback, useState, type ReactNode } from "react";
import { ApiError } from "../../api/client";
import { lifecycleApi } from "../../api/sentra";
import type {
  Asset,
  AssetReconcileResult,
  DuplicateAsset,
  DuplicateCandidate,
  DuplicateEvidence,
  ReconcilePreview,
} from "../../api/types";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  ACK_WEAK_EVIDENCE,
  CONFIDENCE_CLASSES,
  CONFIDENCE_LABELS,
  CONFLICT_LABELS,
  DISPOSITION_LABELS,
  DUPLICATE_REASON_LABELS,
  NOT_CONFIRMED_HINT,
  STRENGTH_CLASSES,
  STRENGTH_LABELS,
  blockerLabel,
  historyText,
  isAssetId,
  lifecycleError,
  needsAcknowledgement,
  reasonLabel,
  warningLabel,
} from "../../lib/lifecycle";
import { usePolling } from "../../lib/usePolling";
import { CredentialBadge } from "../agents/AgentBadges";
import { Modal } from "../Modal";
import { MethodBadge } from "../NetworkBadges";

const STEPS = ["Origen", "Destino", "Evidencia", "Impacto", "Confirmación", "Resultado"] as const;
type Step = 0 | 1 | 2 | 3 | 4 | 5;

// Los candidatos solo se cargan una vez al abrir el asistente.
const CANDIDATES_REFRESH_MS = 10 * 60_000;

/** Lista de evidencias con su fuerza (fuerte / media / débil). */
export function EvidenceList({ evidence }: { evidence: DuplicateEvidence[] }) {
  if (evidence.length === 0) return <span className="muted">Sin evidencia</span>;
  return (
    <ul className="small" aria-label="Evidencia">
      {evidence.map((item) => (
        <li key={item.code}>
          {DUPLICATE_REASON_LABELS[item.code] ?? item.code}{" "}
          <span className={`badge ${STRENGTH_CLASSES[item.strength] ?? "badge--muted"}`}>
            {STRENGTH_LABELS[item.strength] ?? item.strength}
          </span>
        </li>
      ))}
    </ul>
  );
}

function ConflictList({ conflicts }: { conflicts: string[] }) {
  if (conflicts.length === 0) return null;
  return (
    <p className="banner banner--warn">
      Conflicto: {conflicts.map((c) => CONFLICT_LABELS[c as keyof typeof CONFLICT_LABELS] ?? reasonLabel(c)).join("; ")}.
    </p>
  );
}

function Side({ title, asset }: { title: string; asset: DuplicateAsset }) {
  const row = (label: string, value: ReactNode) => (
    <div className="field">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
  return (
    <section aria-label={title}>
      <h3 className="small">{title}</h3>
      <dl className="fields">
        {row("Nombre", asset.display_name)}
        {row("Hostname", asset.hostname ?? "—")}
        {row("IP", <span className="mono">{asset.primary_ip}</span>)}
        {row("MAC", <span className="mono">{asset.mac_address ?? "—"}</span>)}
        {row("SO", asset.os_name ?? "—")}
        {row("Método", <MethodBadge method={asset.monitoring_method} />)}
        {row("Agente", asset.agent_version ? `v${asset.agent_version}` : "—")}
        {row("Credencial", asset.credential_status ? <CredentialBadge status={asset.credential_status} /> : "—")}
        {row("Último contacto", <span title={formatDateTime(asset.last_seen_at)}>{formatRelative(asset.last_seen_at)}</span>)}
        {row("Asset ID", <span className="mono small">{asset.asset_id}</span>)}
      </dl>
    </section>
  );
}

function previewErrorText(error: unknown): string {
  if (error instanceof ApiError && (error.status === 404 || error.status === 400)) {
    return "No existe ningún activo con ese Asset ID (o no es válido como destino).";
  }
  return errorMessage(error instanceof Error ? error : new Error(String(error)));
}

/**
 * Reconciliación manual desde el activo SOURCE (el agente nuevo): origen → destino →
 * evidencia → impacto → confirmación → resultado. El servidor vuelve a validar todo al
 * confirmar; la UI nunca presenta un posible duplicado como confirmado.
 */
export function ReconcileWizard({
  source,
  initialTargetId,
  onClose,
  onDone,
}: {
  source: Asset;
  initialTargetId?: string;
  onClose: () => void;
  /** Tras reconciliar, "Ir al activo existente". */
  onDone: (targetId: string) => void;
}) {
  const [step, setStep] = useState<Step>(0);
  const [selected, setSelected] = useState(initialTargetId ?? "");
  const [manual, setManual] = useState("");
  const [preview, setPreview] = useState<ReconcilePreview>();
  const [ack, setAck] = useState(false);
  const [forceAck, setForceAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [result, setResult] = useState<AssetReconcileResult>();

  const fetchCandidates = useCallback(
    (signal: AbortSignal) => lifecycleApi.candidates(source.asset_id, signal),
    [source.asset_id],
  );
  const candidates = usePolling(fetchCandidates, CANDIDATES_REFRESH_MS);
  const items: DuplicateCandidate[] = candidates.data?.items ?? [];

  const targetId = (manual.trim() || selected).toLowerCase();
  const targetProblem = !targetId
    ? "Elige un candidato o pega el Asset ID del activo existente."
    : !isAssetId(targetId)
      ? "El Asset ID no tiene un formato válido."
      : targetId === source.asset_id.toLowerCase()
        ? "El destino no puede ser el mismo activo que el origen."
        : undefined;

  const go = (next: Step) => {
    setError(undefined);
    setStep(next);
  };

  async function loadPreview() {
    if (targetProblem) {
      setError(targetProblem);
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const data = await lifecycleApi.reconcilePreview(source.asset_id, targetId);
      setPreview(data);
      setAck(false);
      setForceAck(false);
      setStep(2);
    } catch (err) {
      setError(previewErrorText(err));
    } finally {
      setBusy(false);
    }
  }

  const ackRequired = Boolean(preview?.requires_acknowledgement) || forceAck;

  async function confirm() {
    if (!preview) return;
    if (ackRequired && !ack) {
      setError("Marca la confirmación explícita para continuar.");
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const done = await lifecycleApi.reconcile(
        source.asset_id,
        preview.target.asset_id,
        preview.source.version,
        preview.target.version,
        ackRequired && ack,
      );
      setResult(done);
      setStep(5);
    } catch (err) {
      if (needsAcknowledgement(err)) {
        setForceAck(true);
        setAck(false);
      }
      setError(errorMessage(lifecycleError(err)));
    } finally {
      setBusy(false);
    }
  }

  const back = (to: Step) => (
    <button type="button" className="button" disabled={busy} onClick={() => go(to)}>
      Atrás
    </button>
  );

  let body: ReactNode;
  let actions: ReactNode;
  if (step === 0) {
    body = (
      <>
        <p>
          El <strong>origen</strong> es este activo: el agente nuevo (recién enrolado). Su agente pasará a informar en el
          activo existente que elijas como <strong>destino</strong>, que conserva su historial.
        </p>
        <dl className="fields">
          <div className="field">
            <dt>Nombre</dt>
            <dd>{source.display_name}</dd>
          </div>
          <div className="field">
            <dt>IP</dt>
            <dd className="mono">{source.primary_ip}</dd>
          </div>
          <div className="field">
            <dt>Asset ID</dt>
            <dd className="mono small">{source.asset_id}</dd>
          </div>
          <div className="field">
            <dt>Método</dt>
            <dd>
              <MethodBadge method={source.monitoring_method} />
            </dd>
          </div>
          <div className="field">
            <dt>Agente</dt>
            <dd>{source.agent_version ? `v${source.agent_version}` : "—"}</dd>
          </div>
        </dl>
        {source.monitoring_method !== "agent" && (
          <p className="banner banner--warn">Este activo no tiene agente: el servidor rechazará la reconciliación.</p>
        )}
      </>
    );
    actions = (
      <button type="button" className="button button--primary" onClick={() => go(1)}>
        Siguiente
      </button>
    );
  } else if (step === 1) {
    body = (
      <>
        <p className="muted small">{NOT_CONFIRMED_HINT}</p>
        {candidates.loading ? (
          <p className="muted small">Buscando candidatos…</p>
        ) : items.length === 0 ? (
          <p className="muted small">No hay candidatos sugeridos para este activo.</p>
        ) : (
          <fieldset className="stack">
            <legend className="small">Candidatos sugeridos</legend>
            {items.map((c) => (
              <label key={c.asset.asset_id} className="checkbox small">
                <input
                  type="radio"
                  name="reconcile-target"
                  value={c.asset.asset_id}
                  checked={!manual.trim() && selected === c.asset.asset_id}
                  disabled={c.asset.asset_id === source.asset_id}
                  onChange={() => {
                    setSelected(c.asset.asset_id);
                    setManual("");
                  }}
                />{" "}
                <strong>{c.asset.display_name}</strong> <span className="mono">{c.asset.primary_ip}</span>{" "}
                <span className={`badge ${CONFIDENCE_CLASSES[c.confidence]}`}>{CONFIDENCE_LABELS[c.confidence]}</span>
                {c.conflicts.length > 0 && <span className="badge badge--warn">Con conflictos</span>}
                {!c.reconcilable && (
                  <span className="muted"> · no reconciliable: {c.reconcile_blockers.map(blockerLabel).join("; ")}</span>
                )}
              </label>
            ))}
          </fieldset>
        )}
        <label className="form-field">
          O pega el Asset ID del activo existente
          <input
            className="input mono"
            aria-label="Asset ID del destino"
            value={manual}
            placeholder="00000000-0000-0000-0000-000000000000"
            maxLength={64}
            onChange={(event) => setManual(event.target.value)}
          />
        </label>
        {targetId && targetProblem && <p className="muted small">{targetProblem}</p>}
      </>
    );
    actions = (
      <>
        {back(0)}
        <button
          type="button"
          className="button button--primary"
          disabled={busy || Boolean(targetProblem)}
          onClick={() => void loadPreview()}
        >
          {busy ? "Cargando…" : "Ver evidencia"}
        </button>
      </>
    );
  } else if (step === 2 && preview) {
    body = (
      <>
        <p className="muted small">{NOT_CONFIRMED_HINT}</p>
        <p>
          <span className={`badge ${CONFIDENCE_CLASSES[preview.confidence]}`}>{CONFIDENCE_LABELS[preview.confidence]}</span>
        </p>
        <div className="panels-2">
          <Side title="Origen (agente nuevo)" asset={preview.source} />
          <Side title="Destino (activo existente)" asset={preview.target} />
        </div>
        <EvidenceList evidence={preview.evidence} />
        <ConflictList conflicts={preview.conflicts} />
        {preview.reconcile_warnings.length > 0 && (
          <p className="banner banner--warn">
            Avisos: {preview.reconcile_warnings.map(warningLabel).join("; ")}. Solo se puede reconciliar confirmando
            explícitamente que es la misma máquina.
          </p>
        )}
        {!preview.reconcilable && (
          <p className="banner banner--warn" role="alert">
            No se puede reconciliar: {preview.reconcile_blockers.map(blockerLabel).join("; ")}.
          </p>
        )}
      </>
    );
    actions = (
      <>
        {back(1)}
        <button type="button" className="button button--primary" disabled={!preview.reconcilable} onClick={() => go(3)}>
          Ver impacto
        </button>
      </>
    );
  } else if (step === 3 && preview) {
    body = (
      <ul className="stack" aria-label="Impacto">
        <li>
          <strong>Destino ({preview.target.display_name})</strong>: conserva su historial — {historyText(preview.target_history)}.
          El agente nuevo pasa a informar aquí.
        </li>
        <li>
          <strong>Origen ({preview.source.display_name})</strong>: {DISPOSITION_LABELS[preview.source_disposition]}{" "}
          {preview.source_disposition === "source_archived" && <>Queda con: {historyText(preview.source_history)}.</>}
          {preview.source_disposition_reasons.length > 0 && (
            <span className="muted small"> Motivos: {preview.source_disposition_reasons.map(reasonLabel).join("; ")}.</span>
          )}
        </li>
        <li>
          {preview.target_has_previous_agent
            ? "El agente anterior del destino queda como histórico: no vuelve a informar y su credencial no se reutiliza."
            : "El destino no tiene un agente anterior que pasar a histórico."}
        </li>
      </ul>
    );
    actions = (
      <>
        {back(2)}
        <button type="button" className="button button--primary" onClick={() => go(4)}>
          Continuar
        </button>
      </>
    );
  } else if (step === 4 && preview) {
    body = (
      <>
        <p>
          El agente de <strong>{preview.source.display_name}</strong> pasará a informar en{" "}
          <strong>{preview.target.display_name}</strong> ({preview.target.primary_ip}). El servidor vuelve a validar la
          evidencia; ninguna credencial sale del servidor.
        </p>
        {ackRequired && (
          <>
            <p className="banner banner--warn">
              {preview.reconcile_warnings.length > 0
                ? `Avisos: ${preview.reconcile_warnings.map(warningLabel).join("; ")}.`
                : "La evidencia es débil o contradictoria."}
            </p>
            <label className="checkbox">
              <input type="checkbox" checked={ack} onChange={(event) => setAck(event.target.checked)} /> {ACK_WEAK_EVIDENCE}
            </label>
          </>
        )}
      </>
    );
    actions = (
      <>
        {back(3)}
        <button
          type="button"
          className="button button--primary"
          disabled={busy || (ackRequired && !ack)}
          onClick={() => void confirm()}
        >
          {busy ? "Procesando…" : "Reconciliar"}
        </button>
      </>
    );
  } else if (step === 5 && result) {
    body = (
      <>
        <p className="banner banner--ok" role="status">
          Reconciliado: el agente informa ahora en el activo existente.
        </p>
        <p>{DISPOSITION_LABELS[result.source_disposition]}</p>
        {result.source_disposition_reasons.length > 0 && (
          <p className="muted small">Motivos: {result.source_disposition_reasons.map(reasonLabel).join("; ")}.</p>
        )}
        {result.previous_target_agent_id && (
          <p className="muted small">
            Agente anterior del destino (queda histórico): <span className="mono">{result.previous_target_agent_id}</span>
          </p>
        )}
        {result.acknowledged_warnings.length > 0 && (
          <p className="muted small">Avisos aceptados: {result.acknowledged_warnings.map(warningLabel).join("; ")}.</p>
        )}
      </>
    );
    actions = (
      <button type="button" className="button button--primary" onClick={() => onDone(result.target_asset_id)}>
        Ir al activo existente
      </button>
    );
  }

  return (
    <Modal title="Reconciliar con activo existente" onClose={busy ? () => undefined : onClose} wide>
      <div className="stack">
        <ol className="wizard__steps" aria-label="Pasos">
          {STEPS.map((label, index) => (
            <li
              key={label}
              className={index === step ? "is-current" : index < step ? "is-done" : undefined}
              aria-current={index === step ? "step" : undefined}
            >
              {label}
            </li>
          ))}
        </ol>
        {body}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          {step !== 5 && (
            <button type="button" className="button" disabled={busy} onClick={onClose}>
              Cancelar
            </button>
          )}
          {actions}
        </div>
      </div>
    </Modal>
  );
}
