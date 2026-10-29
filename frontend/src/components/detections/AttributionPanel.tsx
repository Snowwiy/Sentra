import { useCallback, useState } from "react";
import { attributionApi } from "../../api/sentra7b";
import type { AnalystVerdict } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { VERDICT_CLASS, VERDICT_LABELS } from "../../lib/attribution";
import { usePolling } from "../../lib/usePolling";
import { Modal } from "../Modal";
import { ErrorState, LoadingState } from "../StateViews";

const RESULT_LABELS: Record<string, string> = {
  pass: "Coincide",
  fail: "No coincide",
  missing: "Falta el dato",
  not_required: "No se exige",
};

const RISK_EFFECT: Record<string, string> = {
  excluded: "No suma riesgo activo mientras siga verificada.",
  kept: "Sigue sumando riesgo.",
  kept_exposure: "La exposición del puerto sigue sumando riesgo aunque el proceso sea legítimo.",
};

const ANALYST_OPTIONS: { value: AnalystVerdict; label: string }[] = [
  { value: "confirmed_malicious", label: VERDICT_LABELS.confirmed_malicious },
  { value: "suspicious_unverified", label: VERDICT_LABELS.suspicious_unverified },
  { value: "insufficient_evidence", label: VERDICT_LABELS.insufficient_evidence },
];

interface Check {
  check: string;
  result: string;
  expected: unknown;
  observed: unknown;
}

interface Item {
  kind: string;
  label: string;
  occurred_at: string;
  result: string;
  checks: Check[];
  missing: string[];
  context_only: boolean;
}

interface Detail {
  operation?: { title?: string; operation_key?: string; version?: number } | null;
  items?: Item[];
  missing_evidence?: { code: string; how_to_obtain: string }[];
  explanation?: string[];
  tamper_suspected?: boolean;
  risk_effect?: string;
  // Política de autorización: una operación la describiría, pero no se aplica sola.
  review_required?: { operation_id: string; title: string; reason: string } | null;
}

const REVIEW_REASON: Record<string, string> = {
  approved_after_activity: "se aprobó después de esta actividad",
  auto_recognition_disabled: "el reconocimiento automático está desactivado en el servidor",
};

function show(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  return typeof value === "string" ? value : JSON.stringify(value);
}

function VerdictDialog({
  detectionId,
  onClose,
  onDone,
}: {
  detectionId: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [verdict, setVerdict] = useState<AnalystVerdict>("confirmed_malicious");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const trimmed = reason.trim();
  const submit = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await attributionApi.verdict(detectionId, verdict, trimmed);
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
      setBusy(false);
    }
  };
  return (
    <Modal title="Veredicto del analista" onClose={busy ? () => undefined : onClose}>
      <div className="stack">
        <p className="small muted">
          Queda en el historial y en la auditoría. «Verificada como legítima» no se puede fijar a mano: exige una
          operación de mantenimiento aprobada que cubra toda la evidencia.
        </p>
        <label className="field">
          <span>Veredicto</span>
          <select className="input input--select" value={verdict} onChange={(e) => setVerdict(e.target.value as AnalystVerdict)}>
            {ANALYST_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Motivo</span>
          <textarea className="input" rows={3} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
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
          <button
            type="button"
            className="button button--primary"
            disabled={busy || trimmed.length < 3}
            onClick={() => void submit()}
          >
            {busy ? "Guardando…" : "Guardar veredicto"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

/**
 * Fase 7B.1: atribución de la detección a una operación de mantenimiento. Muestra cada
 * comprobación (hash, ruta, cuenta, ventana, firma...), lo que falta y cómo obtenerlo sin
 * desactivar controles, el efecto en el riesgo y el historial de veredictos. Nunca se marca
 * como legítimo algo por su nombre: lo decide el servidor con evidencia.
 */
export function AttributionPanel({ detectionId }: { detectionId: string }) {
  const canManage = useAuth().can("detections:manage");
  const fetcher = useCallback((signal: AbortSignal) => attributionApi.get(detectionId, signal), [detectionId]);
  const state = usePolling(fetcher, config.refreshIntervalMs * 2);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string>();
  const [deciding, setDeciding] = useState(false);
  const data = state.data;

  if (!data) {
    return (
      <section className="panel panel--padded" aria-label="Atribución">
        <h2>Atribución</h2>
        {state.error ? (
          <ErrorState message={errorMessage(state.error)} onRetry={state.refresh} />
        ) : (
          <LoadingState label="Cargando atribución…" />
        )}
      </section>
    );
  }
  // Las reglas sin artefacto que comparar no muestran el panel.
  if (!data.attributable) return null;
  const detail = (data.attribution ?? {}) as Detail;
  const reevaluate = async () => {
    setBusy(true);
    setActionError(undefined);
    try {
      await attributionApi.evaluate(detectionId);
      state.refresh();
    } catch (err) {
      setActionError(errorMessage(err instanceof Error ? err : new Error(String(err))));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel panel--padded" aria-label="Atribución">
      <h2>
        Atribución{" "}
        {data.verdict && <span className={`badge ${VERDICT_CLASS[data.verdict]}`}>{VERDICT_LABELS[data.verdict]}</span>}
      </h2>
      {data.evaluated_at && (
        <p className="small muted" title={formatDateTime(data.evaluated_at)}>
          Evaluada {formatRelative(data.evaluated_at)}
          {detail.risk_effect && ` · ${RISK_EFFECT[detail.risk_effect] ?? detail.risk_effect}`}
        </p>
      )}
      {detail.tamper_suspected && (
        <div className="banner banner--warn" role="alert">
          Un script coincide en ruta pero no en SHA-256, o un servicio coincide en nombre pero no en ImagePath: posible suplantación.
        </div>
      )}
      {detail.review_required && (
        <div className="banner banner--warn" role="status">
          La operación «{detail.review_required.title}» describiría esta actividad, pero{" "}
          {REVIEW_REASON[detail.review_required.reason] ?? detail.review_required.reason}. La detección sigue activa hasta
          que un administrador la revise con «Vista previa» y «Aplicar» en Administración → Mantenimiento.
        </div>
      )}
      {detail.operation ? (
        <p>
          Operación: <strong>{detail.operation.title}</strong>{" "}
          <span className="muted small">
            ({detail.operation.operation_key} v{detail.operation.version})
          </span>
        </p>
      ) : (
        <p className="muted">Ninguna operación de mantenimiento aprobada cubre esta evidencia.</p>
      )}
      {detail.explanation && detail.explanation.length > 0 && (
        <ul className="small">
          {detail.explanation.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}
      {(detail.items ?? []).map((item, index) => (
        <details key={`${item.kind}-${item.occurred_at}-${index}`} className="attribution-item" open={item.result === "fail"}>
          <summary>
            {item.label} <span className="muted small">({RESULT_LABELS[item.result] ?? item.result}{item.context_only ? ", contexto" : ""})</span>
          </summary>
          <div className="table-wrap">
            <table className="table table--nostack table--compact">
              <thead>
                <tr>
                  <th>Comprobación</th>
                  <th>Resultado</th>
                  <th>Esperado</th>
                  <th>Observado</th>
                </tr>
              </thead>
              <tbody>
                {item.checks.map((c, i) => (
                  <tr key={`${c.check}-${i}`}>
                    <td>{c.check}</td>
                    <td>{RESULT_LABELS[c.result] ?? c.result}</td>
                    <td className="mono small">{show(c.expected)}</td>
                    <td className="mono small">{show(c.observed)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      ))}
      {detail.missing_evidence && detail.missing_evidence.length > 0 && (
        <div>
          <h3 className="small">Evidencia que falta y cómo obtenerla</h3>
          <ul className="small">
            {detail.missing_evidence.map((m) => (
              <li key={m.code}>
                <span className="mono">{m.code}</span>: {m.how_to_obtain || "sin indicación"}
              </li>
            ))}
          </ul>
        </div>
      )}
      {data.history.length > 0 && (
        <details>
          <summary>Historial ({data.history.length})</summary>
          <ol className="small">
            {data.history.map((h) => (
              <li key={h.id}>
                {formatDateTime(h.created_at)}: {VERDICT_LABELS[h.verdict]} ({h.source === "analyst" ? `analista ${h.actor}` : "sistema"})
                {h.reason && ` · ${h.reason}`}
              </li>
            ))}
          </ol>
        </details>
      )}
      {actionError && (
        <div className="banner banner--warn" role="alert">
          {actionError}
        </div>
      )}
      {canManage && (
        <div className="actions">
          <button type="button" className="button button--small" disabled={busy} onClick={() => void reevaluate()}>
            {busy ? "Reevaluando…" : "Reevaluar"}
          </button>
          <button type="button" className="button button--small" onClick={() => setDeciding(true)}>
            Veredicto del analista…
          </button>
        </div>
      )}
      {deciding && <VerdictDialog detectionId={detectionId} onClose={() => setDeciding(false)} onDone={state.refresh} />}
    </section>
  );
}
