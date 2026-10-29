import { useState } from "react";
import { Link } from "react-router-dom";
import { correlationReviewApi } from "../../api/sentra7b";
import type { CorrelationReviewApplyResult, CorrelationReviewPreview } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { REVIEW_VERDICT_LABELS } from "../../lib/detectionDetails";
import { errorMessage } from "../../lib/format";
import { ErrorState } from "../StateViews";

/**
 * Fase 7B-Fix1: revisión explícita de las CORR-002 creadas con la v4, que unía cualquier
 * PowerShell con cualquier servicio nuevo. Primero la vista previa (sin efectos); después el
 * administrador marca las que ha revisado y confirma. Solo se resuelven las que la v5 no ve
 * causales; la evidencia y los SCR-001 se conservan y queda auditado.
 */
export function CorrelationReviewPanel({ assetId }: { assetId?: string }) {
  const canManage = useAuth().can("detections:manage");
  const [preview, setPreview] = useState<CorrelationReviewPreview | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirmed, setConfirmed] = useState(false);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CorrelationReviewApplyResult | null>(null);
  if (!canManage) return null;

  const load = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const data = await correlationReviewApi.preview(assetId);
      setPreview(data);
      setSelected(new Set(data.items.filter((item) => item.would_resolve).map((item) => item.detection_id)));
      setConfirmed(false);
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await correlationReviewApi.apply([...selected], note));
      setPreview(null);
      setSelected(new Set());
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
    } finally {
      setBusy(false);
    }
  };

  const toggle = (id: string) =>
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <details className="panel panel--padded" aria-label="Revisión de correlaciones CORR-002">
      <summary>Revisar correlaciones CORR-002 anteriores a la v5</summary>
      <div className="stack">
        <p className="small muted">
          La v4 unía cualquier PowerShell sospechoso con cualquier servicio nuevo de la ventana. La vista previa reevalúa
          cada una con la evidencia guardada; al aplicar solo se resuelven las marcadas que no tienen relación causal.
          Nada se borra y los SCR-001 siguen activos.
        </p>
        <div className="actions">
          <button type="button" className="button" onClick={load} disabled={busy}>
            {preview ? "Actualizar vista previa" : "Vista previa"}
          </button>
        </div>
        {error && <ErrorState message={error} />}
        {result && (
          <p role="status">
            Revisadas {result.reviewed}: {result.resolved} resueltas, {result.kept} se mantienen. El riesgo se recalcula.
          </p>
        )}
        {preview && preview.items.length === 0 && <p className="muted">No hay correlaciones anteriores a la v5 activas.</p>}
        {preview && preview.items.length > 0 && (
          <>
            <p className="small">
              {preview.causal} causales, {preview.temporal_only} solo temporales, {preview.insufficient_evidence} sin
              evidencia suficiente.
            </p>
            <ul className="plain-list" aria-label="Correlaciones a revisar">
              {preview.items.map((item) => (
                <li key={item.detection_id} className="stack">
                  <label className="checkbox">
                    <input
                      type="checkbox"
                      checked={selected.has(item.detection_id)}
                      disabled={!item.would_resolve}
                      onChange={() => toggle(item.detection_id)}
                    />{" "}
                    <Link to={`/detections/${item.detection_id}`}>{item.title}</Link>
                    {item.hostname && <span className="muted"> · {item.hostname}</span>}
                    {" · "}
                    <strong>{REVIEW_VERDICT_LABELS[item.verdict] ?? item.verdict}</strong>
                  </label>
                  <span className="small">{item.explanation.join(" ")}</span>
                </li>
              ))}
            </ul>
            <label className="field">
              <span>Nota de la revisión (opcional)</span>
              <input value={note} maxLength={500} onChange={(event) => setNote(event.target.value)} />
            </label>
            <label className="checkbox">
              <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /> He
              revisado la evidencia de las {selected.size} correlaciones marcadas
            </label>
            <div className="actions">
              <button
                type="button"
                className="button button--primary"
                onClick={apply}
                disabled={busy || !confirmed || selected.size === 0}
              >
                Aplicar revisión
              </button>
            </div>
          </>
        )}
      </div>
    </details>
  );
}
