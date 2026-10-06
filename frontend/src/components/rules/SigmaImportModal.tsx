import { useState } from "react";
import { rulesApi } from "../../api/sentra";
import type { SigmaImportResult, SigmaPreview } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { errorMessage } from "../../lib/format";
import { SIGMA_OUTCOME_LABELS, SIGMA_RESULT_LABELS } from "../../lib/rules";
import { DetectionSeverityBadge } from "../detections/DetectionBadges";
import { Modal } from "../Modal";
import { IssueList } from "./RuleBadges";

// Igual que MAX_SIGMA_CHARS del backend; el servidor vuelve a comprobarlo.
const MAX_BYTES = 64 * 1024;

/**
 * Importar una regla Sigma: pegar o subir un .yml, ver la vista previa (qué se soporta y qué
 * no) e importar. El YAML es contenido NO confiable: solo se lee como texto y se envía al
 * backend, que lo analiza con un cargador seguro. La regla importada nunca queda activa.
 */
export function SigmaImportModal({
  onClose,
  onImported,
}: {
  onClose: () => void;
  onImported: (result: SigmaImportResult) => void;
}) {
  const auth = useAuth();
  const canImport = auth.can("rules:manage");
  const [yaml, setYaml] = useState("");
  const [preview, setPreview] = useState<SigmaPreview>();
  const [result, setResult] = useState<SigmaImportResult>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const run = async <T,>(action: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(undefined);
    try {
      return await action();
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
      return undefined;
    } finally {
      setBusy(false);
    }
  };

  const onFile = (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      setError("El fichero supera 64 KB.");
      return;
    }
    // Solo texto: el contenido nunca se ejecuta ni se inserta como HTML.
    void file.text().then((text) => {
      setYaml(text);
      setPreview(undefined);
      setResult(undefined);
    });
  };

  const doPreview = async () => {
    const found = await run(() => rulesApi.sigmaPreview(yaml));
    if (found) {
      setPreview(found);
      setResult(undefined);
    }
  };

  const doImport = async () => {
    const duplicate = preview?.duplicate;
    const update =
      duplicate && duplicate.state === "changed" && duplicate.revision ? { revision: duplicate.revision } : undefined;
    const imported = await run(() => rulesApi.sigmaImport(yaml, update));
    if (imported) {
      setResult(imported);
      setPreview(imported.preview);
      onImported(imported);
    }
  };

  const tooBig = new TextEncoder().encode(yaml).length > MAX_BYTES;
  const duplicateState = preview?.duplicate.state ?? "none";

  return (
    <Modal title="Importar regla Sigma" onClose={busy ? () => undefined : onClose} wide>
      <div className="stack">
        <p className="muted small">
          Sentra admite un subconjunto de Sigma (selecciones, and/or/not, 1 of/all of, modificadores contains,
          startswith, endswith, all y count() con timeframe). Lo que no se puede ejecutar fielmente se marca como no
          soportado; nunca se finge cobertura. La regla importada queda desactivada hasta que la revises.
        </p>
        <label className="form-field">
          <span className="muted small">Fichero .yml (opcional)</span>
          <input
            type="file"
            accept=".yml,.yaml,text/yaml,text/plain"
            aria-label="Subir fichero Sigma"
            onChange={(e) => onFile(e.target.files?.[0])}
          />
        </label>
        <label className="form-field">
          <span className="muted small">YAML Sigma</span>
          <textarea
            className="input mono"
            rows={12}
            spellCheck={false}
            value={yaml}
            onChange={(e) => {
              setYaml(e.target.value);
              setPreview(undefined);
              setResult(undefined);
            }}
            aria-label="YAML Sigma"
          />
        </label>
        {tooBig && <div className="banner banner--warn">El YAML supera 64 KB.</div>}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        {preview && (
          <section className="panel panel--padded" aria-label="Vista previa">
            <div className="actions">
              <strong>{preview.title || "(sin título)"}</strong>
              <span className={`badge ${preview.outcome === "supported" ? "badge--ok" : preview.outcome === "partial" ? "badge--warn" : "badge--crit"}`}>
                {SIGMA_OUTCOME_LABELS[preview.outcome] ?? preview.outcome}
              </span>
              <DetectionSeverityBadge severity={preview.severity} />
            </div>
            <dl className="fields">
              <div className="field">
                <dt>Sigma id</dt>
                <dd className="mono">{preview.sigma_id ?? "—"}</dd>
              </div>
              <div className="field">
                <dt>Logsource Sentra</dt>
                <dd className="mono">{preview.sentra_logsource ?? "—"}</dd>
              </div>
              <div className="field">
                <dt>MITRE</dt>
                <dd className="mono">
                  {[preview.mitre_tactic, preview.mitre_subtechnique ?? preview.mitre_technique].filter(Boolean).join(" · ") ||
                    "—"}
                </dd>
              </div>
              <div className="field">
                <dt>Confianza inicial</dt>
                <dd>{preview.confidence}</dd>
              </div>
            </dl>
            <IssueList issues={preview.errors} tone="crit" />
            <IssueList issues={preview.unsupported} tone="crit" />
            <IssueList issues={preview.warnings} tone="warn" />
            {duplicateState === "identical" && (
              <p className="muted small">Ya está importada con el mismo contenido ({preview.duplicate.rule_id}).</p>
            )}
            {duplicateState === "changed" && (
              <p className="text-warn small">
                Ya existe como {preview.duplicate.rule_id} con otro contenido: importar crea una versión nueva.
              </p>
            )}
            {duplicateState === "retired" && (
              <p className="text-warn small">La regla existente ({preview.duplicate.rule_id}) está retirada.</p>
            )}
          </section>
        )}
        {result && (
          <div className={`banner ${result.result === "rejected" ? "banner--warn" : "banner--ok"}`} role="status">
            {SIGMA_RESULT_LABELS[result.result] ?? result.result}
            {result.rule && <span className="mono"> · {result.rule.rule_id}</span>}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cerrar
          </button>
          <button
            type="button"
            className="button"
            onClick={() => void doPreview()}
            disabled={busy || !yaml.trim() || tooBig}
          >
            Vista previa
          </button>
          {canImport && (
            <button
              type="button"
              className="button button--primary"
              onClick={() => void doImport()}
              disabled={busy || !preview || preview.outcome === "invalid" || duplicateState === "retired" || Boolean(result)}
            >
              Importar
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}
