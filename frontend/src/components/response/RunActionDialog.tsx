import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../../api/client";
import { responseApi, type ExecutionInput } from "../../api/sentra";
import type { ResponseAction, ResponseExecution, ResponseIssue, ResponsePreview } from "../../api/types";
import { errorMessage } from "../../lib/format";
import { LEVEL_LABELS } from "../../lib/incidents";
import {
  blockedInfo,
  buildParameters,
  initialParamValues,
  missingParameters,
  newIdempotencyKey,
  paramFields,
  ROLE_REQUIRED_LABELS,
  type ParamField,
} from "../../lib/response";
import { useAssetOptions } from "../../lib/useAssetOptions";
import { Modal } from "../Modal";
import { IssueList, LiveExecution, RiskBadge } from "./ResponseViews";

function asError(err: unknown): string {
  if (err instanceof ApiError && err.code === "confirmation_required") {
    return "Esta acción cambia datos: marca la confirmación explícita antes de ejecutarla.";
  }
  return err instanceof Error ? errorMessage(err) : String(err);
}

/** Etiqueta de una opción de enum: los niveles de incidente se muestran en español. */
function optionLabel(value: string): string {
  return (LEVEL_LABELS as Record<string, string>)[value] ?? value;
}

/** Formulario de parámetros generado del JSON Schema (solo texto, entero o enum). */
export function ParamsForm({
  fields,
  values,
  onChange,
  disabled,
}: {
  fields: ParamField[];
  values: Record<string, string>;
  onChange: (name: string, value: string) => void;
  disabled?: boolean;
}) {
  if (fields.length === 0) return null;
  return (
    <fieldset className="stack" disabled={disabled}>
      {fields.map((field) => (
        <label key={field.name} className="form-field">
          <span className="muted small">
            {field.label}
            {field.required ? "" : " (opcional)"}
          </span>
          {field.kind === "enum" ? (
            <select
              className="input input--select"
              aria-label={field.label}
              value={values[field.name] ?? ""}
              onChange={(e) => onChange(field.name, e.target.value)}
            >
              {!field.required && field.defaultValue === undefined && <option value="">—</option>}
              {field.options.map((option) => (
                <option key={option} value={option}>
                  {optionLabel(option)}
                </option>
              ))}
            </select>
          ) : field.kind === "integer" ? (
            <input
              className="input"
              type="number"
              aria-label={field.label}
              min={field.minimum}
              max={field.maximum}
              step={1}
              value={values[field.name] ?? ""}
              onChange={(e) => onChange(field.name, e.target.value)}
            />
          ) : (field.maxLength ?? 0) > 200 ? (
            <textarea
              className="input"
              aria-label={field.label}
              maxLength={field.maxLength}
              value={values[field.name] ?? ""}
              onChange={(e) => onChange(field.name, e.target.value)}
            />
          ) : (
            <input
              className="input"
              aria-label={field.label}
              maxLength={field.maxLength}
              value={values[field.name] ?? ""}
              onChange={(e) => onChange(field.name, e.target.value)}
            />
          )}
        </label>
      ))}
    </fieldset>
  );
}

function AssetPicker({ value, onChange }: { value: string; onChange: (assetId: string) => void }) {
  const [query, setQuery] = useState("");
  const options = useAssetOptions(query, value);
  return (
    <label className="form-field">
      <span className="muted small">Activo objetivo</span>
      <input
        className="input"
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Buscar por nombre o IP"
        aria-label="Buscar activo"
      />
      <select
        className="input input--select"
        aria-label="Activo objetivo"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value="">Elige un activo</option>
        {options.map((asset) => (
          <option key={asset.asset_id} value={asset.asset_id}>
            {asset.display_name}
            {asset.primary_ip ? ` · ${asset.primary_ip}` : ""}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Lo que el servidor dice que pasará: objetivo, riesgo, rol, precondiciones, bloqueos y avisos. */
function PreviewView({ preview }: { preview: ResponsePreview }) {
  return (
    <div className="stack">
      <dl className="fields">
        <div className="field">
          <dt>Acción</dt>
          <dd>
            {preview.action_name} <span className="muted small mono">{preview.action}</span>
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
          <dt>Requiere agente</dt>
          <dd>{preview.requires_agent ? "Sí" : "No"}</dd>
        </div>
        <div className="field">
          <dt>Requiere confirmación</dt>
          <dd>{preview.requires_confirmation ? "Sí" : "No"}</dd>
        </div>
      </dl>
      <p>
        <span className="muted small">Efecto esperado: </span>
        {preview.expected_effect}
      </p>
      {Object.keys(preview.parameters).length > 0 && (
        <div>
          <span className="muted small">Parámetros</span>
          <pre className="code-block small">{JSON.stringify(preview.parameters, null, 2)}</pre>
        </div>
      )}
      {preview.preconditions.length > 0 && (
        <div>
          <span className="muted small">Precondiciones</span>
          <ul>
            {preview.preconditions.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        </div>
      )}
      <IssueList issues={preview.blockers} title="No se puede ejecutar:" />
      <IssueList issues={preview.warnings} title="Avisos" warn={false} />
    </div>
  );
}

/**
 * Diálogo para lanzar una acción del catálogo: previsualiza en el servidor (POST /preview),
 * muestra bloqueos y avisos, y solo permite ejecutar sin bloqueos y, si la acción lo exige,
 * con una confirmación explícita. La clave de idempotencia se genera una vez por diálogo.
 */
export function RunActionDialog({
  action,
  assetId,
  incidentId,
  detectionId,
  onClose,
  onDone,
}: {
  action: ResponseAction;
  /** Sin activo, el diálogo muestra un selector. */
  assetId?: string;
  incidentId?: string;
  detectionId?: string;
  onClose: () => void;
  onDone?: (execution: ResponseExecution) => void;
}) {
  const fields = useMemo(() => paramFields(action.parameters_schema), [action.parameters_schema]);
  const [idempotencyKey] = useState(newIdempotencyKey);
  const [chosenAsset, setChosenAsset] = useState(assetId ?? "");
  const [values, setValues] = useState(() => initialParamValues(fields));
  const [reason, setReason] = useState("");
  const [preview, setPreview] = useState<ResponsePreview>();
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [blocked, setBlocked] = useState<{ executionId: string | null; blockers: ResponseIssue[] }>();
  const [execution, setExecution] = useState<ResponseExecution>();

  // Una acción sobre un incidente (p. ej. añadir nota) solo tiene objetivo con contexto de incidente.
  const targetId = action.target_type === "incident" ? (incidentId ?? "") : chosenAsset;
  const request: ExecutionInput = {
    action_id: action.id,
    target_type: action.target_type,
    target_id: targetId,
    parameters: buildParameters(fields, values),
    incident_id: incidentId ?? null,
    detection_id: detectionId ?? null,
    reason: reason.trim() || null,
    idempotency_key: idempotencyKey,
  };
  const incomplete = !targetId || missingParameters(fields, values);
  const unavailable = action.availability !== "available";

  // Sin parámetros y con objetivo fijo, la previsualización se pide al abrir: el usuario ve de
  // inmediato qué pasará y qué lo bloquea. (Solo actualiza estado al llegar la respuesta.)
  const autoPreview = fields.length === 0 && Boolean(targetId) && !unavailable;
  const actionId = action.id;
  const targetType = action.target_type;
  useEffect(() => {
    if (!autoPreview) return;
    let cancelled = false;
    responseApi
      .preview({
        action_id: actionId,
        target_type: targetType,
        target_id: targetId,
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
  }, [autoPreview, actionId, targetType, targetId, incidentId, detectionId, idempotencyKey]);

  // Cambiar el objetivo o un parámetro invalida la previsualización (y la confirmación).
  const invalidate = () => {
    setPreview(undefined);
    setConfirmed(false);
    setBlocked(undefined);
    setError(undefined);
  };

  const runPreview = async () => {
    setBusy(true);
    setError(undefined);
    try {
      setPreview(await responseApi.preview(request));
    } catch (err) {
      setError(asError(err));
    } finally {
      setBusy(false);
    }
  };

  const execute = async () => {
    if (!preview) return;
    setBusy(true);
    setError(undefined);
    setBlocked(undefined);
    try {
      const result = await responseApi.execute({ ...request, confirm: preview.requires_confirmation && confirmed });
      setExecution(result);
      onDone?.(result);
    } catch (err) {
      const info = blockedInfo(err);
      if (info) setBlocked({ executionId: info.executionId, blockers: info.blockers });
      else setError(asError(err));
    } finally {
      setBusy(false);
    }
  };

  const hasBlockers = !preview || preview.blockers.length > 0 || !preview.allowed;
  const needsConfirmation = Boolean(preview?.requires_confirmation) && !confirmed;
  const canExecute = !busy && !incomplete && !hasBlockers && !needsConfirmation && !unavailable;

  return (
    <Modal title={`Ejecutar: ${action.name}`} onClose={busy ? () => undefined : onClose} wide>
      {execution ? (
        <div className="stack">
          <LiveExecution initial={execution} />
          <div className="modal__actions">
            <button type="button" className="button button--primary" onClick={onClose}>
              Cerrar
            </button>
          </div>
        </div>
      ) : (
        <div className="stack">
          <p className="muted small">{action.description}</p>
          {unavailable && (
            <div className="banner banner--warn" role="alert">
              Acción reservada: aún no está implementada y el servidor la rechaza siempre.
            </div>
          )}
          {action.target_type === "incident" && !incidentId && (
            <div className="banner banner--warn" role="alert">
              Esta acción se ejecuta sobre un incidente: lánzala desde el detalle del incidente.
            </div>
          )}
          {action.target_type === "asset" && !assetId && (
            <AssetPicker
              value={chosenAsset}
              onChange={(id) => {
                setChosenAsset(id);
                invalidate();
              }}
            />
          )}
          <ParamsForm
            fields={fields}
            values={values}
            disabled={busy}
            onChange={(name, value) => {
              setValues((prev) => ({ ...prev, [name]: value }));
              invalidate();
            }}
          />
          <label className="form-field">
            <span className="muted small">Motivo (opcional, queda en la auditoría)</span>
            <input className="input" maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Motivo de la ejecución" />
          </label>
          {!preview && (!autoPreview || error) && (
            <div className="actions">
              <button
                type="button"
                className="button"
                disabled={busy || incomplete || unavailable}
                onClick={() => void runPreview()}
              >
                Previsualizar
              </button>
            </div>
          )}
          {!preview && autoPreview && !error && <p className="muted small">Calculando previsualización…</p>}
          {preview && <PreviewView preview={preview} />}
          {preview?.requires_confirmation && preview.blockers.length === 0 && (
            <label className="checkbox">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> Confirmo
              que quiero ejecutar esta acción sobre {preview.target_label}
            </label>
          )}
          {blocked && (
            <div className="stack">
              <IssueList issues={blocked.blockers} title="La política de respuesta bloqueó la ejecución:" />
              {blocked.executionId && (
                <p className="muted small">
                  El intento quedó registrado:{" "}
                  <Link to={`/response?tab=executions&execution=${encodeURIComponent(blocked.executionId)}`}>
                    ver ejecución bloqueada
                  </Link>
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
              className={`button ${preview?.requires_confirmation ? "button--danger" : "button--primary"}`}
              disabled={!canExecute}
              onClick={() => void execute()}
            >
              {busy ? "Procesando…" : "Ejecutar"}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
