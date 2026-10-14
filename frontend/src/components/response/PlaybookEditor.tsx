import { useCallback, useState, type FormEvent } from "react";
import { ApiError } from "../../api/client";
import { responseApi } from "../../api/sentra";
import type { Playbook, PlaybookStepInput, ResponseAction } from "../../api/types";
import { config } from "../../config";
import { errorMessage } from "../../lib/format";
import { buildParameters, initialParamValues, missingParameters, paramFields } from "../../lib/response";
import { usePolling } from "../../lib/usePolling";
import { Modal } from "../Modal";
import { ErrorState, LoadingState } from "../StateViews";
import { RiskBadge } from "./ResponseViews";
import { ParamsForm } from "./RunActionDialog";

// Igual que MAX_STEPS en backend/app/response/playbooks.py.
const MAX_STEPS = 10;

interface DraftStep {
  key: number;
  actionId: string;
  onFailure: "stop" | "continue";
  values: Record<string, string>;
}

function valuesFrom(action: ResponseAction | undefined, parameters: Record<string, unknown>): Record<string, string> {
  const fields = action ? paramFields(action.parameters_schema) : [];
  const initial = initialParamValues(fields);
  for (const [name, value] of Object.entries(parameters)) {
    if (typeof value === "string" || typeof value === "number") initial[name] = String(value);
  }
  return initial;
}

/**
 * Crear o editar un playbook (admin). Los pasos solo pueden ser acciones disponibles sobre un
 * activo; "continuar si falla" solo se ofrece en pasos de riesgo bajo, porque seguir tras el
 * fallo de una mutación podría dejar el caso a medias (el backend lo valida igualmente).
 */
export function PlaybookEditor({
  playbook,
  onClose,
  onSaved,
}: {
  playbook?: Playbook;
  onClose: () => void;
  onSaved: (playbook: Playbook) => void;
}) {
  const fetcher = useCallback((signal: AbortSignal) => responseApi.actions(undefined, signal), []);
  const catalog = usePolling(fetcher, config.refreshIntervalMs * 10);
  const actions = (catalog.data?.items ?? []).filter((a) => a.availability === "available" && a.target_type === "asset");
  const byId = new Map(actions.map((a) => [a.id, a]));

  const [name, setName] = useState(playbook?.name ?? "");
  const [description, setDescription] = useState(playbook?.description ?? "");
  const [nextKey, setNextKey] = useState(100);
  // Los valores de los parámetros se rellenan al cargar el catálogo (ver `stepValues`).
  const [steps, setSteps] = useState<DraftStep[]>(
    () =>
      playbook?.steps.map((s, i) => ({
        key: i,
        actionId: s.action_id,
        onFailure: s.on_failure === "continue" ? "continue" : "stop",
        values: Object.fromEntries(
          Object.entries(s.parameters)
            .filter(([, v]) => typeof v === "string" || typeof v === "number")
            .map(([k, v]) => [k, String(v)]),
        ),
      })) ?? [],
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  // Revisión con la que se guarda; tras un 409 se actualiza a la del servidor.
  const [revision, setRevision] = useState(playbook?.revision ?? 0);

  const update = (key: number, change: Partial<DraftStep>) =>
    setSteps((prev) => prev.map((s) => (s.key === key ? { ...s, ...change } : s)));
  const move = (index: number, delta: number) =>
    setSteps((prev) => {
      const next = [...prev];
      const [item] = next.splice(index, 1);
      if (item) next.splice(index + delta, 0, item);
      return next;
    });

  const addStep = () => {
    const first = actions[0];
    if (!first) return;
    setSteps((prev) => [...prev, { key: nextKey, actionId: first.id, onFailure: "stop", values: valuesFrom(first, {}) }]);
    setNextKey((k) => k + 1);
  };

  const stepValues = (step: DraftStep) => ({ ...valuesFrom(byId.get(step.actionId), {}), ...step.values });
  const invalid =
    name.trim().length < 3 ||
    steps.length === 0 ||
    steps.some((s) => {
      const action = byId.get(s.actionId);
      return !action || missingParameters(paramFields(action.parameters_schema), stepValues(s));
    });

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    const payload: PlaybookStepInput[] = steps.map((s) => {
      const action = byId.get(s.actionId);
      const fields = action ? paramFields(action.parameters_schema) : [];
      return {
        action_id: s.actionId,
        parameters: buildParameters(fields, stepValues(s)),
        on_failure: action?.risk_level === "low" ? s.onFailure : "stop",
      };
    });
    const input = { name: name.trim(), description: description.trim(), steps: payload };
    try {
      const saved = playbook
        ? await responseApi.updatePlaybook(playbook.playbook_id, revision, input)
        : await responseApi.createPlaybook(input);
      onSaved(saved);
    } catch (err) {
      if (playbook && err instanceof ApiError && err.code === "response_conflict") {
        // Otro admin lo cambió: se toma su revisión pero se conservan los cambios del formulario,
        // para que el usuario los revise y guarde a sabiendas (nunca se sobrescribe en silencio).
        try {
          const current = await responseApi.playbook(playbook.playbook_id);
          setRevision(current.revision);
        } catch {
          // Si tampoco se puede leer, el error original basta.
        }
        setError(
          "Otro administrador ha modificado este playbook mientras lo editabas. Revisa los cambios y guarda de nuevo para crear una versión nueva sobre la actual.",
        );
      } else {
        setError(err instanceof Error ? errorMessage(err) : String(err));
      }
      setBusy(false);
    }
  };

  return (
    <Modal title={playbook ? `Editar playbook: ${playbook.name}` : "Nuevo playbook"} onClose={busy ? () => undefined : onClose} wide>
      {catalog.loading ? (
        <LoadingState label="Cargando acciones…" />
      ) : !catalog.data ? (
        <ErrorState message={catalog.error ? errorMessage(catalog.error) : "Sin datos"} onRetry={catalog.refresh} />
      ) : (
        <form className="stack" onSubmit={(e) => void submit(e)}>
          {playbook && (
            <p className="muted small">
              Guardar crea la versión {playbook.version + 1}; las ejecuciones anteriores conservan la suya.
            </p>
          )}
          <label className="form-field">
            <span className="muted small">Nombre</span>
            <input
              className="input"
              required
              minLength={3}
              maxLength={120}
              value={name}
              onChange={(e) => setName(e.target.value)}
              aria-label="Nombre"
            />
          </label>
          <label className="form-field">
            <span className="muted small">Descripción (opcional)</span>
            <textarea
              className="input"
              maxLength={1000}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              aria-label="Descripción"
            />
          </label>
          <h3>Pasos</h3>
          {steps.length === 0 && <p className="muted small">Añade al menos un paso.</p>}
          {steps.map((step, index) => {
            const action = byId.get(step.actionId);
            const fields = action ? paramFields(action.parameters_schema) : [];
            const low = action?.risk_level === "low";
            return (
              <fieldset key={step.key} className="panel panel--padded stack">
                <legend className="strong">Paso {index + 1}</legend>
                <div className="actions">
                  <label className="form-field">
                    <span className="muted small">Acción</span>
                    <select
                      className="input input--select"
                      aria-label={`Acción del paso ${index + 1}`}
                      value={step.actionId}
                      onChange={(e) =>
                        update(step.key, {
                          actionId: e.target.value,
                          values: valuesFrom(byId.get(e.target.value), {}),
                          // Al cambiar a una acción de más riesgo vuelve a "parar".
                          onFailure: byId.get(e.target.value)?.risk_level === "low" ? step.onFailure : "stop",
                        })
                      }
                    >
                      {!action && <option value={step.actionId}>{step.actionId} (no disponible)</option>}
                      {actions.map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="form-field">
                    <span className="muted small">Si falla</span>
                    <select
                      className="input input--select"
                      aria-label={`Si falla el paso ${index + 1}`}
                      value={low ? step.onFailure : "stop"}
                      onChange={(e) => update(step.key, { onFailure: e.target.value === "continue" ? "continue" : "stop" })}
                    >
                      <option value="stop">Parar</option>
                      {low && <option value="continue">Continuar</option>}
                    </select>
                  </label>
                  {action && <RiskBadge risk={action.risk_level} />}
                </div>
                <ParamsForm
                  fields={fields}
                  values={stepValues(step)}
                  onChange={(field, value) => update(step.key, { values: { ...stepValues(step), [field]: value } })}
                />
                <div className="actions">
                  <button type="button" className="button button--small" disabled={index === 0} onClick={() => move(index, -1)}>
                    Subir
                  </button>
                  <button
                    type="button"
                    className="button button--small"
                    disabled={index === steps.length - 1}
                    onClick={() => move(index, 1)}
                  >
                    Bajar
                  </button>
                  <button
                    type="button"
                    className="button button--small"
                    onClick={() => setSteps((prev) => prev.filter((s) => s.key !== step.key))}
                  >
                    Quitar
                  </button>
                </div>
              </fieldset>
            );
          })}
          <div className="actions">
            <button
              type="button"
              className="button"
              disabled={steps.length >= MAX_STEPS || actions.length === 0}
              onClick={addStep}
            >
              Añadir paso
            </button>
            <span className="muted small">
              {steps.length} / {MAX_STEPS}
            </span>
          </div>
          {error && (
            <div className="banner banner--warn" role="alert">
              {error}
            </div>
          )}
          <div className="modal__actions">
            <button type="button" className="button" onClick={onClose} disabled={busy}>
              Cancelar
            </button>
            <button type="submit" className="button button--primary" disabled={busy || invalid}>
              {busy ? "Guardando…" : "Guardar"}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
