import { useMemo, useState, type FormEvent } from "react";
import { toolsApi } from "../../api/sentra7b";
import type { ToolExecutionOut, ToolOut } from "../../api/types";
import { errorMessage } from "../../lib/format";
import { buildInput, fieldsOf, initialValues, type FieldValues } from "../../lib/toolSchema";

export const CATEGORY_LABELS: Record<string, string> = {
  read: "Lectura",
  investigation: "Investigación",
  action: "Acción",
};

/**
 * Formulario de una herramienta del catálogo 7A. Lecturas e investigaciones se ejecutan
 * directamente; una acción solo genera la vista previa (la ejecución exige confirmar después,
 * con su versión, en la tarjeta del resultado).
 */
export function ToolRunner({
  tool,
  preset,
  siteId,
  incidentId,
  onResult,
}: {
  tool: ToolOut;
  preset?: Record<string, string>;
  siteId?: string;
  incidentId?: string;
  onResult: (execution: ToolExecutionOut) => void;
}) {
  const fields = useMemo(() => fieldsOf(tool.input_schema), [tool.input_schema]);
  const [values, setValues] = useState<FieldValues>(() => initialValues(fields, preset));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const action = tool.policy === "preview_confirm";
  const disabled = !tool.permitted || tool.availability !== "available";

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const built = buildInput(fields, values);
    if ("error" in built) {
      setError(built.error);
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const run = { input: built.input, siteId, incidentId };
      onResult(action ? await toolsApi.preview(tool.id, run) : await toolsApi.execute(tool.id, run));
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="stack tool-runner" onSubmit={(event) => void submit(event)} aria-label={`Ejecutar ${tool.name}`}>
      <p className="small muted">{tool.description}</p>
      <div className="tool-runner__fields">
        {fields.map((field) => {
          const id = `tool-${tool.id}-${field.name}`;
          const value = values[field.name];
          const set = (next: string | boolean) => setValues((current) => ({ ...current, [field.name]: next }));
          if (field.kind === "boolean") {
            return (
              <label key={field.name} className="checkbox small">
                <input type="checkbox" checked={value === true} onChange={(e) => set(e.target.checked)} /> {field.label}
              </label>
            );
          }
          return (
            <label key={field.name} className="field" htmlFor={id}>
              <span>
                {field.label}
                {field.required && " *"}
              </span>
              {field.kind === "enum" ? (
                <select id={id} className="input input--select" value={String(value)} onChange={(e) => set(e.target.value)}>
                  {!field.required && <option value="">—</option>}
                  {field.options?.map((o) => (
                    <option key={o} value={o}>
                      {o}
                    </option>
                  ))}
                </select>
              ) : field.kind === "json" ? (
                <textarea
                  id={id}
                  className="input mono"
                  rows={2}
                  value={String(value)}
                  onChange={(e) => set(e.target.value)}
                  placeholder="{}"
                />
              ) : (
                <input
                  id={id}
                  className="input"
                  type={field.kind === "number" ? "number" : "text"}
                  min={field.min}
                  max={field.max}
                  maxLength={field.maxLength}
                  value={String(value)}
                  onChange={(e) => set(e.target.value)}
                />
              )}
            </label>
          );
        })}
      </div>
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      <div className="actions">
        <button type="submit" className="button button--primary button--small" disabled={busy || disabled}>
          {busy ? "Ejecutando…" : action ? "Vista previa" : "Ejecutar"}
        </button>
        {!tool.permitted && <span className="small muted">Tu rol no tiene permiso para esta herramienta.</span>}
        {tool.permitted && tool.availability !== "available" && (
          <span className="small muted">No disponible: {tool.unavailable_reason ?? "motivo desconocido"}.</span>
        )}
      </div>
    </form>
  );
}
