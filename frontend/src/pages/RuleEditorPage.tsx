import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { rulesApi } from "../api/sentra";
import type {
  DetectionConfidence,
  DetectionSeverity,
  RuleCatalog,
  RuleContentInput,
  RuleDefinition,
  RuleDetail,
  RuleField,
  RuleOperator,
  RuleTestResult,
  RuleValidation,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import {
  CATEGORY_LABELS,
  CONFIDENCE_LABELS,
  CONFIDENCE_ORDER,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
} from "../components/detections/DetectionBadges";
import { CompileBadge, IssueList } from "../components/rules/RuleBadges";
import { ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage } from "../lib/format";
import {
  OPERATOR_LABELS,
  definitionFromEditor,
  editorFromDefinition,
  emptyEditor,
  newRow,
  parseSyntheticEvents,
  splitList,
  type ConditionRow,
  type EditorState,
} from "../lib/rules";

interface Meta {
  title: string;
  description: string;
  why: string;
  recommendations: string;
  severity: DetectionSeverity;
  confidence: DetectionConfidence;
  category: string;
  mitreTactic: string;
  mitreTechnique: string;
  mitreSubtechnique: string;
  tags: string;
}

const EMPTY_META: Meta = {
  title: "",
  description: "",
  why: "",
  recommendations: "",
  severity: "medium",
  // Confianza conservadora por defecto: sube cuando la regla demuestra pocos falsos positivos.
  confidence: "low",
  category: "",
  mitreTactic: "",
  mitreTechnique: "",
  mitreSubtechnique: "",
  tags: "",
};

function metaFrom(rule: RuleDetail): Meta {
  return {
    title: rule.title,
    description: rule.description,
    why: rule.why,
    recommendations: rule.recommendations.join("\n"),
    severity: rule.severity,
    confidence: rule.confidence,
    category: rule.category,
    mitreTactic: rule.mitre_tactic ?? "",
    mitreTechnique: rule.mitre_technique ?? "",
    mitreSubtechnique: rule.mitre_subtechnique ?? "",
    tags: rule.tags.join(", "),
  };
}

const errorText = (err: unknown) => errorMessage(err instanceof Error ? err : new Error(String(err)));

/**
 * Editor estructurado de reglas (rules:manage). Construye el JSON declarativo sentra-rule/1
 * con selectores del catálogo: no hay campo de "código" que el backend pudiera ejecutar. El
 * modo avanzado edita ese mismo JSON (también validado con allowlist en el servidor).
 */
export function RuleEditorPage() {
  const { ruleId } = useParams();
  const editing = Boolean(ruleId);
  const auth = useAuth();
  const navigate = useNavigate();
  const [catalog, setCatalog] = useState<RuleCatalog>();
  const [rule, setRule] = useState<RuleDetail>();
  const [loadError, setLoadError] = useState<string>();
  const [meta, setMeta] = useState<Meta>(EMPTY_META);
  const [editor, setEditor] = useState<EditorState>();
  const [advanced, setAdvanced] = useState(false);
  const [json, setJson] = useState("");
  const [validation, setValidation] = useState<RuleValidation>();
  const [testText, setTestText] = useState("");
  const [testResult, setTestResult] = useState<RuleTestResult>();
  const [ackPartial, setAckPartial] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      const found = await rulesApi.catalog(controller.signal);
      setCatalog(found);
      if (!ruleId) {
        setEditor(emptyEditor(found.logsources[0]?.name ?? "windows_security"));
        return;
      }
      const existing = await rulesApi.get(ruleId, controller.signal);
      setRule(existing);
      setMeta(metaFrom(existing));
      const definition = existing.definition;
      const structured = definition ? editorFromDefinition(definition) : null;
      if (structured) setEditor(structured);
      else {
        setAdvanced(true);
        setEditor(emptyEditor(definition?.logsource ?? found.logsources[0]?.name ?? "windows_security"));
      }
      setJson(JSON.stringify(definition ?? {}, null, 2));
    };
    load().catch((err: unknown) => {
      if (!controller.signal.aborted) setLoadError(errorText(err));
    });
    return () => controller.abort();
  }, [ruleId]);

  const logsource = catalog?.logsources.find((s) => s.name === editor?.logsource);
  const fields = useMemo(() => {
    const map = new Map<string, RuleField>();
    for (const field of [...(logsource?.fields ?? []), ...(catalog?.asset_fields ?? [])]) map.set(field.name, field);
    return map;
  }, [logsource, catalog]);
  const eventFields = logsource?.fields ?? [];
  // La lógica de una regla Sigma solo cambia reimportando su YAML (trazabilidad con el origen).
  const logicLocked = rule?.source === "sigma";

  if (!auth.can("rules:manage")) {
    return <ErrorState title="Sin permiso" message="Crear y editar reglas requiere rules:manage (admin)." />;
  }
  if (loadError) return <ErrorState message={loadError} />;
  if (!catalog || !editor) return <LoadingState label="Cargando editor…" />;
  if (rule?.read_only) {
    return <ErrorState title="Regla built-in" message="Las reglas built-in son de solo lectura." />;
  }

  const definition = (): RuleDefinition => {
    if (!advanced) return definitionFromEditor(editor, fields);
    // JSON.parse solo produce datos; el backend los valida con allowlist estricta.
    return JSON.parse(json) as RuleDefinition;
  };
  const updateRow = (id: number, patch: Partial<ConditionRow>) =>
    setEditor({ ...editor, rows: editor.rows.map((row) => (row.id === id ? { ...row, ...patch } : row)) });
  const content = (): RuleContentInput => ({
    title: meta.title.trim(),
    description: meta.description.trim(),
    why: meta.why.trim(),
    recommendations: meta.recommendations
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
    severity: meta.severity,
    confidence: meta.confidence,
    category: meta.category || null,
    mitre_tactic: meta.mitreTactic.trim() || null,
    mitre_technique: meta.mitreTechnique.trim() || null,
    mitre_subtechnique: meta.mitreSubtechnique.trim() || null,
    tags: splitList(meta.tags),
    definition: definition(),
  });

  const guarded = async (action: () => Promise<void>) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
    } catch (err) {
      if (err instanceof SyntaxError) setError("El JSON avanzado no es válido.");
      else if (err instanceof ApiError && err.code === "detection_rule_conflict")
        setError("Otro administrador cambió la regla. Recarga la página para ver su versión.");
      else setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const validate = () =>
    guarded(async () => {
      const body = content();
      setValidation(await rulesApi.validate(body.definition, body));
    });
  const test = () =>
    guarded(async () => {
      const events = parseSyntheticEvents(testText, fields);
      if (!events.length) throw new Error("Escribe al menos un evento (campo = valor).");
      setTestResult(await rulesApi.test({ definition: definition() }, events));
    });
  const save = (event: FormEvent) => {
    event.preventDefault();
    void guarded(async () => {
      const body = content();
      let saved: RuleDetail;
      if (rule) {
        const { definition: logic, ...rest } = body;
        saved = await rulesApi.update(rule.rule_id, {
          ...rest,
          ...(logicLocked ? {} : { definition: logic }),
          revision: rule.revision ?? 1,
          acknowledge_partial: ackPartial,
        });
      } else saved = await rulesApi.create(body);
      navigate(`/detections/rules/${encodeURIComponent(saved.rule_id)}`);
    });
  };

  const setMetaField = <K extends keyof Meta>(key: K, value: Meta[K]) => setMeta({ ...meta, [key]: value });

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <Link to={rule ? `/detections/rules/${encodeURIComponent(rule.rule_id)}` : "/detections/rules"} className="back">
            ← {rule ? rule.rule_id : "Reglas"}
          </Link>
          <h1>{editing ? "Editar regla" : "Nueva regla"}</h1>
          {rule && <p className="muted small">Guardar un cambio de contenido crea la versión {rule.version + 1}.</p>}
        </div>
      </div>
      <form className="stack" onSubmit={save}>
        <section className="panel panel--padded incident-form" aria-label="Descripción">
          <label>
            <span className="muted small">Título</span>
            <input
              className="input"
              value={meta.title}
              maxLength={200}
              onChange={(e) => setMetaField("title", e.target.value)}
              aria-label="Título"
            />
          </label>
          <label>
            <span className="muted small">Qué detecta</span>
            <textarea
              className="input"
              maxLength={2000}
              value={meta.description}
              onChange={(e) => setMetaField("description", e.target.value)}
              aria-label="Descripción"
            />
          </label>
          <label>
            <span className="muted small">Por qué importa</span>
            <textarea
              className="input"
              maxLength={1000}
              value={meta.why}
              onChange={(e) => setMetaField("why", e.target.value)}
              aria-label="Por qué importa"
            />
          </label>
          <label>
            <span className="muted small">Recomendaciones (una por línea)</span>
            <textarea
              className="input"
              value={meta.recommendations}
              onChange={(e) => setMetaField("recommendations", e.target.value)}
              aria-label="Recomendaciones"
            />
          </label>
          <div className="actions">
            <label>
              <span className="muted small">Severidad</span>
              <select
                className="input input--select"
                value={meta.severity}
                onChange={(e) => setMetaField("severity", e.target.value as DetectionSeverity)}
                aria-label="Severidad"
              >
                {SEVERITY_ORDER.map((value) => (
                  <option key={value} value={value}>
                    {SEVERITY_LABELS[value]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span className="muted small">Confianza</span>
              <select
                className="input input--select"
                value={meta.confidence}
                onChange={(e) => setMetaField("confidence", e.target.value as DetectionConfidence)}
                aria-label="Confianza"
              >
                {CONFIDENCE_ORDER.map((value) => (
                  <option key={value} value={value}>
                    {CONFIDENCE_LABELS[value]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span className="muted small">Categoría</span>
              <select
                className="input input--select"
                value={meta.category}
                onChange={(e) => setMetaField("category", e.target.value)}
                aria-label="Categoría"
              >
                <option value="">Según el logsource</option>
                {catalog.categories.map((value) => (
                  <option key={value} value={value}>
                    {CATEGORY_LABELS[value] ?? value}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="actions">
            <label>
              <span className="muted small">MITRE táctica (TA0006)</span>
              <input
                className="input mono"
                value={meta.mitreTactic}
                maxLength={16}
                onChange={(e) => setMetaField("mitreTactic", e.target.value)}
                aria-label="MITRE táctica"
              />
            </label>
            <label>
              <span className="muted small">Técnica (T1110)</span>
              <input
                className="input mono"
                value={meta.mitreTechnique}
                maxLength={16}
                onChange={(e) => setMetaField("mitreTechnique", e.target.value)}
                aria-label="MITRE técnica"
              />
            </label>
            <label>
              <span className="muted small">Subtécnica (T1110.001)</span>
              <input
                className="input mono"
                value={meta.mitreSubtechnique}
                maxLength={16}
                onChange={(e) => setMetaField("mitreSubtechnique", e.target.value)}
                aria-label="MITRE subtécnica"
              />
            </label>
          </div>
          <label>
            <span className="muted small">Etiquetas (separadas por comas)</span>
            <input
              className="input"
              value={meta.tags}
              onChange={(e) => setMetaField("tags", e.target.value)}
              aria-label="Etiquetas"
            />
          </label>
        </section>

        <section className="panel panel--padded incident-form" aria-label="Lógica">
          <div className="actions">
            <h2>Lógica</h2>
            {!logicLocked && (
              <label className="form-field form-field--inline">
                <input
                  type="checkbox"
                  checked={advanced}
                  onChange={(e) => {
                    if (e.target.checked) setJson(JSON.stringify(definitionFromEditor(editor, fields), null, 2));
                    setAdvanced(e.target.checked);
                  }}
                />
                <span className="small">Modo avanzado (JSON declarativo)</span>
              </label>
            )}
          </div>
          {logicLocked ? (
            <p className="muted small">
              La lógica de una regla Sigma solo cambia reimportando su YAML. Aquí se editan los textos, la severidad y la
              confianza.
            </p>
          ) : advanced ? (
            <textarea
              className="input mono"
              rows={14}
              spellCheck={false}
              value={json}
              onChange={(e) => setJson(e.target.value)}
              aria-label="Definición JSON"
            />
          ) : (
            <>
              <div className="actions">
                <label>
                  <span className="muted small">Logsource</span>
                  <select
                    className="input input--select"
                    value={editor.logsource}
                    onChange={(e) => setEditor({ ...emptyEditor(e.target.value) })}
                    aria-label="Logsource"
                  >
                    {catalog.logsources.map((s) => (
                      <option key={s.name} value={s.name}>
                        {s.title}
                        {s.support !== "supported" ? " (parcial)" : ""}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span className="muted small">Coincide si se cumplen</span>
                  <select
                    className="input input--select"
                    value={editor.mode}
                    onChange={(e) => setEditor({ ...editor, mode: e.target.value as "all" | "any" })}
                    aria-label="Combinación"
                  >
                    <option value="all">todas las condiciones</option>
                    <option value="any">cualquier condición</option>
                  </select>
                </label>
              </div>
              {logsource?.notes && <p className="muted small">{logsource.notes}</p>}
              {editor.rows.map((row, index) => {
                const field = fields.get(row.field);
                const ops: RuleOperator[] = field?.operators ?? ["equals"];
                return (
                  <div className="actions" key={row.id} aria-label={`Condición ${index + 1}`}>
                    <label className="form-field form-field--inline">
                      <input
                        type="checkbox"
                        checked={row.negate}
                        onChange={(e) => updateRow(row.id, { negate: e.target.checked })}
                        aria-label={`Negar condición ${index + 1}`}
                      />
                      <span className="small">NO</span>
                    </label>
                    <select
                      className="input input--select"
                      value={row.field}
                      onChange={(e) => {
                        const next = fields.get(e.target.value);
                        const op = next?.operators.includes(row.op) ? row.op : (next?.operators[0] ?? "equals");
                        updateRow(row.id, { field: e.target.value, op });
                      }}
                      aria-label={`Campo ${index + 1}`}
                    >
                      <option value="">Campo…</option>
                      {[...fields.values()].map((f) => (
                        <option key={f.name} value={f.name}>
                          {f.name}
                        </option>
                      ))}
                    </select>
                    <select
                      className="input input--select"
                      value={row.op}
                      onChange={(e) => updateRow(row.id, { op: e.target.value as RuleOperator })}
                      aria-label={`Operador ${index + 1}`}
                    >
                      {ops.map((op) => (
                        <option key={op} value={op}>
                          {OPERATOR_LABELS[op]}
                        </option>
                      ))}
                    </select>
                    {row.op === "exists" ? (
                      <select
                        className="input input--select"
                        value={row.value === "false" ? "false" : "true"}
                        onChange={(e) => updateRow(row.id, { value: e.target.value })}
                        aria-label={`Valor ${index + 1}`}
                      >
                        <option value="true">sí</option>
                        <option value="false">no</option>
                      </select>
                    ) : field?.values.length && row.op !== "regex" ? (
                      <select
                        className="input input--select"
                        value={row.value}
                        onChange={(e) => updateRow(row.id, { value: e.target.value })}
                        aria-label={`Valor ${index + 1}`}
                      >
                        <option value="">Valor…</option>
                        {field.values.map((value) => (
                          <option key={value} value={value}>
                            {value}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        className="input mono"
                        value={row.value}
                        maxLength={row.op === "in" ? 2000 : 256}
                        placeholder={row.op === "in" ? "valor1, valor2" : "valor"}
                        onChange={(e) => updateRow(row.id, { value: e.target.value })}
                        aria-label={`Valor ${index + 1}`}
                      />
                    )}
                    {field?.type === "string" && row.op !== "exists" && (
                      <label className="form-field form-field--inline">
                        <input
                          type="checkbox"
                          checked={row.caseSensitive}
                          onChange={(e) => updateRow(row.id, { caseSensitive: e.target.checked })}
                        />
                        <span className="small">Mayúsculas</span>
                      </label>
                    )}
                    <button
                      type="button"
                      className="button button--ghost button--small"
                      onClick={() => setEditor({ ...editor, rows: editor.rows.filter((r) => r.id !== row.id) })}
                      disabled={editor.rows.length <= 1}
                      aria-label={`Quitar condición ${index + 1}`}
                    >
                      ✕
                    </button>
                  </div>
                );
              })}
              <div>
                <button
                  type="button"
                  className="button button--small"
                  onClick={() => setEditor({ ...editor, rows: [...editor.rows, newRow()] })}
                >
                  Añadir condición
                </button>
              </div>
              <label className="form-field form-field--inline">
                <input
                  type="checkbox"
                  checked={editor.thresholdEnabled}
                  onChange={(e) => setEditor({ ...editor, thresholdEnabled: e.target.checked })}
                />
                <span className="small">Umbral: solo detectar si se repite</span>
              </label>
              {editor.thresholdEnabled && (
                <div className="actions">
                  <label>
                    <span className="muted small">Veces</span>
                    <input
                      className="input"
                      type="number"
                      min={catalog.limits.threshold_min}
                      max={catalog.limits.threshold_max}
                      value={editor.thresholdCount}
                      onChange={(e) => setEditor({ ...editor, thresholdCount: Number(e.target.value) })}
                      aria-label="Umbral"
                    />
                  </label>
                  <label>
                    <span className="muted small">En minutos</span>
                    <input
                      className="input"
                      type="number"
                      min={catalog.limits.window_min_minutes}
                      max={catalog.limits.window_max_minutes}
                      value={editor.windowMinutes}
                      onChange={(e) => setEditor({ ...editor, windowMinutes: Number(e.target.value) })}
                      aria-label="Ventana"
                    />
                  </label>
                  <label>
                    <span className="muted small">Agrupar por</span>
                    <select
                      className="input input--select"
                      multiple
                      value={editor.groupBy}
                      onChange={(e) =>
                        setEditor({ ...editor, groupBy: Array.from(e.target.selectedOptions, (o) => o.value) })
                      }
                      aria-label="Agrupar por"
                    >
                      {eventFields.map((f) => (
                        <option key={f.name} value={f.name}>
                          {f.name}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
              )}
              <label>
                <span className="muted small">Cooldown en minutos (vacío = por defecto)</span>
                <input
                  className="input"
                  type="number"
                  min={0}
                  max={catalog.limits.cooldown_max_minutes}
                  value={editor.cooldownMinutes}
                  onChange={(e) => setEditor({ ...editor, cooldownMinutes: e.target.value })}
                  aria-label="Cooldown"
                />
              </label>
            </>
          )}
          {!logicLocked && (
            <div className="actions">
              <button type="button" className="button" onClick={() => void validate()} disabled={busy}>
                Validar
              </button>
              {validation && <CompileBadge status={validation.valid ? validation.compile_status : "invalid"} />}
              {validation?.complexity && <span className="muted small">Complejidad: {validation.complexity}</span>}
            </div>
          )}
          {validation && (
            <>
              <IssueList issues={validation.errors} tone="crit" />
              <IssueList issues={validation.warnings} tone="warn" />
            </>
          )}
        </section>

        {!logicLocked && auth.can("rules:test") && (
          <section className="panel panel--padded incident-form" aria-label="Prueba sintética">
            <h2>Probar con eventos sintéticos</h2>
            <p className="muted small">
              Un campo por línea (<span className="mono">event.code = 4625</span>); una línea en blanco separa eventos.
              No se guarda nada ni se crean detecciones.
            </p>
            <textarea
              className="input mono"
              rows={6}
              spellCheck={false}
              value={testText}
              onChange={(e) => setTestText(e.target.value)}
              aria-label="Eventos sintéticos"
            />
            <div>
              <button type="button" className="button" onClick={() => void test()} disabled={busy}>
                Probar
              </button>
            </div>
            {testResult && (
              <div className="small" role="status">
                {testResult.matched} de {testResult.events.length} eventos coinciden.
                {testResult.would_detect.length > 0
                  ? ` Crearía ${testResult.would_detect.length} detección(es).`
                  : " No crearía detecciones."}
                <ul className="plain-list">
                  {testResult.events.map((ev) => (
                    <li key={ev.index}>
                      Evento {ev.index + 1}: {ev.matched ? "coincide" : "no coincide"}
                      {ev.missing_fields.length > 0 && (
                        <span className="muted"> (faltan: {ev.missing_fields.join(", ")})</span>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </section>
        )}

        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        {rule?.status === "active" && (
          <label className="form-field form-field--inline">
            <input type="checkbox" checked={ackPartial} onChange={(e) => setAckPartial(e.target.checked)} />
            <span className="small">Entiendo que la nueva versión puede tener cobertura parcial</span>
          </label>
        )}
        <div className="modal__actions">
          <Link to={rule ? `/detections/rules/${encodeURIComponent(rule.rule_id)}` : "/detections/rules"} className="button">
            Cancelar
          </Link>
          <button type="submit" className="button button--primary" disabled={busy || meta.title.trim().length < 3}>
            {busy ? "Guardando…" : editing ? "Guardar versión" : "Crear borrador"}
          </button>
        </div>
      </form>
    </div>
  );
}
