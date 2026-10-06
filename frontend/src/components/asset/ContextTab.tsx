import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { ApiError } from "../../api/client";
import { assetContextApi } from "../../api/sentra";
import type { AssetContext, AssetContextOptions, FieldProvenance } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import {
  buildUpdate,
  ENVIRONMENT_LABELS,
  ENVIRONMENT_ORDER,
  exposureLabel,
  FIELD_LABELS,
  MANAGED_STATE_LABELS,
  ROLE_LABELS,
  ROLE_ORDER,
  SENSITIVITY_LABELS,
  SENSITIVITY_ORDER,
  SOURCE_LABELS,
  toForm,
  validateForm,
  ZONE_LABELS,
  ZONE_ORDER,
  type ContextForm,
} from "../../lib/assetContext";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { CRITICALITY_LABELS, CRITICALITY_ORDER, RISK_LEVEL_LABELS } from "../../lib/risk";
import { usePolling } from "../../lib/usePolling";
import { CriticalityBadge } from "../risk/RiskBadges";
import { ErrorState, LoadingState } from "../StateViews";

// Límites por defecto (los reales llegan en /assets/context/options).
const DEFAULT_LIMITS = { owner: 128, department: 64, rationale: 200, tags: 20 };

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

/** "manual · ana · hace 2 h": de dónde sale el dato. Nada para valores desconocidos. */
function Provenance({ item }: { item: FieldProvenance | undefined }) {
  if (!item) return null;
  const who = item.updated_by ? ` · ${item.updated_by}` : "";
  const when = item.updated_at ? ` · ${formatRelative(item.updated_at)}` : "";
  return (
    <span className="muted small" title={item.updated_at ? formatDateTime(item.updated_at) : undefined}>
      {" "}
      ({SOURCE_LABELS[item.source] ?? item.source}
      {who}
      {when})
    </span>
  );
}

/** Valor desconocido: se dice tal cual, sin color de alerta (no es una amenaza). */
function Unknown({ children = "Desconocido" }: { children?: ReactNode }) {
  return <span className="muted">{children}</span>;
}

function ContextView({ ctx }: { ctx: AssetContext }) {
  const p = ctx.provenance;
  return (
    <dl className="fields">
      <Field label="Criticidad">
        <CriticalityBadge criticality={ctx.criticality} />
        {!ctx.criticality_confirmed && <span className="muted small"> (valor por defecto)</span>}
        <Provenance item={p.criticality} />
        {ctx.criticality_rationale && <div className="small">{ctx.criticality_rationale}</div>}
      </Field>
      <Field label="Rol">
        {ctx.role === "unknown" ? <Unknown /> : ROLE_LABELS[ctx.role]}
        <Provenance item={p.role} />
        {ctx.role_suggestion && (
          <div className="muted small">
            Sugerido: {ROLE_LABELS[ctx.role_suggestion.value]} (inferido de{" "}
            {SOURCE_LABELS[ctx.role_suggestion.source] ?? ctx.role_suggestion.source}
            {ctx.role_suggestion.confidence && `, confianza ${ctx.role_suggestion.confidence}`}) · no
            confirmado
          </div>
        )}
      </Field>
      <Field label="Entorno">
        {ctx.environment === "unknown" ? <Unknown /> : ENVIRONMENT_LABELS[ctx.environment]}
        <Provenance item={p.environment} />
      </Field>
      <Field label="Owner">
        {ctx.owner ?? <Unknown>Sin asignar</Unknown>}
        <Provenance item={p.owner} />
      </Field>
      <Field label="Equipo/Departamento">
        {ctx.department ?? <Unknown>Sin asignar</Unknown>}
        <Provenance item={p.department} />
      </Field>
      <Field label="Sensibilidad">
        {ctx.data_sensitivity === "unknown" ? (
          <Unknown>Desconocida</Unknown>
        ) : (
          SENSITIVITY_LABELS[ctx.data_sensitivity]
        )}
        <Provenance item={p.data_sensitivity} />
      </Field>
      <Field label="Zona de red">
        {ctx.network_zone === "unknown" ? <Unknown>Desconocida</Unknown> : ZONE_LABELS[ctx.network_zone]}
        <Provenance item={p.network_zone} />
      </Field>
      <Field label="Exposición Internet">
        {ctx.internet_exposed === null ? (
          <Unknown>{exposureLabel(null)}</Unknown>
        ) : (
          exposureLabel(ctx.internet_exposed)
        )}
        <Provenance item={p.internet_exposed} />
      </Field>
      <Field label="Estado de gestión">{MANAGED_STATE_LABELS[ctx.managed_state]}</Field>
      <Field label="Tags">
        {ctx.tags.length ? (
          ctx.tags.map((tag) => (
            <span key={tag} className="badge">
              {tag}
            </span>
          ))
        ) : (
          <Unknown>Sin tags</Unknown>
        )}
      </Field>
      <Field label="Fuentes">
        {ctx.visibility_sources.map((s) => SOURCE_LABELS[s] ?? s).join(", ") || "—"}
      </Field>
      <Field label="Última actualización">
        {ctx.updated_at ? (
          <span title={formatDateTime(ctx.updated_at)}>
            {formatRelative(ctx.updated_at)}
            {ctx.updated_by && ` por ${ctx.updated_by}`}
          </span>
        ) : (
          <Unknown>Nunca configurado</Unknown>
        )}
      </Field>
    </dl>
  );
}

function Select<T extends string>({
  label,
  value,
  options,
  labels,
  onChange,
}: {
  label: string;
  value: T;
  options: T[];
  labels: Record<T, string>;
  onChange: (value: T) => void;
}) {
  return (
    <label className="form-field">
      <span>{label}</span>
      <select
        className="input input--select"
        aria-label={label}
        value={value}
        onChange={(event) => onChange(event.target.value as T)}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {labels[option]}
          </option>
        ))}
      </select>
    </label>
  );
}

function ContextEditor({
  ctx,
  options,
  onSaved,
  onCancel,
  onConflict,
}: {
  ctx: AssetContext;
  options: AssetContextOptions | undefined;
  onSaved: (ctx: AssetContext) => void;
  onCancel: () => void;
  onConflict: (message: string) => void;
}) {
  const [form, setForm] = useState<ContextForm>(() => toForm(ctx));
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const limits = options
    ? {
        owner: options.limits.owner_max,
        department: options.limits.department_max,
        rationale: options.limits.rationale_max,
        tags: options.limits.max_tags,
      }
    : DEFAULT_LIMITS;
  const set = <K extends keyof ContextForm>(key: K, value: ContextForm[K]) =>
    setForm((current) => ({ ...current, [key]: value }));

  async function submit(event: FormEvent) {
    event.preventDefault();
    const problems = validateForm(form, limits);
    setErrors(problems);
    if (problems.length) return;
    const body = buildUpdate(ctx, form);
    if (Object.keys(body).length === 1) {
      onCancel(); // nada cambió
      return;
    }
    setBusy(true);
    try {
      onSaved(await assetContextApi.update(ctx.asset_id, body));
    } catch (err) {
      if (err instanceof ApiError && err.code === "asset_context_conflict") {
        // Nunca se reintenta solo ni se pisa el cambio del otro: se recarga y se avisa.
        onConflict(err.message);
      } else {
        setErrors([err instanceof Error ? errorMessage(err) : String(err)]);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      className="stack panel--padded"
      onSubmit={(event) => void submit(event)}
      aria-label="Editar contexto"
    >
      <div className="fields fields--inline">
        <Select
          label="Criticidad"
          value={form.criticality}
          options={CRITICALITY_ORDER}
          labels={CRITICALITY_LABELS}
          onChange={(v) => set("criticality", v)}
        />
        <label className="form-field">
          <span>Justificación de la criticidad</span>
          <input
            className="input"
            value={form.criticality_rationale}
            maxLength={limits.rationale}
            placeholder="p. ej. Servidor de autenticación"
            onChange={(event) => set("criticality_rationale", event.target.value)}
          />
        </label>
        <Select
          label="Rol"
          value={form.role}
          options={ROLE_ORDER}
          labels={ROLE_LABELS}
          onChange={(v) => set("role", v)}
        />
        <Select
          label="Entorno"
          value={form.environment}
          options={ENVIRONMENT_ORDER}
          labels={ENVIRONMENT_LABELS}
          onChange={(v) => set("environment", v)}
        />
        <label className="form-field">
          <span>Owner</span>
          <input
            className="input"
            value={form.owner}
            maxLength={limits.owner}
            onChange={(event) => set("owner", event.target.value)}
          />
        </label>
        <label className="form-field">
          <span>Equipo/Departamento</span>
          <input
            className="input"
            list="asset-context-departments"
            value={form.department}
            maxLength={limits.department}
            onChange={(event) => set("department", event.target.value)}
          />
          <datalist id="asset-context-departments">
            {(options?.departments ?? []).map((d) => (
              <option key={d} value={d} />
            ))}
          </datalist>
        </label>
        <Select
          label="Sensibilidad"
          value={form.data_sensitivity}
          options={SENSITIVITY_ORDER}
          labels={SENSITIVITY_LABELS}
          onChange={(v) => set("data_sensitivity", v)}
        />
        <Select
          label="Zona de red"
          value={form.network_zone}
          options={ZONE_ORDER}
          labels={ZONE_LABELS}
          onChange={(v) => set("network_zone", v)}
        />
        <Select
          label="Exposición Internet"
          value={form.internet_exposed}
          options={["unknown", "true", "false"]}
          labels={{ unknown: "Desconocida", true: "Expuesto (confirmado)", false: "No expuesto" }}
          onChange={(v) => set("internet_exposed", v)}
        />
        <label className="form-field">
          <span>Tags (separados por comas)</span>
          <input
            className="input"
            value={form.tags}
            placeholder="critical-service, pci"
            onChange={(event) => set("tags", event.target.value)}
          />
        </label>
      </div>
      <p className="muted small">
        Marca "Expuesto" solo con evidencia (NAT, firewall, publicación): un puerto abierto visto desde Sentra
        no demuestra exposición a Internet. La zona de red es contexto lógico, no una VLAN.
      </p>
      {errors.length > 0 && (
        <div className="banner banner--warn" role="alert">
          {errors.map((e) => (
            <div key={e}>{e}</div>
          ))}
        </div>
      )}
      <div className="actions">
        <button type="submit" className="button button--primary" disabled={busy}>
          {busy ? "Guardando…" : "Guardar"}
        </button>
        <button type="button" className="button button--ghost" onClick={onCancel} disabled={busy}>
          Cancelar
        </button>
      </div>
    </form>
  );
}

function ThreatPanel({ assetId }: { assetId: string }) {
  const fetchSummary = useCallback(
    (signal: AbortSignal) => assetContextApi.threatSummary(assetId, signal),
    [assetId],
  );
  const { data, error } = usePolling(fetchSummary, config.refreshIntervalMs);
  return (
    <section className="panel" aria-label="Contexto de amenaza">
      <div className="panel__toolbar">
        <h2>Contexto de amenaza</h2>
        <span className="muted small">datos internos de Sentra (sin feeds externos)</span>
      </div>
      {!data ? (
        error ? (
          <p className="muted small panel--padded">{errorMessage(error)}</p>
        ) : (
          <LoadingState label="Cargando…" />
        )
      ) : (
        <dl className="fields fields--inline">
          <Field label="Detecciones activas">{data.active_detection_count}</Field>
          <Field label="Altas/críticas activas">{data.high_critical_detection_count}</Field>
          <Field label="Incidentes abiertos">
            {data.open_incident_count}
            {data.highest_incident_severity && (
              <span className="muted small"> (máx. {data.highest_incident_severity})</span>
            )}
          </Field>
          <Field label="Riesgo actual">
            {data.current_risk ? (
              `${data.current_risk.score} / ${RISK_LEVEL_LABELS[data.current_risk.level]}`
            ) : (
              <Unknown>Sin evaluar</Unknown>
            )}
          </Field>
          <Field label={`Cambios de exposición (${data.window_days} d)`}>
            {data.recent_exposure_changes}
          </Field>
          <Field label={`Cambios de contexto (${data.window_days} d)`}>{data.recent_context_changes}</Field>
          <Field label="Última actividad de seguridad">
            {data.last_security_activity ? (
              formatRelative(data.last_security_activity)
            ) : (
              <Unknown>Ninguna</Unknown>
            )}
          </Field>
        </dl>
      )}
    </section>
  );
}

function HistoryPanel({ assetId, version }: { assetId: string; version: number }) {
  const fetchHistory = useCallback(
    (signal: AbortSignal) => assetContextApi.history(assetId, signal),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [assetId, version],
  );
  const { data } = usePolling(fetchHistory, config.refreshIntervalMs);
  if (!data || data.items.length === 0) return null;
  return (
    <section className="panel" aria-label="Historial de contexto">
      <div className="panel__toolbar">
        <h2>Historial de contexto</h2>
        <span className="muted small">{data.total} cambios</span>
      </div>
      <div className="table-wrap">
        <table className="table table--compact">
          <thead>
            <tr>
              <th>Cuándo</th>
              <th>Campo</th>
              <th>Antes</th>
              <th>Después</th>
              <th>Quién</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((item, index) => (
              <tr key={`${item.changed_at}-${item.field}-${index}`}>
                <td title={formatDateTime(item.changed_at)}>{formatRelative(item.changed_at)}</td>
                <td>{FIELD_LABELS[item.field] ?? item.field}</td>
                <td className="muted">{item.old_value ?? "—"}</td>
                <td>{item.new_value ?? "—"}</td>
                <td>
                  {item.actor}{" "}
                  <span className="muted small">({SOURCE_LABELS[item.source] ?? item.source})</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/**
 * Pestaña "Contexto" del activo (Fase 4L): qué función tiene, quién responde, entorno,
 * sensibilidad, zona, exposición y tags, con su procedencia. Todos los roles leen; solo admin
 * (assets:manage) edita. "Desconocido" se muestra como dato que falta, nunca como amenaza.
 */
export function ContextTab({ assetId }: { assetId: string }) {
  const auth = useAuth();
  const canEdit = auth.can("assets:manage");
  const fetchContext = useCallback((signal: AbortSignal) => assetContextApi.get(assetId, signal), [assetId]);
  const { data, error, loading, refresh } = usePolling(fetchContext, config.refreshIntervalMs);
  // Respuesta del PATCH: se muestra al momento hasta que un sondeo traiga esa versión o más.
  const [saved, setSaved] = useState<AssetContext>();
  const [editing, setEditing] = useState(false);
  const [notice, setNotice] = useState<string>();
  const [options, setOptions] = useState<AssetContextOptions>();
  const ctx = saved && (!data || saved.version > data.version) ? saved : data;

  useEffect(() => {
    if (!editing || options) return;
    const controller = new AbortController();
    assetContextApi.options(controller.signal).then(setOptions, () => undefined);
    return () => controller.abort();
  }, [editing, options]);

  if (loading) return <LoadingState label="Cargando contexto…" />;
  if (!ctx) return <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />;

  const { completeness } = ctx;
  return (
    <div className="stack">
      <section className="panel" aria-label="Contexto del activo">
        <div className="panel__toolbar">
          <h2>
            Contexto del activo{" "}
            <span
              className={`badge ${completeness.complete ? "badge--ok" : ""}`}
              title="Calidad del inventario, no nivel de seguridad"
            >
              {completeness.complete
                ? "Contexto completo"
                : `Contexto incompleto · ${completeness.percent} %`}
            </span>
          </h2>
          {canEdit && !editing && (
            <button
              type="button"
              className="button button--small"
              onClick={() => {
                setNotice(undefined);
                setEditing(true);
              }}
            >
              Editar
            </button>
          )}
        </div>
        {notice && (
          <div className="banner banner--warn" role="alert">
            {notice}
          </div>
        )}
        {editing ? (
          <ContextEditor
            key={ctx.version}
            ctx={ctx}
            options={options}
            onSaved={(next) => {
              setSaved(next);
              setEditing(false);
            }}
            onCancel={() => setEditing(false)}
            onConflict={(message) => {
              setNotice(message);
              setEditing(false);
              setSaved(undefined);
              refresh();
            }}
          />
        ) : (
          <ContextView ctx={ctx} />
        )}
        {!canEdit && (
          <p className="muted small panel--padded">Solo lectura: el contexto lo edita un administrador.</p>
        )}
      </section>
      <ThreatPanel assetId={assetId} />
      <HistoryPanel assetId={assetId} version={ctx.version} />
    </div>
  );
}
