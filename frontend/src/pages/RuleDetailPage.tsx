import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { detectionsApi, rulesApi } from "../api/sentra";
import type {
  AuditEventList,
  DetectionList,
  HistoricalTestResult,
  RuleDetail,
  RuleDiff,
  RuleVersionList,
  SigmaSource,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import {
  CATEGORY_LABELS,
  ConfidenceBadge,
  DetectionSeverityBadge,
  DetectionStatusBadge,
} from "../components/detections/DetectionBadges";
import { ConfirmDialog } from "../components/Modal";
import { CompileBadge, IssueList, RuleSourceBadge, RuleStatusBadge } from "../components/rules/RuleBadges";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { displayValue } from "../lib/rules";
import { usePolling } from "../lib/usePolling";

type Tab = "overview" | "logic" | "versions" | "detections" | "tests" | "audit";

const TABS: { key: Tab; label: string }[] = [
  { key: "overview", label: "Resumen" },
  { key: "logic", label: "Lógica" },
  { key: "versions", label: "Versiones" },
  { key: "detections", label: "Detecciones" },
  { key: "tests", label: "Pruebas" },
  { key: "audit", label: "Auditoría" },
];

type Action = "enable" | "disable" | "retire" | "unretire";

const ACTION_TEXT: Record<Action, { label: string; confirm: string; danger?: boolean }> = {
  enable: { label: "Activar", confirm: "La regla empezará a evaluarse en el siguiente lote del motor." },
  disable: { label: "Desactivar", confirm: "La regla deja de evaluarse. Sus detecciones se conservan." },
  retire: {
    label: "Retirar",
    confirm: "Retirar no borra: la regla, sus versiones y sus detecciones se conservan como historial.",
    danger: true,
  },
  unretire: { label: "Recuperar", confirm: "La regla vuelve como desactivada; activarla es otra acción." },
};

const errorText = (err: unknown) => errorMessage(err instanceof Error ? err : new Error(String(err)));

/** Detalle de una regla: resumen, lógica, versiones, detecciones, pruebas y auditoría. */
export function RuleDetailPage() {
  const { ruleId = "" } = useParams();
  const auth = useAuth();
  const [tab, setTab] = useState<Tab>("overview");
  const [action, setAction] = useState<Action>();
  const [ackPartial, setAckPartial] = useState(false);

  const fetchRule = useCallback((signal: AbortSignal) => rulesApi.get(ruleId, signal), [ruleId]);
  const { data: rule, error, loading, refresh } = usePolling(fetchRule, config.refreshIntervalMs);

  if (loading) return <LoadingState label="Cargando regla…" />;
  if (!rule) return <ErrorState message={error ? errorMessage(error) : "Regla no encontrada"} onRetry={refresh} />;

  const manage = auth.can("rules:manage") && !rule.read_only;
  const actions: Action[] = !manage
    ? []
    : rule.status === "retired"
      ? ["unretire"]
      : rule.status === "active"
        ? ["disable", "retire"]
        : ["enable", "retire"];
  const tabs = TABS.filter((t) => t.key !== "audit" || auth.can("audit:read"));

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <Link to="/detections/rules" className="back">
            ← Reglas
          </Link>
          <h1>{rule.title}</h1>
          <div className="actions">
            <span className="mono">{rule.rule_id}</span>
            <span className="mono muted">v{rule.version}</span>
            <RuleSourceBadge source={rule.source} />
            <RuleStatusBadge status={rule.status} />
            <CompileBadge status={rule.compile_status} />
            <DetectionSeverityBadge severity={rule.severity} />
            <ConfidenceBadge confidence={rule.confidence} />
          </div>
        </div>
        {manage && (
          <div className="actions">
            {rule.status !== "retired" && (
              <Link to={`/detections/rules/${encodeURIComponent(rule.rule_id)}/edit`} className="button">
                Editar
              </Link>
            )}
            {actions.map((a) => (
              <button
                key={a}
                type="button"
                className={`button${a === "enable" ? " button--primary" : ""}`}
                onClick={() => setAction(a)}
                disabled={a === "enable" && !["valid", "partial"].includes(rule.compile_status)}
              >
                {ACTION_TEXT[a].label}
              </button>
            ))}
          </div>
        )}
      </div>
      {rule.read_only && (
        <div className="banner" role="note">
          Regla built-in: vive en el código de Sentra y es de solo lectura. Se desactiva con DETECTION_DISABLED_RULES en el
          servidor.
        </div>
      )}
      {error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}
      {rule.consecutive_errors >= 10 && (
        <div className="banner banner--warn" role="alert">
          La regla falla de forma repetida ({rule.consecutive_errors} errores seguidos). Revisa su lógica.
        </div>
      )}

      <nav className="tabs" role="tablist" aria-label="Secciones de la regla">
        {tabs.map(({ key, label }) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={`tabs__item${tab === key ? " tabs__item--active" : ""}`}
            onClick={() => setTab(key)}
          >
            {label}
          </button>
        ))}
      </nav>
      <div role="tabpanel">
        {tab === "overview" && <OverviewTab rule={rule} />}
        {tab === "logic" && <LogicTab rule={rule} />}
        {tab === "versions" && <VersionsTab rule={rule} manage={manage} onChanged={refresh} />}
        {tab === "detections" && <DetectionsTab ruleId={rule.rule_id} />}
        {tab === "tests" && <TestsTab rule={rule} />}
        {tab === "audit" && <AuditTab ruleId={rule.rule_id} />}
      </div>

      {action && (
        <ConfirmDialog
          title={`${ACTION_TEXT[action].label} ${rule.rule_id}`}
          confirmLabel={ACTION_TEXT[action].label}
          danger={ACTION_TEXT[action].danger}
          onClose={() => {
            setAction(undefined);
            setAckPartial(false);
          }}
          onConfirm={async () => {
            await rulesApi.setState(rule.rule_id, action, rule.revision ?? 1, ackPartial);
            refresh();
          }}
        >
          <p>{ACTION_TEXT[action].confirm}</p>
          {action === "enable" && rule.compile_status === "partial" && (
            <label className="form-field form-field--inline">
              <input type="checkbox" checked={ackPartial} onChange={(e) => setAckPartial(e.target.checked)} />
              <span className="small">Entiendo que esta regla solo cubre parcialmente su logsource</span>
            </label>
          )}
        </ConfirmDialog>
      )}
    </div>
  );
}

function OverviewTab({ rule }: { rule: RuleDetail }) {
  const stats = rule.stats;
  return (
    <div className="detail-grid">
      <section className="panel panel--padded stack">
        {rule.description && <p>{rule.description}</p>}
        {rule.why && (
          <div>
            <h3>Por qué importa</h3>
            <p>{rule.why}</p>
          </div>
        )}
        {rule.recommendations.length > 0 && (
          <div>
            <h3>Qué revisar</h3>
            <ul className="recommendations">
              {rule.recommendations.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </div>
        )}
      </section>
      <section className="panel">
        <dl className="fields">
          <Field label="Categoría">{CATEGORY_LABELS[rule.category] ?? rule.category}</Field>
          <Field label="Logsource">{rule.logsource_title ?? rule.logsource ?? "—"}</Field>
          <Field label="MITRE">
            <span className="mono">
              {[rule.mitre_tactic, rule.mitre_subtechnique ?? rule.mitre_technique].filter(Boolean).join(" · ") || "—"}
            </span>
          </Field>
          <Field label="Cooldown">{rule.cooldown_minutes} min</Field>
          <Field label="Detecciones 24 h">{rule.detections_24h}</Field>
          <Field label="Detecciones totales">{rule.detections_total}</Field>
          <Field label="Última detección">{formatRelative(rule.last_triggered_at)}</Field>
          <Field label="Evaluaciones">{stats.evaluations}</Field>
          <Field label="Coincidencias">{stats.matches}</Field>
          <Field label="Errores">
            {stats.errors}
            {stats.last_error ? ` (último: ${stats.last_error})` : ""}
          </Field>
          <Field label="Tiempo medio">{stats.avg_eval_ms === null ? "—" : `${stats.avg_eval_ms.toFixed(3)} ms`}</Field>
          <Field label="Actualizada">
            {rule.updated_at ? `${formatDateTime(rule.updated_at)} · ${rule.updated_by ?? ""}` : "—"}
          </Field>
          {rule.sigma_id && (
            <Field label="Sigma id">
              <span className="mono">{rule.sigma_id}</span>
            </Field>
          )}
          {rule.tags.length > 0 && <Field label="Etiquetas">{rule.tags.join(", ")}</Field>}
        </dl>
      </section>
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function LogicTab({ rule }: { rule: RuleDetail }) {
  const [sigma, setSigma] = useState<SigmaSource>();
  const [sigmaError, setSigmaError] = useState<string>();
  useEffect(() => {
    if (!rule.has_sigma_source) return;
    const controller = new AbortController();
    rulesApi
      .sigmaSource(rule.rule_id, controller.signal)
      .then(setSigma)
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setSigmaError(errorText(err));
      });
    return () => controller.abort();
  }, [rule.rule_id, rule.has_sigma_source]);

  if (rule.read_only) {
    return (
      <section className="panel panel--padded stack">
        <p className="muted">La lógica de las reglas built-in está en el código (docs/detection-engine.md).</p>
        <Field label="Datos que usa">{rule.required_data.join(", ") || "—"}</Field>
      </section>
    );
  }
  return (
    <section className="panel panel--padded stack">
      <IssueList issues={rule.compile_issues} tone={rule.compile_status === "valid" ? "warn" : "crit"} />
      {rule.complexity && <p className="muted small">Complejidad: {rule.complexity}</p>}
      <div>
        <h3>Definición (sentra-rule/1)</h3>
        <pre className="code-block">{displayValue(rule.definition)}</pre>
      </div>
      {sigma && (
        <div>
          <h3>YAML Sigma original</h3>
          {/* Texto: React lo escapa; el YAML nunca se interpreta como HTML. */}
          <pre className="code-block">{sigma.yaml}</pre>
        </div>
      )}
      {sigmaError && <p className="text-warn small">{sigmaError}</p>}
    </section>
  );
}

function VersionsTab({ rule, manage, onChanged }: { rule: RuleDetail; manage: boolean; onChanged: () => void }) {
  const [versions, setVersions] = useState<RuleVersionList>();
  const [diff, setDiff] = useState<RuleDiff>();
  const [restore, setRestore] = useState<number>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    if (rule.read_only) return;
    const controller = new AbortController();
    rulesApi
      .versions(rule.rule_id, controller.signal)
      .then(setVersions)
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(errorText(err));
      });
    return () => controller.abort();
  }, [rule.rule_id, rule.version, rule.read_only]);

  if (rule.read_only) return <EmptyState title="Las reglas built-in se versionan con Sentra" />;
  if (error) return <ErrorState message={error} />;
  if (!versions) return <LoadingState label="Cargando versiones…" />;
  return (
    <section className="panel stack">
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Versión</th>
              <th>Fecha</th>
              <th>Autor</th>
              <th>Cambio</th>
              <th>Compilación</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {versions.items.map((v) => (
              <tr key={v.version}>
                <td className="mono">
                  v{v.version}
                  {v.current ? " (vigente)" : ""}
                </td>
                <td>{formatDateTime(v.created_at)}</td>
                <td>{v.created_by}</td>
                <td>{v.change_note}</td>
                <td>
                  <CompileBadge status={v.compile_status} />
                </td>
                <td className="actions">
                  {v.version > 1 && (
                    <button
                      type="button"
                      className="button button--small"
                      onClick={() =>
                        void rulesApi
                          .diff(rule.rule_id, v.version - 1, v.version)
                          .then(setDiff)
                          .catch((err: unknown) => setError(errorText(err)))
                      }
                    >
                      Diferencias
                    </button>
                  )}
                  {manage && !v.current && rule.status !== "retired" && rule.source !== "sigma" && (
                    <button type="button" className="button button--small" onClick={() => setRestore(v.version)}>
                      Restaurar
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {diff && (
        <div className="panel--padded">
          <h3>
            v{diff.from_version} → v{diff.to_version}
          </h3>
          {diff.changes.length === 0 ? (
            <p className="muted">Sin cambios de contenido.</p>
          ) : (
            <table className="table table--compact table--wrap">
              <thead>
                <tr>
                  <th>Campo</th>
                  <th>Antes</th>
                  <th>Después</th>
                </tr>
              </thead>
              <tbody>
                {diff.changes.map((c) => (
                  <tr key={c.field}>
                    <td className="mono">{c.field}</td>
                    <td>
                      <pre className="code-block">{displayValue(c.before)}</pre>
                    </td>
                    <td>
                      <pre className="code-block">{displayValue(c.after)}</pre>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
      {restore !== undefined && (
        <ConfirmDialog
          title={`Restaurar v${restore}`}
          confirmLabel="Restaurar"
          onClose={() => setRestore(undefined)}
          onConfirm={async () => {
            await rulesApi.restore(rule.rule_id, restore, rule.revision ?? 1);
            onChanged();
          }}
        >
          <p>Se crea la versión v{rule.version + 1} con el contenido de v{restore}. La historia no se reescribe.</p>
        </ConfirmDialog>
      )}
    </section>
  );
}

function DetectionsTab({ ruleId }: { ruleId: string }) {
  const fetchDetections = useCallback(
    (signal: AbortSignal) => detectionsApi.list({ ruleId, limit: 50, offset: 0 }, signal),
    [ruleId],
  );
  const { data, error, loading } = usePolling<DetectionList>(fetchDetections, config.refreshIntervalMs);
  if (loading) return <LoadingState label="Cargando detecciones…" />;
  if (!data) return <ErrorState message={error ? errorMessage(error) : "Sin datos"} />;
  if (data.items.length === 0) return <EmptyState title="Esta regla no ha generado detecciones" />;
  return (
    <section className="panel">
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Severidad</th>
              <th>Activo</th>
              <th>Título</th>
              <th>Versión</th>
              <th>Última vez</th>
              <th>Estado</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((d) => (
              <tr key={d.detection_id}>
                <td>
                  <DetectionSeverityBadge severity={d.severity} />
                </td>
                <td>{d.hostname}</td>
                <td>
                  <Link to={`/detections/${d.detection_id}`}>{d.title}</Link>
                </td>
                <td className="mono">v{d.rule_version}</td>
                <td title={formatDateTime(d.last_seen_at)}>{formatRelative(d.last_seen_at)}</td>
                <td>
                  <DetectionStatusBadge status={d.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

const HOURS = [
  { value: 1, label: "Última hora" },
  { value: 24, label: "Últimas 24 h" },
  { value: 72, label: "Últimas 72 h" },
];

function TestsTab({ rule }: { rule: RuleDetail }) {
  const auth = useAuth();
  const [hours, setHours] = useState(24);
  const [result, setResult] = useState<HistoricalTestResult>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  if (rule.read_only) return <EmptyState title="Las reglas built-in no se prueban desde aquí" />;
  if (!auth.can("rules:manage")) {
    return (
      <EmptyState title="La prueba histórica es solo para administradores">
        Lee datos reales del despliegue; la prueba con eventos sintéticos está en el editor.
      </EmptyState>
    );
  }
  const run = async () => {
    setBusy(true);
    setError(undefined);
    try {
      setResult(
        await rulesApi.testHistorical(
          { rule_id: rule.rule_id },
          { since: new Date(Date.now() - hours * 3_600_000).toISOString() },
        ),
      );
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="panel panel--padded stack">
      <p className="muted small">
        Ejecuta la versión vigente sobre datos guardados, en solo lectura y con límites de tiempo y filas. No crea
        detecciones, alertas ni incidentes, no cambia el riesgo y nunca usa la IA.
      </p>
      <div className="actions">
        <select
          className="input input--select"
          value={hours}
          onChange={(e) => setHours(Number(e.target.value))}
          aria-label="Periodo de la prueba"
        >
          {HOURS.map((h) => (
            <option key={h.value} value={h.value}>
              {h.label}
            </option>
          ))}
        </select>
        <button type="button" className="button" onClick={() => void run()} disabled={busy}>
          {busy ? "Probando…" : "Probar con datos históricos"}
        </button>
      </div>
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      {result && (
        <div className="stack" role="status">
          <p>
            {result.scanned} registros examinados ({result.data_source}), {result.matched} coincidencias
            {result.truncated ? " (se alcanzó el máximo de filas: hay más datos sin examinar)" : ""}.
            {result.threshold !== null && ` Grupos que alcanzan el umbral: ${result.would_detect.length}.`}
          </p>
          {result.notes.map((note) => (
            <p key={note} className="muted small">
              {note}
            </p>
          ))}
          {result.sample.length > 0 && (
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Cuándo</th>
                  <th>Activo</th>
                  <th>Resumen</th>
                </tr>
              </thead>
              <tbody>
                {result.sample.map((m, index) => (
                  <tr key={`${m.occurred_at}-${index}`}>
                    <td>{formatDateTime(m.occurred_at)}</td>
                    <td>{m.hostname}</td>
                    <td>{m.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </section>
  );
}

function AuditTab({ ruleId }: { ruleId: string }) {
  const [audit, setAudit] = useState<AuditEventList>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    const controller = new AbortController();
    rulesApi
      .audit(ruleId, controller.signal)
      .then(setAudit)
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(errorText(err));
      });
    return () => controller.abort();
  }, [ruleId]);
  if (error) return <ErrorState message={error} />;
  if (!audit) return <LoadingState label="Cargando auditoría…" />;
  if (audit.items.length === 0) return <EmptyState title="Sin eventos de auditoría" />;
  return (
    <section className="panel">
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Cuándo</th>
              <th>Acción</th>
              <th>Resultado</th>
              <th>Quién</th>
              <th>Detalle</th>
            </tr>
          </thead>
          <tbody>
            {audit.items.map((event) => (
              <tr key={`${event.created_at}-${event.action}`}>
                <td>{formatDateTime(event.created_at)}</td>
                <td className="mono">{event.action}</td>
                <td>{event.result}</td>
                <td>{event.actor}</td>
                <td className="small">{event.details ? JSON.stringify(event.details) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
