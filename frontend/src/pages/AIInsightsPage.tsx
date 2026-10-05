// AI Security Insights (Fase 4J): estado de la IA, Ask Sentra AI, resumen SOC e historial.
//
// Nada aquí llama al modelo sin una acción explícita del usuario: el historial solo lee
// análisis guardados. La pregunta viaja al backend, que decide qué datos de Sentra leer
// (el modelo nunca consulta la base de datos ni ejecuta herramientas).
import { useCallback, useState } from "react";
import { aiApi } from "../api/sentra";
import type { AIWindow, Insight } from "../api/types";
import { AINotAvailable, useAIStatus } from "../components/ai/AIAnalyzePanel";
import { InsightMeta, InsightView } from "../components/ai/InsightView";
import { ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { KIND_LABELS } from "../lib/ai";
import { errorMessage } from "../lib/format";
import { usePolling } from "../lib/usePolling";

const EXAMPLES = [
  "¿Qué activos debería revisar primero?",
  "Resume las detecciones críticas de las últimas 24 horas.",
  "¿Qué cambió en el riesgo esta semana?",
];

const WINDOWS: { value: AIWindow; label: string }[] = [
  { value: "24h", label: "24 horas" },
  { value: "7d", label: "7 días" },
  { value: "30d", label: "30 días" },
];

export function AIInsightsPage() {
  const { status, error: statusError } = useAIStatus();
  const [question, setQuestion] = useState("");
  const [socWindow, setSocWindow] = useState<AIWindow>("24h");
  const [current, setCurrent] = useState<Insight>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [selected, setSelected] = useState<string>();

  const fetchHistory = useCallback((signal: AbortSignal) => aiApi.list({ limit: 25 }, signal), []);
  const history = usePolling(fetchHistory, Math.max(config.refreshIntervalMs, 30_000));

  async function run(action: () => Promise<Insight>) {
    setBusy(true);
    setError(undefined);
    try {
      setCurrent(await action());
      history.refresh();
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
    } finally {
      setBusy(false);
    }
  }

  const available = Boolean(status?.available);
  const trimmed = question.trim();
  return (
    <div className="page">
      <div className="page__header">
        <h1>AI Security Insights</h1>
        {status && (
          <span className="muted small">
            {status.available
              ? `Modelo ${status.model ?? "—"} · ${status.location === "external" ? "proveedor externo" : "local"}${
                  status.redaction.length ? ` · seudonimiza ${status.redaction.join(", ")}` : ""
                }`
              : "IA no disponible"}
          </span>
        )}
      </div>
      {statusError && <ErrorState message={errorMessage(statusError)} />}
      {status && !available && (
        <section className="panel panel--padded">
          <AINotAvailable status={status} />
        </section>
      )}

      {available && (
        <section className="panel panel--padded ai-ask" aria-label="Ask Sentra AI">
          <h2>Ask Sentra AI</h2>
          <p className="muted small">
            Responde solo con datos de Sentra (detecciones, riesgo, exposición). No ejecuta acciones.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (trimmed.length >= 3) void run(() => aiApi.ask(trimmed));
            }}
          >
            <textarea
              className="input"
              rows={2}
              maxLength={500}
              value={question}
              placeholder="¿Por qué este equipo tiene riesgo alto?"
              aria-label="Pregunta para Sentra AI"
              onChange={(e) => setQuestion(e.target.value)}
            />
            <div className="actions">
              <button type="submit" className="button button--primary" disabled={busy || trimmed.length < 3}>
                {busy ? "Analizando…" : "Preguntar"}
              </button>
              {EXAMPLES.map((example) => (
                <button
                  key={example}
                  type="button"
                  className="button button--ghost button--small"
                  disabled={busy}
                  onClick={() => setQuestion(example)}
                >
                  {example}
                </button>
              ))}
            </div>
          </form>
          <div className="actions ai-soc">
            <span className="strong">Resumen SOC</span>
            <select
              className="input"
              value={socWindow}
              aria-label="Ventana del resumen"
              onChange={(e) => setSocWindow(e.target.value as AIWindow)}
            >
              {WINDOWS.map((w) => (
                <option key={w.value} value={w.value}>
                  {w.label}
                </option>
              ))}
            </select>
            <button type="button" className="button" disabled={busy} onClick={() => void run(() => aiApi.socSummary(socWindow))}>
              Generar resumen SOC
            </button>
          </div>
          {error && (
            <p className="banner banner--warn" role="alert">
              {error}
            </p>
          )}
          {current && <InsightView insight={current} />}
        </section>
      )}

      <section className="panel panel--padded" aria-label="Historial de análisis">
        <h2>Historial</h2>
        {history.loading && <LoadingState label="Cargando análisis…" />}
        {history.error && !history.data && <ErrorState message={errorMessage(history.error)} onRetry={history.refresh} />}
        {history.data && history.data.items.length === 0 && <p className="muted">Todavía no hay análisis.</p>}
        <ul className="ai-history">
          {history.data?.items.map((item) => (
            <li key={item.insight_id}>
              <button
                type="button"
                className="ai-history__item"
                aria-expanded={selected === item.insight_id}
                onClick={() => setSelected(selected === item.insight_id ? undefined : item.insight_id)}
              >
                <span className="strong">{item.question ?? item.asset_name ?? KIND_LABELS[item.kind]}</span>
                <InsightMeta insight={item} />
              </button>
              {selected === item.insight_id && <InsightView insight={item} />}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
