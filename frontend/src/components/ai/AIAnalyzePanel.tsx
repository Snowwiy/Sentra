// Botón "Analizar con IA" reutilizable (Asset Detail, Detection Detail, Riesgo).
//
// El análisis solo se pide al pulsar (nunca al cargar la página ni en el sondeo): cada
// llamada al modelo cuesta y está limitada por usuario en el servidor. Al abrir se muestra
// el último análisis guardado de esa entidad, marcado como desactualizado si procede.
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { aiApi } from "../../api/sentra";
import type { AIStatus, Insight, InsightKind } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { errorMessage } from "../../lib/format";
import { InsightView } from "./InsightView";

export function useAIStatus(): { status?: AIStatus; error?: Error } {
  const [status, setStatus] = useState<AIStatus>();
  const [error, setError] = useState<Error>();
  useEffect(() => {
    const controller = new AbortController();
    aiApi
      .status(controller.signal)
      .then(setStatus)
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(err instanceof Error ? err : new Error(String(err)));
      });
    return () => controller.abort();
  }, []);
  return { status, error };
}

export function AINotAvailable({ status }: { status: AIStatus }) {
  return (
    <p className="muted small" role="note">
      {status.reason ?? "IA no configurada."} El resto de Sentra funciona igual sin IA.
    </p>
  );
}

interface Props {
  title: string;
  buttonLabel: string;
  kind: InsightKind;
  assetId?: string;
  detectionId?: string;
  run: (refresh: boolean) => Promise<Insight>;
}

export function AIAnalyzePanel({ title, buttonLabel, kind, assetId, detectionId, run }: Props) {
  const auth = useAuth();
  const { status, error: statusError } = useAIStatus();
  const [insight, setInsight] = useState<Insight>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const allowed = auth.can("ai:use");

  // Último análisis guardado (lectura barata: no llama al modelo).
  useEffect(() => {
    if (!allowed) return;
    const controller = new AbortController();
    aiApi
      .list({ kind, assetId: kind === "detection_analysis" ? undefined : assetId, detectionId, limit: 1 }, controller.signal)
      .then((list) => {
        if (list.items[0]) setInsight((current) => current ?? list.items[0]);
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [allowed, kind, assetId, detectionId]);

  const analyze = useCallback(
    async (refresh: boolean) => {
      setBusy(true);
      setError(undefined);
      try {
        setInsight(await run(refresh));
      } catch (err) {
        setError(err instanceof Error ? errorMessage(err) : String(err));
      } finally {
        setBusy(false);
      }
    },
    [run],
  );

  if (!allowed) return null;
  return (
    <section className="panel panel--padded ai-panel" aria-label={title}>
      <div className="ai-panel__head">
        <h2>{title}</h2>
        {status?.available && (
          <div className="actions">
            <button type="button" className="button button--primary" disabled={busy} onClick={() => void analyze(false)}>
              {busy ? "Analizando…" : buttonLabel}
            </button>
            {insight && (
              <button type="button" className="button" disabled={busy} onClick={() => void analyze(true)}>
                Regenerar
              </button>
            )}
          </div>
        )}
      </div>
      {statusError && <p className="muted small">No se pudo consultar el estado de la IA.</p>}
      {status && !status.available && <AINotAvailable status={status} />}
      {error && (
        <p className="banner banner--warn" role="alert">
          {error}
        </p>
      )}
      {insight ? (
        <InsightView insight={insight} />
      ) : (
        status?.available && (
          <p className="muted small">
            Sin análisis todavía. La IA interpreta los datos de Sentra; no cambia severidades ni el riesgo.{" "}
            <Link to="/ai">Ver AI Insights</Link>
          </p>
        )
      )}
    </section>
  );
}
