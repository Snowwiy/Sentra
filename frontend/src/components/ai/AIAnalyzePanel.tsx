// Botón "Analizar con IA" reutilizable (Asset Detail, Detection Detail, Riesgo, Incidentes).
//
// El análisis solo se pide al pulsar (nunca al cargar la página ni en el sondeo): cada
// llamada al modelo cuesta y está limitada por usuario en el servidor. Al abrir se muestra
// el último análisis guardado de esa entidad, marcado como desactualizado si procede.
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { aiApi } from "../../api/sentra";
import type { AIProviderState, AIStatus, Insight, InsightKind } from "../../api/types";
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

const STATE_LABELS: Record<AIProviderState, string> = {
  disabled: "Desactivada",
  not_configured: "Sin configurar",
  local_available: "Disponible",
  local_unavailable: "No disponible",
  external_blocked: "Bloqueado",
  external_available: "Disponible",
  external_unavailable: "No disponible",
};

/**
 * Modo, modelo y estado del proveedor. Se muestra "Local AI" o "External AI" según dónde
 * está el servidor, nunca el nombre del protocolo: un modelo local OpenAI-compatible no es
 * "OpenAI".
 */
export function AIProviderBadge({ status }: { status: AIStatus }) {
  const ok = status.state === "local_available" || status.state === "external_available";
  const tone = ok ? "badge--ok" : status.state === "disabled" || status.state === "not_configured" ? "" : "badge--warn";
  const parts = [status.mode_label ?? "IA", status.model, STATE_LABELS[status.state]].filter(Boolean);
  return (
    <span className={`badge ${tone}`.trim()} aria-label="Estado de la IA">
      {parts.join(" · ")}
    </span>
  );
}

export function AIUnreachable({ status }: { status: AIStatus }) {
  if (status.reachable !== false) return null;
  return (
    <p className="banner banner--warn small" role="note">
      {status.location === "local"
        ? "El servidor de IA local no responde. Sentra sigue funcionando; no se usará ningún otro proveedor."
        : "El proveedor de IA no responde. Sentra sigue funcionando sin IA."}
    </p>
  );
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
  /** Fase 4K: análisis de un incidente (solo lectura; nunca cambia el caso). */
  incidentId?: string;
  run: (refresh: boolean) => Promise<Insight>;
}

export function AIAnalyzePanel({ title, buttonLabel, kind, assetId, detectionId, incidentId, run }: Props) {
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
      .list(
        { kind, assetId: kind === "detection_analysis" ? undefined : assetId, detectionId, incidentId, limit: 1 },
        controller.signal,
      )
      .then((list) => {
        if (list.items[0]) setInsight((current) => current ?? list.items[0]);
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [allowed, kind, assetId, detectionId, incidentId]);

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
      {status?.available && <AIUnreachable status={status} />}
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
